package route

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/cors"
	"github.com/metacubex/chi/middleware"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

var (
	settingsMu sync.RWMutex
	uiPath     = ""
	serverMu   sync.Mutex

	httpServer controllerServer
	tlsServer  controllerServer
	unixServer controllerServer
	pipeServer controllerServer

	embedMode = false
)

func SetEmbedMode(embed bool) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	embedMode = embed
}

type Traffic struct {
	Up        int64 `json:"up"`
	Down      int64 `json:"down"`
	UpTotal   int64 `json:"upTotal"`
	DownTotal int64 `json:"downTotal"`
}

type Memory struct {
	Inuse   uint64 `json:"inuse"`
	OSLimit uint64 `json:"oslimit"` // maybe we need it in the future
}

type Config struct {
	Addr           string
	TLSAddr        string
	UnixAddr       string
	PipeAddr       string
	RoutingMark    int
	Secret         string
	Certificate    string
	PrivateKey     string
	ClientAuthType string
	ClientAuthCert string
	EchKey         string
	DohServer      string
	IsDebug        bool
	Cors           Cors
}

type Cors struct {
	AllowOrigins        []string
	AllowPrivateNetwork bool
}

func (c Cors) Apply(r chi.Router) {
	r.Use(cors.New(cors.Options{
		AllowedOrigins:      c.AllowOrigins,
		AllowedMethods:      []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowedHeaders:      []string{"Content-Type", "Authorization"},
		AllowPrivateNetwork: c.AllowPrivateNetwork,
		MaxAge:              300,
	}).Handler)
}

// ReCreateServer serializes listener ownership. Only serving runs in goroutines:
// when this returns, a stopped listener cannot be resurrected by an older startup.
func ReCreateServer(cfg *Config) {
	if cfg == nil {
		cfg = &Config{}
	}
	snapshot := *cfg
	snapshot.Cors.AllowOrigins = slices.Clone(cfg.Cors.AllowOrigins)
	serverMu.Lock()
	defer serverMu.Unlock()
	httpServer.close()
	tlsServer.close()
	unixServer.close()
	pipeServer.close()
	start(&snapshot)
	startTLS(&snapshot)
	startUnix(&snapshot)
	if inbound.SupportNamedPipe {
		startPipe(&snapshot)
	}
}

// Keep the listener as well as the server: Close can run before Serve has registered
// its listener. Closing only http.Server in that window leaves the port bound.
// All slot fields belong to serverMu; the goroutine only captures local values.
type controllerServer struct {
	server   *http.Server
	listener net.Listener
	done     chan struct{}
}

func (c *controllerServer) close() {
	if c.listener != nil {
		_ = c.listener.Close()
	}
	if c.server != nil {
		_ = c.server.Close()
	}
	if c.done != nil {
		<-c.done
	}
	*c = controllerServer{}
}

func (c *controllerServer) serve(listener net.Listener, handler http.Handler, kind string) {
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	c.server, c.listener, c.done = server, listener, done
	go func() {
		defer close(done)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			log.Errorln("External controller %s serve error: %s", kind, err)
		}
	}()
}

func SetUIPath(path string) {
	resolved := C.Path.Resolve(path)
	settingsMu.Lock()
	defer settingsMu.Unlock()
	uiPath = resolved
}

func router(isDebug bool, secret string, dohServer string, cors Cors) *chi.Mux {
	settingsMu.RLock()
	embedded, directory := embedMode, uiPath
	settingsMu.RUnlock()
	r := chi.NewRouter()
	cors.Apply(r)
	if isDebug {
		r.Mount("/debug", func() http.Handler {
			r := chi.NewRouter()
			r.Put("/gc", func(w http.ResponseWriter, r *http.Request) {
				debug.FreeOSMemory()
			})
			handler := middleware.Profiler
			r.Mount("/", handler())
			return r
		}())
	}
	r.Group(func(r chi.Router) {
		if secret != "" {
			r.Use(authentication(secret))
		}
		r.Get("/", hello)
		r.Get("/logs", getLogs)
		r.Get("/traffic", traffic)
		r.Get("/memory", memory)
		r.Get("/version", version)
		r.Mount("/configs", configRouter(embedded))
		r.Mount("/proxies", proxyRouter())
		r.Mount("/group", groupRouter())
		r.Mount("/rules", ruleRouter(embedded))
		r.Mount("/connections", connectionRouter())
		r.Mount("/providers/proxies", proxyProviderRouter())
		r.Mount("/providers/rules", ruleProviderRouter())
		r.Mount("/cache", cacheRouter())
		r.Mount("/dns", dnsRouter())
		r.Mount("/storage", storageRouter())
		if !embedded { // disallow restart in embed mode
			r.Mount("/restart", restartRouter())
		}
		r.Mount("/upgrade", upgradeRouter(embedded))
		addExternalRouters(r)

	})

	if directory != "" {
		r.Group(func(r chi.Router) {
			fs := http.StripPrefix("/ui", http.FileServer(http.Dir(directory)))
			r.Get("/ui", http.RedirectHandler("/ui/", http.StatusTemporaryRedirect).ServeHTTP)
			r.Get("/ui/*", func(w http.ResponseWriter, r *http.Request) {
				fs.ServeHTTP(w, r)
			})
		})
	}
	if len(dohServer) > 0 && dohServer[0] == '/' {
		r.Mount(dohServer, dohRouter())
	}

	return r
}

func start(cfg *Config) {
	if cfg.Addr == "" {
		return
	}
	lc := inbound.NewListenConfig()
	lc.SetRouteMark(cfg.RoutingMark)
	listener, err := lc.Listen(context.Background(), "tcp", cfg.Addr)
	if err != nil {
		log.Errorln("External controller listen error: %s", err)
		return
	}
	httpServer.serve(listener, router(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors), "http")
	log.Infoln("RESTful API listening at: %s", listener.Addr())
}

func startTLS(cfg *Config) {
	if cfg.TLSAddr == "" {
		return
	}
	certLoader, err := ca.NewTLSKeyPairLoader(cfg.Certificate, cfg.PrivateKey)
	if err != nil {
		log.Errorln("External controller tls listen error: %s", err)
		return
	}
	tlsConfig := &tls.Config{Time: ntp.Now, NextProtos: []string{"h2", "http/1.1"}}
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certLoader() }
	tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(cfg.ClientAuthType)
	if cfg.ClientAuthCert != "" && tlsConfig.ClientAuth == tls.NoClientCert {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		pool, err := ca.LoadCertificates(cfg.ClientAuthCert)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			return
		}
		tlsConfig.ClientCAs = pool
	}
	if cfg.EchKey != "" {
		if err := ech.LoadECHKey(cfg.EchKey, tlsConfig); err != nil {
			log.Errorln("External controller tls serve error: %s", err)
			return
		}
	}
	// Validate everything before binding: invalid CA/ECH input must not leak a port.
	lc := inbound.NewListenConfig()
	lc.SetRouteMark(cfg.RoutingMark)
	listener, err := lc.Listen(context.Background(), "tcp", cfg.TLSAddr)
	if err != nil {
		log.Errorln("External controller tls listen error: %s", err)
		return
	}
	tlsServer.serve(tls.NewListener(listener, tlsConfig), router(cfg.IsDebug, cfg.Secret, cfg.DohServer, cfg.Cors), "tls")
	log.Infoln("RESTful API tls listening at: %s", listener.Addr())
}

func startUnix(cfg *Config) {
	if cfg.UnixAddr == "" {
		return
	}
	addr := C.Path.Resolve(cfg.UnixAddr)
	if err := os.MkdirAll(filepath.Dir(addr), 0o755); err != nil {
		log.Errorln("External controller unix listen error: %s", err)
		return
	}
	_ = syscall.Unlink(addr)
	lc := inbound.NewListenConfig()
	lc.SetRouteMark(0)
	listener, err := lc.Listen(context.Background(), "unix", addr)
	if err != nil {
		log.Errorln("External controller unix listen error: %s", err)
		return
	}
	_ = os.Chmod(addr, 0o666)
	unixServer.serve(listener, router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors), "unix")
	log.Infoln("RESTful API unix listening at: %s", listener.Addr())
}

func startPipe(cfg *Config) {
	if cfg.PipeAddr == "" {
		return
	}
	if !strings.HasPrefix(cfg.PipeAddr, `\\.\pipe\`) {
		log.Errorln("External controller pipe listen error: invalid named pipe path")
		return
	}
	listener, err := inbound.ListenNamedPipe(cfg.PipeAddr)
	if err != nil {
		log.Errorln("External controller pipe listen error: %s", err)
		return
	}
	pipeServer.serve(listener, router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors), "pipe")
	log.Infoln("RESTful API pipe listening at: %s", listener.Addr())
}

func safeEqual(a, b string) bool {
	aBuf := utils.ImmutableBytesFromString(a)
	bBuf := utils.ImmutableBytesFromString(b)
	return subtle.ConstantTimeCompare(aBuf, bBuf) == 1
}

func authentication(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Browser websocket not support custom header
			if r.Header.Get("Upgrade") == "websocket" && r.URL.Query().Get("token") != "" {
				token := r.URL.Query().Get("token")
				if !safeEqual(token, secret) {
					render.Status(r, http.StatusUnauthorized)
					render.JSON(w, r, ErrUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get("Authorization")
			bearer, token, found := strings.Cut(header, " ")

			hasInvalidHeader := bearer != "Bearer"
			hasInvalidSecret := !found || !safeEqual(token, secret)
			if hasInvalidHeader || hasInvalidSecret {
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, ErrUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func hello(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"hello": "mihomo"})
}

func traffic(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	buf := &bytes.Buffer{}
	var err error
	for range tick.C {
		buf.Reset()
		up, down := t.Now()
		upTotal, downTotal := t.Total()
		if err := json.NewEncoder(buf).Encode(Traffic{
			Up:        up,
			Down:      down,
			UpTotal:   upTotal,
			DownTotal: downTotal,
		}); err != nil {
			break
		}

		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func memory(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	buf := &bytes.Buffer{}
	var err error
	first := true
	for range tick.C {
		buf.Reset()

		inuse := t.Memory()
		// make chat.js begin with zero
		// this is shit var,but we need output 0 for first time
		if first {
			inuse = 0
			first = false
		}
		if err := json.NewEncoder(buf).Encode(Memory{
			Inuse:   inuse,
			OSLimit: 0,
		}); err != nil {
			break
		}
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

type Log struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}
type LogStructuredField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type LogStructured struct {
	Time    string               `json:"time"`
	Level   string               `json:"level"`
	Message string               `json:"message"`
	Fields  []LogStructuredField `json:"fields"`
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	levelText := r.URL.Query().Get("level")
	if levelText == "" {
		levelText = "info"
	}

	formatText := r.URL.Query().Get("format")
	isStructured := false
	if formatText == "structured" {
		isStructured = true
	}

	level, ok := log.LogLevelMapping[levelText]
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, err = wsUpgrade(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	ch := make(chan log.Event, 1024)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	buf := &bytes.Buffer{}

	go func() {
		for logM := range sub {
			select {
			case ch <- logM:
			default:
			}
		}
		close(ch)
	}()

	for logM := range ch {
		if logM.LogLevel < level {
			continue
		}
		buf.Reset()

		if !isStructured {
			if err := json.NewEncoder(buf).Encode(Log{
				Type:    logM.Type(),
				Payload: logM.Payload,
			}); err != nil {
				break
			}
		} else {
			newLevel := logM.Type()
			if newLevel == "warning" {
				newLevel = "warn"
			}
			if err := json.NewEncoder(buf).Encode(LogStructured{
				Time:    time.Now().Format(time.TimeOnly),
				Level:   newLevel,
				Message: logM.Payload,
				Fields:  []LogStructuredField{},
			}); err != nil {
				break
			}
		}

		var err error
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsWriteServerText(wsConn, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func version(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"meta": C.Meta, "version": C.Version})
}
