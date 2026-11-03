package route

import (
	"context"
	"crypto/tls"
	"github.com/metacubex/mihomo/component/ca"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestControllerConcurrentRecreateAndStop(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	defer ReCreateServer(&Config{})
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				ReCreateServer(&Config{Addr: addr})
				ReCreateServer(&Config{})
			}
		}()
	}
	wg.Wait()
	ReCreateServer(&Config{})
	// No delayed start may resurrect an old configuration after the stop.
	for i := 0; i < 20; i++ {
		probe, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatalf("controller retained or resurrected its listener: %v", err)
		}
		probe.Close()
		time.Sleep(time.Millisecond)
	}
}

func TestControllerCopiesConfiguration(t *testing.T) {
	cfg := &Config{Addr: "127.0.0.1:0", Cors: Cors{AllowOrigins: []string{"https://one.example"}}}
	for i := 0; i < 50; i++ {
		ReCreateServer(cfg)
		cfg.Cors.AllowOrigins[0] = "https://two.example"
		cfg.Secret = "changed"
		cfg.Addr = ""
		ReCreateServer(&Config{})
		cfg.Addr = "127.0.0.1:0"
	}
	ReCreateServer(&Config{})
}

func TestControllerTLSAndUnixReleaseListeners(t *testing.T) {
	certificate, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{TLSAddr: "127.0.0.1:0", Certificate: certificate, PrivateKey: key}
	if runtime.GOOS != "windows" {
		directory, err := os.MkdirTemp("", "mm-ctl-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(directory) })
		cfg.UnixAddr = filepath.Join(directory, "api.sock")
	}
	defer ReCreateServer(&Config{})
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for i := 0; i < 10; i++ {
		ReCreateServer(cfg)
		serverMu.Lock()
		address := tlsServer.listener.Addr().String()
		serverMu.Unlock()
		response, err := client.Get("https://" + address + "/version")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal(response.Status)
		}
		if cfg.UnixAddr != "" {
			tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", cfg.UnixAddr)
			}}
			unixClient := &http.Client{Transport: tr, Timeout: time.Second}
			r, err := unixClient.Get("http://controller/version")
			if err != nil {
				t.Fatal(err)
			}
			r.Body.Close()
			tr.CloseIdleConnections()
		}
		ReCreateServer(&Config{})
		l, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("TLS port retained", err)
		}
		l.Close()
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	cfg.TLSAddr = address
	cfg.UnixAddr = ""
	cfg.ClientAuthCert = "invalid CA"
	ReCreateServer(cfg)
	l, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatal("invalid TLS configuration leaked its listener", err)
	}
	l.Close()
}

func TestControllerSettingsWhileBuildingRouters(t *testing.T) {
	settingsMu.RLock()
	previousMode, previousUI := embedMode, uiPath
	settingsMu.RUnlock()
	defer func() { settingsMu.Lock(); embedMode, uiPath = previousMode, previousUI; settingsMu.Unlock() }()
	directory := t.TempDir()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			SetEmbedMode(i%2 == 0)
			SetUIPath(directory)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = router(false, "", "", Cors{})
		}
	}()
	wg.Wait()
}
