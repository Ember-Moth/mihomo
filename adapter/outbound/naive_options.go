package outbound

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/metacubex/mihomo/component/ech/echparser"
	C "github.com/metacubex/mihomo/constant"
)

// NaiveOption uses Chromium's TLS stack. Certificate contains trusted CA PEM
// data (or a file path), not a client certificate as in some other outbounds.
type NaiveOption struct {
	BasicOption
	Name                     string            `proxy:"name"`
	Server                   string            `proxy:"server"`
	Port                     int               `proxy:"port"`
	Username                 string            `proxy:"username,omitempty"`
	Password                 string            `proxy:"password,omitempty"`
	SNI                      string            `proxy:"sni,omitempty"`
	Certificate              string            `proxy:"certificate,omitempty"`
	ECHOpts                  ECHOptions        `proxy:"ech-opts,omitempty"`
	Headers                  map[string]string `proxy:"headers,omitempty"`
	InsecureConcurrency      int               `proxy:"insecure-concurrency,omitempty"`
	StreamReceiveWindow      uint64            `proxy:"stream-receive-window,omitempty"`
	QUIC                     bool              `proxy:"quic,omitempty"`
	QUICCongestionControl    string            `proxy:"quic-congestion-control,omitempty"`
	QUICSessionReceiveWindow uint64            `proxy:"quic-session-receive-window,omitempty"`
	UDP                      bool              `proxy:"udp,omitempty"`
	UDPOverTCP               bool              `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion        int               `proxy:"udp-over-tcp-version,omitempty"`

	// Decode unsupported TLS options so they fail explicitly instead of being ignored.
	SkipCertVerify    bool     `proxy:"skip-cert-verify,omitempty"`
	ClientFingerprint string   `proxy:"client-fingerprint,omitempty"`
	Fingerprint       string   `proxy:"fingerprint,omitempty"`
	NameCertVerify    string   `proxy:"name-cert-verify,omitempty"`
	PrivateKey        string   `proxy:"private-key,omitempty"`
	ALPN              []string `proxy:"alpn,omitempty"`
}

func (o NaiveOption) validate() error {
	if o.Server == "" || strings.TrimSpace(o.Server) != o.Server || strings.ContainsAny(o.Server, "/\\@?#\x00\r\n") {
		return errors.New("naive: server must be a hostname or IP address")
	}
	if strings.Contains(o.Server, ":") {
		if _, err := netip.ParseAddr(o.Server); err != nil {
			return errors.New("naive: server must not contain a port or URL scheme")
		}
	}
	if o.Port < 1 || o.Port > 65535 {
		return errors.New("naive: port must be between 1 and 65535")
	}
	if strings.ContainsAny(o.SNI, "/\\@?#\x00\r\n\t ") {
		return errors.New("naive: sni must be a hostname or IP address")
	}
	if strings.Contains(o.Username, ":") {
		return errors.New("naive: username must not contain ':' in HTTP Basic authentication")
	}
	if o.SkipCertVerify || o.ClientFingerprint != "" || o.Fingerprint != "" || o.NameCertVerify != "" || o.PrivateKey != "" || len(o.ALPN) != 0 {
		return errors.New("naive: skip-cert-verify, client-fingerprint, fingerprint, name-cert-verify, private-key and alpn are unsupported by Chromium TLS")
	}
	if o.InsecureConcurrency < 0 {
		return errors.New("naive: insecure-concurrency must not be negative")
	}
	if !o.QUIC && (o.QUICCongestionControl != "" || o.QUICSessionReceiveWindow != 0) {
		return errors.New("naive: QUIC options require quic: true")
	}
	switch o.QUICCongestionControl {
	case "", "bbr", "bbr2", "cubic", "reno":
	default:
		return fmt.Errorf("naive: unknown QUIC congestion control %q", o.QUICCongestionControl)
	}
	if !o.QUIC && o.StreamReceiveWindow > 1<<31-1 {
		return errors.New("naive: HTTP/2 stream-receive-window must not exceed 2147483647")
	}
	if o.QUIC && (o.StreamReceiveWindow > 1<<62-1 || o.QUICSessionReceiveWindow > 1<<62-1) {
		return errors.New("naive: QUIC receive windows must fit in a 62-bit unsigned integer")
	}
	if o.UDP && !o.UDPOverTCP {
		return errors.New("naive: UDP requires udp-over-tcp: true and a compatible server")
	}
	if o.UDPOverTCPVersion != 0 && !o.UDPOverTCP {
		return errors.New("naive: udp-over-tcp-version requires udp-over-tcp: true")
	}
	switch o.UDPOverTCPVersion {
	case 0, 1, 2:
	default:
		return errors.New("naive: udp-over-tcp-version must be 1 or 2")
	}
	headerNames := make(map[string]bool, len(o.Headers))
	for key, value := range o.Headers {
		if !validNaiveHeaderName(key) || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("naive: invalid header %q", key)
		}
		lowerKey := strings.ToLower(key)
		if headerNames[lowerKey] {
			return fmt.Errorf("naive: duplicate header %q", key)
		}
		headerNames[lowerKey] = true
		switch strings.ToLower(key) {
		case "padding", "proxy-authorization", "host", "connection", "proxy-connection", "transfer-encoding", "content-length", "upgrade":
			return fmt.Errorf("naive: header %q is managed by the transport", key)
		}
	}
	return nil
}

func validNaiveHeaderName(key string) bool {
	// Leading '-' names are private Cronet controls (e.g. -connect-authority).
	if key == "" || key[0] == '-' {
		return false
	}
	for _, ch := range key {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", ch) {
			continue
		}
		return false
	}
	return true
}

func (o NaiveOption) echConfig() ([]byte, error) {
	if !o.ECHOpts.Enable || o.ECHOpts.Config == "" {
		return nil, nil
	}
	config, err := base64.StdEncoding.DecodeString(o.ECHOpts.Config)
	if err != nil {
		return nil, fmt.Errorf("naive: decode ECH config: %w", err)
	}
	configs, err := echparser.ParseECHConfigList(config)
	if err != nil || len(configs) == 0 {
		return nil, errors.New("naive: invalid ECH config list")
	}
	return config, nil
}

func (o NaiveOption) trustedCertificates() (string, error) {
	if o.Certificate == "" {
		return "", nil
	}
	certificates := []byte(o.Certificate)
	if !strings.Contains(o.Certificate, "-----BEGIN CERTIFICATE-----") {
		path := C.Path.Resolve(o.Certificate)
		if !C.Path.IsSafePath(path) {
			return "", C.Path.ErrNotSafePath(path)
		}
		var err error
		certificates, err = os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("naive: read CA certificate: %w", err)
		}
	}
	if !x509.NewCertPool().AppendCertsFromPEM(certificates) {
		return "", errors.New("naive: certificate must contain PEM encoded CA certificates")
	}
	return string(certificates), nil
}
