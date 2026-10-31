package outbound

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/ech"
)

func TestNaiveOptions(t *testing.T) {
	valid := NaiveOption{Name: "naive", Server: "proxy.example.org", Port: 443}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*NaiveOption){
		"empty server":               func(o *NaiveOption) { o.Server = "" },
		"server URL":                 func(o *NaiveOption) { o.Server = "https://proxy.example.org" },
		"server port":                func(o *NaiveOption) { o.Server = "proxy.example.org:443" },
		"zero port":                  func(o *NaiveOption) { o.Port = 0 },
		"port overflow":              func(o *NaiveOption) { o.Port = 65536 },
		"skip verification":          func(o *NaiveOption) { o.SkipCertVerify = true },
		"custom fingerprint":         func(o *NaiveOption) { o.ClientFingerprint = "chrome" },
		"ALPN":                       func(o *NaiveOption) { o.ALPN = []string{"h2"} },
		"concurrency":                func(o *NaiveOption) { o.InsecureConcurrency = -1 },
		"QUIC settings without QUIC": func(o *NaiveOption) { o.QUICCongestionControl = "bbr" },
		"unknown congestion control": func(o *NaiveOption) { o.QUIC = true; o.QUICCongestionControl = "unknown" },
		"HTTP2 window overflow":      func(o *NaiveOption) { o.StreamReceiveWindow = 1 << 31 },
		"UDP without UoT":            func(o *NaiveOption) { o.UDP = true },
		"unsupported UoT":            func(o *NaiveOption) { o.UDPOverTCP = true; o.UDPOverTCPVersion = 3 },
		"header injection":           func(o *NaiveOption) { o.Headers = map[string]string{"X-Test": "a\r\nb"} },
		"padding override":           func(o *NaiveOption) { o.Headers = map[string]string{"PADDING": "x"} },
		"auth override":              func(o *NaiveOption) { o.Headers = map[string]string{"Proxy-Authorization": "x"} },
		"Cronet control override":    func(o *NaiveOption) { o.Headers = map[string]string{"-connect-authority": "other:443"} },
	} {
		t.Run(name, func(t *testing.T) {
			option := valid
			change(&option)
			if err := option.validate(); err == nil {
				t.Fatal("expected invalid configuration to be rejected")
			}
		})
	}
	valid.Server = "::1"
	valid.QUIC = true
	valid.QUICCongestionControl = "bbr2"
	valid.UDPOverTCP = true
	valid.UDPOverTCPVersion = 2
	valid.Headers = map[string]string{"X-Test": "value"}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNaiveECHConfig(t *testing.T) {
	encoded, _, err := ech.GenECHConfig("public.example.org")
	if err != nil {
		t.Fatal(err)
	}
	option := NaiveOption{ECHOpts: ECHOptions{Enable: true, Config: encoded}}
	if result, err := option.echConfig(); err != nil || len(result) == 0 {
		t.Fatalf("valid ECH config: %v", err)
	}
	for _, encoded := range []string{"not base64", base64.StdEncoding.EncodeToString([]byte{0, 0}), base64.StdEncoding.EncodeToString([]byte{0, 5, 1})} {
		option.ECHOpts.Config = encoded
		if _, err := option.echConfig(); err == nil {
			t.Fatal("accepted malformed ECH config")
		}
	}
}

func TestNaiveInvalidCertificate(t *testing.T) {
	option := NaiveOption{Certificate: "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"}
	if _, err := option.trustedCertificates(); err == nil || !strings.Contains(err.Error(), "PEM") {
		t.Fatalf("expected invalid PEM error, got %v", err)
	}
}
