package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestNowhereOptions(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"name": "nw", "type": "nowhere", "server": "localhost", "port": 443, "password": "0123456789abcdef0123456789abcdef"}
	}
	for _, network := range []string{"tcp", "udp"} {
		config := base()
		config["network"] = network
		p, err := ParseProxy(config)
		require.NoError(t, err)
		require.Equal(t, C.Nowhere, p.Type())
		require.True(t, p.SupportUDP())
		require.Equal(t, network == "tcp", p.SupportUOT())
		require.NoError(t, p.Close())
	}
	for _, test := range []struct {
		key   string
		value any
	}{
		{"password", "short"}, {"password", "ABCDEF0123456789abcdef0123456789"}, {"port", 0}, {"port", 65536},
		{"network", "quic"}, {"morph", "garbage"}, {"pin", "bad"}, {"skip-cert-verify", true}, {"alpn", []string{"nw3"}},
		{"client-fingerprint", "chrome"}, {"tcp-prelude", "random"}, {"setup-timeout", -1}, {"handshake-timeout", 300001},
		{"server", "https://example.com"},
	} {
		t.Run(test.key+"/invalid", func(t *testing.T) {
			config := base()
			config[test.key] = test.value
			p, err := ParseProxy(config)
			if p != nil {
				p.Close()
			}
			require.Error(t, err)
		})
	}
	config := base()
	config["udp"] = false
	config["morph"] = false
	p, err := ParseProxy(config)
	require.NoError(t, err)
	defer p.Close()
	require.False(t, p.SupportUDP())
}
