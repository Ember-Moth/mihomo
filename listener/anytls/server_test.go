package anytls

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/stretchr/testify/require"
)

func TestRealityConfigValidation(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, testCase := range []struct {
		name   string
		modify func(*LC.AnyTLSServer)
		error  string
	}{
		{"missing private key", func(c *LC.AnyTLSServer) { c.RealityConfig.PrivateKey = "" }, "private-key"},
		{"invalid private key", func(c *LC.AnyTLSServer) { c.RealityConfig.PrivateKey = "bad" }, "private key"},
		{"invalid short ID", func(c *LC.AnyTLSServer) { c.RealityConfig.ShortID = []string{"xyz"} }, "short_id"},
		{"certificate conflict", func(c *LC.AnyTLSServer) { c.Certificate = "unused.pem" }, "cannot be combined"},
		{"ECH conflict", func(c *LC.AnyTLSServer) { c.EchKey = "unused" }, "cannot be combined"},
		{"client auth conflict", func(c *LC.AnyTLSServer) { c.ClientAuthType = "require-any" }, "cannot be combined"},
		{"ShadowTLS conflict", func(c *LC.AnyTLSServer) { c.ShadowTLS.Enable = true }, "mutually exclusive"},
		{"Restls conflict", func(c *LC.AnyTLSServer) { c.ResTLS.Enable = true }, "mutually exclusive"},
		{"JLS conflict", func(c *LC.AnyTLSServer) { c.JLSConfig.Enable = true }, "mutually exclusive"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := LC.AnyTLSServer{RealityConfig: reality.Config{
				Dest: "example.org:443", PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()),
				ShortID: []string{"1234"}, ServerNames: []string{"example.org"},
			}}
			testCase.modify(&config)
			// Validation must complete before accessing the listening socket or tunnel.
			_, err := New(config, nil, nil)
			require.ErrorContains(t, err, testCase.error)
		})
	}
}
