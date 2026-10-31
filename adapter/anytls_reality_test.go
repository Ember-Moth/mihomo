package adapter

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnyTLSRealityOptions(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	newConfig := func() map[string]any {
		return map[string]any{
			"name": "anytls-reality", "type": "anytls", "server": "127.0.0.1", "port": 443,
			"password": "anytls-password", "sni": "example.org", "client-fingerprint": "chrome",
			"reality-opts": map[string]any{"public-key": publicKey, "short-id": "1234"},
		}
	}
	proxy, err := ParseProxy(newConfig())
	require.NoError(t, err)
	require.NoError(t, proxy.Close())

	for _, testCase := range []struct {
		name   string
		modify func(map[string]any)
		error  string
	}{
		{"invalid key", func(c map[string]any) { c["reality-opts"] = map[string]any{"public-key": "invalid"} }, "public key"},
		{"missing key", func(c map[string]any) { c["reality-opts"] = map[string]any{"short-id": "1234"} }, "public-key"},
		{"invalid short ID", func(c map[string]any) { c["reality-opts"].(map[string]any)["short-id"] = "xyz" }, "short ID"},
		{"missing fingerprint", func(c map[string]any) { delete(c, "client-fingerprint") }, "client-fingerprint"},
		{"invalid fingerprint", func(c map[string]any) { c["client-fingerprint"] = "not-a-browser" }, "client-fingerprint"},
		{"ECH conflict", func(c map[string]any) { c["ech-opts"] = map[string]any{"enable": true} }, "cannot be combined"},
		{"certificate conflict", func(c map[string]any) { c["certificate"] = "client.pem" }, "cannot be combined"},
		{"ShadowTLS conflict", func(c map[string]any) { c["shadow-tls-opts"] = map[string]any{"password": "test", "version": 3} }, "mutually exclusive"},
		{"Restls conflict", func(c map[string]any) { c["restls-opts"] = map[string]any{"password": "test", "version-hint": "tls13"} }, "mutually exclusive"},
		{"JLS conflict", func(c map[string]any) { c["jls-opts"] = map[string]any{"username": "test", "password": "test"} }, "mutually exclusive"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := newConfig()
			testCase.modify(config)
			proxy, err := ParseProxy(config)
			if proxy != nil {
				_ = proxy.Close()
			}
			require.ErrorContains(t, err, testCase.error)
		})
	}
}
