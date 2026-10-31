package outbound

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/stretchr/testify/require"
)

func TestRealityHybridDefault(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, testCase := range []struct {
		name      string
		present   bool
		value     any
		want      bool
		wantError bool
	}{
		{name: "omitted", want: true},
		{name: "null", present: true, value: nil, want: true},
		{name: "enabled", present: true, value: true, want: true},
		{name: "disabled", present: true, value: false, want: false},
		{name: "string is not a YAML boolean", present: true, value: "false", wantError: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			mapping := map[string]any{"public-key": publicKey, "short-id": "1234"}
			if testCase.present {
				mapping["support-x25519mlkem768"] = testCase.value
			}
			var option RealityOptions
			decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
			err := decoder.Decode(mapping, &option)
			if testCase.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			config, err := option.Parse()
			require.NoError(t, err)
			require.NotNil(t, config)
			require.Equal(t, testCase.want, config.SupportX25519MLKEM768)
		})
	}
	// A default for a REALITY setting must not enable REALITY on ordinary TLS nodes.
	config, err := (RealityOptions{}).Parse()
	require.NoError(t, err)
	require.Nil(t, config)
}
