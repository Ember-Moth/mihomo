package outbound

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSnellOptions(t *testing.T) {
	for _, test := range []struct {
		name   string
		option SnellOption
	}{
		{"unknown version", SnellOption{Version: 7}},
		{"legacy UDP", SnellOption{Version: 2, UDP: true}},
		{"legacy user key", SnellOption{Version: 3, UserKey: "user"}},
		{"mode on v5", SnellOption{Version: 5, Version6Mode: "unshaped"}},
		{"unknown mode", SnellOption{Version: 6, Version6Mode: "unknown"}},
		{"long user key", SnellOption{Version: 5, UserKey: strings.Repeat("x", 256)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			option := test.option
			option.Name, option.Server, option.Port, option.Psk = "snell", "127.0.0.1", 443, "test-snell-password"
			_, err := NewSnell(option)
			require.Error(t, err)
		})
	}
	t.Run("legacy default", func(t *testing.T) {
		proxy, err := NewSnell(SnellOption{Name: "snell", Server: "127.0.0.1", Port: 443, Psk: "password"})
		require.NoError(t, err)
		defer proxy.Close()
		require.Equal(t, 1, proxy.version)
	})
	t.Run("v6 short psk", func(t *testing.T) {
		_, err := NewSnell(SnellOption{Name: "snell", Server: "127.0.0.1", Port: 443, Psk: "short", Version: 6})
		require.ErrorContains(t, err, "12 and 255")
	})
}
