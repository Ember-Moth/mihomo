package convert_test

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/stretchr/testify/require"
)

func TestNowhereShareLink(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef"
	input := "nowhere://" + key + "@[::1]:443?net=udp&net=tcp&morph=0&sni=localhost&pin=" + strings.Repeat("ab", 32) + "#%E6%B5%8B%E8%AF%95"
	proxies, err := convert.ConvertsV2Ray([]byte(input + "\n" + input))
	require.NoError(t, err)
	require.Len(t, proxies, 2)
	p := proxies[0]
	require.Equal(t, "测试", p["name"])
	require.Equal(t, "测试-01", proxies[1]["name"])
	require.Equal(t, "udp", p["network"])
	require.Equal(t, false, p["morph"])
	require.Equal(t, "::1", p["server"])
	proxy, err := adapter.ParseProxy(p)
	require.NoError(t, err)
	proxy.Close()
	for _, suffix := range []string{"/tcp:443", "?net=quic", "?morph=true", "?morph=bad&morph=1", "?pin=bad", "?net=%xx"} {
		_, err := convert.ConvertsV2Ray([]byte("nowhere://" + key + "@localhost:443" + suffix))
		require.Error(t, err, suffix)
	}
	proxies, err = convert.ConvertsV2Ray([]byte("nowhere://%30" + key[1:] + "@localhost:443"))
	require.NoError(t, err)
	require.Equal(t, key, proxies[0]["password"])
	require.Equal(t, "tcp", proxies[0]["network"])
	require.Equal(t, true, proxies[0]["morph"])
	_, err = convert.ConvertsV2Ray([]byte("nowhere://%2530" + key[1:] + "@localhost:443"))
	require.Error(t, err)
}
