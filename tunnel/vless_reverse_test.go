package tunnel_test

import (
	"context"
	"net"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/require"
)

func TestVlessReverseProxyReload(t *testing.T) {
	previous, providers := tunnel.Proxies(), tunnel.Providers()
	defer tunnel.UpdateProxies(previous, providers)
	makeProxy := func() C.Proxy {
		proxy, err := adapter.ParseProxy(map[string]any{"type": "vless-reverse", "name": "reverse-reload-test"}, adapter.WithTunnelForAPI(tunnel.Tunnel))
		require.NoError(t, err)
		t.Cleanup(func() { proxy.Close() })
		return proxy
	}
	first := makeProxy()
	tunnel.UpdateProxies(map[string]C.Proxy{first.Name(): first}, providers)
	pool := tunnel.Tunnel.VLESSReverseRegistry().Get(first.Name())
	require.NotNil(t, pool)
	second := makeProxy()
	tunnel.UpdateProxies(map[string]C.Proxy{second.Name(): second}, providers)
	require.Same(t, pool, tunnel.Tunnel.VLESSReverseRegistry().Get(second.Name()))
	_, err := first.DialContext(context.Background(), &C.Metadata{})
	require.ErrorIs(t, err, net.ErrClosed)
	tunnel.UpdateProxies(map[string]C.Proxy{}, providers)
	require.Nil(t, tunnel.Tunnel.VLESSReverseRegistry().Get(second.Name()))
	_, err = second.DialContext(context.Background(), &C.Metadata{})
	require.ErrorIs(t, err, net.ErrClosed)
}
