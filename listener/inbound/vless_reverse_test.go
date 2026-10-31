package inbound_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/vless/encryption"
	"github.com/metacubex/mihomo/transport/vless/reverse"
	"github.com/stretchr/testify/require"
)

type reverseTestTunnel struct {
	*TestTunnel
	registry *reverse.Registry
	mu       sync.RWMutex
	proxies  map[string]C.Proxy
}

func (t *reverseTestTunnel) VLESSReverseRegistry() *reverse.Registry { return t.registry }
func (t *reverseTestTunnel) ProxyByName(name string) C.Proxy {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.proxies[name]
}
func (t *reverseTestTunnel) setProxy(proxy C.Proxy) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.proxies[proxy.Name()] = proxy
}
func newReverseTunnel(t *testing.T) *reverseTestTunnel {
	t.Helper()
	tunnel := &reverseTestTunnel{TestTunnel: NewHttpTestTunnel(), registry: reverse.NewRegistry(), proxies: make(map[string]C.Proxy)}
	t.Cleanup(func() { tunnel.Close() })
	return tunnel
}

func reverseOutbound(t *testing.T, tunnel *reverseTestTunnel, name string) C.Proxy {
	t.Helper()
	proxy, err := adapter.ParseProxy(map[string]any{"name": name, "type": "vless-reverse"}, adapter.WithTunnelForAPI(tunnel))
	require.NoError(t, err)
	t.Cleanup(func() { proxy.Close() })
	tunnel.setProxy(proxy)
	return proxy
}

func TestVlessReverseRoundTrip(t *testing.T) {
	for _, mode := range []string{"tls", "vision", "reality", "reality-vision", "ws", "grpc", "encryption", "encryption-vision"} {
		t.Run(mode, func(t *testing.T) {
			hub := newReverseTunnel(t)
			leaf := newReverseTunnel(t)
			poolProxy := reverseOutbound(t, hub, "home")
			seen := make(chan C.Metadata, 16)
			leaf.HandleTCPConnFn = func(conn net.Conn, metadata *C.Metadata) {
				defer conn.Close()
				seen <- *metadata
				_, _ = io.Copy(conn, conn)
			}
			leaf.HandleUDPPacketFn = func(packet C.UDPPacket, metadata *C.Metadata) {
				defer packet.Drop()
				_, _ = packet.WriteBack(packet.Data(), metadata.UDPAddr())
			}
			flow := ""
			if mode == "vision" || mode == "reality-vision" || mode == "encryption-vision" {
				flow = "xtls-rprx-vision"
			}
			options := &inbound.VlessOption{BaseOption: inbound.BaseOption{NameStr: "public-vless", Listen: "127.0.0.1", Port: "0"},
				Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
				Users: []inbound.VlessUser{{Username: "home", UUID: userUUID, Flow: flow, Reverse: &LC.VlessReverse{Tag: "home"}}}}
			if mode == "reality" || mode == "reality-vision" {
				options.Certificate = ""
				options.PrivateKey = ""
				options.RealityConfig = inbound.RealityConfig{Dest: net.JoinHostPort(realityDest, "443"), PrivateKey: realityPrivateKey, ShortID: []string{realityShortid}, ServerNames: []string{realityDest}}
			}
			var encryptionClient string
			if mode == "encryption" || mode == "encryption-vision" {
				seed, client, _, err := encryption.GenMLKEM768("")
				require.NoError(t, err)
				private, password, _, err := encryption.GenX25519("")
				require.NoError(t, err)
				options.Certificate = ""
				options.PrivateKey = ""
				options.Decryption = "mlkem768x25519plus.native.600s." + private + "." + seed
				encryptionClient = "mlkem768x25519plus.native.0rtt." + password + "." + client
			}
			if mode == "ws" {
				options.WsPath = "/reverse"
			}
			if mode == "grpc" {
				options.GrpcServiceName = "ReverseService"
			}
			server, err := inbound.NewVless(options)
			require.NoError(t, err)
			require.NoError(t, server.Listen(hub))
			defer server.Close()
			address, err := netip.ParseAddrPort(server.Address())
			require.NoError(t, err)
			linkOptions := outbound.VlessOption{BasicOption: outbound.BasicOption{DialerForAPI: leaf.NewDialer(), TunnelForAPI: leaf},
				Name: "hub-link", Server: address.Addr().String(), Port: int(address.Port()), UUID: userUUID, TLS: true, Fingerprint: tlsFingerprint, Flow: flow}
			if encryptionClient != "" {
				linkOptions.TLS = false
				linkOptions.Fingerprint = ""
				linkOptions.Encryption = encryptionClient
			}
			if mode == "ws" {
				linkOptions.Network = "ws"
				linkOptions.WSOpts = outbound.WSOptions{Path: "/reverse"}
			}
			if mode == "grpc" {
				linkOptions.Network = "grpc"
				linkOptions.GrpcOpts = outbound.GrpcOptions{GrpcServiceName: "ReverseService"}
			}
			if mode == "reality" || mode == "reality-vision" {
				linkOptions.Fingerprint = ""
				linkOptions.ServerName = realityDest
				linkOptions.ClientFingerprint = "chrome"
				linkOptions.RealityOpts = outbound.RealityOptions{PublicKey: realityPublickey, ShortID: realityShortid}
			}
			link, err := outbound.NewVless(linkOptions)
			require.NoError(t, err)
			defer link.Close()
			leaf.setProxy(adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(link)))
			bridge, err := inbound.NewVlessReverse(&inbound.VlessReverseOption{BaseOption: inbound.BaseOption{NameStr: "home-in", SpecialProxy: "DIRECT"}, Outbound: "hub-link"})
			require.NoError(t, err)
			require.NoError(t, bridge.Listen(leaf))
			defer bridge.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pool := hub.registry.Get("home")
			require.NoError(t, pool.WaitReady(ctx))
			metadata := &C.Metadata{NetWork: C.TCP, Host: "inside.example", DstPort: 22, SrcIP: netip.MustParseAddr("127.0.0.2"), SrcPort: 23456, InIP: netip.MustParseAddr("127.0.0.3"), InPort: 8443}
			conn, err := poolProxy.DialContext(ctx, metadata)
			require.NoError(t, err)
			reverseEchoTCP(t, conn, 64*1024)
			got := <-seen
			require.Equal(t, "home-in", got.InName)
			require.Equal(t, "hub-link", got.InUser)
			require.Equal(t, "DIRECT", got.SpecialProxy)
			require.Equal(t, metadata.SrcIP, got.SrcIP)
			require.Equal(t, metadata.SrcPort, got.SrcPort)
			require.Equal(t, metadata.InIP, got.InIP)
			require.Equal(t, metadata.InPort, got.InPort)
			require.Equal(t, metadata.Host, got.Host)
			require.Equal(t, metadata.DstPort, got.DstPort)
			packet, err := poolProxy.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.9"), DstPort: 5353, SrcIP: metadata.SrcIP, SrcPort: 23457, InIP: metadata.InIP, InPort: 8443})
			require.NoError(t, err)
			reverseEchoUDP(t, packet)
			// Replacing an outbound with the same name retains its established pool.
			replacement := reverseOutbound(t, hub, "home")
			require.Same(t, pool, hub.registry.Get("home"))
			require.NoError(t, poolProxy.Close())
			conn, err = replacement.DialContext(ctx, metadata)
			require.NoError(t, err)
			reverseEchoTCP(t, conn, 1024)
			<-seen
			require.NoError(t, server.Close())
			require.Eventually(t, func() bool { return pool.Connections() == 0 }, time.Second, 10*time.Millisecond)
			_, err = replacement.DialContext(ctx, metadata)
			require.ErrorIs(t, err, reverse.ErrNoWorker)
			require.NoError(t, bridge.Close())
		})
	}
}

func reverseEchoTCP(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	want := bytes.Repeat([]byte{0x42}, size)
	written := make(chan error, 1)
	go func() { _, err := conn.Write(want); written <- err }()
	got := make([]byte, len(want))
	_, err := io.ReadFull(conn, got)
	require.NoError(t, err)
	require.NoError(t, <-written)
	require.Equal(t, want, got)
}
func reverseEchoUDP(t *testing.T, conn net.PacketConn) {
	t.Helper()
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	for _, address := range []string{"127.0.0.9:5353", "[::1]:5354"} {
		target := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(address))
		want := bytes.Repeat([]byte{0x43}, 1400)
		_, err := conn.WriteTo(want, target)
		require.NoError(t, err)
		got := make([]byte, 8192)
		n, source, err := conn.ReadFrom(got)
		require.NoError(t, err)
		require.Equal(t, want, got[:n])
		require.Equal(t, address, source.String())
	}
}

func TestVlessReverseAuthorization(t *testing.T) {
	hub := newReverseTunnel(t)
	reverseOutbound(t, hub, "home")
	server, err := inbound.NewVless(&inbound.VlessOption{BaseOption: inbound.BaseOption{NameStr: "public", Listen: "127.0.0.1", Port: "0"}, AllowInsecure: true,
		Users: []inbound.VlessUser{{UUID: userUUID, Reverse: &LC.VlessReverse{Tag: "home"}}, {UUID: "ordinary-forward-user"}}})
	require.NoError(t, err)
	require.NoError(t, server.Listen(hub))
	defer server.Close()
	address, err := netip.ParseAddrPort(server.Address())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, test := range []struct {
		name, uuid string
		reverse    bool
	}{{"forward user cannot register", "ordinary-forward-user", true}, {"reverse user cannot forward", userUUID, false}} {
		t.Run(test.name, func(t *testing.T) {
			client, err := outbound.NewVless(outbound.VlessOption{Name: "test", Server: address.Addr().String(), Port: int(address.Port()), UUID: test.uuid})
			require.NoError(t, err)
			defer client.Close()
			var conn net.Conn
			if test.reverse {
				conn, err = client.DialReverseContext(ctx)
			} else {
				conn, err = client.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "inside.example", DstPort: 22})
			}
			require.NoError(t, err)
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write([]byte("request"))
			_, err = conn.Read(make([]byte, 1))
			require.Error(t, err)
		})
	}
	require.Zero(t, hub.registry.Get("home").Connections())
}
