package inbound_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowtls"

	SS "github.com/Ember-Moth/sing-snell"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testInboundSnell(t *testing.T, inboundOptions inbound.SnellOption, outboundOptions outbound.SnellOption) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "snell_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Psk = userUUID
	in, err := inbound.NewSnell(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions.Name = "snell_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Psk = userUUID
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

	out, err := outbound.NewSnell(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}

func TestInboundSnell(t *testing.T) {
	testCase := []struct {
		name    string
		version int
		reuse   bool
		mode    string
		obfs    string
	}{
		{name: "v1", version: 1},
		{name: "v2", version: 2},
		{name: "v3", version: 3},
		{name: "v4", version: 4},
		{name: "v5", version: 5},
		{name: "v6", version: 6},
		{name: "v4-reuse", version: 4, reuse: true},
		{name: "v5-reuse", version: 5, reuse: true},
		{name: "v6-reuse", version: 6, reuse: true},
		{name: "v6-unshaped", version: 6, mode: "unshaped"},
		{name: "v6-unsafe-raw", version: 6, mode: "unsafe-raw"},
		{name: "v4-http", version: 4, obfs: "http"},
		{name: "v5-tls", version: 5, obfs: "tls"},
	}
	for _, tc := range testCase {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			inboundOptions := inbound.SnellOption{Version: tc.version, Version6Mode: tc.mode, ObfsOpts: inbound.SnellObfsOption{Mode: tc.obfs}}
			outboundOptions := outbound.SnellOption{Version: tc.version, Reuse: tc.reuse, Version6Mode: tc.mode, ObfsOpts: map[string]any{"mode": tc.obfs}}
			testInboundSnell(t, inboundOptions, outboundOptions)
		})
	}
}

func TestInboundSnellUDP(t *testing.T) {
	for _, version := range []int{3, 4, 5, 6} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			in, err := inbound.NewSnell(&inbound.SnellOption{
				BaseOption: inbound.BaseOption{NameStr: "snell-udp", Listen: "127.0.0.1", Port: "0"},
				Psk:        userUUID, Version: version, UDP: true,
			})
			require.NoError(t, err)
			tunnel := NewHttpTestTunnel()
			defer tunnel.Close()
			tunnel.HandleUDPPacketFn = func(packet C.UDPPacket, metadata *C.Metadata) {
				defer packet.Drop()
				_, err := packet.WriteBack(packet.Data(), metadata.UDPAddr())
				assert.NoError(t, err)
			}
			require.NoError(t, in.Listen(tunnel))
			defer in.Close()
			addrPort, err := netip.ParseAddrPort(in.Address())
			require.NoError(t, err)
			out, err := outbound.NewSnell(outbound.SnellOption{
				BasicOption: outbound.BasicOption{DialerForAPI: tunnel.NewDialer()},
				Name:        "snell-udp", Server: addrPort.Addr().String(), Port: int(addrPort.Port()),
				Psk: userUUID, Version: version, UDP: true,
			})
			require.NoError(t, err)
			defer out.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			metadata := &C.Metadata{NetWork: C.UDP, DstIP: remoteAddr, DstPort: 5353}
			conn, err := out.ListenPacketContext(ctx, metadata)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
			for _, target := range []netip.AddrPort{netip.AddrPortFrom(remoteAddr, 5353), netip.MustParseAddrPort("[::1]:5354")} {
				sizes := []int{1, 1400}
				if version == 3 || version == 6 {
					sizes = append(sizes, 16000)
				}
				if version == 6 {
					sizes = append(sizes, 60000)
				}
				for _, size := range sizes {
					payload := bytes.Repeat([]byte{byte(size)}, size)
					n, err := conn.WriteTo(payload, net.UDPAddrFromAddrPort(target))
					require.NoError(t, err)
					require.Equal(t, len(payload), n)
					buffer := make([]byte, 65535)
					n, source, err := conn.ReadFrom(buffer)
					require.NoError(t, err)
					require.Equal(t, payload, buffer[:n])
					require.Equal(t, target.String(), source.String())
				}
				if version == 4 || version == 5 {
					// sing-snell follows the current v4/v5 frame window instead of
					// splitting a large datagram into separate protocol packets.
					_, err := conn.WriteTo(make([]byte, 65535), net.UDPAddrFromAddrPort(target))
					require.ErrorIs(t, err, SS.ErrPayloadTooLarge)
				}
			}
		})
	}
}

func testInboundSnellUTLS(t *testing.T, inboundOptions inbound.SnellOption, outboundOptions outbound.SnellOption) {
	t.Parallel()
	t.Run("Conn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		testInboundSnell(t, inboundOptions, outboundOptions)
	})
	t.Run("UConn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		outboundOptions.ClientFingerprint = "chrome"
		testInboundSnell(t, inboundOptions, outboundOptions)
	})
}

func TestInboundSnell_ShadowTlsv2(t *testing.T) {
	inboundOptions := inbound.SnellOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   2,
			Password:  shadowsocksPassword16,
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.SnellOption{
		Version:  5,
		ObfsOpts: map[string]any{"mode": shadowtls.Mode, "host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 2},
	}
	outboundOptions.ObfsOpts["alpn"] = []string{"http/1.1"} // shadowtls v2 work confuse with http/2 server, so we set alpn to http/1.1 to pass the test
	testInboundSnellUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundSnell_ShadowTlsv3(t *testing.T) {
	inboundOptions := inbound.SnellOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: shadowsocksPassword16}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.SnellOption{
		Version:  5,
		ObfsOpts: map[string]any{"mode": shadowtls.Mode, "host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 3},
	}
	testInboundSnellUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundSnell_Restls(t *testing.T) {
	const password = "restls-password"
	inboundOptions := inbound.SnellOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: password,
		},
	}
	outboundOptions := outbound.SnellOption{
		Version:  5,
		ObfsOpts: map[string]any{"mode": restls.Mode, "host": realityDest, "password": password, "fingerprint": tlsFingerprint, "version-hint": "tls13"},
	}
	testInboundSnellUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundSnell_JLS(t *testing.T) {
	const username = "jls-user"
	const password = "jls-password"
	inboundOptions := inbound.SnellOption{
		JLSConfig: inbound.JLSConfig{
			Enable: true,
			Users:  []inbound.JLSUser{{Username: username, Password: password}},
			SNI:    realityDest,
			Dest:   net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.SnellOption{
		Version:  5,
		ObfsOpts: map[string]any{"mode": jls.Mode, "host": realityDest, "username": username, "password": password},
	}
	testInboundSnellUTLS(t, inboundOptions, outboundOptions)
}
