package inbound_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	legacy "github.com/metacubex/mihomo/transport/snell"
	"github.com/metacubex/sing/common"
	"github.com/stretchr/testify/require"
)

type snellCountingDialer struct {
	C.Dialer
	calls atomic.Int32
}

func (d *snellCountingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls.Add(1)
	return d.Dialer.DialContext(ctx, network, address)
}

func TestInboundSnellHalfCloseAndReuse(t *testing.T) {
	for _, version := range []int{4, 5, 6} {
		for _, reuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/reuse=%t", version, reuse), func(t *testing.T) {
				tunnel := NewHttpTestTunnel()
				defer tunnel.Close()
				results := make(chan error, 3)
				tunnel.HandleTCPConnFn = func(conn net.Conn, metadata *C.Metadata) {
					defer conn.Close()
					if _, err := conn.Write([]byte("ready")); err != nil {
						results <- err
						return
					}
					payload, err := io.ReadAll(conn)
					if err == nil {
						_, err = conn.Write(payload)
					}
					results <- err
				}
				in, err := inbound.NewSnell(&inbound.SnellOption{
					BaseOption: inbound.BaseOption{NameStr: "snell-reuse", Listen: "127.0.0.1", Port: "0"},
					Psk:        userUUID, Version: version,
				})
				require.NoError(t, err)
				require.NoError(t, in.Listen(tunnel))
				defer in.Close()
				address, err := netip.ParseAddrPort(in.Address())
				require.NoError(t, err)
				dialer := &snellCountingDialer{Dialer: tunnel.NewDialer()}
				out, err := outbound.NewSnell(outbound.SnellOption{
					BasicOption: outbound.BasicOption{DialerForAPI: dialer},
					Name:        "snell-reuse", Server: address.Addr().String(), Port: int(address.Port()),
					Psk: userUUID, Version: version, Reuse: reuse,
				})
				require.NoError(t, err)
				defer out.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				metadata := &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 22}
				for i := 0; i < 3; i++ {
					conn, err := out.DialContext(ctx, metadata)
					require.NoError(t, err)
					require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
					greeting := make([]byte, 5)
					_, err = io.ReadFull(conn, greeting)
					require.NoError(t, err)
					require.Equal(t, "ready", string(greeting), "server-first connections must send the request before Read")
					payload := bytes.Repeat([]byte{byte(i + 1)}, 8192+i)
					_, err = conn.Write(payload)
					require.NoError(t, err)
					closer, ok := common.Cast[interface{ CloseWrite() error }](conn)
					require.True(t, ok)
					require.NoError(t, closer.CloseWrite())
					response, err := io.ReadAll(conn)
					require.NoError(t, err)
					require.Equal(t, payload, response, "the peer must still be able to respond after EOF")
					// A deadline used to stop this logical connection must not leak
					// into the next request on the pooled transport.
					require.NoError(t, conn.SetDeadline(time.Now().Add(-time.Second)))
					require.NoError(t, conn.Close())
					require.NoError(t, <-results)
				}
				wantDials := int32(3)
				if reuse {
					wantDials = 1
				}
				require.Equal(t, wantDials, dialer.calls.Load())
				require.NoError(t, out.Close())
				_, err = out.DialContext(ctx, metadata)
				require.ErrorIs(t, err, net.ErrClosed)
			})
		}
	}
}

func TestInboundSnellLegacyV4Client(t *testing.T) {
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	payload := bytes.Repeat([]byte("old-client"), 3000)
	result := make(chan error, 1)
	tunnel.HandleTCPConnFn = func(conn net.Conn, metadata *C.Metadata) {
		defer conn.Close()
		buffer := make([]byte, len(payload))
		_, err := io.ReadFull(conn, buffer)
		if err == nil {
			if !bytes.Equal(buffer, payload) || metadata.Host != "example.org" || metadata.DstPort != 443 {
				err = fmt.Errorf("unexpected request metadata or payload")
			} else {
				_, err = conn.Write(buffer)
			}
		}
		result <- err
	}
	in, err := inbound.NewSnell(&inbound.SnellOption{
		BaseOption: inbound.BaseOption{NameStr: "snell-legacy", Listen: "127.0.0.1", Port: "0"},
		Psk:        userUUID, Version: 4,
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel))
	defer in.Close()
	raw, err := net.DialTimeout("tcp", in.Address(), 5*time.Second)
	require.NoError(t, err)
	defer raw.Close()
	require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
	conn := legacy.StreamConn(raw, []byte(userUUID), legacy.Version4)
	require.NoError(t, legacy.WriteHeader(conn, "example.org", 443, legacy.Version4))
	_, err = conn.Write(payload)
	require.NoError(t, err)
	response := make([]byte, len(payload))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, payload, response)
	require.NoError(t, <-result)
}

func TestInboundSnellCloseUnblocksHandshake(t *testing.T) {
	in, err := inbound.NewSnell(&inbound.SnellOption{
		BaseOption: inbound.BaseOption{NameStr: "snell-close", Listen: "127.0.0.1", Port: "0"},
		Psk:        userUUID, Version: 6,
	})
	require.NoError(t, err)
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	require.NoError(t, in.Listen(tunnel))
	defer in.Close()
	conn, err := net.DialTimeout("tcp", in.Address(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, in.Close())
	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err)
	if timeout, ok := err.(net.Error); ok {
		require.False(t, timeout.Timeout(), "listener shutdown left the handshake blocked")
	}
}
