package outbound_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/internal/testutil/nowheretest"
	"github.com/metacubex/mihomo/pkg/nowhere"
	"github.com/stretchr/testify/require"
)

type nowhereTestDialer struct{ tcp, udp atomic.Int32 }

func (d *nowhereTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.tcp.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
func (d *nowhereTestDialer) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	d.udp.Add(1)
	return (&net.ListenConfig{}).ListenPacket(ctx, network, "127.0.0.1:0")
}

func TestNowhereRustAdapterInterop(t *testing.T) {
	for _, masked := range []bool{false, true} {
		t.Run(fmt.Sprintf("morph=%t", masked), func(t *testing.T) {
			server, pin, _ := nowheretest.StartPortal(t, masked)
			host, portString, _ := net.SplitHostPort(server)
			port, _ := strconv.Atoi(portString)
			tcpTarget, udpTarget := nowheretest.EchoTargets(t)
			_, otherUDP := nowheretest.EchoTargets(t)
			metadata := func(target nowhere.Target, network C.NetWork) *C.Metadata {
				return &C.Metadata{NetWork: network, DstIP: netip.MustParseAddr(target.Host), DstPort: target.Port}
			}
			for _, network := range []string{"tcp", "udp"} {
				t.Run(network, func(t *testing.T) {
					dialer := &nowhereTestDialer{}
					config := map[string]any{"name": "nowhere-test", "type": "nowhere", "server": host, "port": port, "password": nowheretest.SharedKey,
						"network": network, "morph": masked, "pin": pin, "sni": "localhost", "setup-timeout": 2000}
					proxy, err := adapter.ParseProxy(config, adapter.WithDialerForAPI(dialer))
					require.NoError(t, err)
					defer proxy.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					conn, err := proxy.DialContext(ctx, metadata(tcpTarget, C.TCP))
					require.NoError(t, err)
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					_, err = conn.Write([]byte("mihomo"))
					require.NoError(t, err)
					b := make([]byte, 6)
					_, err = io.ReadFull(conn, b)
					require.NoError(t, err)
					require.Equal(t, "mihomo", string(b))
					conn.Close()
					packet, err := proxy.ListenPacketContext(ctx, metadata(udpTarget, C.UDP))
					require.NoError(t, err)
					defer packet.Close()
					for i, target := range []nowhere.Target{udpTarget, otherUDP, udpTarget, otherUDP} {
						address := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(target.Host), target.Port))
						payload := bytes.Repeat([]byte{byte(i)}, i*1500)
						_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
						n, err := packet.WriteTo(payload, address)
						require.NoError(t, err)
						require.Equal(t, len(payload), n)
						buffer := make([]byte, 65535)
						n, from, err := packet.ReadFrom(buffer)
						require.NoError(t, err)
						require.Equal(t, address.String(), from.String())
						require.Equal(t, payload, buffer[:n])
					}
					_ = packet.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
					_, _, err = packet.ReadFrom(b)
					require.ErrorIs(t, err, os.ErrDeadlineExceeded)
					_ = packet.SetReadDeadline(time.Time{})
					readDone := make(chan error, 1)
					go func() { _, _, err := packet.ReadFrom(b); readDone <- err }()
					require.NoError(t, proxy.Close())
					select {
					case err := <-readDone:
						require.Error(t, err)
					case <-time.After(time.Second):
						t.Fatal("adapter close did not unblock UDP reader")
					}
					_, err = proxy.DialContext(ctx, metadata(tcpTarget, C.TCP))
					require.Error(t, err)
					if network == "tcp" {
						require.Positive(t, dialer.tcp.Load())
					} else {
						require.Positive(t, dialer.udp.Load())
					}
					for _, test := range []struct {
						name   string
						change func(*outbound.NowhereOption)
					}{
						{"wrong pin", func(o *outbound.NowhereOption) { o.Pin = strings.Repeat("00", 32) }},
						{"untrusted certificate", func(o *outbound.NowhereOption) { o.Pin = "" }},
						{"wrong key", func(o *outbound.NowhereOption) { o.Password = "1123456789abcdef0123456789abcdef" }},
					} {
						t.Run(test.name, func(t *testing.T) {
							o := outbound.NowhereOption{Name: "bad", Server: host, Port: port, Password: nowheretest.SharedKey, Network: network, Morph: &masked, Pin: pin, SNI: "localhost", SetupTimeout: 250, HandshakeTimeout: 250}
							test.change(&o)
							p, err := outbound.NewNowhere(o)
							require.NoError(t, err)
							defer p.Close()
							c, err := p.DialContext(context.Background(), metadata(tcpTarget, C.TCP))
							if c != nil {
								c.Close()
							}
							require.Error(t, err)
						})
					}
				})
			}
		})
	}
}
