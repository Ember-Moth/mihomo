package nowhere_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/internal/testutil/nowheretest"
	. "github.com/metacubex/mihomo/pkg/nowhere"
)

func TestRustPortalInterop(t *testing.T) {
	for _, masked := range []bool{false, true} {
		t.Run(fmt.Sprintf("morph=%t", masked), func(t *testing.T) {
			address, _, tlsConfig := nowheretest.StartPortal(t, masked)
			tcpTarget, udpTarget := nowheretest.EchoTargets(t)
			for _, network := range []string{"tcp", "udp"} {
				t.Run(network, func(t *testing.T) {
					options := Options{SharedKey: nowheretest.SharedKey, Network: network, TLSConfig: tlsConfig, Morph: masked,
						DialStream: func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", address) },
						DialPacket: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
							addr, err := net.ResolveUDPAddr("udp", address)
							if err != nil {
								return nil, nil, err
							}
							pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
							return pc, addr, err
						}}
					client, err := NewClient(options)
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					conn, err := client.DialTCP(ctx, tcpTarget)
					if err != nil {
						t.Fatal(err)
					}
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					payload := bytes.Repeat([]byte("nw3"), 40000)
					if _, err = conn.Write(payload); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(payload))
					if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
						t.Fatal("TCP", err)
					}
					if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					if n, err := conn.Read(got); n != 0 || err != io.EOF {
						t.Fatal("half-close", n, err)
					}
					conn.Close()
					pc, err := client.DialUDP(ctx, udpTarget)
					if err != nil {
						t.Fatal(err)
					}
					defer pc.Close()
					largest := 60000
					if runtime.GOOS == "darwin" {
						// Darwin defaults net.inet.udp.maxdgram to 9216. The Rust
						// Portal's real target socket is subject to this OS limit.
						largest = 8192
					}
					for _, size := range []int{0, 1, 100, 5000, largest} {
						_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
						p := bytes.Repeat([]byte{byte(size)}, size)
						if n, err := pc.Write(p); err != nil || n != size {
							t.Fatal("UDP write", size, n, err)
						}
						b := make([]byte, 65535)
						n, err := pc.Read(b)
						if err != nil || !bytes.Equal(b[:n], p) {
							t.Fatal("UDP read", size, n, err)
						}
					}
					var wg sync.WaitGroup
					for i := 0; i < 8; i++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							c, err := client.DialTCP(ctx, tcpTarget)
							if err != nil {
								t.Error(err)
								return
							}
							defer c.Close()
							_ = c.SetDeadline(time.Now().Add(3 * time.Second))
							_, err = c.Write([]byte("test"))
							if err != nil {
								t.Error(err)
								return
							}
							b := make([]byte, 4)
							_, err = io.ReadFull(c, b)
							if err != nil || string(b) != "test" {
								t.Error("concurrent flow", err)
							}
						}()
					}
					wg.Wait()
					t.Run("IPv6 targets", func(t *testing.T) {
						tcp6, udp6 := nowheretest.EchoTargetsIP(t, "::1")
						for _, target := range []Target{tcp6, udp6} {
							var flow net.Conn
							if target == tcp6 {
								flow, err = client.DialTCP(ctx, target)
							} else {
								flow, err = client.DialUDP(ctx, target)
							}
							if err != nil {
								t.Fatal(err)
							}
							_ = flow.SetDeadline(time.Now().Add(3 * time.Second))
							_, err = flow.Write([]byte("ipv6"))
							if err != nil {
								flow.Close()
								t.Fatal(err)
							}
							b := make([]byte, 4)
							_, err = io.ReadFull(flow, b)
							flow.Close()
							if err != nil || string(b) != "ipv6" {
								t.Fatal(err)
							}
						}
					})
					// All Prelude sender policies share the same wire decoder.
					if masked {
						for _, policy := range []string{"full8", "low7"} {
							options.TCPPrelude, options.UDPPrelude = policy, policy
							variant, err := NewClient(options)
							if err != nil {
								t.Fatal(err)
							}
							for _, udp := range []bool{false, true} {
								var flow net.Conn
								if udp {
									flow, err = variant.DialUDP(ctx, udpTarget)
								} else {
									flow, err = variant.DialTCP(ctx, Target{Host: "localhost", Port: tcpTarget.Port})
								}
								if err != nil {
									variant.Close()
									t.Fatal(policy, err)
								}
								_ = flow.SetDeadline(time.Now().Add(3 * time.Second))
								_, err = flow.Write([]byte("policy"))
								if err != nil {
									t.Fatal(policy, err)
								}
								b := make([]byte, 6)
								_, err = io.ReadFull(flow, b)
								flow.Close()
								if err != nil || string(b) != "policy" {
									t.Fatal(policy, err)
								}
							}
							variant.Close()
						}
					}
				})
			}
		})
	}
}
