package nowhere

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

const lifecycleKey = "0123456789abcdef0123456789abcdef"

type quicPeer struct {
	address     net.Addr
	tls         *tls.Config
	connections chan *quic.Conn
	streams     chan *quic.Stream
	result      atomic.Uint32
	hold        atomic.Bool
}

func testTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{ALPN}, MinVersion: tls.VersionTLS13}, &tls.Config{RootCAs: roots, ServerName: "localhost"}
}

func newQUICPeer(t *testing.T, datagrams, ready bool) *quicPeer {
	t.Helper()
	serverTLS, clientTLS := testTLS(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: datagrams, MaxIncomingStreams: 128, MaxIncomingUniStreams: -1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &quicPeer{address: listener.Addr(), tls: clientTLS, connections: make(chan *quic.Conn, 8), streams: make(chan *quic.Stream, 32)}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var conns []*quic.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			p.connections <- conn
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.CloseWithError(0, "")
				auth, err := conn.AcceptStream(ctx)
				if err != nil {
					return
				}
				_ = auth.SetDeadline(time.Now().Add(3 * time.Second))
				b, err := io.ReadAll(auth)
				if err != nil || len(b) != 16 || auth.StreamID() != 0 {
					return
				}
				state := conn.ConnectionState()
				exporter, err := state.TLS.ExportKeyingMaterial(exporterLabel, []byte{}, 32)
				if err != nil {
					return
				}
				expected := authFrame(vectorKey(lifecycleKey), 2, exporter)
				if !bytes.Equal(b, expected[:]) {
					return
				}
				_ = auth.Close()
				if datagrams {
					wg.Add(1)
					go func() {
						defer wg.Done()
						r, _ := NewDatagramReassembler(DefaultReassemblyConfig())
						var packetID uint32 = 1
						for {
							b, err := conn.ReceiveDatagram(ctx)
							if err != nil {
								return
							}
							f, err := DecodeUDPFrame(b)
							if err != nil {
								continue
							}
							payload := f.Payload
							if f.Type == UDPFrameFragment {
								var complete bool
								payload, complete, err = r.Push(f, time.Now())
								if err != nil || !complete {
									continue
								}
							} else if f.Type != UDPFrameData {
								continue
							}
							frames, err := EncodeUDPFragments(f.FlowID, packetID, payload, 1000)
							packetID++
							if err != nil {
								return
							}
							for _, frame := range frames {
								if err := conn.SendDatagram(frame); err != nil {
									return
								}
							}
						}
					}()
				}
				for {
					s, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						_ = s.SetReadDeadline(time.Now().Add(3 * time.Second))
						request := make([]byte, 8) // known IPv4 test target
						if _, err := io.ReadFull(s, request); err != nil {
							return
						}
						p.streams <- s
						if !ready {
							<-conn.Context().Done()
							return
						}
						if _, err := s.Write([]byte{byte(p.result.Load())}); err != nil {
							return
						}
						if p.hold.Load() {
							<-conn.Context().Done()
							return
						}
						_ = s.SetReadDeadline(time.Time{})
						if request[0]&1 == 0 {
							_, _ = io.Copy(s, s)
							_ = s.Close()
						} else {
							var b [1]byte
							_, _ = s.Read(b[:])
						}
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		mu.Lock()
		for _, c := range conns {
			c.CloseWithError(0, "")
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("QUIC peer leaked tasks")
		}
	})
	return p
}

func (p *quicPeer) client(t *testing.T) *Client {
	c, err := NewClient(Options{SharedKey: lifecycleKey, Network: "udp", TLSConfig: p.tls, SetupTimeout: time.Second, DialPacket: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
		return pc, p.address, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestNowhereQUICLifecycle(t *testing.T) {
	peer := newQUICPeer(t, true, true)
	client := peer.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := Target{"127.0.0.1", 80}
	for _, end := range []string{"fin", "reset", "stop"} {
		t.Run(end, func(t *testing.T) {
			packet, err := client.DialUDP(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			stream := <-peer.streams
			_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
			payload := bytes.Repeat([]byte{7}, 65535)
			if _, err := packet.Write(payload); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 65535)
			n, err := packet.Read(b)
			if err != nil || !bytes.Equal(b[:n], payload) {
				t.Fatal("maximum QUIC payload", n, err)
			}
			_ = packet.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			if _, err := packet.Read(b); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
			_ = packet.SetReadDeadline(time.Now().Add(time.Second))
			switch end {
			case "fin":
				_ = stream.Close()
			case "reset":
				stream.CancelWrite(7)
			case "stop":
				stream.CancelRead(7)
			}
			if _, err := packet.Read(b); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("control stream failed to close UDP flow", err)
			}
		})
	}
	conn, err := client.DialTCP(ctx, target)
	if err != nil {
		t.Fatal("unrelated flow failed", err)
	}
	<-peer.streams
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte("alive"))
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if _, err = io.ReadFull(conn, b); err != nil || string(b) != "alive" {
		t.Fatal(err)
	}
	conn.Close()
	server := <-peer.connections
	client.mu.Lock()
	old := client.quic
	client.mu.Unlock()
	_ = server.CloseWithError(1, "reconnect test")
	select {
	case <-old.ctx.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	conn, err = client.DialTCP(ctx, target)
	if err != nil {
		t.Fatal("reconnect", err)
	}
	conn.Close()
	client.Close()
	client.mu.Lock()
	active := len(client.active)
	client.mu.Unlock()
	if active != 0 || len(client.permits) != 0 {
		t.Fatal("client retained flows")
	}
}

func TestNowhereNoDatagramFallback(t *testing.T) {
	peer := newQUICPeer(t, false, true)
	client := peer.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := client.DialUDP(ctx, Target{"127.0.0.1", 80}); err == nil {
		conn.Close()
		t.Fatal("missing DATAGRAM support accepted")
	}
	conn, err := client.DialTCP(ctx, Target{"127.0.0.1", 80})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestNowhereCancelSetup(t *testing.T) {
	peer := newQUICPeer(t, true, false)
	client := peer.client(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := client.DialUDP(ctx, Target{"127.0.0.1", 80})
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	select {
	case <-peer.streams:
	case <-time.After(3 * time.Second):
		t.Fatal("flow did not reach setup")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("setup completed without READY")
		}
	case <-time.After(time.Second):
		t.Fatal("setup did not cancel")
	}
	client.mu.Lock()
	q := client.quic
	client.mu.Unlock()
	if q == nil {
		t.Fatal("handshake did not complete")
	}
	q.mu.Lock()
	flows := len(q.flows)
	reserved := q.reassembly.ReservedBytes()
	q.mu.Unlock()
	if flows != 0 || reserved != 0 || len(client.permits) != 0 {
		t.Fatal("cancelled setup leaked resources")
	}
}

func TestNowhereQUICFailuresAreIsolated(t *testing.T) {
	peer := newQUICPeer(t, true, true)
	client := peer.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target := Target{"127.0.0.1", 80}
	peer.result.Store(255)
	if conn, err := client.DialTCP(ctx, target); err == nil {
		conn.Close()
		t.Fatal("unknown setup result accepted")
	}
	<-peer.streams
	peer.result.Store(0)
	packet, err := client.DialUDP(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	<-peer.streams
	_ = packet.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := packet.Write([]byte("must not send")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	_ = packet.SetDeadline(time.Now().Add(time.Second))
	if _, err := packet.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 100)
	n, err := packet.Read(b)
	if err != nil || string(b[:n]) != "ok" {
		t.Fatal("deadline recovery", n, err)
	}
	server := <-peer.connections
	stream, err := server.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = stream.Write([]byte{0})
	client.mu.Lock()
	q := client.quic
	client.mu.Unlock()
	select {
	case <-q.ctx.Done():
	case <-ctx.Done():
		t.Fatal("server-initiated stream did not close the connection")
	}
}

func TestNowhereQUICCloseUnblocksWrite(t *testing.T) {
	peer := newQUICPeer(t, true, true)
	peer.hold.Store(true)
	client := peer.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialTCP(ctx, Target{"127.0.0.1", 80})
	if err != nil {
		t.Fatal(err)
	}
	<-peer.streams
	done := make(chan error, 1)
	go func() { _, err := conn.Write(make([]byte, 8<<20)); done <- err }()
	// Give Write time to fill the peer's receive window; this peer never reads.
	select {
	case err := <-done:
		t.Fatal("write did not wait for flow control", err)
	case <-time.After(30 * time.Millisecond):
	}
	conn.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed write succeeded")
		}
	case <-ctx.Done():
		t.Fatal("Close did not interrupt Write")
	}
}

func TestNowhereCancelTLSHandshake(t *testing.T) {
	_, config := testTLS(t)
	for _, masked := range []bool{false, true} {
		left, right := net.Pipe()
		client, err := NewClient(Options{SharedKey: lifecycleKey, Network: "tcp", TLSConfig: config, Morph: masked, DialStream: func(context.Context) (net.Conn, error) { return left, nil }})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err = client.DialTCP(ctx, Target{"127.0.0.1", 80})
		cancel()
		client.Close()
		right.Close()
		if err == nil || len(client.permits) != 0 {
			t.Fatal("TLS cancellation", err)
		}
	}
}
