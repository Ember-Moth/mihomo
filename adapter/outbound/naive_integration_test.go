//go:build with_naive

package outbound_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
)

func TestNaiveInterop(t *testing.T) {
	binary := os.Getenv("NAIVE_TEST_SERVER")
	if binary == "" {
		t.Skip("set NAIVE_TEST_SERVER to a sing-box executable to run native interoperability tests")
	}
	certificate, key := naiveTestCertificates(t)
	tcpAddress, udpAddress := naiveEchoServers(t)
	for _, quic := range []bool{false, true} {
		t.Run(fmt.Sprintf("quic=%t", quic), func(t *testing.T) {
			port := naiveStartServer(t, binary, certificate, key, quic)
			mapping := map[string]any{
				"type": "naive", "name": "naive-test", "server": "127.0.0.1", "port": port,
				"sni": "naive.example.org", "username": "test", "password": "test-password",
				"certificate": certificate, "quic": quic, "udp-over-tcp": true,
			}
			dialer := &naiveRecordingDialer{}
			newProxy := func(t *testing.T, changes map[string]any) C.Proxy {
				t.Helper()
				config := make(map[string]any, len(mapping))
				for key, value := range mapping {
					config[key] = value
				}
				for key, value := range changes {
					config[key] = value
				}
				proxy, err := adapter.ParseProxy(config, adapter.WithDialerForAPI(dialer))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = proxy.Close() })
				return proxy
			}
			proxy := newProxy(t, nil)
			if proxy.Type() != C.Naive || !proxy.SupportUDP() || !proxy.SupportUOT() {
				t.Fatal("incorrect adapter capabilities")
			}
			t.Run("TCP padding and reuse", func(t *testing.T) {
				for connection := 0; connection < 3; connection++ {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					conn, err := proxy.DialContext(ctx, naiveMetadata(t, tcpAddress, C.TCP))
					cancel()
					if err != nil {
						t.Fatal(err)
					}
					_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
					// Cross both the 8 padded writes and 65535-byte chunk boundaries.
					for i := 0; i < 12; i++ {
						payload := bytes.Repeat([]byte{byte(i + 1)}, 70000+i)
						if _, err = conn.Write(payload); err != nil {
							_ = conn.Close()
							t.Fatal(err)
						}
						got := make([]byte, len(payload))
						if _, err = io.ReadFull(conn, got); err != nil {
							_ = conn.Close()
							t.Fatal(err)
						}
						if !bytes.Equal(payload, got) {
							_ = conn.Close()
							t.Fatal("payload corrupted")
						}
					}
					_ = conn.Close()
				}
				if dialer.calls.Load() == 0 {
					t.Fatal("API dialer was bypassed")
				}
			})
			for _, version := range []int{1, 2} {
				t.Run(fmt.Sprintf("UoT version %d", version), func(t *testing.T) {
					p := newProxy(t, map[string]any{"udp-over-tcp-version": version})
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					conn, err := p.ListenPacketContext(ctx, naiveMetadata(t, udpAddress, C.UDP))
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
					address, err := net.ResolveUDPAddr("udp", udpAddress)
					if err != nil {
						t.Fatal(err)
					}
					payload := []byte("Naive UoT round trip")
					if _, err = conn.WriteTo(payload, address); err != nil {
						t.Fatal(err)
					}
					buffer := make([]byte, 2048)
					n, source, err := conn.ReadFrom(buffer)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(buffer[:n], payload) || source.String() != udpAddress {
						t.Fatalf("bad UDP response from %v", source)
					}
				})
			}
			for name, changes := range map[string]map[string]any{
				"wrong credentials":     {"password": "wrong-password"},
				"wrong TLS hostname":    {"sni": "wrong.example.org"},
				"untrusted certificate": {"certificate": ""},
			} {
				t.Run(name, func(t *testing.T) {
					p := newProxy(t, changes)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					conn, err := p.DialContext(ctx, naiveMetadata(t, tcpAddress, C.TCP))
					if conn != nil {
						_ = conn.Close()
					}
					if err == nil {
						t.Fatal("invalid authentication or TLS configuration succeeded")
					}
				})
			}
			t.Run("cancellation and shutdown", func(t *testing.T) {
				p := newProxy(t, nil)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if _, err := p.DialContext(ctx, naiveMetadata(t, tcpAddress, C.TCP)); !errors.Is(err, context.Canceled) {
					t.Fatalf("expected cancellation: %v", err)
				}
				ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				conn, err := p.DialContext(ctx, naiveMetadata(t, tcpAddress, C.TCP))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				done := make(chan error, 1)
				go func() { done <- p.Close() }()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("Close blocked with an active stream")
				}
				if _, err := p.DialContext(ctx, naiveMetadata(t, tcpAddress, C.TCP)); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("dial after Close: %v", err)
				}
				if err := p.Close(); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestNaivePendingDialShutdown(t *testing.T) {
	if os.Getenv("NAIVE_TEST_SERVER") == "" {
		t.Skip("set NAIVE_TEST_SERVER to enable tests that require the native Cronet library")
	}
	dialer := &naiveBlockingDialer{started: make(chan struct{})}
	proxy, err := adapter.ParseProxy(map[string]any{
		"type": "naive", "name": "blocked", "server": "127.0.0.1", "port": 443,
	}, adapter.WithDialerForAPI(dialer))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = proxy.DialContext(ctx, naiveMetadata(t, "127.0.0.1:80", C.TCP))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending handshake did not honor context deadline: %v", err)
	}
	select {
	case <-dialer.started:
	default:
		t.Fatal("transport dialer was not called")
	}
	done := make(chan error, 1)
	go func() { done <- proxy.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel the pending transport dial")
	}
}

func TestNaiveECHInterop(t *testing.T) {
	binary := os.Getenv("NAIVE_TEST_SERVER")
	if binary == "" {
		t.Skip("set NAIVE_TEST_SERVER to run native ECH interoperability tests")
	}
	certificate, key := naiveTestCertificates(t)
	echConfig, echKey, err := ech.GenECHConfig("public.example.org")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddress, _ := naiveEchoServers(t)
	for _, quic := range []bool{false, true} {
		t.Run(fmt.Sprintf("quic=%t", quic), func(t *testing.T) {
			port := naiveStartServer(t, binary, certificate, key, quic, echKey)
			proxy, err := adapter.ParseProxy(map[string]any{
				"type": "naive", "name": "ech", "server": "127.0.0.1", "port": port,
				"sni": "naive.example.org", "certificate": certificate, "quic": quic,
				"username": "test", "password": "test-password",
				"ech-opts": map[string]any{"enable": true, "config": echConfig},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := proxy.DialContext(ctx, naiveMetadata(t, tcpAddress, C.TCP))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("Naive ECH round trip")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, buffer); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buffer, payload) {
				t.Fatal("ECH tunnel payload corrupted")
			}
		})
	}
}

type naiveBlockingDialer struct {
	C.Dialer
	started chan struct{}
	once    sync.Once
}

func (d *naiveBlockingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

type naiveRecordingDialer struct{ calls atomic.Int32 }
type naiveWrappedConn struct{ net.Conn }

func (d *naiveRecordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.calls.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	// Hide the raw socket to exercise Cronet's relay path used by proxy dialers.
	return naiveWrappedConn{conn}, nil
}
func (d *naiveRecordingDialer) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}

func naiveMetadata(t *testing.T, address string, network C.NetWork) *C.Metadata {
	t.Helper()
	m := &C.Metadata{NetWork: network}
	if err := m.SetRemoteAddress(address); err != nil {
		t.Fatal(err)
	}
	return m
}

func naiveEchoServers(t *testing.T) (string, string) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, addr, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buffer[:n], addr)
		}
	}()
	return tcp.Addr().String(), udp.LocalAddr().String()
}

func naiveTestCertificates(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "naive.example.org"},
		DNSNames: []string{"naive.example.org"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func naiveStartServer(t *testing.T, binary, certificate, key string, quic bool, echKey ...string) int {
	t.Helper()
	dir := t.TempDir()
	var port int
	if quic {
		listener, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = listener.LocalAddr().(*net.UDPAddr).Port
		_ = listener.Close()
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte(certificate), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	network := "tcp"
	if quic {
		network = "udp"
	}
	tlsConfig := map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath}
	if len(echKey) > 0 {
		echPath := filepath.Join(dir, "ech.pem")
		if err := os.WriteFile(echPath, []byte(echKey[0]), 0600); err != nil {
			t.Fatal(err)
		}
		tlsConfig["ech"] = map[string]any{"enabled": true, "key_path": echPath}
	}
	config := map[string]any{
		"log": map[string]any{"level": "info", "disabled": false},
		"inbounds": []any{map[string]any{
			"type": "naive", "listen": "127.0.0.1", "listen_port": port, "network": network,
			"users": []any{map[string]any{"username": "test", "password": "test-password"}},
			"tls":   tlsConfig,
		}},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-c", configPath)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done; _ = logFile.Close() })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output, _ := os.ReadFile(logPath)
		if strings.Contains(string(output), "sing-box started") {
			return port
		}
		select {
		case <-done:
			t.Fatalf("sing-box exited: %s", output)
		case <-time.After(20 * time.Millisecond):
		}
	}
	output, _ := os.ReadFile(logPath)
	t.Fatalf("sing-box did not become ready: %s", output)
	return 0
}
