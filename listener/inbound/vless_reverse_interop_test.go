package inbound_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/require"
)

// The wire-format reference and the CI binary are pinned to Xray v26.10.31.
func reverseXrayBinary(t *testing.T) string {
	t.Helper()
	if skip, _ := strconv.ParseBool(os.Getenv("SKIP_INTEROP_TEST")); skip {
		t.Skip("SKIP_INTEROP_TEST is set")
	}
	binary := os.Getenv("XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("set XRAY_TEST_BINARY to an Xray v26.10.31 executable")
	}
	output, err := exec.Command(binary, "version").CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "Xray 26.10.31")
	return binary
}

func reverseTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func reverseXrayTLS(t *testing.T) map[string]any {
	t.Helper()
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(cert, []byte(tlsCertificate), 0600))
	require.NoError(t, os.WriteFile(key, []byte(tlsPrivateKey), 0600))
	return map[string]any{"security": "tls", "network": "raw", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": cert, "keyFile": key}}}}
}

func reverseXrayFreedom() map[string]any {
	return map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8", "::1/128"}}}}}
}

func reverseXrayTLSClient(t *testing.T) map[string]any {
	t.Helper()
	certificate, _ := pem.Decode([]byte(tlsCertificate))
	require.NotNil(t, certificate)
	fingerprint := sha256.Sum256(certificate.Bytes)
	return map[string]any{"network": "raw", "security": "tls", "tlsSettings": map[string]any{"serverName": "localhost", "pinnedPeerCertSha256": hex.EncodeToString(fingerprint[:])}}
}

func startReverseXray(t *testing.T, binary string, config map[string]any, port int) {
	t.Helper()
	dir := t.TempDir()
	configPath, logPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "xray.log")
	config["log"] = map[string]any{"loglevel": "debug"}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, data, 0600))
	checked, err := exec.Command(binary, "run", "-test", "-config", configPath).CombinedOutput()
	require.NoError(t, err, string(checked))
	logFile, err := os.Create(logPath)
	require.NoError(t, err)
	command := exec.Command(binary, "run", "-config", configPath)
	command.Stdout = logFile
	command.Stderr = logFile
	require.NoError(t, command.Start())
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		_ = command.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Xray did not exit")
		}
		logFile.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			t.Log(string(data))
		}
	})
	if port != 0 {
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		require.Eventually(t, func() bool {
			conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err != nil {
				return false
			}
			conn.Close()
			return true
		}, 5*time.Second, 20*time.Millisecond)
	}
}

func TestVlessReverseXrayHub(t *testing.T) {
	binary := reverseXrayBinary(t)
	for _, flow := range []string{"", "xtls-rprx-vision"} {
		t.Run("flow="+flow, func(t *testing.T) {
			vlessPort, socksPort := reverseTestPort(t), reverseTestPort(t)
			config := map[string]any{
				"inbounds": []any{
					map[string]any{"tag": "reverse-transport", "listen": "127.0.0.1", "port": vlessPort, "protocol": "vless", "settings": map[string]any{"decryption": "none", "users": []any{map[string]any{"id": userUUID, "flow": flow, "reverse": map[string]any{"tag": "home"}}}}, "streamSettings": reverseXrayTLS(t)},
					map[string]any{"tag": "entry", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"udp": true}},
				},
				"outbounds": []any{reverseXrayFreedom()},
				"routing":   map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"entry"}, "outboundTag": "home"}}},
			}
			startReverseXray(t, binary, config, vlessPort)
			leaf := newReverseTunnel(t)
			seen := make(chan C.Metadata, 8)
			leaf.HandleTCPConnFn = func(conn net.Conn, metadata *C.Metadata) {
				defer conn.Close()
				seen <- *metadata
				_, _ = io.Copy(conn, conn)
			}
			leaf.HandleUDPPacketFn = func(packet C.UDPPacket, metadata *C.Metadata) {
				defer packet.Drop()
				_, _ = packet.WriteBack(packet.Data(), metadata.UDPAddr())
			}
			link, err := adapter.ParseProxy(map[string]any{"name": "hub-link", "type": "vless", "server": "127.0.0.1", "port": vlessPort, "uuid": userUUID, "tls": true, "fingerprint": tlsFingerprint, "flow": flow}, adapter.WithTunnelForAPI(leaf), adapter.WithDialerForAPI(leaf.NewDialer()))
			require.NoError(t, err)
			defer link.Close()
			leaf.setProxy(link)
			bridge, err := inbound.NewVlessReverse(&inbound.VlessReverseOption{BaseOption: inbound.BaseOption{NameStr: "home-in", SpecialProxy: "DIRECT"}, Outbound: "hub-link"})
			require.NoError(t, err)
			require.NoError(t, bridge.Listen(leaf))
			defer bridge.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			require.NoError(t, bridge.WaitReady(ctx))
			entry, err := outbound.NewSocks5(outbound.Socks5Option{Name: "xray-entry", Server: "127.0.0.1", Port: socksPort, UDP: true})
			require.NoError(t, err)
			defer entry.Close()
			conn, err := entry.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "inside.example", DstPort: 22})
			require.NoError(t, err)
			reverseEchoTCP(t, conn, 128*1024)
			metadata := <-seen
			require.Equal(t, netip.MustParseAddr("127.0.0.1"), metadata.SrcIP)
			require.NotZero(t, metadata.SrcPort)
			require.EqualValues(t, socksPort, metadata.InPort)
			require.Equal(t, "home-in", metadata.InName)
			packet, err := entry.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.9"), DstPort: 5353})
			require.NoError(t, err)
			reverseEchoUDP(t, packet)
		})
	}
}

func reverseEchoServers(t *testing.T) (netip.AddrPort, []netip.AddrPort) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	var udpAddresses []netip.AddrPort
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		conn, err := net.ListenPacket("udp", address)
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		udpAddresses = append(udpAddresses, conn.LocalAddr().(*net.UDPAddr).AddrPort())
		go func() {
			buffer := make([]byte, 8192)
			for {
				n, addr, err := conn.ReadFrom(buffer)
				if err != nil {
					return
				}
				if _, err = conn.WriteTo(buffer[:n], addr); err != nil {
					return
				}
			}
		}()
	}
	return listener.Addr().(*net.TCPAddr).AddrPort(), udpAddresses
}

func TestVlessReverseXraySpoke(t *testing.T) {
	binary := reverseXrayBinary(t)
	for _, flow := range []string{"", "xtls-rprx-vision"} {
		t.Run("flow="+flow, func(t *testing.T) {
			tcpAddress, udpAddresses := reverseEchoServers(t)
			hub := newReverseTunnel(t)
			proxy := reverseOutbound(t, hub, "home")
			server, err := inbound.NewVless(&inbound.VlessOption{BaseOption: inbound.BaseOption{NameStr: "public-vless", Listen: "127.0.0.1", Port: "0"}, Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
				Users: []inbound.VlessUser{{UUID: userUUID, Flow: flow, Reverse: &LC.VlessReverse{Tag: "home"}}}})
			require.NoError(t, err)
			require.NoError(t, server.Listen(hub))
			defer server.Close()
			address, err := netip.ParseAddrPort(server.Address())
			require.NoError(t, err)
			config := map[string]any{
				"outbounds": []any{reverseXrayFreedom(), map[string]any{"tag": "reverse-link", "protocol": "vless", "settings": map[string]any{"address": "127.0.0.1", "port": address.Port(), "id": userUUID, "encryption": "none", "flow": flow, "reverse": map[string]any{"tag": "reverse-in"}}, "streamSettings": reverseXrayTLSClient(t)}},
				"routing":   map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"reverse-in"}, "outboundTag": "direct"}}},
			}
			startReverseXray(t, binary, config, 0)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			require.NoError(t, hub.registry.Get("home").WaitReady(ctx))
			conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: tcpAddress.Addr(), DstPort: tcpAddress.Port()})
			require.NoError(t, err)
			reverseEchoTCP(t, conn, 128*1024)
			packet, err := proxy.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: udpAddresses[0].Addr(), DstPort: udpAddresses[0].Port()})
			require.NoError(t, err)
			defer packet.Close()
			packet.SetDeadline(time.Now().Add(5 * time.Second))
			for _, target := range udpAddresses {
				want := bytes.Repeat([]byte("xray-udp"), 100)
				_, err = packet.WriteTo(want, net.UDPAddrFromAddrPort(target))
				require.NoError(t, err)
				buffer := make([]byte, 8192)
				n, source, err := packet.ReadFrom(buffer)
				require.NoError(t, err)
				require.Equal(t, want, buffer[:n])
				require.Equal(t, target.String(), source.String())
			}
		})
	}
}
