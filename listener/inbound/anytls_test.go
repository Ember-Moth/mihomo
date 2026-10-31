package inbound_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testInboundAnyTLS(t *testing.T, inboundOptions inbound.AnyTLSOption, outboundOptions outbound.AnyTLSOption) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "anytls_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = map[string]string{"test": userUUID}
	in, err := inbound.NewAnyTLS(&inboundOptions)
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

	outboundOptions.Name = "anytls_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = userUUID
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

	out, err := outbound.NewAnyTLS(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}

func TestInboundAnyTLS_TLS(t *testing.T) {
	inboundOptions := inbound.AnyTLSOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.AnyTLSOption{
		Fingerprint: tlsFingerprint,
	}
	testInboundAnyTLS(t, inboundOptions, outboundOptions)
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundAnyTLS(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		testInboundAnyTLS(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS+ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundAnyTLS(t, inboundOptions, outboundOptions)
	})
}

func testInboundAnyTLSUTLS(t *testing.T, inboundOptions inbound.AnyTLSOption, outboundOptions outbound.AnyTLSOption) {
	t.Parallel()
	t.Run("Conn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		testInboundAnyTLS(t, inboundOptions, outboundOptions)
	})
	t.Run("UConn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		outboundOptions.ClientFingerprint = "chrome"
		testInboundAnyTLS(t, inboundOptions, outboundOptions)
	})
}

func TestInboundAnyTLS_ShadowTLS(t *testing.T) {
	const password = "shadow-tls-password"
	inboundOptions := inbound.AnyTLSOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: password}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.AnyTLSOption{
		SNI:           realityDest,
		Fingerprint:   tlsFingerprint,
		ShadowTLSOpts: outbound.ShadowTLSOptions{Password: password, Version: 3},
	}
	testInboundAnyTLSUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundAnyTLS_Restls(t *testing.T) {
	const password = "restls-password"
	inboundOptions := inbound.AnyTLSOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: password,
		},
	}
	outboundOptions := outbound.AnyTLSOption{
		SNI:         realityDest,
		Fingerprint: tlsFingerprint,
		RestlsOpts:  outbound.RestlsOptions{Password: password, VersionHint: "tls13"},
	}
	testInboundAnyTLSUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundAnyTLS_JLS(t *testing.T) {
	const username = "jls-user"
	const password = "jls-password"
	inboundOptions := inbound.AnyTLSOption{
		JLSConfig: inbound.JLSConfig{
			Enable: true,
			Users:  []inbound.JLSUser{{Username: username, Password: password}},
			SNI:    realityDest,
			Dest:   net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.AnyTLSOption{
		SNI:     realityDest,
		JLSOpts: outbound.JLSOptions{Username: username, Password: password},
	}
	testInboundAnyTLSUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundAnyTLS_Reality(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		hybrid       bool
		disableReuse bool
	}{
		{name: "X25519"},
		{name: "X25519MLKEM768", hybrid: true},
		{name: "DisableReuse", disableReuse: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			inboundOptions := inbound.AnyTLSOption{
				RealityConfig: inbound.RealityConfig{
					Dest:        net.JoinHostPort(realityDest, "443"),
					PrivateKey:  realityPrivateKey,
					ShortID:     []string{realityShortid},
					ServerNames: []string{realityDest},
				},
			}
			outboundOptions := outbound.AnyTLSOption{
				SNI:               realityDest,
				ClientFingerprint: "chrome",
				DisableReuse:      testCase.disableReuse,
				RealityOpts: outbound.RealityOptions{
					PublicKey:             realityPublickey,
					ShortID:               realityShortid,
					SupportX25519MLKEM768: &testCase.hybrid,
				},
			}
			testInboundAnyTLS(t, inboundOptions, outboundOptions)
		})
	}
}

func TestInboundAnyTLS_RealityUDP(t *testing.T) {
	in, err := listener.ParseListener(map[string]any{
		"name": "anytls-reality", "type": "anytls", "listen": "127.0.0.1", "port": 0,
		"users": map[string]any{"test": userUUID},
		"reality-config": map[string]any{
			"dest": net.JoinHostPort(realityDest, "443"), "private-key": realityPrivateKey,
			"short-id": []string{realityShortid}, "server-names": []string{realityDest},
		},
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
	out, err := outbound.NewAnyTLS(outbound.AnyTLSOption{
		BasicOption: outbound.BasicOption{DialerForAPI: tunnel.NewDialer()},
		Name:        "anytls-reality", Server: addrPort.Addr().String(), Port: int(addrPort.Port()),
		Password: userUUID, SNI: realityDest, ClientFingerprint: "chrome", UDP: true,
		RealityOpts: outbound.RealityOptions{PublicKey: realityPublickey, ShortID: realityShortid},
	})
	require.NoError(t, err)
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	metadata := &C.Metadata{NetWork: C.UDP, DstIP: remoteAddr, DstPort: 5353}
	conn, err := out.ListenPacketContext(ctx, metadata)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	payload := []byte("AnyTLS over REALITY UDP round trip")
	_, err = conn.WriteTo(payload, metadata.UDPAddr())
	require.NoError(t, err)
	buffer := make([]byte, 1024)
	n, source, err := conn.ReadFrom(buffer)
	require.NoError(t, err)
	require.Equal(t, payload, buffer[:n])
	require.Equal(t, metadata.UDPAddr().String(), source.String())
}

func TestInboundAnyTLS_RealityRejectsWrongShortID(t *testing.T) {
	in, err := inbound.NewAnyTLS(&inbound.AnyTLSOption{
		BaseOption: inbound.BaseOption{NameStr: "anytls-reality", Listen: "127.0.0.1", Port: "0"},
		Users:      map[string]string{"test": userUUID},
		RealityConfig: inbound.RealityConfig{
			Dest: net.JoinHostPort(realityDest, "443"), PrivateKey: realityPrivateKey,
			ShortID: []string{realityShortid}, ServerNames: []string{realityDest},
		},
	})
	require.NoError(t, err)
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	require.NoError(t, in.Listen(tunnel))
	defer in.Close()
	addrPort, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)
	out, err := outbound.NewAnyTLS(outbound.AnyTLSOption{
		BasicOption: outbound.BasicOption{DialerForAPI: tunnel.NewDialer()},
		Name:        "anytls-reality", Server: addrPort.Addr().String(), Port: int(addrPort.Port()),
		Password: userUUID, SNI: realityDest, ClientFingerprint: "chrome",
		RealityOpts: outbound.RealityOptions{PublicKey: realityPublickey, ShortID: "0000000000000000"},
	})
	require.NoError(t, err)
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: remoteAddr, DstPort: 80})
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err, "wrong REALITY short ID must not fall back to a plain AnyTLS connection")
}
