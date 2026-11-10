package outbound

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/pkg/nowhere"
	"github.com/metacubex/tls"
)

type NowhereOption struct {
	BasicOption
	Name             string `proxy:"name"`
	Server           string `proxy:"server"`
	Port             int    `proxy:"port"`
	Password         string `proxy:"password"`
	Network          string `proxy:"network,omitempty"`
	SNI              string `proxy:"sni,omitempty"`
	Pin              string `proxy:"pin,omitempty"`
	Morph            *bool  `proxy:"morph,omitempty"`
	TCPPrelude       string `proxy:"tcp-prelude,omitempty"`
	UDPPrelude       string `proxy:"udp-prelude,omitempty"`
	UDP              *bool  `proxy:"udp,omitempty"`
	HandshakeTimeout int    `proxy:"handshake-timeout,omitempty"` // milliseconds
	SetupTimeout     int    `proxy:"setup-timeout,omitempty"`     // milliseconds
	// NW3 fixes ALPN and requires certificate authentication. Decode these
	// common options so unsupported security overrides fail explicitly.
	SkipCertVerify    bool     `proxy:"skip-cert-verify,omitempty"`
	ClientFingerprint string   `proxy:"client-fingerprint,omitempty"`
	ALPN              []string `proxy:"alpn,omitempty"`
}

type Nowhere struct {
	*Base
	option         NowhereOption
	client         *nowhere.Client
	ctx            context.Context
	cancel         context.CancelFunc
	queuedUDPBytes atomic.Int64
}

func NewNowhere(option NowhereOption) (*Nowhere, error) {
	if option.Server == "" || strings.TrimSpace(option.Server) != option.Server || strings.ContainsAny(option.Server, "/\\@?#\x00\r\n\t ") {
		return nil, errors.New("nowhere: server must be a hostname or IP address")
	}
	if strings.Contains(option.Server, ":") {
		if ip, err := netip.ParseAddr(option.Server); err != nil || ip.Zone() != "" {
			return nil, errors.New("nowhere: server must not contain a port or scope")
		}
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, errors.New("nowhere: port must be between 1 and 65535")
	}
	if option.Network == "" {
		option.Network = "tcp"
	}
	if option.Network != "tcp" && option.Network != "udp" {
		return nil, errors.New("nowhere: network must be tcp (TLS) or udp (QUIC)")
	}
	if option.SkipCertVerify || option.ClientFingerprint != "" || option.ALPN != nil {
		return nil, errors.New("nowhere: skip-cert-verify, client-fingerprint and custom ALPN are unsupported")
	}
	if option.HandshakeTimeout < 0 || option.SetupTimeout < 0 || option.HandshakeTimeout > 300000 || option.SetupTimeout > 300000 {
		return nil, errors.New("nowhere: timeouts must be between 0 and 300000 milliseconds")
	}
	serverName := option.SNI
	if serverName == "" {
		serverName = option.Server
	}
	if strings.ContainsAny(serverName, "/\\@?#\x00\r\n\t ") {
		return nil, errors.New("nowhere: invalid SNI")
	}
	tlsConfig, err := ca.GetTLSConfig(ca.Option{TLSConfig: &tls.Config{ServerName: serverName}})
	if err != nil {
		return nil, err
	}
	if option.Pin != "" {
		pin, err := hex.DecodeString(option.Pin)
		if err != nil || len(pin) != 32 || option.Pin != strings.ToLower(option.Pin) {
			return nil, errors.New("nowhere: pin must be 64 lowercase hexadecimal characters")
		}
		// Nowhere pins exactly the leaf certificate, including for self-signed
		// peers. This differs from mihomo's chain-aware fingerprint option.
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("nowhere: peer supplied no certificate")
			}
			digest := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(pin, digest[:]) != 1 {
				return errors.New("nowhere: certificate pin mismatch")
			}
			return nil
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &Nowhere{Base: NewBase(BaseOption{Name: option.Name, Addr: net.JoinHostPort(option.Server, strconv.Itoa(option.Port)), Type: C.Nowhere,
		ProviderName: option.ProviderName, UDP: option.UDP == nil || *option.UDP, TFO: option.TFO, MPTCP: option.MPTCP,
		Interface: option.Interface, RoutingMark: option.RoutingMark, Prefer: option.IPVersion}), option: option, ctx: ctx, cancel: cancel}
	n.dialer = option.NewDialer(n.DialOptions())
	n.client, err = nowhere.NewClient(nowhere.Options{SharedKey: option.Password, Network: option.Network, TLSConfig: tlsConfig,
		Morph: option.Morph == nil || *option.Morph, TCPPrelude: option.TCPPrelude, UDPPrelude: option.UDPPrelude,
		HandshakeTimeout: time.Duration(option.HandshakeTimeout) * time.Millisecond, SetupTimeout: time.Duration(option.SetupTimeout) * time.Millisecond,
		DialStream: func(ctx context.Context) (net.Conn, error) { return n.dialer.DialContext(ctx, "tcp", n.addr) },
		DialPacket: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			remote, err := resolveUDPAddr(ctx, "udp", n.addr, n.prefer)
			if err != nil {
				return nil, nil, err
			}
			pc, err := n.dialer.ListenPacket(ctx, "udp", "", remote.AddrPort())
			return pc, remote, err
		}})
	if err != nil {
		cancel()
		return nil, err
	}
	return n, nil
}

func (n *Nowhere) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := n.client.DialTCP(ctx, nowhere.Target{Host: metadata.String(), Port: metadata.DstPort})
	if err != nil {
		return nil, err
	}
	return NewConn(c, n), nil
}

func (n *Nowhere) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if !n.SupportUDP() {
		return nil, C.ErrNotSupport
	}
	if err := n.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc := newNowherePacketConn(n.ctx, n.client, &n.queuedUDPBytes)
	if _, err := pc.flow(ctx, metadata.UDPAddr()); err != nil {
		pc.Close()
		return nil, err
	}
	return NewPacketConn(pc, n), nil
}

func (n *Nowhere) SupportUOT() bool { return n.option.Network == "tcp" }
func (n *Nowhere) ProxyInfo() C.ProxyInfo {
	info := n.Base.ProxyInfo()
	info.DialerProxy = n.option.DialerProxy
	return info
}
func (n *Nowhere) Close() error { n.cancel(); return n.client.Close() }
