//go:build with_naive

package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	cronet "github.com/Ember-Moth/cronet-go"
	M "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
	"github.com/metacubex/sing/common/uot"
)

type Naive struct {
	*Base
	option NaiveOption
	client *cronet.NaiveClient
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
}

func NewNaive(option NaiveOption) (*Naive, error) {
	if err := option.validate(); err != nil {
		return nil, err
	}
	certificates, err := option.trustedCertificates()
	if err != nil {
		return nil, err
	}
	echConfig, err := option.echConfig()
	if err != nil {
		return nil, err
	}
	if option.UDPOverTCPVersion == 0 {
		option.UDPOverTCPVersion = uot.Version
	}
	// Do not retain a mutable map supplied by an API caller.
	headers := make(map[string]string, len(option.Headers))
	for key, value := range option.Headers {
		headers[strings.ToLower(key)] = value
	}
	option.Headers = headers
	n := &Naive{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.Naive,
			ProviderName: option.ProviderName,
			UDP:          option.UDPOverTCP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: option,
	}
	n.dialer = option.NewDialer(n.DialOptions())
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	congestion := map[string]cronet.QUICCongestionControl{
		"":      cronet.QUICCongestionControlDefault,
		"bbr":   cronet.QUICCongestionControlBBR,
		"bbr2":  cronet.QUICCongestionControlBBRv2,
		"cubic": cronet.QUICCongestionControlCubic,
		"reno":  cronet.QUICCongestionControlReno,
	}[option.QUICCongestionControl]
	n.client, err = cronet.NewNaiveClient(cronet.NaiveClientOptions{
		Context:                  ctx,
		Logger:                   log.SingInfoToDebugLogger,
		ServerAddress:            M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
		ServerName:               option.SNI,
		Username:                 option.Username,
		Password:                 option.Password,
		InsecureConcurrency:      option.InsecureConcurrency,
		ExtraHeaders:             headers,
		ReceiveWindow:            option.StreamReceiveWindow,
		TrustedRootCertificates:  certificates,
		Dialer:                   naiveDialer{n.dialer},
		DNSResolver:              naiveDNSResolver(option.IPVersion),
		ECHEnabled:               option.ECHOpts.Enable,
		ECHConfigList:            echConfig,
		ECHQueryServerName:       option.ECHOpts.QueryServerName,
		QUIC:                     option.QUIC,
		QUICCongestionControl:    congestion,
		QUICSessionReceiveWindow: option.QUICSessionReceiveWindow,
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("naive: create client: %w", err)
	}
	if err = n.client.Start(); err != nil {
		cancel()
		_ = n.client.Close()
		return nil, fmt.Errorf("naive: start client: %w", err)
	}
	return n, nil
}

func (n *Naive) dial(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Cronet tracks active streams in a WaitGroup. Serialize stream creation
	// against Close so its Add cannot race the engine's shutdown/Wait.
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil, net.ErrClosed
	}
	conn, err := n.client.DialEarly(ctx, destination)
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (n *Naive) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := n.dial(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(conn, n), nil
}

func (n *Naive) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if !n.option.UDPOverTCP {
		return nil, C.ErrNotSupport
	}
	if err := n.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	version := uint8(n.option.UDPOverTCPVersion)
	requestDestination := uot.RequestDestination(version)
	conn, err := n.dial(ctx, M.ParseSocksaddr(requestDestination.String()))
	if err != nil {
		return nil, err
	}
	var packetConn net.PacketConn
	if version == uot.LegacyVersion {
		packetConn = uot.NewConn(conn, uot.Request{})
	} else {
		packetConn = uot.NewLazyConn(conn, uot.Request{Destination: M.SocksaddrFromNet(metadata.UDPAddr())})
	}
	return NewPacketConn(N.NewThreadSafePacketConn(packetConn), n), nil
}

func (n *Naive) SupportUOT() bool { return n.option.UDPOverTCP }

func (n *Naive) ProxyInfo() C.ProxyInfo {
	info := n.Base.ProxyInfo()
	info.DialerProxy = n.option.DialerProxy
	return info
}

func (n *Naive) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	n.cancel()
	return n.client.Close()
}

// Adapt mihomo's string-address dialer while preserving its socket policy.
type naiveDialer struct{ C.Dialer }

var _ SN.Dialer = naiveDialer{}

func (d naiveDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, destination.String())
}

func (d naiveDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.Dialer.ListenPacket(ctx, "udp", "", destination.AddrPort())
}
