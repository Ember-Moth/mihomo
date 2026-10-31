package outbound

import (
	"context"
	"fmt"
	"net"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/snell"

	SS "github.com/Ember-Moth/sing-snell"
	"github.com/Ember-Moth/sing-snell/snellv4"
	"github.com/Ember-Moth/sing-snell/snellv6"
	M "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
)

type snellClient interface {
	SS.Method
	DialContext(context.Context, M.Socksaddr) (net.Conn, error)
	Close() error
}

func (s *Snell) initSingSnell() (err error) {
	server := M.ParseSocksaddr(s.addr)
	if s.version == snell.Version6 {
		if len(s.psk) < 12 || len(s.psk) > 255 {
			return fmt.Errorf("snell v6 psk length must be between 12 and 255 bytes")
		}
		mode, err := snellv6.ParseMode(s.option.Version6Mode)
		if err != nil {
			return err
		}
		s.client, err = snellv6.NewClient(snellv6.ClientOptions{
			PSK: s.psk, UserKey: []byte(s.option.UserKey), Mode: mode,
			Reuse: s.reuse, Dialer: snellDialer{s}, Server: server,
		})
		return err
	}
	var obfsMode SS.ObfsMode
	switch s.obfsOption.Mode {
	case "http":
		obfsMode = SS.ObfsModeHTTP
	case "tls":
		obfsMode = SS.ObfsModeTLS
	}
	// The v4 client also implements the v5 TCP transport and UDP-over-TCP.
	s.client, err = snellv4.NewClient(snellv4.ClientOptions{
		PSK: s.psk, UserKey: []byte(s.option.UserKey), Reuse: s.reuse,
		ObfsMode: obfsMode, ObfsHost: s.obfsOption.Host,
		Dialer: snellDialer{s}, Server: server,
	})
	return err
}

func (s *Snell) streamSingSnell(ctx context.Context, conn net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	conn, err = s.wrapConnContext(ctx, conn)
	if err != nil {
		return nil, err
	}
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, conn)
		defer done(&err)
	}
	return s.client.DialConn(conn, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
}

func (s *Snell) dialSingSnell(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	conn, err := s.client.DialContext(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	defer func() { safeConnClose(conn, err) }()
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, conn)
		defer done(&err)
	}
	// Preserve mihomo's eager request handshake, including server-first traffic.
	if _, err = conn.Write(nil); err != nil {
		return nil, err
	}
	return NewConn(conn, s), nil
}

func (s *Snell) listenSingSnellPacket(ctx context.Context) (_ C.PacketConn, err error) {
	conn, err := (snellDialer{s}).DialContext(ctx, "tcp", M.ParseSocksaddr(s.addr))
	if err != nil {
		return nil, err
	}
	defer func() { safeConnClose(conn, err) }()
	packetConn, err := s.client.DialPacketConn(conn)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(N.NewThreadSafePacketConn(packetConn), s), nil
}

// Keep socket policy and transport wrappers in mihomo; sing-snell owns framing
// and the reuse pool. Both libraries use MetaCubeX/sing connection types.
type snellDialer struct{ snell *Snell }

func (d snellDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (_ net.Conn, err error) {
	conn, err := d.snell.dialer.DialContext(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	defer func() { safeConnClose(conn, err) }()
	return d.snell.wrapConnContext(ctx, conn)
}

func (d snellDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.snell.dialer.ListenPacket(ctx, "udp", "", destination.AddrPort())
}

var _ SN.Dialer = snellDialer{}
