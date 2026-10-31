package snell

import (
	"context"
	"errors"
	"io"
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/transport/snell"

	SS "github.com/Ember-Moth/sing-snell"
	"github.com/Ember-Moth/sing-snell/snellv5"
	"github.com/Ember-Moth/sing-snell/snellv6"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	MN "github.com/metacubex/sing/common/network"
)

func (l *Listener) initSingSnell(tunnel C.Tunnel) (err error) {
	l.handler, err = sing.NewListenerHandler(sing.ListenerConfig{Tunnel: tunnel, Type: C.SNELL})
	if err != nil {
		return err
	}
	handler := singHandler{handler: l.handler, udp: l.config.UDP, packetSize: SS.MaxPayloadLen}
	if l.config.Version == snell.Version6 {
		handler.packetSize = 65535
		mode, err := snellv6.ParseMode(l.config.Version6Mode)
		if err != nil {
			return err
		}
		l.service, err = snellv6.NewService(snellv6.ServerOptions{
			PSK: []byte(l.config.Psk), Mode: mode, Handler: handler,
		})
		return err
	}
	var obfsMode SS.ObfsMode
	switch l.config.ObfsMode {
	case "http":
		obfsMode = SS.ObfsModeHTTP
	case "tls":
		obfsMode = SS.ObfsModeTLS
	}
	// Snell v4 and v5 use the same TCP record transport.
	l.service, err = snellv5.NewService(snellv5.ServiceOptions{
		PSK: []byte(l.config.Psk), ObfsMode: obfsMode, Handler: handler,
	})
	return err
}

type singHandler struct {
	handler    *sing.ListenerHandler
	udp        bool
	packetSize int
}

func (h singHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose SS.CloseHandlerFunc) {
	err := h.handler.NewConnection(ctx, conn, M.Metadata{Source: source, Destination: destination})
	_ = conn.Close()
	if onClose != nil {
		onClose(err)
	}
	if err != nil {
		h.handler.NewError(ctx, err)
	}
}

func (h singHandler) NewPacketConnectionEx(ctx context.Context, conn MN.PacketConn, source, destination M.Socksaddr, onClose SS.CloseHandlerFunc) {
	var err error
	if h.udp {
		packetConn := &singPacketConn{NetPacketConn: bufio.NewNetPacketConn(conn), packetSize: h.packetSize}
		err = h.handler.NewPacketConnection(ctx, packetConn, M.Metadata{Source: source, Destination: destination})
	} else {
		err = errors.New("snell UDP is disabled")
	}
	_ = conn.Close()
	if onClose != nil {
		onClose(err)
	}
	if err != nil && !isClosedError(err) {
		h.handler.NewError(ctx, err)
	}
}

func isClosedError(err error) bool {
	var timeout net.Error
	return sing.ShouldIgnorePacketError(err) || errors.Is(err, io.EOF) ||
		(errors.As(err, &timeout) && timeout.Timeout())
}

// The generic mihomo packet reader allocates 16 KiB. Snell v6 datagrams can
// exceed that size; reserve a full datagram before crossing net.PacketConn.
type singPacketConn struct {
	MN.NetPacketConn
	readWaitOptions MN.ReadWaitOptions
	packetSize      int
}

func (c *singPacketConn) InitializeReadWaiter(options MN.ReadWaitOptions) bool {
	options.MTU = c.packetSize
	c.readWaitOptions = options
	return false
}

func (c *singPacketConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	buffer := c.readWaitOptions.NewPacketBuffer()
	destination, err := c.ReadPacket(buffer)
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	c.readWaitOptions.PostReturn(buffer)
	return buffer, destination, nil
}

var _ SS.Handler = singHandler{}
