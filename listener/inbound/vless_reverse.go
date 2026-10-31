package inbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	A "github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vless/reverse"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
)

type VlessReverseOption struct {
	BaseOption
	Outbound    string `inbound:"outbound"`
	Connections int    `inbound:"connections,omitempty"`
}

func (o VlessReverseOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type VlessReverse struct {
	*Base
	config *VlessReverseOption
	mu     sync.Mutex
	bridge *reverse.Bridge
}

func NewVlessReverse(options *VlessReverseOption) (*VlessReverse, error) {
	if options.NameStr == "" || options.Outbound == "" {
		return nil, errors.New("vless-reverse requires name and outbound")
	}
	if options.Connections == 0 {
		options.Connections = 1
	}
	if options.Connections < 1 || options.Connections > 8 {
		return nil, errors.New("vless-reverse connections must be between 1 and 8")
	}
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &VlessReverse{Base: base, config: options}, nil
}
func (v *VlessReverse) Config() C.InboundConfig { return v.config }
func (v *VlessReverse) Address() string         { return "outbound://" + v.config.Outbound }
func (v *VlessReverse) Listen(tunnel C.Tunnel) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.bridge != nil {
		return nil
	}
	if _, _, err := reverseDialer(tunnel, v.config.Outbound); err != nil {
		return err
	}
	handler, err := sing.NewListenerHandler(sing.ListenerConfig{Tunnel: tunnel, Type: C.VLESS, Additions: v.Additions()})
	if err != nil {
		return err
	}
	dial := func(ctx context.Context) (net.Conn, error) {
		proxy, dialer, err := reverseDialer(tunnel, v.config.Outbound)
		if err != nil {
			return nil, err
		}
		conn, err := dialer.DialReverseContext(ctx)
		if err != nil {
			return nil, err
		}
		// Keep the selected transport alive across configuration replacement.
		return N.NewRefConn(conn, proxy), nil
	}
	bridge, err := reverse.NewBridge(dial, reverseHandler{handler: handler, user: v.config.Outbound}, v.config.Connections, func(err error) { log.Warnln("VLESS reverse[%s] connect failed: %s", v.Name(), err) })
	if err != nil {
		return err
	}
	if err = bridge.Start(); err != nil {
		bridge.Close()
		return err
	}
	v.bridge = bridge
	log.Infoln("VLESS reverse[%s] connecting through %s", v.Name(), v.config.Outbound)
	return nil
}
func (v *VlessReverse) Close() error {
	v.mu.Lock()
	bridge := v.bridge
	v.bridge = nil
	v.mu.Unlock()
	if bridge != nil {
		return bridge.Close()
	}
	return nil
}

func (v *VlessReverse) WaitReady(ctx context.Context) error {
	v.mu.Lock()
	bridge := v.bridge
	v.mu.Unlock()
	if bridge == nil {
		return net.ErrClosed
	}
	return bridge.WaitReady(ctx)
}

type vlessReverseDialer interface {
	DialReverseContext(context.Context) (net.Conn, error)
}

func reverseDialer(tunnel C.Tunnel, name string) (C.Proxy, vlessReverseDialer, error) {
	proxy, err := proxydialer.LookupProxy(tunnel, name)
	if err != nil {
		return nil, nil, err
	}
	dialer, ok := proxydialer.UnwrapAdapter(proxy.Adapter()).(vlessReverseDialer)
	if !ok {
		return nil, nil, fmt.Errorf("vless-reverse outbound %q must be a VLESS transport without smux", name)
	}
	return proxy, dialer, nil
}

type reverseHandler struct {
	handler *sing.ListenerHandler
	user    string
}

func (h reverseHandler) context(ctx context.Context, metadata reverse.Metadata) context.Context {
	ctx = sing.WithAdditions(ctx, A.WithInUser(h.user))
	if metadata.Local.IsValid() {
		ctx = sing.WithInAddr(ctx, metadata.Local.TCPAddr())
	}
	return ctx
}
func (h reverseHandler) HandleTCP(ctx context.Context, conn net.Conn, metadata reverse.Metadata) error {
	defer conn.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !metadata.Source.IsValid() {
		metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr())
	}
	return h.handler.NewConnection(h.context(ctx, metadata), conn, M.Metadata{Source: metadata.Source, Destination: metadata.Destination})
}
func (h reverseHandler) HandleUDP(ctx context.Context, conn net.PacketConn, metadata reverse.Metadata) error {
	defer conn.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	return h.handler.NewPacketConnection(h.context(ctx, metadata), bufio.NewPacketConn(conn), M.Metadata{Source: metadata.Source, Destination: metadata.Destination})
}

var _ C.InboundListener = (*VlessReverse)(nil)
