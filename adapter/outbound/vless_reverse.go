package outbound

import (
	"context"
	"errors"
	"net"
	"sync/atomic"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vless/reverse"
	M "github.com/metacubex/sing/common/metadata"
)

type VlessReverseOption struct {
	BasicOption
	Name string `proxy:"name"`
}

type VlessReverse struct {
	*Base
	pool    *reverse.Pool
	release func()
	closed  atomic.Bool
}

func NewVlessReverse(option VlessReverseOption) (*VlessReverse, error) {
	if option.ProviderName != "" {
		return nil, errors.New("vless-reverse must be declared in static proxies")
	}
	provider, ok := option.NewTunnel().(reverse.RegistryProvider)
	if !ok || provider.VLESSReverseRegistry() == nil {
		return nil, errors.New("vless-reverse requires a tunnel with a reverse registry")
	}
	pool, release, err := provider.VLESSReverseRegistry().Acquire(option.Name)
	if err != nil {
		return nil, err
	}
	return &VlessReverse{Base: NewBase(BaseOption{Name: option.Name, Type: C.VlessReverse, UDP: true, ProviderName: option.ProviderName}), pool: pool, release: release}, nil
}

func reverseMetadata(metadata *C.Metadata) reverse.Metadata {
	return reverse.Metadata{
		Destination: M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort),
		Source:      M.SocksaddrFrom(metadata.SrcIP, metadata.SrcPort),
		Local:       M.SocksaddrFrom(metadata.InIP, metadata.InPort),
	}
}

func (v *VlessReverse) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if v.closed.Load() {
		return nil, net.ErrClosed
	}
	conn, err := v.pool.DialContext(ctx, reverseMetadata(metadata))
	if err != nil {
		return nil, err
	}
	return NewConn(conn, v), nil
}
func (v *VlessReverse) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if v.closed.Load() {
		return nil, net.ErrClosed
	}
	if err := v.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	conn, err := v.pool.ListenPacket(ctx, reverseMetadata(metadata))
	if err != nil {
		return nil, err
	}
	return NewPacketConn(conn, v), nil
}
func (v *VlessReverse) SupportUOT() bool { return true }
func (v *VlessReverse) Close() error {
	if !v.closed.Swap(true) {
		v.release()
	}
	return nil
}
