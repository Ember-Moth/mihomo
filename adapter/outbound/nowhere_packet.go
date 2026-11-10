package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
	"github.com/metacubex/mihomo/pkg/nowhere"
)

type nowherePacket struct {
	payload []byte
	addr    net.Addr
}
type nowhereFlow struct {
	net.Conn
	addr *net.UDPAddr
}

// One mihomo UDP association can address multiple destinations. NW3 binds each
// flow to one destination, so this layer owns a bounded set of separate flows.
type nowherePacketConn struct {
	client                      *nowhere.Client
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu                          sync.Mutex
	flows                       map[string]*nowhereFlow
	writeTime                   time.Time
	readDeadline, writeDeadline deadline.PipeDeadline
	gate                        chan struct{}
	incoming                    chan nowherePacket
	once                        sync.Once
	budget                      *atomic.Int64
}

func newNowherePacketConn(parent context.Context, client *nowhere.Client, budget *atomic.Int64) *nowherePacketConn {
	ctx, cancel := context.WithCancel(parent)
	c := &nowherePacketConn{client: client, ctx: ctx, cancel: cancel, flows: make(map[string]*nowhereFlow), budget: budget,
		readDeadline: deadline.MakePipeDeadline(), writeDeadline: deadline.MakePipeDeadline(), gate: make(chan struct{}, 1), incoming: make(chan nowherePacket, 64)}
	go func() { <-ctx.Done(); c.Close() }()
	return c
}

// flow is called with exclusive creation ownership (before publication or via gate).
func (c *nowherePacketConn) flow(ctx context.Context, addr net.Addr) (*nowhereFlow, error) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok || udp == nil || !udp.AddrPort().IsValid() || udp.Port == 0 {
		return nil, errors.New("nowhere: UDP destination must be a resolved address")
	}
	key := udp.AddrPort().String()
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if f := c.flows[key]; f != nil {
		c.mu.Unlock()
		return f, nil
	}
	if len(c.flows) >= 256 {
		c.mu.Unlock()
		return nil, errors.New("nowhere: UDP association target limit reached")
	}
	c.mu.Unlock()
	conn, err := c.client.DialUDP(ctx, nowhere.Target{Host: udp.AddrPort().Addr().Unmap().String(), Port: uint16(udp.Port)})
	if err != nil {
		return nil, err
	}
	f := &nowhereFlow{Conn: conn, addr: net.UDPAddrFromAddrPort(udp.AddrPort())}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	_ = conn.SetWriteDeadline(c.writeTime)
	c.flows[key] = f
	c.mu.Unlock()
	go c.receive(key, f)
	return f, nil
}

func (c *nowherePacketConn) receive(key string, f *nowhereFlow) {
	defer func() {
		f.Close()
		c.mu.Lock()
		if c.flows[key] == f {
			delete(c.flows, key)
		}
		c.mu.Unlock()
	}()
	b := make([]byte, 65535)
	for {
		_ = f.SetReadDeadline(time.Now().Add(time.Minute))
		n, err := f.Read(b)
		if err != nil {
			return
		}
		c.mu.Lock()
		if c.ctx.Err() != nil {
			c.mu.Unlock()
			return
		}
		cost := int64(max(n, 1))
		if c.reserve(cost) {
			packet := nowherePacket{append([]byte{}, b[:n]...), f.addr}
			select {
			case c.incoming <- packet:
			default:
				c.budget.Add(-cost)
			}
		}
		c.mu.Unlock()
	}
}

func (c *nowherePacketConn) reserve(cost int64) bool {
	for {
		used := c.budget.Load()
		if cost > (4<<20)-used {
			return false
		}
		if c.budget.CompareAndSwap(used, used+cost) {
			return true
		}
	}
}

func (c *nowherePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}
	select {
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case packet := <-c.incoming:
		c.budget.Add(-int64(max(len(packet.payload), 1)))
		n := copy(p, packet.payload)
		if n < len(packet.payload) {
			return n, packet.addr, io.ErrShortBuffer
		}
		return n, packet.addr, nil
	}
}

func (c *nowherePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > 65535 {
		return 0, errors.New("nowhere: UDP packet too large")
	}
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	select {
	case c.gate <- struct{}{}:
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	}
	defer func() { <-c.gate }()
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	go func() {
		select {
		case <-c.writeDeadline.Wait():
			cancel()
		case <-ctx.Done():
		}
	}()
	f, err := c.flow(ctx, addr)
	if err != nil {
		return 0, err
	}
	_ = f.SetReadDeadline(time.Now().Add(time.Minute))
	return f.Write(p)
}

func (c *nowherePacketConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.readDeadline.Set(time.Time{})
		c.writeDeadline.Set(time.Time{})
		c.mu.Lock()
		flows := c.flows
		c.flows = make(map[string]*nowhereFlow)
	drain:
		for {
			select {
			case packet := <-c.incoming:
				c.budget.Add(-int64(max(len(packet.payload), 1)))
			default:
				break drain
			}
		}
		c.mu.Unlock()
		for _, f := range flows {
			f.Close()
		}
	})
	return nil
}
func (c *nowherePacketConn) LocalAddr() net.Addr               { return &net.UDPAddr{} }
func (c *nowherePacketConn) SetReadDeadline(t time.Time) error { c.readDeadline.Set(t); return nil }
func (c *nowherePacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeTime = t
	for _, f := range c.flows {
		_ = f.SetWriteDeadline(t)
	}
	return nil
}
func (c *nowherePacketConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
