package reverse

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Registry belongs to a tunnel instance. Retaining a pool while its outbound is
// replaced allows unchanged authenticated reverse connections to survive reload.
type Registry struct {
	mu    sync.Mutex
	pools map[string]*poolReference
}
type poolReference struct {
	pool *Pool
	refs int
}

type RegistryProvider interface{ VLESSReverseRegistry() *Registry }

func NewRegistry() *Registry { return &Registry{pools: make(map[string]*poolReference)} }

func (r *Registry) Acquire(tag string) (*Pool, func(), error) {
	if tag == "" {
		return nil, nil, errors.New("vless reverse: empty outbound tag")
	}
	r.mu.Lock()
	if r.pools == nil {
		r.pools = make(map[string]*poolReference)
	}
	entry := r.pools[tag]
	if entry == nil {
		entry = &poolReference{pool: NewPool()}
		r.pools[tag] = entry
	}
	entry.refs++
	r.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			r.mu.Lock()
			entry.refs--
			last := entry.refs == 0
			if last {
				delete(r.pools, tag)
			}
			r.mu.Unlock()
			if last {
				entry.pool.Close()
			}
		})
	}
	return entry.pool, release, nil
}
func (r *Registry) Get(tag string) *Pool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry := r.pools[tag]; entry != nil {
		return entry.pool
	}
	return nil
}

type Pool struct {
	mu       sync.Mutex
	sessions map[*Session]struct{}
	closed   bool
	notify   chan struct{}
}

func NewPool() *Pool {
	return &Pool{sessions: make(map[*Session]struct{}), notify: make(chan struct{})}
}
func (p *Pool) signal() {
	p.mu.Lock()
	close(p.notify)
	p.notify = make(chan struct{})
	p.mu.Unlock()
}
func (p *Pool) Connections() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.sessions) }

func (p *Pool) Accept(ctx context.Context, conn net.Conn) error {
	if err := ctx.Err(); err != nil {
		conn.Close()
		return err
	}
	p.mu.Lock()
	if p.closed || len(p.sessions) >= 16 {
		p.mu.Unlock()
		conn.Close()
		return ErrBusy
	}
	s := newHub(conn, p.signal)
	p.sessions[s] = struct{}{}
	p.mu.Unlock()
	p.signal()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	<-s.Done()
	p.mu.Lock()
	delete(p.sessions, s)
	p.mu.Unlock()
	p.signal()
	return s.Err()
}

func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	sessions := p.sessions
	p.sessions = make(map[*Session]struct{})
	p.mu.Unlock()
	for s := range sessions {
		s.Close()
	}
	p.signal()
	return nil
}

func (p *Pool) WaitReady(ctx context.Context) error {
	for {
		p.mu.Lock()
		closed := p.closed
		ready := false
		for session := range p.sessions {
			if session.available() {
				ready = true
				break
			}
		}
		notify := p.notify
		p.mu.Unlock()
		if closed {
			return net.ErrClosed
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-notify:
		}
	}
}

func (p *Pool) open(ctx context.Context, network byte, metadata Metadata) (*stream, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, net.ErrClosed
	}
	candidates := make([]*Session, 0, len(p.sessions))
	for s := range p.sessions {
		candidates = append(candidates, s)
	}
	p.mu.Unlock()
	for len(candidates) > 0 {
		best := 0
		for i := 1; i < len(candidates); i++ {
			if candidates[i].Active() < candidates[best].Active() {
				best = i
			}
		}
		selected := candidates[best]
		candidates = append(candidates[:best], candidates[best+1:]...)
		stream, err := selected.open(ctx, network, metadata)
		if err != ErrBusy {
			return stream, err
		}
	}
	return nil, ErrNoWorker
}
func (p *Pool) DialContext(ctx context.Context, metadata Metadata) (net.Conn, error) {
	return p.open(ctx, networkTCP, metadata)
}
func (p *Pool) ListenPacket(ctx context.Context, metadata Metadata) (net.PacketConn, error) {
	s, err := p.open(ctx, networkUDP, metadata)
	if err != nil {
		return nil, err
	}
	return &packetConn{s}, nil
}
