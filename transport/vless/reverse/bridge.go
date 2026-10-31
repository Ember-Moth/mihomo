package reverse

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type DialFunc func(context.Context) (net.Conn, error)

type Bridge struct {
	dial        DialFunc
	handler     Handler
	connections int
	logError    func(error)
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	sessions    map[*Session]struct{}
	started     bool
	closed      bool
	changed     chan struct{}
	wg          sync.WaitGroup
}

func NewBridge(dial DialFunc, handler Handler, connections int, logError func(error)) (*Bridge, error) {
	if dial == nil || handler == nil {
		return nil, errors.New("vless reverse: missing dialer or handler")
	}
	if connections == 0 {
		connections = 1
	}
	if connections < 1 || connections > 8 {
		return nil, errors.New("vless reverse: connections must be between 1 and 8")
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Bridge{dial: dial, handler: handler, connections: connections, logError: logError, ctx: ctx, cancel: cancel, sessions: make(map[*Session]struct{}), changed: make(chan struct{})}, nil
}
func (b *Bridge) Start() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return net.ErrClosed
	}
	if b.started {
		return nil
	}
	b.started = true
	for i := 0; i < b.connections; i++ {
		b.wg.Add(1)
		go b.run()
	}
	return nil
}
func (b *Bridge) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.cancel()
	b.signalLocked()
	sessions := make([]*Session, 0, len(b.sessions))
	for s := range b.sessions {
		sessions = append(sessions, s)
	}
	b.mu.Unlock()
	for _, s := range sessions {
		s.Close()
	}
	b.wg.Wait()
	return nil
}
func (b *Bridge) run() {
	defer b.wg.Done()
	backoff := time.Second
	for b.ctx.Err() == nil {
		b.mu.Lock()
		full := len(b.sessions) >= b.connections+8
		changed := b.changed
		b.mu.Unlock()
		if full {
			select {
			case <-b.ctx.Done():
				return
			case <-changed:
				continue
			}
		}
		ctx, cancel := context.WithTimeout(b.ctx, 15*time.Second)
		conn, err := b.dial(ctx)
		cancel()
		if err != nil {
			if b.ctx.Err() != nil {
				return
			}
			if b.logError != nil {
				b.logError(err)
			}
			if !b.wait(backoff) {
				return
			}
			backoff = min(30*time.Second, backoff*2)
			continue
		}
		s := NewSpoke(conn, b.handler)
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			s.Close()
			return
		}
		b.sessions[s] = struct{}{}
		b.signalLocked()
		b.wg.Add(1)
		b.mu.Unlock()
		go func() {
			defer b.wg.Done()
			<-s.Done()
			b.mu.Lock()
			delete(b.sessions, s)
			b.signalLocked()
			b.mu.Unlock()
		}()
		select {
		case <-b.ctx.Done():
			s.Close()
			return
		case <-s.Ready():
			backoff = time.Second
			b.mu.Lock()
			b.signalLocked()
			b.mu.Unlock()
		case <-s.Done():
			if b.logError != nil && b.ctx.Err() == nil {
				b.logError(s.Err())
			}
			if !b.wait(backoff) {
				return
			}
			backoff = min(30*time.Second, backoff*2)
			continue
		}
		select {
		case <-b.ctx.Done():
			s.Close()
			return
		case <-s.Draining():
		case <-s.Done():
			if !b.wait(backoff) {
				return
			}
		}
	}
}

func (b *Bridge) signalLocked() { close(b.changed); b.changed = make(chan struct{}) }

func (b *Bridge) WaitReady(ctx context.Context) error {
	for {
		b.mu.Lock()
		closed := b.closed
		ready := false
		changed := b.changed
		for s := range b.sessions {
			select {
			case <-s.Done():
				continue
			default:
			}
			select {
			case <-s.Draining():
				continue
			default:
			}
			select {
			case <-s.Ready():
				ready = true
			default:
			}
			if ready {
				break
			}
		}
		b.mu.Unlock()
		if closed {
			return net.ErrClosed
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}
func (b *Bridge) wait(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-b.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
