package reverse

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
	M "github.com/metacubex/sing/common/metadata"
)

type payload struct {
	data []byte
	addr M.Socksaddr
}

type stream struct {
	session       *Session
	id            uint16
	network       byte
	metadata      Metadata
	queue         chan payload
	done          chan struct{}
	readMu        sync.Mutex
	writeMu       sync.Mutex
	pending       []byte
	mu            sync.Mutex
	closed        bool
	localClosed   bool
	err           error
	writeUntil    time.Time
	readDeadline  deadline.PipeDeadline
	writeDeadline deadline.PipeDeadline
}

func newStream(s *Session, id uint16, network byte, metadata Metadata) *stream {
	return &stream{session: s, id: id, network: network, metadata: metadata,
		queue: make(chan payload, 32), done: make(chan struct{}),
		readDeadline: deadline.MakePipeDeadline(), writeDeadline: deadline.MakePipeDeadline()}
}

func (s *stream) enqueue(p payload) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return true
	}
	select {
	case s.queue <- p:
		return true
	default:
		return false
	}
}

func (s *stream) receive() (payload, error) {
	for {
		s.mu.Lock()
		closed, local, err := s.closed, s.localClosed, s.err
		s.mu.Unlock()
		if local {
			return payload{}, net.ErrClosed
		}
		select {
		case <-s.readDeadline.Wait():
			return payload{}, os.ErrDeadlineExceeded
		default:
		}
		select {
		case p := <-s.queue:
			return p, nil
		default:
		}
		if closed {
			return payload{}, err
		}
		select {
		case p := <-s.queue:
			return p, nil
		case <-s.done:
		case <-s.readDeadline.Wait():
			return payload{}, os.ErrDeadlineExceeded
		}
	}
}

func (s *stream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.mu.Lock()
	localClosed := s.localClosed
	s.mu.Unlock()
	if localClosed {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	for len(s.pending) == 0 {
		packet, err := s.receive()
		if err != nil {
			return 0, err
		}
		s.pending = packet.data
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

func (s *stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var written int
	for len(p) > 0 {
		n := min(len(p), MaxPacketSize)
		if err := s.send(p[:n], M.Socksaddr{}); err != nil {
			return written, err
		}
		p = p[n:]
		written += n
	}
	return written, nil
}

func (s *stream) send(data []byte, destination M.Socksaddr) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	f := frame{id: s.id, status: statusKeep, options: optionData, data: data}
	if s.network == networkUDP {
		f.network = networkUDP
		f.Destination = destination
	}
	return s.session.send(f, s)
}

func (s *stream) finish(err error, local, notify bool) {
	if err == nil {
		err = io.EOF
	}
	s.mu.Lock()
	if local {
		s.localClosed = true
	}
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed, s.err = true, err
	close(s.done)
	s.mu.Unlock()
	s.session.remove(s.id)
	if notify {
		f := frame{id: s.id, status: statusEnd}
		if err != io.EOF && err != net.ErrClosed {
			f.options = optionError
		}
		s.session.end(f)
	}
}

func (s *stream) Close() error { s.finish(net.ErrClosed, true, true); return nil }
func (s *stream) LocalAddr() net.Addr {
	if s.metadata.Local.IsValid() {
		return s.metadata.Local.TCPAddr()
	}
	return s.session.conn.LocalAddr()
}
func (s *stream) RemoteAddr() net.Addr {
	if s.session.initiator {
		return s.metadata.Destination.TCPAddr()
	}
	if s.metadata.Source.IsValid() {
		return s.metadata.Source.TCPAddr()
	}
	return s.session.conn.RemoteAddr()
}
func (s *stream) SetReadDeadline(t time.Time) error { s.readDeadline.Set(t); return nil }
func (s *stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeUntil = t
	s.mu.Unlock()
	s.writeDeadline.Set(t)
	s.session.updateWriteDeadline(s)
	return nil
}
func (s *stream) SetDeadline(t time.Time) error { s.SetReadDeadline(t); return s.SetWriteDeadline(t) }

type packetConn struct{ *stream }

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	packet, err := c.receive()
	if err != nil {
		return 0, nil, err
	}
	return copy(p, packet.data), packet.addr.UDPAddr(), nil
}
func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > MaxPacketSize {
		return 0, ErrPacketTooLarge
	}
	destination := c.metadata.Destination
	if addr != nil {
		destination = M.SocksaddrFromNet(addr)
	}
	if !destination.IsValid() {
		return 0, os.ErrInvalid
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.send(p, destination); err != nil {
		return 0, err
	}
	return len(p), nil
}

var _ net.Conn = (*stream)(nil)
var _ net.PacketConn = (*packetConn)(nil)
