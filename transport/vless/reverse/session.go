package reverse

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	"google.golang.org/protobuf/encoding/protowire"
)

var (
	ErrNoWorker       = errors.New("vless reverse: no available tunnel")
	ErrBusy           = errors.New("vless reverse: tunnel is full or draining")
	ErrPacketTooLarge = errors.New("vless reverse: UDP payload exceeds 8192 bytes")
	ErrRemote         = errors.New("vless reverse: remote stream failed")
	ErrSlowReader     = errors.New("vless reverse: receive queue is full")
)

const (
	maxStreams        = 256
	maxRequests       = 256
	writeTimeout      = 15 * time.Second
	heartbeatInterval = 10 * time.Second
	heartbeatTimeout  = 35 * time.Second
)

type Handler interface {
	HandleTCP(context.Context, net.Conn, Metadata) error
	HandleUDP(context.Context, net.PacketConn, Metadata) error
}

type Session struct {
	conn         net.Conn
	initiator    bool
	handler      Handler
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	streams      map[uint16]*stream
	nextID       uint32
	requests     int
	controlID    uint16
	controlSeen  bool
	ready        chan struct{}
	controlMu    sync.Mutex
	draining     bool
	closed       bool
	err          error
	done         chan struct{}
	drain        chan struct{}
	writes       chan writeRequest
	ends         chan frame
	writeState   sync.Mutex
	activeWriter *stream
	writeLimit   time.Time
	onChange     func()
}

type writeRequest struct {
	data   []byte
	owner  *stream
	result chan error
}

func newSession(conn net.Conn, initiator bool, handler Handler, onChange func()) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{conn: conn, initiator: initiator, handler: handler, ctx: ctx, cancel: cancel,
		streams: make(map[uint16]*stream), nextID: 1, controlID: 1,
		done: make(chan struct{}), drain: make(chan struct{}), ready: make(chan struct{}), writes: make(chan writeRequest), ends: make(chan frame, maxStreams), onChange: onChange}
}

func NewSpoke(conn net.Conn, handler Handler) *Session {
	s := newSession(conn, false, handler, nil)
	go s.writeLoop()
	go s.readLoop()
	return s
}

func newHub(conn net.Conn, onChange func()) *Session {
	s := newSession(conn, true, nil, onChange)
	go s.writeLoop()
	go s.readLoop()
	go s.heartbeat()
	return s
}

func (s *Session) Done() <-chan struct{}     { return s.done }
func (s *Session) Draining() <-chan struct{} { return s.drain }
func (s *Session) Ready() <-chan struct{}    { return s.ready }
func (s *Session) Err() error                { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *Session) Active() int               { s.mu.Lock(); defer s.mu.Unlock(); return len(s.streams) }
func (s *Session) available() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && !s.draining && s.requests < maxRequests && len(s.streams) < maxStreams
}

func (s *Session) Close() error { s.close(net.ErrClosed); return nil }
func (s *Session) close(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.err = err
	streams := s.streams
	s.streams = make(map[uint16]*stream)
	close(s.done)
	s.mu.Unlock()
	s.cancel()
	_ = s.conn.Close()
	for _, stream := range streams {
		stream.finish(err, false, false)
	}
	s.changed()
}
func (s *Session) changed() {
	if s.onChange != nil {
		s.onChange()
	}
}

func (s *Session) remove(id uint16) {
	s.mu.Lock()
	delete(s.streams, id)
	finished := s.draining && len(s.streams) == 0
	s.mu.Unlock()
	s.changed()
	if finished {
		s.close(io.EOF)
	}
}

func (s *Session) markDraining() {
	s.mu.Lock()
	if !s.draining {
		s.draining = true
		close(s.drain)
	}
	finished := len(s.streams) == 0
	s.mu.Unlock()
	s.changed()
	if finished {
		s.close(io.EOF)
	}
}

func (s *Session) open(ctx context.Context, network byte, metadata Metadata) (*stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !metadata.Destination.IsValid() || metadata.Destination.Port == 0 {
		return nil, errors.New("vless reverse: invalid destination")
	}
	s.mu.Lock()
	if s.closed || s.draining || s.requests >= maxRequests || len(s.streams) >= maxStreams || s.nextID >= 65535 {
		s.mu.Unlock()
		return nil, ErrBusy
	}
	if metadata.Source.IsValid() && !metadata.Local.IsValid() {
		metadata.Local = M.SocksaddrFromNet(s.conn.LocalAddr())
	}
	s.nextID++
	id := uint16(s.nextID)
	stream := newStream(s, id, network, metadata)
	s.streams[id] = stream
	s.requests++
	drain := s.requests >= maxRequests
	s.mu.Unlock()
	if drain {
		defer func() {
			s.markDraining()
			go func() {
				if err := s.control(false, true); err != nil {
					s.close(err)
				}
			}()
		}()
	}
	select {
	case <-ctx.Done():
		stream.finish(ctx.Err(), true, false)
		return nil, ctx.Err()
	default:
	}
	// Let context cancellation drive this deadline; a second timer at the same
	// instant can fire before ctx.Err is published and lose the cancellation cause.
	stop := context.AfterFunc(ctx, func() { stream.SetWriteDeadline(time.Now()) })
	err := s.send(frame{id: id, status: statusNew, network: network, Metadata: metadata}, stream)
	stop()
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	if err != nil {
		stream.finish(err, true, true)
		return nil, err
	}
	stream.SetWriteDeadline(time.Time{})
	return stream, nil
}

func (s *Session) send(f frame, owner *stream) error {
	data, err := f.encode()
	if err != nil {
		return err
	}
	var deadline, closed <-chan struct{}
	if owner != nil {
		deadline = owner.writeDeadline.Wait()
		closed = owner.done
	}
	timer := time.NewTimer(writeTimeout)
	defer timer.Stop()
	request := writeRequest{data: data, owner: owner, result: make(chan error, 1)}
	select {
	case s.writes <- request:
	case <-s.done:
		return net.ErrClosed
	case <-closed:
		return net.ErrClosed
	case <-deadline:
		return os.ErrDeadlineExceeded
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
	select {
	case err := <-request.result:
		return err
	case <-s.done:
		return net.ErrClosed
	case <-closed:
		return net.ErrClosed
	case <-deadline:
		return os.ErrDeadlineExceeded
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

// A single writer owns frame boundaries. Closing a logical stream can unblock
// its caller while an already accepted frame finishes on the shared transport.
func (s *Session) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case request := <-s.writes:
			err := s.write(request.data, request.owner)
			request.result <- err
			if err != nil && err != net.ErrClosed && err != os.ErrDeadlineExceeded {
				s.close(err)
				return
			}
		case end := <-s.ends:
			data, err := end.encode()
			if err == nil {
				err = s.write(data, nil)
			}
			if err != nil {
				s.close(err)
				return
			}
		}
	}
}

func (s *Session) write(data []byte, owner *stream) error {
	if owner != nil {
		select {
		case <-owner.done:
			return net.ErrClosed
		case <-owner.writeDeadline.Wait():
			return os.ErrDeadlineExceeded
		default:
		}
	}
	s.writeState.Lock()
	s.activeWriter = owner
	s.writeLimit = time.Now().Add(writeTimeout)
	s.setWriteDeadlineLocked(owner)
	s.writeState.Unlock()
	var err error
	for len(data) > 0 {
		var n int
		n, err = s.conn.Write(data)
		data = data[n:]
		if err != nil {
			break
		}
		if n == 0 {
			err = io.ErrNoProgress
			break
		}
	}
	s.writeState.Lock()
	s.activeWriter = nil
	_ = s.conn.SetWriteDeadline(time.Time{})
	s.writeState.Unlock()
	if err != nil {
		s.close(err)
	}
	return err
}

func (s *Session) end(f frame) {
	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.ends <- f:
	case <-s.done:
	default:
		s.close(errors.New("vless reverse: control queue is full"))
	}
}

func (s *Session) setWriteDeadlineLocked(owner *stream) {
	limit := s.writeLimit
	if owner != nil {
		owner.mu.Lock()
		deadline := owner.writeUntil
		owner.mu.Unlock()
		if !deadline.IsZero() && deadline.Before(limit) {
			limit = deadline
		}
	}
	_ = s.conn.SetWriteDeadline(limit)
}
func (s *Session) updateWriteDeadline(owner *stream) {
	s.writeState.Lock()
	if s.activeWriter == owner {
		s.setWriteDeadlineLocked(owner)
	}
	s.writeState.Unlock()
}

func (s *Session) control(first, drain bool) error {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	s.mu.Lock()
	isDraining := s.draining
	s.mu.Unlock()
	if isDraining && !drain {
		return nil
	}
	var padding [8]byte
	if _, err := rand.Read(padding[:]); err != nil {
		return err
	}
	data := protowire.AppendTag(nil, 1, protowire.VarintType)
	state := uint64(0)
	if drain {
		state = 1
	}
	data = protowire.AppendVarint(data, state)
	data = protowire.AppendTag(data, 99, protowire.BytesType)
	data = protowire.AppendBytes(data, padding[:])
	f := frame{id: 1, status: statusKeep, options: optionData, network: networkUDP, data: data, Metadata: Metadata{Destination: M.Socksaddr{Fqdn: controlDomain}}}
	if first {
		f.status = statusNew
	}
	return s.send(f, nil)
}
func (s *Session) heartbeat() {
	if err := s.control(true, false); err != nil {
		s.close(err)
		return
	}
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-s.drain:
			return
		case <-ticker.C:
			if err := s.control(false, false); err != nil {
				s.close(err)
				return
			}
		}
	}
}

func (s *Session) readLoop() {
	for {
		if !s.initiator {
			s.mu.Lock()
			draining := s.draining
			s.mu.Unlock()
			deadline := time.Time{}
			if !draining {
				deadline = time.Now().Add(heartbeatTimeout)
			}
			_ = s.conn.SetReadDeadline(deadline)
		}
		f, err := readFrame(s.conn)
		if err != nil {
			s.close(err)
			return
		}
		if err = s.handleFrame(f); err != nil {
			s.close(err)
			return
		}
	}
}
func (s *Session) handleFrame(f frame) error {
	if f.status == statusKeepAlive {
		return nil
	}
	if !s.initiator && f.status == statusNew && f.Destination.Fqdn == controlDomain {
		if s.controlSeen || f.network != networkUDP || f.Destination.Port != 0 {
			return errors.New("vless reverse: invalid control stream")
		}
		s.controlSeen = true
		s.controlID = f.id
		close(s.ready)
	}
	if !s.initiator && s.controlSeen && f.id == s.controlID {
		if f.options&optionData != 0 {
			drain, err := readControl(f.data)
			if err != nil {
				return err
			}
			if drain {
				s.markDraining()
			}
		}
		return nil
	}
	s.mu.Lock()
	stream := s.streams[f.id]
	s.mu.Unlock()
	if f.status == statusNew {
		if s.initiator || stream != nil {
			return errors.New("vless reverse: unexpected new stream")
		}
		s.mu.Lock()
		if s.closed || len(s.streams) >= maxStreams {
			s.mu.Unlock()
			s.end(frame{id: f.id, status: statusEnd, options: optionError})
			return nil
		}
		stream = newStream(s, f.id, f.network, f.Metadata)
		s.streams[f.id] = stream
		s.mu.Unlock()
		go s.dispatch(stream)
	}
	if stream == nil {
		// Discard data already in flight for a closed stream. Its END frame is
		// queued once by finish; responding to every late frame can flood it.
		return nil
	}
	if f.status == statusEnd {
		err := io.EOF
		if f.options&optionError != 0 {
			err = ErrRemote
		}
		stream.finish(err, false, false)
		return nil
	}
	if f.options&optionData != 0 {
		if stream.network == networkUDP && len(f.data) > MaxPacketSize {
			return ErrPacketTooLarge
		}
		addr := f.Destination
		if !addr.IsValid() {
			addr = stream.metadata.Destination
		}
		if !stream.enqueue(payload{data: f.data, addr: addr}) {
			stream.finish(ErrSlowReader, false, true)
		}
	}
	return nil
}
func (s *Session) dispatch(stream *stream) {
	var err error
	if s.handler == nil {
		err = ErrRemote
	} else if stream.network == networkTCP {
		err = s.handler.HandleTCP(s.ctx, stream, stream.metadata)
	} else {
		err = s.handler.HandleUDP(s.ctx, &packetConn{stream}, stream.metadata)
	}
	stream.finish(err, false, true)
}
