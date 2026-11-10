package nowhere

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go"
)

const udpBudget = 4 << 20

type quicSession struct {
	conn        *quic.Conn
	transport   *quic.Transport
	packet      net.PacketConn
	ctx         context.Context
	cancel      context.CancelFunc
	once        sync.Once
	draining    atomic.Bool
	mu          sync.Mutex
	flows       map[FlowID]*quicUDPConn
	queuedBytes int
	reassembly  *DatagramReassembler
	send        chan udpSend
}

func (c *Client) session(ctx context.Context) (*quicSession, error) {
	select {
	case c.connecting <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.connecting }()
	c.mu.Lock()
	q := c.quic
	c.mu.Unlock()
	if q != nil && q.ctx.Err() == nil && q.conn.Context().Err() == nil && !q.draining.Load() {
		return q, nil
	}
	q, err := c.newSession(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		q.close()
		return nil, net.ErrClosed
	}
	c.quic = q
	return q, nil
}

func (c *Client) newSession(ctx context.Context) (_ *quicSession, err error) {
	pc, remote, err := c.options.DialPacket(ctx)
	if err != nil {
		return nil, err
	}
	if pc == nil || remote == nil {
		if pc != nil {
			_ = pc.Close()
		}
		return nil, errors.New("nowhere: packet dialer returned no transport or peer")
	}
	rawPacket := pc
	ok := false
	defer func() {
		if !ok {
			_ = rawPacket.Close()
		}
	}()
	if c.options.Morph {
		pc, err = c.morph.WrapPacket(pc)
		if err != nil {
			return nil, err
		}
	}
	transport := &quic.Transport{Conn: pc}
	defer func() {
		if !ok {
			_ = transport.Close()
		}
	}()
	config := &quic.Config{
		HandshakeIdleTimeout: c.options.HandshakeTimeout, MaxIdleTimeout: c.options.IdleTimeout,
		KeepAlivePeriod: 15 * time.Second, EnableDatagrams: true,
		MaxIncomingStreams: 1, MaxIncomingUniStreams: -1,
		InitialStreamReceiveWindow: 256 << 10, MaxStreamReceiveWindow: 4 << 20,
		InitialConnectionReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 8 << 20,
	}
	if c.options.Morph {
		// 1200 QUIC bytes + 12 nonce bytes fit the minimum IPv6 UDP MTU.
		// The masking wrapper disables OOB/GSO, so PMTU probing cannot account
		// for its prefix. Use a conservative fixed transport packet size.
		config.InitialPacketSize = 1200
		config.DisablePathMTUDiscovery = true
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, c.options.HandshakeTimeout)
	conn, err := transport.Dial(handshakeCtx, remote, c.options.TLSConfig, config)
	cancel()
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			_ = conn.CloseWithError(1, "setup failed")
		}
	}()
	state := conn.ConnectionState()
	if state.TLS.NegotiatedProtocol != ALPN || state.Used0RTT {
		return nil, errors.New("nowhere: invalid QUIC handshake")
	}
	exporter, err := state.TLS.ExportKeyingMaterial(exporterLabel, []byte{}, 32)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if stream.StreamID() != 0 {
		return nil, errors.New("nowhere: authentication requires stream 0")
	}
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	auth := authFrame(c.key, 2, exporter)
	if err = writeFull(stream, auth[:]); err != nil {
		return nil, err
	}
	if err = stream.Close(); err != nil {
		return nil, err
	}
	var extra [1]byte
	// An authentication-only stream has FIN in both directions, no ACK byte.
	if n, readErr := stream.Read(extra[:]); n != 0 || readErr != io.EOF {
		if readErr == nil {
			readErr = errors.New("nowhere: unexpected authentication response")
		}
		return nil, readErr
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	qctx, qcancel := context.WithCancel(c.ctx)
	reassembler, _ := NewDatagramReassembler(ReassemblyConfig{MaxSlots: 64, MaxBytes: udpBudget, TTL: 10 * time.Second})
	q := &quicSession{conn: conn, transport: transport, packet: pc, ctx: qctx, cancel: qcancel,
		flows: make(map[FlowID]*quicUDPConn), reassembly: reassembler, send: make(chan udpSend, 32)}
	ok = true
	go q.dispatch()
	go q.sendLoop()
	go func() {
		if _, err := conn.AcceptStream(qctx); err == nil {
			_ = conn.CloseWithError(1, "unexpected server stream")
		}
		q.close()
	}()
	go q.maintain()
	return q, nil
}

func (c *Client) dialQUIC(ctx context.Context, request []byte, target Target, udp bool) (_ net.Conn, err error) {
	q, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	if udp && !q.conn.ConnectionState().SupportsDatagrams.Remote {
		return nil, errors.New("nowhere: peer does not support QUIC DATAGRAM")
	}
	stream, err := q.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			stream.CancelRead(1)
			stream.CancelWrite(1)
		}
	}()
	id, err := udpFlowID(uint64(stream.StreamID()))
	if err != nil {
		if q.draining.CompareAndSwap(false, true) {
			time.AfterFunc(5*time.Second, q.close)
		}
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	var packet *quicUDPConn
	if udp {
		packet = &quicUDPConn{session: q, stream: stream, id: id, target: target.addr(), incoming: make(chan []byte, 64),
			done: make(chan struct{}), readDeadline: newDeadline(), writeDeadline: newDeadline(), idleTimeout: c.options.IdleTimeout}
		q.mu.Lock()
		if q.ctx.Err() != nil {
			q.mu.Unlock()
			return nil, net.ErrClosed
		}
		q.flows[id] = packet
		q.mu.Unlock()
		defer func() {
			if !ok {
				_ = packet.Close()
			}
		}()
	}
	if err = writeFull(stream, request); err != nil {
		return nil, err
	}
	if err = readReady(stream); err != nil {
		return nil, err
	}
	if !stop() || ctx.Err() != nil {
		return nil, ctx.Err()
	}
	_ = stream.SetDeadline(time.Time{})
	if packet != nil {
		q.mu.Lock()
		if q.ctx.Err() != nil || q.flows[id] != packet {
			q.mu.Unlock()
			return nil, net.ErrClosed
		}
		packet.ready = true
		q.mu.Unlock()
		packet.touch()
		packet.idleMu.Lock()
		select {
		case <-packet.done:
			packet.idleMu.Unlock()
			return nil, net.ErrClosed
		default:
			packet.idle = time.AfterFunc(packet.idleTimeout, packet.expire)
		}
		packet.idleMu.Unlock()
		go packet.monitor()
		ok = true
		return packet, nil
	}
	ok = true
	return &quicTCPConn{Stream: stream, local: q.conn.LocalAddr(), remote: q.conn.RemoteAddr()}, nil
}

type quicTCPConn struct {
	*quic.Stream
	local, remote net.Addr
}

func (c *quicTCPConn) LocalAddr() net.Addr  { return c.local }
func (c *quicTCPConn) RemoteAddr() net.Addr { return c.remote }
func (c *quicTCPConn) CloseWrite() error    { return c.Stream.Close() }
func (c *quicTCPConn) CloseRead() error     { c.Stream.CancelRead(0); return nil }
func (c *quicTCPConn) Close() error {
	c.Stream.CancelRead(0)
	c.Stream.CancelWrite(0)
	return nil
}

func (q *quicSession) close() {
	q.once.Do(func() {
		q.cancel()
		_ = q.conn.CloseWithError(0, "")
		_ = q.packet.Close()
		_ = q.transport.Close()
		q.mu.Lock()
		flows := make([]*quicUDPConn, 0, len(q.flows))
		for _, f := range q.flows {
			flows = append(flows, f)
		}
		q.mu.Unlock()
		for _, f := range flows {
			_ = f.Close()
		}
	})
}

func (q *quicSession) dispatch() {
	defer q.close()
	for {
		data, err := q.conn.ReceiveDatagram(q.ctx)
		if err != nil {
			return
		}
		frame, err := DecodeUDPFrame(data)
		if err != nil {
			continue
		}
		q.mu.Lock()
		f := q.flows[frame.FlowID]
		if f == nil || !f.ready {
			q.mu.Unlock()
			continue
		}
		if frame.Type == UDPFrameClose {
			q.mu.Unlock()
			_ = f.Close()
			continue
		}
		payload := frame.Payload
		if frame.Type == UDPFrameFragment {
			var complete bool
			payload, complete, err = q.reassembly.PushWithLimit(frame, time.Now(), udpBudget-q.queuedBytes)
			if err != nil || !complete {
				q.mu.Unlock()
				continue
			}
		}
		cost := max(1, len(payload))
		if q.queuedBytes+q.reassembly.ReservedBytes()+cost <= udpBudget {
			select {
			case f.incoming <- payload:
				q.queuedBytes += cost
				f.touch()
			default:
			}
		}
		q.mu.Unlock()
	}
}

func (q *quicSession) maintain() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer q.close()
	for {
		select {
		case <-q.ctx.Done():
			return
		case now := <-ticker.C:
			q.mu.Lock()
			q.reassembly.Expire(now)
			q.mu.Unlock()
		}
	}
}

// One worker bounds blocked SendDatagram calls without leaking one goroutine
// for every deadline/cancellation. Callers can stop waiting independently.
type udpSend struct {
	flow    *quicUDPConn
	payload []byte
	result  chan error
}

func (q *quicSession) sendLoop() {
	for {
		select {
		case <-q.ctx.Done():
			return
		case task := <-q.send:
			err := q.sendPacket(task.flow, task.payload)
			task.result <- err
		}
	}
}

func (q *quicSession) sendPacket(f *quicUDPConn, payload []byte) error {
	select {
	case <-f.done:
		return net.ErrClosed
	default:
	}
	data, err := EncodeUDPData(f.id, payload)
	if err != nil {
		return err
	}
	err = q.conn.SendDatagram(data)
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	// Packet IDs belong to this flow. Close on exhaustion instead of reusing an
	// ID that might still identify incomplete fragments at the peer.
	id := f.packetID.Add(1)
	if id == 0 {
		_ = f.Close()
		return errors.New("nowhere: UDP packet ID exhausted")
	}
	frames, err := EncodeUDPFragments(f.id, id, payload, int(tooLarge.MaxDatagramPayloadSize))
	if err != nil {
		return err
	}
	for _, frame := range frames {
		select {
		case <-f.done:
			return net.ErrClosed
		default:
		}
		if err := q.conn.SendDatagram(frame); err != nil {
			return err
		}
	}
	return nil
}

type deadline struct {
	mu      sync.Mutex
	at      time.Time
	changed chan struct{}
}

func newDeadline() *deadline { return &deadline{changed: make(chan struct{})} }
func (d *deadline) expired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.at.IsZero() && !time.Now().Before(d.at)
}
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	d.at = t
	close(d.changed)
	d.changed = make(chan struct{})
	d.mu.Unlock()
}
func (d *deadline) timer() (*time.Timer, <-chan time.Time, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.at.IsZero() {
		return nil, nil, d.changed
	}
	t := time.NewTimer(max(0, time.Until(d.at)))
	return t, t.C, d.changed
}
func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

type quicUDPConn struct {
	session                     *quicSession
	stream                      *quic.Stream
	id                          FlowID
	target                      net.Addr
	ready                       bool // protected by session.mu
	incoming                    chan []byte
	done                        chan struct{}
	once                        sync.Once
	wmu                         sync.Mutex
	packetID                    atomic.Uint32
	readDeadline, writeDeadline *deadline
	lastActivity                atomic.Int64
	idleMu                      sync.Mutex
	idle                        *time.Timer
	idleTimeout                 time.Duration
}

func (f *quicUDPConn) touch() { f.lastActivity.Store(time.Now().UnixNano()) }
func (f *quicUDPConn) expire() {
	f.idleMu.Lock()
	remaining := f.idleTimeout - time.Since(time.Unix(0, f.lastActivity.Load()))
	select {
	case <-f.done:
		f.idleMu.Unlock()
		return
	default:
	}
	if remaining > 0 {
		f.idle.Reset(remaining)
		f.idleMu.Unlock()
		return
	}
	f.idleMu.Unlock()
	_ = f.Close()
}
func (f *quicUDPConn) monitor() {
	go func() {
		select {
		case <-f.stream.Context().Done():
			_ = f.Close()
		case <-f.done:
		}
	}()
	var b [1]byte
	_, _ = f.stream.Read(b[:]) // FIN, reset, or any post-READY bytes end the flow.
	_ = f.Close()
}
func (f *quicUDPConn) Close() error {
	f.once.Do(func() {
		close(f.done)
		f.idleMu.Lock()
		if f.idle != nil {
			f.idle.Stop()
		}
		f.idleMu.Unlock()
		f.stream.CancelRead(0)
		f.stream.CancelWrite(0)
		q := f.session
		q.mu.Lock()
		defer q.mu.Unlock()
		delete(q.flows, f.id)
		q.reassembly.RemoveFlow(f.id)
		for {
			select {
			case p := <-f.incoming:
				q.queuedBytes -= max(1, len(p))
			default:
				return
			}
		}
	})
	return nil
}
func (f *quicUDPConn) LocalAddr() net.Addr                { return f.session.conn.LocalAddr() }
func (f *quicUDPConn) RemoteAddr() net.Addr               { return f.target }
func (f *quicUDPConn) SetReadDeadline(t time.Time) error  { f.readDeadline.set(t); return nil }
func (f *quicUDPConn) SetWriteDeadline(t time.Time) error { f.writeDeadline.set(t); return nil }
func (f *quicUDPConn) SetDeadline(t time.Time) error {
	_ = f.SetReadDeadline(t)
	return f.SetWriteDeadline(t)
}

func (f *quicUDPConn) Read(p []byte) (int, error) {
	for {
		select {
		case <-f.done:
			return 0, net.ErrClosed
		default:
		}
		if f.readDeadline.expired() {
			return 0, os.ErrDeadlineExceeded
		}
		timer, expired, changed := f.readDeadline.timer()
		select {
		case packet := <-f.incoming:
			stopTimer(timer)
			f.session.mu.Lock()
			f.session.queuedBytes -= max(1, len(packet))
			f.session.mu.Unlock()
			f.touch()
			n := copy(p, packet)
			if n < len(packet) {
				return n, io.ErrShortBuffer
			}
			return n, nil
		case <-expired:
			return 0, os.ErrDeadlineExceeded
		case <-changed:
			stopTimer(timer)
		case <-f.done:
			stopTimer(timer)
			return 0, net.ErrClosed
		}
	}
}

func (f *quicUDPConn) Write(p []byte) (int, error) {
	if len(p) > maxPacket {
		return 0, ErrInvalidUDPFrame
	}
	f.wmu.Lock()
	defer f.wmu.Unlock()
	select {
	case <-f.done:
		return 0, net.ErrClosed
	default:
	}
	if f.writeDeadline.expired() {
		return 0, os.ErrDeadlineExceeded
	}
	task := udpSend{flow: f, payload: append([]byte{}, p...), result: make(chan error, 1)}
	sent := false
	for {
		if f.writeDeadline.expired() {
			if sent {
				_ = f.Close()
			}
			return 0, os.ErrDeadlineExceeded
		}
		timer, expired, changed := f.writeDeadline.timer()
		var queue chan udpSend
		if !sent {
			queue = f.session.send
		}
		select {
		case queue <- task:
			sent = true
			stopTimer(timer)
		case err := <-task.result:
			stopTimer(timer)
			if err != nil {
				return 0, err
			}
			f.touch()
			return len(p), nil
		case <-expired:
			if sent {
				_ = f.Close()
			}
			return 0, os.ErrDeadlineExceeded
		case <-changed:
			stopTimer(timer)
		case <-f.done:
			stopTimer(timer)
			return 0, net.ErrClosed
		}
	}
}
