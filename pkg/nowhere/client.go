package nowhere

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/pkg/nowhere/morph"
	"github.com/metacubex/tls"
)

// Options supplies the physical transports; successful dial results belong to
// Client. Network is "tcp" (TLS) or "udp" (QUIC), independently of flow type.
type Options struct {
	SharedKey                                   string
	Network                                     string
	TLSConfig                                   *tls.Config
	DialStream                                  func(context.Context) (net.Conn, error)
	DialPacket                                  func(context.Context) (net.PacketConn, net.Addr, error)
	Morph                                       bool
	TCPPrelude, UDPPrelude                      string
	HandshakeTimeout, SetupTimeout, IdleTimeout time.Duration
}

// Client owns reusable QUIC state and all returned flows. Closing a flow never
// closes unrelated flows; closing Client cancels pending dials and all flows.
type Client struct {
	options    Options
	key        [32]byte
	morph      *morph.Client
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	active     map[*trackedConn]struct{}
	quic       *quicSession
	connecting chan struct{}
	permits    chan struct{}
}

func NewClient(options Options) (*Client, error) {
	if err := validateKey(options.SharedKey); err != nil {
		return nil, err
	}
	if options.Network == "" {
		options.Network = "tcp"
	}
	if options.Network != "tcp" && options.Network != "udp" {
		return nil, errors.New("nowhere: network must be tcp or udp")
	}
	if options.Network == "tcp" && options.DialStream == nil || options.Network == "udp" && options.DialPacket == nil {
		return nil, errors.New("nowhere: transport dialer is required")
	}
	if options.TLSConfig == nil {
		return nil, errors.New("nowhere: TLS configuration is required")
	}
	options.TLSConfig = options.TLSConfig.Clone()
	options.TLSConfig.MinVersion, options.TLSConfig.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	options.TLSConfig.NextProtos = []string{ALPN}
	if options.HandshakeTimeout < 0 || options.SetupTimeout < 0 || options.IdleTimeout < 0 {
		return nil, errors.New("nowhere: timeouts must be positive")
	}
	if options.HandshakeTimeout == 0 {
		options.HandshakeTimeout = 10 * time.Second
	}
	if options.SetupTimeout == 0 {
		options.SetupTimeout = 20 * time.Second
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = 60 * time.Second
	}
	m, err := morph.NewClient(options.SharedKey, options.TCPPrelude, options.UDPPrelude)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{options: options, key: vectorKey(options.SharedKey), morph: m, ctx: ctx, cancel: cancel,
		active: make(map[*trackedConn]struct{}), connecting: make(chan struct{}, 1), permits: make(chan struct{}, 1024)}, nil
}

// DialTCP opens a reliable, bidirectional flow and waits for the peer's READY.
func (c *Client) DialTCP(ctx context.Context, target Target) (net.Conn, error) {
	return c.dial(ctx, target, false)
}

// DialUDP opens a fixed-target datagram flow. Each Write sends one packet and
// each Read receives one packet, including zero-length packets. An undersized
// read buffer consumes that packet and returns io.ErrShortBuffer.
func (c *Client) DialUDP(ctx context.Context, target Target) (net.Conn, error) {
	return c.dial(ctx, target, true)
}

func (c *Client) dial(parent context.Context, target Target, udp bool) (net.Conn, error) {
	request, err := flowRequest(udp, target)
	if err != nil {
		return nil, err
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if c.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	select {
	case c.permits <- struct{}{}:
	default:
		return nil, SetupError(2)
	}
	owned := false
	defer func() {
		if !owned {
			<-c.permits
		}
	}()
	ctx, cancel := context.WithTimeout(parent, c.options.SetupTimeout)
	stop := context.AfterFunc(c.ctx, cancel)
	defer func() { stop(); cancel() }()
	var conn net.Conn
	if c.options.Network == "tcp" {
		conn, err = c.dialTLS(ctx, request)
		if err == nil && udp {
			conn = &uotConn{Conn: conn, target: target.addr()}
		}
	} else {
		conn, err = c.dialQUIC(ctx, request, target, udp)
	}
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil || ctx.Err() != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, net.ErrClosed
	}
	tracked := &trackedConn{Conn: conn, client: c}
	c.active[tracked] = struct{}{}
	owned = true
	return tracked, nil
}

func (c *Client) dialTLS(ctx context.Context, request []byte) (_ net.Conn, err error) {
	raw, err := c.options.DialStream(ctx)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, errors.New("nowhere: stream dialer returned no transport")
	}
	ok := false
	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	handshakeCtx, cancel := context.WithTimeout(ctx, c.options.HandshakeTimeout)
	defer cancel()
	deadline, _ := handshakeCtx.Deadline()
	_ = raw.SetDeadline(deadline)
	var stream net.Conn = raw
	if c.options.Morph {
		stream, err = c.morph.WrapTCP(raw)
		if err != nil {
			return nil, err
		}
	}
	secure := tls.Client(stream, c.options.TLSConfig)
	if err = secure.HandshakeContext(handshakeCtx); err != nil {
		return nil, err
	}
	state := secure.ConnectionState()
	if state.NegotiatedProtocol != ALPN {
		return nil, errors.New("nowhere: peer did not negotiate nw3")
	}
	exporter, err := state.ExportKeyingMaterial(exporterLabel, []byte{}, 32)
	if err != nil {
		return nil, err
	}
	deadline, _ = ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	auth := authFrame(c.key, 1, exporter)
	if err = writeFull(secure, append(auth[:], request...)); err != nil {
		return nil, err
	}
	if err = readReady(secure); err != nil {
		return nil, err
	}
	if !stop() || ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err = raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return secure, nil
}

func (c *Client) Close() error {
	c.cancel()
	c.mu.Lock()
	active := make([]*trackedConn, 0, len(c.active))
	for conn := range c.active {
		active = append(active, conn)
	}
	q := c.quic
	c.quic = nil
	c.mu.Unlock()
	for _, conn := range active {
		_ = conn.Close()
	}
	if q != nil {
		q.close()
	}
	return nil
}

type trackedConn struct {
	net.Conn
	client *Client
	once   sync.Once
}

func (c *trackedConn) Close() (err error) {
	c.once.Do(func() {
		err = c.Conn.Close()
		c.client.mu.Lock()
		delete(c.client.active, c)
		c.client.mu.Unlock()
		<-c.client.permits
	})
	return
}

func (c *trackedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.New("nowhere: flow does not support half-close")
}

type uotConn struct {
	net.Conn
	target      net.Addr
	rmu, wmu    sync.Mutex
	header      [2]byte
	headerRead  int
	payload     []byte
	payloadRead int
}

func (c *uotConn) RemoteAddr() net.Addr { return c.target }
func (c *uotConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for c.headerRead < 2 {
		n, err := c.Conn.Read(c.header[c.headerRead:])
		c.headerRead += n
		if err != nil && c.headerRead < 2 {
			if err == io.EOF && c.headerRead != 0 {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
	}
	size := int(c.header[0])<<8 | int(c.header[1])
	if c.payload == nil {
		c.payload = make([]byte, size)
	}
	for c.payloadRead < size {
		n, err := c.Conn.Read(c.payload[c.payloadRead:])
		c.payloadRead += n
		if err != nil && c.payloadRead < size {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
	}
	n := copy(p, c.payload)
	c.payload, c.headerRead, c.payloadRead = nil, 0, 0
	if n < size {
		return n, io.ErrShortBuffer
	}
	return n, nil
}

func (c *uotConn) Write(p []byte) (int, error) {
	if len(p) > maxPacket {
		return 0, ErrInvalidUOTPacket
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := WriteUOTPacket(c.Conn, p); err != nil {
		_ = c.Conn.Close()
		return 0, err
	}
	return len(p), nil
}
