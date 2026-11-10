// Package morph implements NW3's directional wire masking and the authenticated
// TCP Prelude extension. TLS/QUIC remains responsible for transport security.
package morph

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20"
)

const nonceLen = 12
const streamLimit = uint64(1<<38) - 64
const maxCounter = uint64(1<<48) - 1

type keys struct{ tcpSend, tcpReceive, udpSend, udpReceive, auth, mask [32]byte }

func mac(key, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func derive(sharedKey string) keys {
	root := mac([]byte("nowhere/nw3/morph"), []byte(sharedKey))
	expand := func(label string) [32]byte { return mac(root[:], append([]byte(label), 1)) }
	return keys{expand("tcp c2s"), expand("tcp s2c"), expand("udp c2s"), expand("udp s2c"), expand("tcp prelude auth"), expand("tcp prelude mask")}
}

// Client owns one identity and monotonic counter shared by all its TCP flows.
type Client struct {
	keys                 keys
	tcpPolicy, udpPolicy string
	once                 sync.Once
	identity             uint64
	identityErr          error
	counter              atomic.Uint64
}

func NewClient(sharedKey, tcpPolicy, udpPolicy string) (*Client, error) {
	if tcpPolicy == "" {
		tcpPolicy = "fade"
	}
	if udpPolicy == "" {
		udpPolicy = "fade"
	}
	for _, p := range []string{tcpPolicy, udpPolicy} {
		if p != "fade" && p != "full8" && p != "low7" {
			return nil, errors.New("nowhere: Morph prelude must be fade, full8 or low7")
		}
	}
	return &Client{keys: derive(sharedKey), tcpPolicy: tcpPolicy, udpPolicy: udpPolicy}, nil
}

func randomBelow(n byte) (byte, error) {
	var b [1]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		if int(b[0]) < 256-256%int(n) {
			return b[0] % n, nil
		}
	}
}

func prelude(size int, policy string) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	switch policy {
	case "low7":
		for i := range b {
			b[i] &= 0x7f
		}
	case "fade":
		a, z := 2, 10
		if size == 64 {
			x, err := randomBelow(5)
			if err != nil {
				return nil, err
			}
			y, err := randomBelow(17)
			if err != nil {
				return nil, err
			}
			a, z = int(x)+8, int(y)+16
		}
		for i := 0; i < a; i++ {
			x, err := randomBelow(95)
			if err != nil {
				return nil, err
			}
			b[i] = x + 0x20
		}
		for i := a; i < z; i++ {
			b[i] &= 0x7f
		}
	}
	return b, nil
}

func (c *Client) allocate() (uint64, uint64, error) {
	c.once.Do(func() {
		var b [8]byte
		_, c.identityErr = rand.Read(b[:])
		c.identity = binary.BigEndian.Uint64(b[:])
	})
	if c.identityErr != nil {
		return 0, 0, c.identityErr
	}
	for {
		n := c.counter.Load()
		if n >= maxCounter {
			return 0, 0, errors.New("nowhere: Morph prelude counter exhausted")
		}
		if c.counter.CompareAndSwap(n, n+1) {
			return c.identity, n + 1, nil
		}
	}
}

func (k keys) encodePrelude(p, nonce []byte, identity, counter uint64) {
	var input [62]byte
	copy(input[:12], nonce)
	copy(input[12:44], p[:32])
	for i, b := range p[32:64] {
		input[44+i/8] |= (b >> 7) << (7 - i%8)
	}
	binary.BigEndian.PutUint64(input[48:56], identity)
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], counter)
	copy(input[56:], count[2:])
	tag, mask := mac(k.auth[:], input[:]), mac(k.mask[:], input[:48])
	var payload [28]byte
	copy(payload[:14], input[48:])
	copy(payload[14:], tag[:14])
	for i := range payload {
		payload[i] ^= mask[i]
	}
	for i := 0; i < 32; i++ {
		v := byte(0)
		for j := 0; j < 7; j++ {
			offset := i*7 + j
			v = v<<1 | (payload[offset/8] >> (7 - offset%8) & 1)
		}
		p[32+i] = p[32+i]&0x80 | v
	}
}

func (c *Client) WrapTCP(conn net.Conn) (net.Conn, error) {
	p, err := prelude(64, c.tcpPolicy)
	if err != nil {
		return nil, err
	}
	var nonce [nonceLen]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	id, count, err := c.allocate()
	if err != nil {
		return nil, err
	}
	c.keys.encodePrelude(p, nonce[:], id, count)
	if err = writeFull(conn, append(p, nonce[:]...)); err != nil {
		return nil, err
	}
	r, _ := chacha20.NewUnauthenticatedCipher(c.keys.tcpReceive[:], nonce[:])
	w, _ := chacha20.NewUnauthenticatedCipher(c.keys.tcpSend[:], nonce[:])
	return &tcpConn{Conn: conn, reader: r, writer: w}, nil
}

type tcpConn struct {
	net.Conn
	rmu, wmu                sync.Mutex
	reader, writer          *chacha20.Cipher
	readOffset, writeOffset uint64
}

func (c *tcpConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.readOffset >= streamLimit {
		return 0, errors.New("nowhere: Morph keystream exhausted")
	}
	p = p[:min(uint64(len(p)), streamLimit-c.readOffset)]
	n, err := c.Conn.Read(p)
	c.reader.XORKeyStream(p[:n], p[:n])
	c.readOffset += uint64(n)
	return n, err
}

func (c *tcpConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if uint64(len(p)) > streamLimit-c.writeOffset {
		return 0, errors.New("nowhere: Morph keystream exhausted")
	}
	written := 0
	for len(p) != 0 {
		chunk := p[:min(len(p), 32*1024)]
		out := make([]byte, len(chunk))
		// A cipher is value state. Commit only the bytes accepted by the socket;
		// short writes must not consume the unsent part of the keystream.
		trial := *c.writer
		trial.XORKeyStream(out, chunk)
		n, err := c.Conn.Write(out)
		if n < 0 || n > len(out) {
			return written, io.ErrShortWrite
		}
		if n == len(out) {
			*c.writer = trial
		} else {
			c.writer.XORKeyStream(out[:n], out[:n])
		}
		written += n
		c.writeOffset += uint64(n)
		p = p[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func (c *tcpConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.New("nowhere: underlying connection cannot half-close")
}

// WrapPacket deliberately exposes only net.PacketConn, preventing QUIC's raw
// socket/GSO fast paths from bypassing the per-datagram transform. With Morph,
// the QUIC caller must budget the 12-byte nonce in its path MTU.
func (c *Client) WrapPacket(conn net.PacketConn) (net.PacketConn, error) {
	p, err := prelude(12, c.udpPolicy)
	if err != nil {
		return nil, err
	}
	return &packetConn{PacketConn: conn, send: c.keys.udpSend, receive: c.keys.udpReceive, prelude: p}, nil
}

type packetConn struct {
	net.PacketConn
	mu            sync.Mutex
	send, receive [32]byte
	prelude       []byte
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.prelude) != 0 {
		n, err := c.PacketConn.WriteTo(c.prelude, addr)
		if err != nil {
			return 0, err
		}
		if n != len(c.prelude) {
			return 0, io.ErrShortWrite
		}
		c.prelude = nil
	}
	if len(p) > 65535-nonceLen {
		return 0, errors.New("nowhere: Morph UDP datagram too large")
	}
	b := make([]byte, nonceLen+len(p))
	if _, err := rand.Read(b[:nonceLen]); err != nil {
		return 0, err
	}
	cipher, _ := chacha20.NewUnauthenticatedCipher(c.send[:], b[:nonceLen])
	cipher.XORKeyStream(b[nonceLen:], p)
	n, err := c.PacketConn.WriteTo(b, addr)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	b := make([]byte, 65535)
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return 0, addr, err
		}
		if n <= nonceLen {
			continue
		}
		cipher, _ := chacha20.NewUnauthenticatedCipher(c.receive[:], b[:nonceLen])
		cipher.XORKeyStream(b[nonceLen:n], b[nonceLen:n])
		if n-nonceLen > len(p) {
			continue
		}
		return copy(p, b[nonceLen:n]), addr, nil
	}
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
