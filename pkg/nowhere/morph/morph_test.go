package morph

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20"
)

func TestPreludeReferenceVector(t *testing.T) {
	k := derive("0123456789abcdef0123456789abcdef")
	p := make([]byte, 64)
	for i := 0; i < 32; i++ {
		p[i] = byte(i)
		p[32+i] = byte((uint32(0xf00faa55) >> (31 - i) & 1) << 7)
	}
	nonce, _ := hex.DecodeString("000102030405060708090a0b")
	k.encodePrelude(p, nonce, 0x0123456789abcdef, 1)
	if got := hex.EncodeToString(p[32:]); got != "898f9c840e570537225e187fb7e4c990df489547d61b9e515bad2a8f4dd84d86" {
		t.Fatal(got)
	}
}

type shortSocket struct{ bytes.Buffer }

func (s *shortSocket) Write(p []byte) (int, error)      { return s.Buffer.Write(p[:min(len(p), 7)]) }
func (s *shortSocket) Close() error                     { return nil }
func (s *shortSocket) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (s *shortSocket) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (s *shortSocket) SetDeadline(time.Time) error      { return nil }
func (s *shortSocket) SetReadDeadline(time.Time) error  { return nil }
func (s *shortSocket) SetWriteDeadline(time.Time) error { return nil }

func TestMorphShortWritesAndStreamLimit(t *testing.T) {
	key := derive("0123456789abcdef0123456789abcdef").tcpSend
	nonce := make([]byte, 12)
	cipher, _ := chacha20.NewUnauthenticatedCipher(key[:], nonce)
	socket := &shortSocket{}
	c := &tcpConn{Conn: socket, writer: cipher}
	payload := bytes.Repeat([]byte("continuous"), 10000)
	for _, p := range [][]byte{payload[:13], payload[13:]} {
		n, err := c.Write(p)
		if err != nil || n != len(p) {
			t.Fatal(n, err)
		}
	}
	decoder, _ := chacha20.NewUnauthenticatedCipher(key[:], nonce)
	got := socket.Bytes()
	decoder.XORKeyStream(got, got)
	if !bytes.Equal(got, payload) {
		t.Fatal("short writes lost cipher position")
	}
	c.writeOffset = streamLimit
	if _, err := c.Write([]byte{1}); err == nil {
		t.Fatal("keystream wrapped")
	}
}

func TestMorphPolicyAndPacketBoundaries(t *testing.T) {
	for _, policy := range []string{"fade", "full8", "low7"} {
		client, err := NewClient("key", policy, policy)
		if err != nil {
			t.Fatal(err)
		}
		socket := &shortSocket{}
		conn, err := client.WrapTCP(socket)
		if err != nil {
			t.Fatal(err)
		}
		if len(socket.Bytes()) != 76 {
			t.Fatal("bootstrap length")
		}
		if _, err := conn.Write([]byte("tls")); err != nil {
			t.Fatal(err)
		}
		if len(socket.Bytes()) != 79 {
			t.Fatal("wire length")
		}
		p, err := prelude(64, policy)
		if err != nil {
			t.Fatal(err)
		}
		if policy == "low7" {
			for _, b := range p {
				if b > 127 {
					t.Fatal("low7")
				}
			}
		}
	}
	// A receiver must discard the independent 12-byte Prelude, then decrypt
	// each UDP datagram with its own nonce without joining packet boundaries.
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	client, _ := NewClient("key", "", "")
	wrapped, err := client.WrapPacket(local)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrapped.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = peer.WriteTo(make([]byte, 12), local.LocalAddr())
	for _, payload := range [][]byte{[]byte("one"), []byte("second packet")} {
		wire := make([]byte, 12+len(payload))
		wire[0] = byte(len(payload))
		cipher, _ := chacha20.NewUnauthenticatedCipher(client.keys.udpReceive[:], wire[:12])
		cipher.XORKeyStream(wire[12:], payload)
		_, _ = peer.WriteTo(wire, local.LocalAddr())
		b := make([]byte, 100)
		n, _, err := wrapped.ReadFrom(b)
		if err != nil || !bytes.Equal(b[:n], payload) {
			t.Fatal(n, err)
		}
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	for i := 0; i < 2; i++ {
		if _, err := wrapped.WriteTo([]byte("out"), peer.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 100)
		n, _, err := peer.ReadFrom(b)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if n != 12 {
				t.Fatal("missing UDP Prelude")
			}
			n, _, err = peer.ReadFrom(b)
			if err != nil {
				t.Fatal(err)
			}
		}
		if n != 15 {
			t.Fatal("packet length", n)
		}
		cipher, _ := chacha20.NewUnauthenticatedCipher(client.keys.udpSend[:], b[:12])
		cipher.XORKeyStream(b[12:n], b[12:n])
		if string(b[12:n]) != "out" {
			t.Fatal("outgoing ciphertext")
		}
	}
}

var _ io.Writer = (*shortSocket)(nil)

func TestCounterConcurrencyAndExhaustion(t *testing.T) {
	c, _ := NewClient("key", "", "")
	var wg sync.WaitGroup
	values := make(chan uint64, 1024)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				_, n, err := c.allocate()
				if err != nil {
					t.Error(err)
				}
				values <- n
			}
		}()
	}
	wg.Wait()
	close(values)
	seen := map[uint64]bool{}
	for n := range values {
		if n == 0 || seen[n] {
			t.Fatal("reused counter")
		}
		seen[n] = true
	}
	c.counter.Store(maxCounter - 1)
	if _, n, err := c.allocate(); err != nil || n != maxCounter {
		t.Fatal(n, err)
	}
	if _, _, err := c.allocate(); err == nil {
		t.Fatal("counter wrapped")
	}
}
