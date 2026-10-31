package reverse

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type echoHandler struct{ seen chan Metadata }

func (h echoHandler) HandleTCP(ctx context.Context, conn net.Conn, metadata Metadata) error {
	if h.seen != nil {
		h.seen <- metadata
	}
	_, err := io.Copy(conn, conn)
	return err
}
func (h echoHandler) HandleUDP(ctx context.Context, conn net.PacketConn, metadata Metadata) error {
	if h.seen != nil {
		h.seen <- metadata
	}
	buffer := make([]byte, MaxPacketSize)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if _, err = conn.WriteTo(buffer[:n], addr); err != nil {
			return err
		}
	}
}

func testPair(t *testing.T, h Handler) (*Pool, *Session) {
	t.Helper()
	a, b := net.Pipe()
	pool := NewPool()
	done := make(chan struct{})
	go func() { defer close(done); _ = pool.Accept(context.Background(), a) }()
	spoke := NewSpoke(b, h)
	t.Cleanup(func() { pool.Close(); spoke.Close(); <-done })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, pool.WaitReady(ctx))
	return pool, spoke
}

func TestReverseConcurrentStreams(t *testing.T) {
	pool, _ := testPair(t, echoHandler{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errors := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := pool.DialContext(ctx, Metadata{Destination: M.ParseSocksaddr("example.org:443")})
			if err != nil {
				errors <- err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 128*1024+i)
			written := make(chan error, 1)
			go func() { _, err := conn.Write(want); written <- err }()
			got := make([]byte, len(want))
			_, err = io.ReadFull(conn, got)
			if err == nil {
				err = <-written
			}
			if err == nil && !bytes.Equal(want, got) {
				err = io.ErrUnexpectedEOF
			}
			errors <- err
		}(i)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}

func TestReverseUDPDestinations(t *testing.T) {
	pool, _ := testPair(t, echoHandler{})
	conn, err := pool.ListenPacket(context.Background(), Metadata{Destination: M.ParseSocksaddr("127.0.0.1:53")})
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	for _, target := range []string{"127.0.0.1:53", "[::1]:5353"} {
		for _, size := range []int{0, 1, 1400, MaxPacketSize} {
			want := bytes.Repeat([]byte{0x42}, size)
			destination := M.ParseSocksaddr(target).UDPAddr()
			_, err = conn.WriteTo(want, destination)
			require.NoError(t, err)
			got := make([]byte, MaxPacketSize)
			n, addr, err := conn.ReadFrom(got)
			require.NoError(t, err)
			require.Equal(t, want, got[:n])
			require.Equal(t, target, addr.String())
		}
	}
	_, err = conn.WriteTo(make([]byte, MaxPacketSize+1), M.ParseSocksaddr("127.0.0.1:53").UDPAddr())
	require.ErrorIs(t, err, ErrPacketTooLarge)
}

func TestReverseSourceMetadata(t *testing.T) {
	seen := make(chan Metadata, 1)
	pool, _ := testPair(t, echoHandler{seen})
	want := Metadata{Destination: M.ParseSocksaddr("example.org:443"), Source: M.ParseSocksaddr("127.0.0.2:23456"), Local: M.ParseSocksaddr("127.0.0.1:8443")}
	conn, err := pool.DialContext(context.Background(), want)
	require.NoError(t, err)
	defer conn.Close()
	select {
	case got := <-seen:
		require.Equal(t, want, got)
	case <-time.After(5 * time.Second):
		t.Fatal("handler not called")
	}
}

func TestReverseDeadlineAndShutdown(t *testing.T) {
	pool, spoke := testPair(t, echoHandler{})
	conn, err := pool.DialContext(context.Background(), Metadata{Destination: M.ParseSocksaddr("example.org:443")})
	require.NoError(t, err)
	conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err)
	require.True(t, errors.Is(err, context.DeadlineExceeded) || err.(net.Error).Timeout())
	conn.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	require.NoError(t, spoke.Close())
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not unblock read")
	}
}

func TestReverseRegistryReload(t *testing.T) {
	r := NewRegistry()
	first, releaseFirst, err := r.Acquire("home")
	require.NoError(t, err)
	second, releaseSecond, err := r.Acquire("home")
	require.NoError(t, err)
	require.Same(t, first, second)
	releaseFirst()
	require.Same(t, second, r.Get("home"))
	releaseSecond()
	require.Nil(t, r.Get("home"))
	_, err = first.DialContext(context.Background(), Metadata{})
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestReverseMalformedFrames(t *testing.T) {
	for _, packet := range [][]byte{{0, 3, 0, 0, 1}, {2, 1}, {0, 4, 0, 1, 99, 0}, {0, 5, 0, 1, statusNew, 0, 99}} {
		_, err := readFrame(bytes.NewReader(packet))
		require.Error(t, err)
	}
}

func TestReverseFrameRoundTrip(t *testing.T) {
	want := frame{id: 42, status: statusNew, options: optionData, network: networkUDP, data: []byte("packet"), Metadata: Metadata{
		Destination: M.ParseSocksaddr("example.org:53"), Source: M.ParseSocksaddr("[::1]:54321"), Local: M.ParseSocksaddr("127.0.0.1:8443")}}
	data, err := want.encode()
	require.NoError(t, err)
	got, err := readFrame(bytes.NewReader(data))
	require.NoError(t, err)
	require.Equal(t, want, got)
}

type recordingDeadlineConn struct {
	net.Conn
	cleared atomic.Bool
}

func (c *recordingDeadlineConn) SetReadDeadline(deadline time.Time) error {
	c.cleared.Store(deadline.IsZero())
	return c.Conn.SetReadDeadline(deadline)
}

func TestReverseDrainAndReconnect(t *testing.T) {
	pool := NewPool()
	var calls atomic.Int32
	var mu sync.Mutex
	var hubs []net.Conn
	var leaves []*recordingDeadlineConn
	dial := func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		leaf := &recordingDeadlineConn{Conn: b}
		mu.Lock()
		hubs = append(hubs, a)
		leaves = append(leaves, leaf)
		mu.Unlock()
		calls.Add(1)
		go func() { _ = pool.Accept(context.Background(), a) }()
		return leaf, nil
	}
	bridge, err := NewBridge(dial, echoHandler{}, 1, nil)
	require.NoError(t, err)
	t.Cleanup(func() { bridge.Close(); pool.Close() })
	require.NoError(t, bridge.Start())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, bridge.WaitReady(ctx))
	require.NoError(t, pool.WaitReady(ctx))
	destination := Metadata{Destination: M.ParseSocksaddr("example.org:443")}
	retired, err := pool.DialContext(ctx, destination)
	require.NoError(t, err)
	defer retired.Close()
	for i := 1; i < maxRequests; i++ {
		conn, err := pool.DialContext(ctx, destination)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}
	require.Eventually(t, func() bool { return calls.Load() >= 2 }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, bridge.WaitReady(ctx))
	require.NoError(t, pool.WaitReady(ctx))
	mu.Lock()
	firstLeaf := leaves[0]
	newestHub := hubs[len(hubs)-1]
	mu.Unlock()
	require.Eventually(t, firstLeaf.cleared.Load, time.Second, 10*time.Millisecond, "draining sessions must stop expecting control heartbeats")
	retired.SetDeadline(time.Now().Add(time.Second))
	_, err = retired.Write([]byte("alive"))
	require.NoError(t, err)
	response := make([]byte, 5)
	_, err = io.ReadFull(retired, response)
	require.NoError(t, err)
	require.Equal(t, "alive", string(response))
	// A broken active tunnel is replaced without closing an older draining one.
	newestHub.Close()
	require.Eventually(t, func() bool { return calls.Load() >= 3 }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, bridge.WaitReady(ctx))
	require.NoError(t, pool.WaitReady(ctx))
	conn, err := pool.DialContext(ctx, destination)
	require.NoError(t, err)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte("new"))
	require.NoError(t, err)
	response = make([]byte, 3)
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, "new", string(response))
	retired.Close()
	conn.Close()
	require.NoError(t, bridge.Close())
	require.Eventually(t, func() bool { return pool.Connections() == 0 }, time.Second, 10*time.Millisecond)
}

func TestReverseCancelledOpen(t *testing.T) {
	pool, _ := testPair(t, echoHandler{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < maxRequests+1; i++ {
		_, err := pool.DialContext(ctx, Metadata{Destination: M.ParseSocksaddr("example.org:443")})
		require.ErrorIs(t, err, context.Canceled)
	}
	conn, err := pool.DialContext(context.Background(), Metadata{Destination: M.ParseSocksaddr("example.org:443")})
	require.NoError(t, err)
	conn.Close()
}

func TestReverseBlockedWriterCancellation(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	// No writer is running: cancellation must not synchronously wait for an END
	// frame to get past another blocked write on the shared transport.
	session := newSession(a, true, nil, nil)
	defer session.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := session.open(ctx, networkTCP, Metadata{Destination: M.ParseSocksaddr("example.org:443")})
		result <- err
	}()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("cancelled dial waited for the transport writer")
	}
}

func TestReverseFrameGolden(t *testing.T) {
	f := frame{id: 2, status: statusNew, options: optionData, network: networkTCP, Metadata: Metadata{Destination: M.ParseSocksaddr("127.0.0.1:443")}, data: []byte("abc")}
	want := []byte{0, 12, 0, 2, 1, 1, 1, 1, 0xbb, 1, 127, 0, 0, 1, 0, 3, 'a', 'b', 'c'}
	got, err := f.encode()
	require.NoError(t, err)
	require.Equal(t, want, got)
}
