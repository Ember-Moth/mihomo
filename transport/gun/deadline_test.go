package gun

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConnIndependentDeadlines(t *testing.T) {
	for _, readFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "read", false: "write"}[readFirst], func(t *testing.T) {
			done := make(chan struct{})
			conn := &Conn{onClose: func() { close(done) }}
			defer conn.Close()
			deadline := time.Now().Add(20 * time.Millisecond)
			if readFirst {
				require.NoError(t, conn.SetReadDeadline(deadline))
				require.NoError(t, conn.SetWriteDeadline(time.Time{}))
			} else {
				require.NoError(t, conn.SetWriteDeadline(deadline))
				require.NoError(t, conn.SetReadDeadline(time.Time{}))
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("clearing one direction cancelled the other deadline")
			}
		})
	}
}

func TestConnConcurrentDeadlines(t *testing.T) {
	var closes atomic.Int32
	conn := &Conn{onClose: func() { closes.Add(1) }}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				deadline := time.Now().Add(time.Second)
				if i%2 == 0 {
					_ = conn.SetReadDeadline(deadline)
				} else {
					_ = conn.SetWriteDeadline(deadline)
				}
			}
		}(i)
	}
	wg.Wait()
	require.NoError(t, conn.SetDeadline(time.Time{}))
	require.NoError(t, conn.Close())
	require.NoError(t, conn.Close())
	require.EqualValues(t, 1, closes.Load())
}

func TestConnClearedDeadline(t *testing.T) {
	done := make(chan struct{})
	conn := &Conn{onClose: func() { close(done) }}
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Millisecond)))
	require.NoError(t, conn.SetDeadline(time.Time{}))
	select {
	case <-done:
		t.Fatal("a cleared deadline closed the connection")
	case <-time.After(40 * time.Millisecond):
	}
}
