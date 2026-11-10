package outbound

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestNowherePacketQueueBudgetReleasedOnClose(t *testing.T) {
	var budget atomic.Int64
	association := newNowherePacketConn(context.Background(), nil, &budget)
	left, right := net.Pipe()
	defer right.Close()
	flow := &nowhereFlow{Conn: left, addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}}
	association.flows["flow"] = flow
	done := make(chan struct{})
	go func() { association.receive("flow", flow); close(done) }()
	_ = right.SetWriteDeadline(time.Now().Add(time.Second))
	for i := 0; i < 80; i++ {
		if _, err := right.Write(make([]byte, 4096)); err != nil {
			t.Fatal(err)
		}
	}
	if used := budget.Load(); used <= 0 || used > 64*4096 {
		t.Fatal("unbounded receive queue", used)
	}
	association.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receive task did not stop")
	}
	if budget.Load() != 0 {
		t.Fatal("receive queue leaked its reservation")
	}
}
