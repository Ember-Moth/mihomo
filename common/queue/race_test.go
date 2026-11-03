package queue

import (
	"sync"
	"testing"
)

func TestConcurrentQueueReadersAndProducers(t *testing.T) {
	q := New[int](1)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 1; i <= 5000; i++ {
			q.Put(i)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 5000; i++ {
			_ = q.Last()
			_ = q.Copy()
			_ = q.Len()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 5000; i++ {
			_ = q.Pop()
		}
	}()
	wg.Wait()
	for q.Len() > 0 {
		_ = q.Pop()
	}
	if q.Pop() != 0 || q.Last() != 0 {
		t.Fatal("empty queue must return zero")
	}
}

func TestConcurrentPoppersDoNotDuplicateOrPanic(t *testing.T) {
	q := New[int](1)
	for i := 1; i <= 1000; i++ {
		q.Put(i)
	}
	var wg sync.WaitGroup
	values := make(chan int, 1000)
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				if v := q.Pop(); v != 0 {
					values <- v
				}
			}
		}()
	}
	wg.Wait()
	close(values)
	seen := make(map[int]bool)
	for v := range values {
		if seen[v] {
			t.Fatalf("duplicate %d", v)
		}
		seen[v] = true
	}
	if len(seen) != 1000 {
		t.Fatalf("popped %d items", len(seen))
	}
}
