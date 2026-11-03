package log

import (
	"sync"
	"testing"
)

func TestConcurrentLevelAndLogging(t *testing.T) {
	previous := Level()
	defer SetLevel(previous)
	SetLevel(SILENT)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			SetLevel(ERROR)
			SetLevel(SILENT)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			_ = Level()
			print(Event{LogLevel: DEBUG, Payload: "filtered"})
		}
	}()
	wg.Wait()
}
