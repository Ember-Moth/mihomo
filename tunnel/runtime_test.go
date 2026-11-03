package tunnel

import (
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/sniffer"
)

func TestModeAndSnifferPublication(t *testing.T) {
	oldMode, oldSniffer := Mode(), activeSniffer.Load()
	defer func() { SetMode(oldMode); activeSniffer.Store(oldSniffer) }()
	on, err := sniffer.NewDispatcher(&sniffer.Config{Enable: true})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			SetMode(Direct)
			UpdateSniffer(on)
			SetSniffing(false)
			UpdateSniffer(nil)
			SetMode(Rule)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			if m := Mode(); m != Direct && m != Rule {
				t.Errorf("mode=%v", m)
			}
			_ = IsSniffing()
			if d := connectionSniffer(); d != nil && !d.Enable() {
				t.Error("published disabled sniffer")
			}
		}
	}()
	wg.Wait()
}
