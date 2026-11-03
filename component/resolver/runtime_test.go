package resolver

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/trie"
)

type runtimeResolver struct{ Resolver }

func (runtimeResolver) Invalid() bool { return true }
func (runtimeResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}
func (r runtimeResolver) LookupIPv4(ctx context.Context, s string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, s)
}
func (r runtimeResolver) LookupIPv6(ctx context.Context, s string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, s)
}
func (runtimeResolver) ClearCache()      {}
func (runtimeResolver) ResetConnection() {}

func TestRuntimePublicationDuringLookups(t *testing.T) {
	oldResolver, oldSystem := DefaultResolver.Load(), SystemResolver.Load()
	oldHosts, oldIPv6, oldSystemHosts := DefaultHosts.Load(), DisableIPv6.Load(), UseSystemHosts.Load()
	defer func() {
		DefaultResolver.Store(oldResolver)
		SystemResolver.Store(oldSystem)
		DefaultHosts.Store(oldHosts)
		DisableIPv6.Store(oldIPv6)
		UseSystemHosts.Store(oldSystemHosts)
	}()
	SystemResolver.Store(runtimeResolver{})
	UseSystemHosts.Store(false)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			tree := trie.New[HostValue]()
			value, _ := NewHostValueByIPs([]netip.Addr{netip.MustParseAddr("127.0.0.2")})
			if err := tree.Insert("lookup.example", value); err != nil {
				t.Error(err)
				return
			}
			DefaultHosts.Store(NewHosts(tree))
			DefaultResolver.Store(runtimeResolver{})
			DisableIPv6.Store(i%2 == 0)
			DefaultResolver.Store(nil)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			ips, err := LookupIP(context.Background(), "lookup.example")
			if err != nil || len(ips) != 1 {
				t.Errorf("lookup: %v %v", ips, err)
				return
			}
			if i%100 == 0 {
				ClearCache()
				ResetConnection()
			}
		}
	}()
	wg.Wait()
}

func TestIP4PConcurrentEnableAndIPv4Boundary(t *testing.T) {
	old := GetIP4PEnable()
	defer SetIP4PEnable(old)
	ipv4 := netip.MustParseAddr("32.1.0.0")
	SetIP4PEnable(true)
	if got, port := LookupIP4P(ipv4, "443"); got != ipv4 || port != "443" {
		t.Fatal(got, port)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			SetIP4PEnable(i%2 == 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_, _ = LookupIP4P(ipv4, "443")
			_ = GetIP4PEnable()
		}
	}()
	wg.Wait()
}
