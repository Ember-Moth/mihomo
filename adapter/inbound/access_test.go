package inbound

import (
	"net"
	"net/netip"
	"sync"
	"testing"
)

func TestAccessPrefixesOwnTheirSlices(t *testing.T) {
	a := netip.MustParsePrefix("10.0.0.0/8")
	b := netip.MustParsePrefix("192.168.0.0/16")
	for _, pair := range []struct {
		set func([]netip.Prefix)
		get func() []netip.Prefix
	}{
		{SetAllowedIPs, AllowedIPs}, {SetDisAllowedIPs, DisAllowedIPs}, {SetSkipAuthPrefixes, SkipAuthPrefixes},
	} {
		input := []netip.Prefix{a}
		pair.set(input)
		input[0] = b
		got := pair.get()
		if got[0] != a {
			t.Error("setter retained caller storage")
		}
		got[0] = b
		if pair.get()[0] != a {
			t.Error("getter exposed mutable policy storage")
		}
		pair.set(nil)
	}
}

func TestAccessUpdatesWhileAccepting(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	addr := &net.TCPAddr{IP: net.ParseIP("10.2.3.4"), Port: 443}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			SetAllowedIPs(prefixes)
			SetDisAllowedIPs(prefixes)
			SetSkipAuthPrefixes(prefixes)
			SetDisAllowedIPs(nil)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			_ = IsRemoteAddrDisAllowed(addr)
			_ = SkipAuthRemoteAddr(addr)
			_ = AllowedIPs()
			_ = DisAllowedIPs()
			_ = SkipAuthPrefixes()
		}
	}()
	wg.Wait()
	SetAllowedIPs(nil)
	SetDisAllowedIPs(nil)
	SetSkipAuthPrefixes(nil)
}

func TestAccessPolicyPublicationIsAtomic(t *testing.T) {
	a := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	b := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	addr := &net.TCPAddr{IP: net.ParseIP("10.2.3.4"), Port: 443}
	SetAccessRules(nil, a, a)
	defer SetAccessRules(nil, nil, nil)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			SetAccessRules(nil, a, a)
			PatchAccessRules(nil, &b, &b)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			if IsRemoteAddrDisAllowed(addr) {
				t.Error("accepted a peer denied by both complete policies")
				return
			}
		}
	}()
	wg.Wait()
}
