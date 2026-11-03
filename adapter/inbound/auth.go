package inbound

import (
	"net"
	"net/netip"
	"slices"

	C "github.com/metacubex/mihomo/constant"
)

var skipAuthPrefixes []netip.Prefix

func SetSkipAuthPrefixes(prefixes []netip.Prefix) {
	accessMu.Lock()
	defer accessMu.Unlock()
	skipAuthPrefixes = slices.Clone(prefixes)
}

func SkipAuthPrefixes() []netip.Prefix {
	accessMu.RLock()
	defer accessMu.RUnlock()
	return slices.Clone(skipAuthPrefixes)
}

func SkipAuthRemoteAddr(addr net.Addr) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return false
	}
	return skipAuth(m.AddrPort().Addr())
}

func SkipAuthRemoteAddress(addr string) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddress(addr); err != nil {
		return false
	}
	return skipAuth(m.AddrPort().Addr())
}

func skipAuth(addr netip.Addr) bool {
	accessMu.RLock()
	defer accessMu.RUnlock()
	return prefixesContains(skipAuthPrefixes, addr)
}
