package inbound

import (
	"net"
	"net/netip"
	"slices"

	C "github.com/metacubex/mihomo/constant"
)

var lanAllowedIPs []netip.Prefix
var lanDisAllowedIPs []netip.Prefix

func SetAllowedIPs(prefixes []netip.Prefix) {
	accessMu.Lock()
	defer accessMu.Unlock()
	lanAllowedIPs = slices.Clone(prefixes)
}

func SetDisAllowedIPs(prefixes []netip.Prefix) {
	accessMu.Lock()
	defer accessMu.Unlock()
	lanDisAllowedIPs = slices.Clone(prefixes)
}

func AllowedIPs() []netip.Prefix {
	accessMu.RLock()
	defer accessMu.RUnlock()
	return slices.Clone(lanAllowedIPs)
}

func DisAllowedIPs() []netip.Prefix {
	accessMu.RLock()
	defer accessMu.RUnlock()
	return slices.Clone(lanDisAllowedIPs)
}

func IsRemoteAddrDisAllowed(addr net.Addr) bool {
	m := C.Metadata{}
	if err := m.SetRemoteAddr(addr); err != nil {
		return false
	}
	ipAddr := m.AddrPort().Addr()
	if ipAddr.IsValid() {
		accessMu.RLock()
		defer accessMu.RUnlock()
		return prefixesContains(lanAllowedIPs, ipAddr) && !prefixesContains(lanDisAllowedIPs, ipAddr)
	}
	return false
}
