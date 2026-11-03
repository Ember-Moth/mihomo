package inbound

import (
	"net/netip"
	"slices"
	"sync"
)

// accessMu guards all three lists. A policy owns its slices, and exported getters
// return copies so a caller cannot modify the policy after releasing the lock.
var accessMu sync.RWMutex

// SetAccessRules publishes a configuration's allow, deny and authentication bypass
// lists together. The allow/deny check must not combine different configurations.
func SetAccessRules(skipAuth, allowed, denied []netip.Prefix) {
	skipAuth, allowed, denied = slices.Clone(skipAuth), slices.Clone(allowed), slices.Clone(denied)
	accessMu.Lock()
	skipAuthPrefixes, lanAllowedIPs, lanDisAllowedIPs = skipAuth, allowed, denied
	accessMu.Unlock()
}

// PatchAccessRules updates only the supplied lists, under the same lock as a full apply.
func PatchAccessRules(skipAuth, allowed, denied *[]netip.Prefix) {
	accessMu.Lock()
	defer accessMu.Unlock()
	if skipAuth != nil {
		skipAuthPrefixes = slices.Clone(*skipAuth)
	}
	if allowed != nil {
		lanAllowedIPs = slices.Clone(*allowed)
	}
	if denied != nil {
		lanDisAllowedIPs = slices.Clone(*denied)
	}
}
