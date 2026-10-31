package proxydialer

import (
	"fmt"
	C "github.com/metacubex/mihomo/constant"
)

// LookupProxy uses a synchronized lookup when the tunnel supports live reload.
// API tunnels exposing an immutable proxy map can use the existing interface.
func LookupProxy(tunnel C.Tunnel, name string) (C.Proxy, error) {
	var proxy C.Proxy
	if lookup, ok := tunnel.(interface{ ProxyByName(string) C.Proxy }); ok {
		proxy = lookup.ProxyByName(name)
	} else if lookup, ok := tunnel.(Tunnel); ok {
		proxy = lookup.Proxies()[name]
	} else {
		return nil, fmt.Errorf("tunnel %T does not expose proxies", tunnel)
	}
	if proxy == nil {
		return nil, fmt.Errorf("proxy %q not found", name)
	}
	return proxy, nil
}

func UnwrapAdapter(adapter C.ProxyAdapter) C.ProxyAdapter {
	for {
		wrapper, ok := adapter.(interface{ UnwrapProxyAdapter() C.ProxyAdapter })
		if !ok {
			return adapter
		}
		adapter = wrapper.UnwrapProxyAdapter()
	}
}
