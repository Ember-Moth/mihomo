package config_test

import (
	"testing"

	Cfg "github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/hub/executor" // supplies config's temporary general-settings hook
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/require"
)

func TestVlessReverseConfig(t *testing.T) {
	config, err := Cfg.Parse([]byte(`
mode: rule
proxies:
  - name: reverse-config-home
    type: vless-reverse
  - name: reverse-config-link
    type: vless
    server: 127.0.0.1
    port: 9
    uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68
listeners:
  - name: reverse-config-public
    type: vless
    port: 0
    allow-insecure: true
    users:
      - uuid: 9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68
        reverse:
          tag: reverse-config-home
  - name: reverse-config-in
    type: vless-reverse
    outbound: reverse-config-link
    connections: 2
    rule: reverse-config-access
sub-rules:
  reverse-config-access:
    - MATCH,DIRECT
rules:
  - IP-CIDR,192.168.50.0/24,reverse-config-home,no-resolve
  - MATCH,DIRECT
`))
	require.NoError(t, err)
	defer config.Proxies["reverse-config-home"].Close()
	defer config.Proxies["reverse-config-link"].Close()
	require.Equal(t, C.VlessReverse, config.Proxies["reverse-config-home"].Type())
	public := config.Listeners["reverse-config-public"].Config().(*inbound.VlessOption)
	require.Equal(t, "reverse-config-home", public.Users[0].Reverse.Tag)
	bridge := config.Listeners["reverse-config-in"].Config().(*inbound.VlessReverseOption)
	require.Equal(t, "reverse-config-link", bridge.Outbound)
	require.Equal(t, 2, bridge.Connections)
	require.Equal(t, "reverse-config-access", bridge.SpecialRules)
}

func TestVlessReverseInvalidConfig(t *testing.T) {
	for _, test := range []struct{ name, configuration string }{
		{"missing outbound", "listeners: [{name: home, type: vless-reverse}]"},
		{"invalid connections", "listeners: [{name: home, type: vless-reverse, outbound: hub, connections: 9}]"},
		{"empty reverse tag", "listeners: [{name: public, type: vless, users: [{uuid: example, reverse: {}}]}]"},
		{"duplicate UUID", "listeners: [{name: public, type: vless, users: [{uuid: example, reverse: {tag: home}}, {uuid: example}]}]"},
	} {
		t.Run(test.name, func(t *testing.T) { _, err := Cfg.Parse([]byte(test.configuration)); require.Error(t, err) })
	}
}
