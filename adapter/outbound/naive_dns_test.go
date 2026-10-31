//go:build with_naive

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"

	"github.com/miekg/dns"
)

type naiveTestResolver struct {
	resolver.Resolver
	exchange func(context.Context, *dns.Msg) (*dns.Msg, error)
}

func (r naiveTestResolver) Invalid() bool { return true }
func (r naiveTestResolver) ExchangeContext(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, query)
}

func TestNaiveDNS(t *testing.T) {
	oldProxy, oldSystem, oldDefault := resolver.ProxyServerHostResolver, resolver.SystemResolver, resolver.DefaultResolver
	oldHosts, oldIPv6 := resolver.DefaultHosts, resolver.DisableIPv6
	t.Cleanup(func() {
		resolver.ProxyServerHostResolver, resolver.SystemResolver, resolver.DefaultResolver = oldProxy, oldSystem, oldDefault
		resolver.DefaultHosts, resolver.DisableIPv6 = oldHosts, oldIPv6
	})
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	resolver.DisableIPv6 = false
	var queries []string
	var cached *dns.Msg
	resolver.ProxyServerHostResolver = naiveTestResolver{exchange: func(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
		queries = append(queries, query.Question[0].Name)
		if _, ok := ctx.Deadline(); !ok {
			t.Error("DNS query has no deadline")
		}
		cached = new(dns.Msg).SetReply(query)
		cached.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(127, 0, 0, 1)}}
		return cached, nil
	}}
	resolver.DefaultResolver = naiveTestResolver{exchange: func(context.Context, *dns.Msg) (*dns.Msg, error) {
		t.Error("used application DNS instead of proxy DNS")
		return nil, errors.New("wrong resolver")
	}}
	lookup := naiveDNSResolver(C.DualStack)
	query := new(dns.Msg).SetQuestion("proxy.example.org.", dns.TypeA)
	answer := lookup(context.Background(), query)
	if len(queries) != 1 || len(answer.Answer) != 1 || answer.Rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected DNS result: %v", answer)
	}
	answer.Answer[0].Header().Ttl = 999
	if cached.Answer[0].Header().Ttl == 999 {
		t.Fatal("mutated shared DNS cache response")
	}
	host, _ := resolver.NewHostValueByIPs([]netip.Addr{netip.MustParseAddr("127.0.0.2")})
	_ = resolver.DefaultHosts.Insert("override.example.org", host)
	answer = lookup(context.Background(), new(dns.Msg).SetQuestion("override.example.org.", dns.TypeA))
	if len(queries) != 1 || answer.Answer[0].(*dns.A).A.String() != "127.0.0.2" {
		t.Fatal("did not apply hosts override")
	}
	alias, _ := resolver.NewHostValueByDomain("proxy.example.org")
	_ = resolver.DefaultHosts.Insert("alias.example.org", alias)
	answer = lookup(context.Background(), new(dns.Msg).SetQuestion("alias.example.org.", dns.TypeA))
	if queries[len(queries)-1] != "proxy.example.org." || answer.Question[0].Name != "alias.example.org." || answer.Answer[0].(*dns.CNAME).Target != "proxy.example.org." {
		t.Fatalf("invalid alias response: %v", answer)
	}
	for _, test := range []struct {
		prefer C.DNSPrefer
		qtype  uint16
	}{{C.IPv4Only, dns.TypeAAAA}, {C.IPv6Only, dns.TypeA}} {
		answer = naiveDNSResolver(test.prefer)(context.Background(), new(dns.Msg).SetQuestion("proxy.example.org.", test.qtype))
		if len(answer.Answer) != 0 || answer.Rcode != dns.RcodeSuccess {
			t.Fatal("address family policy was not applied")
		}
	}
	resolver.ProxyServerHostResolver = nil
	resolver.SystemResolver = naiveTestResolver{exchange: func(context.Context, *dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("offline")
	}}
	if answer = lookup(context.Background(), query); answer.Rcode != dns.RcodeServerFailure {
		t.Fatal("DNS errors must produce SERVFAIL")
	}
	resolver.SystemResolver = nil
	if answer = lookup(context.Background(), query); answer.Rcode != dns.RcodeServerFailure {
		t.Fatal("missing resolver must produce SERVFAIL")
	}
}
