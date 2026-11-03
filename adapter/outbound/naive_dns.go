//go:build with_naive

package outbound

import (
	"context"
	"net"
	"strings"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/miekg/dns"
)

func naiveDNSResolver(prefer C.DNSPrefer) func(context.Context, *dns.Msg) *dns.Msg {
	return func(ctx context.Context, request *dns.Msg) *dns.Msg {
		response := new(dns.Msg).SetReply(request)
		if len(request.Question) != 1 {
			response.Rcode = dns.RcodeFormatError
			return response
		}
		question := request.Question[0]
		if question.Qclass != dns.ClassINET {
			response.Rcode = dns.RcodeNotImplemented
			return response
		}
		if question.Qtype == dns.TypeAAAA && (resolver.DisableIPv6.Load() || prefer == C.IPv4Only) || question.Qtype == dns.TypeA && prefer == C.IPv6Only {
			return response
		}
		domain := strings.TrimSuffix(question.Name, ".")
		query := request.Copy()
		var alias string
		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			if host, ok := resolver.DefaultHosts.Load().Search(domain, false); ok {
				for _, address := range host.IPs {
					address = address.Unmap()
					header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}
					if question.Qtype == dns.TypeA && address.Is4() {
						response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.IP(address.AsSlice())})
					} else if question.Qtype == dns.TypeAAAA && address.Is6() {
						response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.IP(address.AsSlice())})
					}
				}
				return response
			}
			if host, ok := resolver.DefaultHosts.Load().Search(domain, true); ok {
				alias = dns.Fqdn(host.Domain)
				query.Question[0].Name = alias
			}
		}
		// Resolve proxy hosts through the proxy resolver, never the DNS service
		// that returns Fake-IP addresses to applications. Read it at query time
		// because config loading constructs outbounds before replacing DNS state.
		r := resolver.ProxyServerHostResolver.Load()
		if r == nil || !r.Invalid() {
			r = resolver.SystemResolver.Load()
		}
		if r == nil {
			response.Rcode = dns.RcodeServerFailure
			return response
		}
		ctx, cancel := context.WithTimeout(ctx, resolver.DefaultDNSTimeout)
		defer cancel()
		answer, err := r.ExchangeContext(ctx, query)
		if err != nil || answer == nil {
			log.Debugln("[Naive] DNS lookup for %s failed: %v", question.Name, err)
			response.Rcode = dns.RcodeServerFailure
			return response
		}
		answer = answer.Copy() // resolver responses may be shared with its cache
		answer.Id = request.Id
		answer.Question = append([]dns.Question(nil), request.Question...)
		if alias != "" && answer.Rcode == dns.RcodeSuccess {
			answer.Answer = append([]dns.RR{&dns.CNAME{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: alias,
			}}, answer.Answer...)
		}
		return answer
	}
}
