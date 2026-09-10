package enrich

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ASN lookup via Team Cymru's DNS service.
//
// Chosen over a downloadable database for one reason: it needs no account, no
// file and no licence click-through, so the tool works fully the moment it is
// built. The published allocation lists in ranges.go still come first and
// answer offline; this fills the long tail of everything that is not
// Cloudflare, AWS, Google, Fastly or GitHub.
//
// The trade is that each lookup is a DNS query, which tells Team Cymru's
// resolvers what you are interested in. Answers are cached for the session and
// it only ever asks once per address.
type ASNInfo struct {
	Number  uint32
	Org     string
	Country string
}

type ASN struct {
	mu      sync.RWMutex
	m       map[netip.Addr]ASNInfo
	orgs    map[uint32]string
	pending map[netip.Addr]bool
	queue   chan netip.Addr

	Enabled bool
}

func NewASN(enabled bool) *ASN {
	return &ASN{
		m:       make(map[netip.Addr]ASNInfo, 512),
		orgs:    make(map[uint32]string, 128),
		pending: make(map[netip.Addr]bool, 64),
		queue:   make(chan netip.Addr, 256),
		Enabled: enabled,
	}
}

func (a *ASN) Run(ctx context.Context, workers int) {
	if !a.Enabled {
		return
	}
	for i := 0; i < workers; i++ {
		go func() {
			var r net.Resolver
			for {
				select {
				case <-ctx.Done():
					return
				case ip := <-a.queue:
					info := a.resolve(ctx, &r, ip)
					a.mu.Lock()
					a.m[ip] = info
					delete(a.pending, ip)
					a.mu.Unlock()
				}
			}
		}()
	}
}

// Lookup returns what is known, queueing a resolve on first sight.
func (a *ASN) Lookup(ip netip.Addr) (ASNInfo, bool) {
	if !ip.IsValid() {
		return ASNInfo{}, false
	}
	a.mu.RLock()
	info, ok := a.m[ip]
	pending := a.pending[ip]
	a.mu.RUnlock()
	if ok {
		return info, info.Number != 0
	}
	if !a.Enabled || pending || !routable(ip) {
		return ASNInfo{}, false
	}
	a.mu.Lock()
	a.pending[ip] = true
	a.mu.Unlock()
	select {
	case a.queue <- ip:
	default:
		a.mu.Lock()
		delete(a.pending, ip)
		a.mu.Unlock()
	}
	return ASNInfo{}, false
}

func routable(ip netip.Addr) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified())
}

func (a *ASN) resolve(ctx context.Context, r *net.Resolver, ip netip.Addr) ASNInfo {
	name := cymruQuery(ip)
	if name == "" {
		return ASNInfo{}
	}
	lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	txt, err := r.LookupTXT(lctx, name)
	if err != nil || len(txt) == 0 {
		return ASNInfo{}
	}
	// "13335 | 104.16.0.0/12 | US | arin | 2010-07-14"
	parts := splitPipe(txt[0])
	if len(parts) < 3 {
		return ASNInfo{}
	}
	// The first field can list several ASNs for anycast space; take the first.
	num, err := strconv.ParseUint(strings.Fields(parts[0])[0], 10, 32)
	if err != nil {
		return ASNInfo{}
	}
	info := ASNInfo{Number: uint32(num), Country: parts[2]}
	info.Org = a.orgName(ctx, r, uint32(num))
	return info
}

// orgName resolves AS number to operator name, cached: many addresses share one.
func (a *ASN) orgName(ctx context.Context, r *net.Resolver, num uint32) string {
	a.mu.RLock()
	cached, ok := a.orgs[num]
	a.mu.RUnlock()
	if ok {
		return cached
	}
	lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	txt, err := r.LookupTXT(lctx, fmt.Sprintf("AS%d.asn.cymru.com", num))
	name := ""
	if err == nil && len(txt) > 0 {
		// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
		if parts := splitPipe(txt[0]); len(parts) >= 5 {
			name = parts[4]
		}
	}
	a.mu.Lock()
	a.orgs[num] = name
	a.mu.Unlock()
	return name
}

func splitPipe(s string) []string {
	raw := strings.Split(s, "|")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// cymruQuery builds the query name: reversed octets for v4, reversed nibbles
// for v6, the same shape as a PTR lookup.
func cymruQuery(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", b[3], b[2], b[1], b[0])
	}
	if !ip.Is6() {
		return ""
	}
	b := ip.As16()
	var sb strings.Builder
	const hex = "0123456789abcdef"
	for i := len(b) - 1; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("origin6.asn.cymru.com")
	return sb.String()
}
