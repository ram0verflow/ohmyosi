// Package enrich turns numbers into things a human recognizes: an address into
// a hostname, a PID into an application with an icon.
//
// This is the difference between a toy and a tool. A graph of 104.18.32.7 and
// 142.250.183.14 teaches nobody anything; the same graph reading notion.so and
// google.com is immediately legible.
package enrich

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Source records how we learned a name, so the UI can show confidence and so
// better sources can overwrite worse ones.
type Source string

const (
	SrcSNI  Source = "sni"  // read off the TLS handshake: exactly what the client asked for
	SrcDNS  Source = "dns"  // sniffed from a DNS response: what the app looked up
	SrcHTTP Source = "http" // cleartext HTTP Host header
	SrcRDNS Source = "rdns" // PTR record: often a hosting provider, not the site
)

type entry struct {
	dns    map[string]time.Time // name -> TTL expiry
	rdns   string
	rdnsAt time.Time // also records a negative PTR result
}

// NameResult preserves ambiguity instead of forcing several DNS candidates
// into one confident address-wide label.
type NameResult struct {
	Name       string
	Source     Source
	Candidates []string
	Ambiguous  bool
}

// Names is an address-to-hostname cache fed only by address-level evidence:
// sniffed DNS responses and optional PTR lookups. Flow-specific evidence such
// as TLS SNI and HTTP Host must stay on its originating 5-tuple; putting it in
// this cache lets one tenant on a shared CDN address mislabel another flow.
type Names struct {
	mu      sync.RWMutex
	m       map[netip.Addr]entry
	pending map[netip.Addr]bool

	queue chan netip.Addr
	// ReverseDNS controls the PTR fallback. It is the only part of ohmyosi
	// that sends packets, so it is worth being able to turn off: on a machine
	// you are auditing, a monitor that phones out is a monitor you have to
	// reason about.
	ReverseDNS bool
	// NegativeTTL is how long a failed lookup is remembered. Without it, every
	// tick re-queues every unresolvable address, which on a busy machine is a
	// steady drip of pointless DNS traffic.
	NegativeTTL time.Duration
	now         func() time.Time
}

func NewNames(reverseDNS bool) *Names {
	return &Names{
		m:           make(map[netip.Addr]entry, 512),
		pending:     make(map[netip.Addr]bool, 64),
		queue:       make(chan netip.Addr, 256),
		ReverseDNS:  reverseDNS,
		NegativeTTL: 10 * time.Minute,
		now:         time.Now,
	}
}

// Run starts the reverse-DNS workers. Lookups never happen on the packet path;
// a blocking resolver call there would drop traffic.
func (n *Names) Run(ctx context.Context, workers int) {
	if !n.ReverseDNS {
		return
	}
	for i := 0; i < workers; i++ {
		go func() {
			var r net.Resolver
			for {
				select {
				case <-ctx.Done():
					return
				case ip := <-n.queue:
					lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
					names, err := r.LookupAddr(lctx, ip.String())
					cancel()
					name := ""
					if err == nil && len(names) > 0 {
						name = strings.TrimSuffix(names[0], ".")
					}
					n.mu.Lock()
					delete(n.pending, ip)
					// Store even the empty result: rdnsAt is what stops us
					// asking again every second. DNS still wins at lookup.
					e := n.m[ip]
					e.rdns, e.rdnsAt = name, n.now()
					n.m[ip] = e
					n.mu.Unlock()
				}
			}
		}()
	}
}

// LearnDNS records a name from a sniffed DNS response. This deliberately does
// not accept a Source: callers cannot accidentally put flow-scoped SNI or HTTP
// evidence into the address-wide cache.
func (n *Names) LearnDNS(ip netip.Addr, name string, ttl time.Duration) {
	if !ip.IsValid() || name == "" {
		return
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	now := n.now()
	n.mu.Lock()
	defer n.mu.Unlock()
	e := n.m[ip]
	if e.dns == nil {
		e.dns = make(map[string]time.Time)
	}
	for candidate, expires := range e.dns {
		if !now.Before(expires) {
			delete(e.dns, candidate)
		}
	}
	if ttl <= 0 {
		delete(e.dns, name)
	} else {
		e.dns[name] = now.Add(ttl)
	}
	n.m[ip] = e
}

// Lookup returns the best known name for an address, queueing a reverse lookup
// if we have nothing and the entry is not already in flight or recently failed.
func (n *Names) Lookup(ip netip.Addr) (string, Source) {
	r := n.LookupResult(ip)
	return r.Name, r.Source
}

// LookupResult returns one DNS name only when exactly one unexpired candidate
// exists. Multiple candidates are evidence, but not enough evidence to choose
// a tenant on a shared address, so they are returned as an explicit ambiguity.
func (n *Names) LookupResult(ip netip.Addr) NameResult {
	now := n.now()
	n.mu.RLock()
	e, ok := n.m[ip]
	pending := n.pending[ip]
	var candidates []string
	for name, expires := range e.dns {
		if now.Before(expires) {
			candidates = append(candidates, name)
		}
	}
	n.mu.RUnlock()
	sort.Strings(candidates)
	switch len(candidates) {
	case 1:
		return NameResult{Name: candidates[0], Source: SrcDNS, Candidates: candidates}
	case 0:
		if e.rdns != "" {
			return NameResult{Name: e.rdns, Source: SrcRDNS}
		}
	default:
		return NameResult{Source: SrcDNS, Candidates: candidates, Ambiguous: true}
	}

	negativeFresh := ok && !e.rdnsAt.IsZero() && now.Sub(e.rdnsAt) <= n.NegativeTTL
	if !negativeFresh && !pending && n.ReverseDNS && isResolvable(ip) {
		queue := false
		n.mu.Lock()
		if !n.pending[ip] {
			n.pending[ip] = true
			queue = true
		}
		n.mu.Unlock()
		if queue {
			select {
			case n.queue <- ip:
			default:
				// Queue full: drop it. It will be retried on a later tick, and a
				// backlog of PTR lookups is never worth the memory.
				n.mu.Lock()
				delete(n.pending, ip)
				n.mu.Unlock()
			}
		}
	}
	return NameResult{}
}

// isResolvable skips addresses no public resolver can answer for.
func isResolvable(ip netip.Addr) bool {
	return !(ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate())
}
