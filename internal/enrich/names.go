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

// Rank orders sources by how much the name tells you about intent.
func (s Source) Rank() int {
	switch s {
	case SrcSNI:
		return 4
	case SrcDNS:
		return 3
	case SrcHTTP:
		return 2
	case SrcRDNS:
		return 1
	}
	return 0
}

type entry struct {
	name string
	src  Source
	at   time.Time
}

// Names is an address-to-hostname cache fed by three sources.
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
}

func NewNames(reverseDNS bool) *Names {
	return &Names{
		m:           make(map[netip.Addr]entry, 512),
		pending:     make(map[netip.Addr]bool, 64),
		queue:       make(chan netip.Addr, 256),
		ReverseDNS:  reverseDNS,
		NegativeTTL: 10 * time.Minute,
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
					// Store even the empty result: that is what stops us
					// asking again every second.
					if cur, ok := n.m[ip]; !ok || cur.src.Rank() <= SrcRDNS.Rank() {
						n.m[ip] = entry{name: name, src: SrcRDNS, at: time.Now()}
					}
					n.mu.Unlock()
				}
			}
		}()
	}
}

// Learn records a name from a sniffed DNS response or a TLS handshake.
func (n *Names) Learn(ip netip.Addr, name string, src Source) {
	if !ip.IsValid() || name == "" {
		return
	}
	name = strings.TrimSuffix(name, ".")
	n.mu.Lock()
	defer n.mu.Unlock()
	if cur, ok := n.m[ip]; ok && cur.src.Rank() > src.Rank() && cur.name != "" {
		return
	}
	n.m[ip] = entry{name: name, src: src, at: time.Now()}
}

// Lookup returns the best known name for an address, queueing a reverse lookup
// if we have nothing and the entry is not already in flight or recently failed.
func (n *Names) Lookup(ip netip.Addr) (string, Source) {
	n.mu.RLock()
	e, ok := n.m[ip]
	pending := n.pending[ip]
	n.mu.RUnlock()

	if ok && e.name != "" {
		return e.name, e.src
	}
	stale := ok && time.Since(e.at) > n.NegativeTTL
	if (!ok || stale) && !pending && n.ReverseDNS && isResolvable(ip) {
		n.mu.Lock()
		n.pending[ip] = true
		n.mu.Unlock()
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
	return "", ""
}

// isResolvable skips addresses no public resolver can answer for.
func isResolvable(ip netip.Addr) bool {
	return !(ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate())
}
