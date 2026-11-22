// Package audit closes the loop between the reader and the enforcer.
//
// A DNS-layer block (/etc/hosts, Pi-hole, NextDNS) works by refusing to
// resolve a name. Its blind spot is everything that never asks the system
// resolver: an app with its own DoH client, a cached answer, a hardcoded
// address. Those connections succeed, and the blocker - which only ever sees
// lookups - has no way to know. It reports success while being bypassed.
//
// ohmyosi reads the name each connection announces in its own handshake. So a
// blocked name that appears in a ClientHello which then got a reply is direct
// evidence the block was evaded, attributed to the process that did it, with
// the address it actually reached. That address is a verified name->address
// fact, read rather than resolved, and is exactly what the next layer (a pf
// table) needs to stop the second attempt in the kernel. Every evasion donates
// the address that defeats the next one.
//
// The reader also audits the enforcer itself: if the managed /etc/hosts region
// or the pf anchor disappears while enforcement is meant to be on, something
// turned it off, and that is reported rather than silently re-applied.
//
// Everything here is a pure function of its inputs, so it is tested without
// root and without a network.
package audit

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"ohmyosi/internal/naming"
)

// Evasion is one blocked name seen in a handshake that the far end answered.
type Evasion struct {
	FlowID string `json:"flow_id"`
	Comm   string `json:"comm"`
	PID    int32  `json:"pid"`
	Name   string `json:"name"` // what the client asked for, read off the handshake
	Rule   string `json:"rule"` // the blocked domain it falls under
	Addr   string `json:"addr"` // the address it actually reached
	// Route explains how the name escaped the DNS layer, from the naming
	// verdict: no lookup witnessed at all, or a lookup that resolved anyway.
	Route string `json:"route"`
	// Shared is how many distinct names resolve to Addr. Above 1, blocking the
	// address in pf will also block unrelated sites on the same CDN edge -
	// stated so the collateral is visible before anyone applies it.
	Shared int `json:"shared,omitempty"`
}

// BlockedBy returns the blocked domain that covers name (the domain itself or
// a subdomain of it), or "" when none does.
func BlockedBy(name string, blocked []string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return ""
	}
	best := ""
	for _, d := range blocked {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" {
			continue
		}
		if name == d || strings.HasSuffix(name, "."+d) {
			if len(d) > len(best) {
				best = d
			}
		}
	}
	return best
}

// Check decides whether one flow is an evasion. answered means the far end
// sent anything back after the handshake: a block that worked produces no
// reply at all, because no connection to a real server was ever made.
func Check(flowID, comm string, pid int32, addr netip.Addr, answered bool,
	v naming.Verdict, blocked []string) (Evasion, bool) {
	if v.Handshake == "" || !answered || !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() {
		return Evasion{}, false
	}
	rule := BlockedBy(v.Handshake, blocked)
	if rule == "" {
		return Evasion{}, false
	}
	e := Evasion{
		FlowID: flowID, Comm: comm, PID: pid, Name: v.Handshake, Rule: rule,
		Addr: addr.String(), Shared: v.FanIn,
	}
	switch v.Class {
	case naming.HandshakeOnly:
		e.Route = "no system DNS lookup was seen for this address: its own resolver (DoH), a cached answer, or a hardcoded address"
	default:
		e.Route = fmt.Sprintf("a DNS answer pointed here (%s) despite the block - resolved outside the system resolver's hosts file", orNone(v.DNSPick))
	}
	return e, true
}

func orNone(s string) string {
	if s == "" {
		return "no name"
	}
	return s
}

// Loop accumulates evasions over a session and turns them into the verified
// addresses the packet filter should drop. It is the memory of the feedback
// loop: an evasion is reported once per flow, and its address stays learned.
type Loop struct {
	mu       sync.Mutex
	seen     map[string]bool         // flow IDs already reported
	verified map[netip.Addr]*Evasion // address -> first evasion that proved it
	byRule   map[string]map[string]bool
	total    int
}

func NewLoop() *Loop {
	return &Loop{seen: map[string]bool{}, verified: map[netip.Addr]*Evasion{}, byRule: map[string]map[string]bool{}}
}

// Observe records an evasion. It returns true the first time a flow is seen,
// so the caller can raise one alert per flow rather than one per tick.
func (l *Loop) Observe(e Evasion) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen[e.FlowID] {
		return false
	}
	l.seen[e.FlowID] = true
	l.total++
	if a, err := netip.ParseAddr(e.Addr); err == nil {
		if _, ok := l.verified[a]; !ok {
			cp := e
			l.verified[a] = &cp
		}
	}
	if l.byRule[e.Rule] == nil {
		l.byRule[e.Rule] = map[string]bool{}
	}
	l.byRule[e.Rule][e.Comm] = true
	return true
}

// Total is the number of evading flows seen this session.
func (l *Loop) Total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// Verified returns the addresses proven to serve a blocked name, sorted, for
// the pf table. Shared addresses are included only when allowShared is set,
// because blocking a CDN edge blocks every site behind it.
func (l *Loop) Verified(allowShared bool) []netip.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]netip.Addr, 0, len(l.verified))
	for a, e := range l.verified {
		if e.Shared > 1 && !allowShared {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// RenderTable is the pf syntax for the verified-address table. Loading it into
// ohmyosi's own anchor keeps it clear of anything else using pf; `block return`
// sends a reset so the evading app fails fast instead of hanging on a timeout.
// Addresses can be added at runtime without a reload:
//
//	pfctl -a ohmyosi -t ohmyosi_verified -T add <addr>
func RenderTable(addrs []netip.Addr) string {
	if len(addrs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("table <ohmyosi_verified> persist {")
	for i, a := range addrs {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(" " + a.String())
	}
	b.WriteString(" }\nblock return out quick to <ohmyosi_verified>\n")
	return b.String()
}

// Problem is something wrong with enforcement that the enforcer itself would
// not report.
type Problem struct {
	Layer  string `json:"layer"` // hosts | pf
	Detail string `json:"detail"`
}

// AuditHosts checks that every domain meant to be blocked is still mapped to a
// sink in the hosts file. It reads the file as the resolver would, so an entry
// commented out, deleted, or pointed elsewhere all count as missing.
func AuditHosts(content string, want []string) []Problem {
	sunk := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if f[0] != "0.0.0.0" && f[0] != "127.0.0.1" && f[0] != "::" && f[0] != "::1" {
			continue
		}
		for _, h := range f[1:] {
			sunk[strings.ToLower(h)] = true
		}
	}
	var missing []string
	for _, d := range want {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !sunk[d] {
			missing = append(missing, d)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	show := missing
	if len(show) > 5 {
		show = show[:5]
	}
	return []Problem{{Layer: "hosts", Detail: fmt.Sprintf(
		"%d blocked domain(s) no longer sunk in /etc/hosts (e.g. %s) - the file was edited or replaced while enforcement was on",
		len(missing), strings.Join(show, ", "))}}
}

// AuditPF checks pf's state against what enforcement expects. info is the
// output of `pfctl -s info`, anchorRules of `pfctl -a <anchor> -s rules`, and
// expectRules whether the anchor should currently hold any.
func AuditPF(info, anchorRules string, expectRules bool) []Problem {
	var out []Problem
	if !strings.Contains(info, "Status: Enabled") {
		out = append(out, Problem{Layer: "pf", Detail: "pf is disabled (pfctl -d) - every kernel-level block is off"})
	}
	if expectRules && strings.TrimSpace(anchorRules) == "" {
		out = append(out, Problem{Layer: "pf", Detail: "the ohmyosi anchor is empty - its rules were flushed by something other than ohmyosi"})
	}
	return out
}
