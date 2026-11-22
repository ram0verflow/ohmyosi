// Package naming measures the gap between reading a destination's name and
// inferring it.
//
// Every host-based monitor in this category names a connection partly or
// wholly by correlation: it watched, or was, the DNS resolver, so when a socket
// connects to 104.18.32.7 it looks up which name resolved to that address and
// prints it. The tools differ in which answers they consult - OpenSnitch and
// Little Snitch for Linux take the latest answer from anyone; Little Snitch's
// "DNS sniffing" and Portmaster track which process knows what - and that
// difference is modelled here as separate strategies, not lumped together.
//
// Correlation fails silently in identifiable ways:
//
//   - co-hosting: one CDN address answers for many names, so "the latest name
//     for this address" can be an unrelated lookup;
//   - bypass: an app with its own DoH client, a cached answer, or a hardcoded
//     address produces no DNS answer to correlate with at all;
//   - cross-process borrowing: the answer that made correlation possible was
//     looked up by a different application;
//   - staleness: the answer had expired by its own TTL when the flow opened;
//   - reuse: the address now serves something it was not answered for.
//
// ohmyosi reads the name the client actually asked for out of the TLS
// ClientHello or QUIC Initial of the very same flow, so for every connection
// the error of each correlation strategy is a number. The reference is the
// handshake name - what a monitor can see - and three cases where that is not
// the destination are flagged rather than trusted: Encrypted Client Hello
// (the SNI is a public outer name), an IP literal in place of a name, and
// HTTP/2-3 connections that may be coalesced across several names.
//
// Nothing here makes network requests. It is a pure function of the wire.
package naming

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"ohmyosi/internal/enrich"
)

// Class grades one flow by how its read name compares with its inferred one.
type Class string

const (
	// Agree: the handshake name equals the correlated name.
	Agree Class = "agree"
	// Alias: the handshake name was among the DNS answers for this address but
	// not the one correlation picked - right building, wrong apartment.
	Alias Class = "alias"
	// SameSite: names differ but share a registrable domain.
	SameSite Class = "same-site"
	// Mismatch: names differ at the registrable domain - the wrong organisation.
	Mismatch Class = "mismatch"
	// HandshakeOnly: a name was announced, but no DNS answer for this address
	// was witnessed. A correlating monitor shows a bare address.
	HandshakeOnly Class = "handshake-only"
	// ECHOuter: the handshake used Encrypted Client Hello, so its SNI is a
	// public front name, not the site. Not comparable either way.
	ECHOuter Class = "ech-outer"
	// DNSOnly: no handshake name; correlation is the only evidence for anyone.
	DNSOnly Class = "dns-only"
	// Unseen: the flow predates capture and no DNS answer is known.
	Unseen Class = "unseen"
	// Neither: watched opening, announced no name, no DNS covers the address.
	Neither Class = "neither"
)

// Classes lists every class in report order.
var Classes = []Class{Agree, Alias, SameSite, Mismatch, HandshakeOnly, ECHOuter, DNSOnly, Unseen, Neither}

// Wrong: correlation showed a name other than the one asked for.
func (c Class) Wrong() bool { return c == Alias || c == SameSite || c == Mismatch }

// Comparable: both a trustworthy handshake name and a correlated name exist.
func (c Class) Comparable() bool { return c == Agree || c.Wrong() }

// Cause explains why correlation was wrong or blank for one flow. Exactly one
// cause is assigned, in a fixed priority order, so causes sum to the total.
type Cause string

const (
	CauseNone         Cause = ""
	CauseBypass       Cause = "bypass"        // no lookup witnessed for the address
	CauseCoalesced    Cause = "coalesced"     // h2/h3 connection; the app also resolved other names here
	CauseStale        Cause = "stale"         // correlated answer had expired by its TTL
	CauseCrossProcess Cause = "cross-process" // correlated answer was another app's lookup
	CauseCoHosted     Cause = "co-hosted"     // several names resolved to this address
	// CauseOtherName: the only name ever resolved to this address was a
	// different one. Co-hosting or address reuse - indistinguishable from here.
	CauseOtherName Cause = "other-name"
)

// Causes lists every non-empty cause in priority order.
var Causes = []Cause{CauseBypass, CauseCoalesced, CauseStale, CauseCrossProcess, CauseCoHosted, CauseOtherName}

type answer struct {
	name  string
	at    time.Time
	ttl   uint32
	asker int32
	comm  string
}

type sighting struct {
	name string
	at   time.Time
	pid  int32
}

// maxPerAddr bounds memory: a big CDN address can collect thousands of
// answers, and only the recent ones matter.
const maxPerAddr = 64

// DefaultSlack absorbs ordering noise between a DNS response and the SYN after
// it. Kept small: anything wider lets correlation "see" lookups made after the
// connection opened, which no real monitor could do. Results should be shown
// at 0 and 500 ms too; see Ledger.Slack.
const DefaultSlack = 100 * time.Millisecond

// Ledger holds timestamped naming evidence per address.
type Ledger struct {
	mu    sync.RWMutex
	dns   map[netip.Addr][]answer
	hs    map[netip.Addr][]sighting
	Slack time.Duration
}

func NewLedger() *Ledger {
	return &Ledger{dns: map[netip.Addr][]answer{}, hs: map[netip.Addr][]sighting{}, Slack: DefaultSlack}
}

// DNS records that name resolved to ip at time at with the given TTL, looked
// up on behalf of asker (the effective PID when pktap supplies one).
func (l *Ledger) DNS(ip netip.Addr, name string, at time.Time, ttl uint32, asker int32, comm string) {
	name = norm(name)
	if !ip.IsValid() || name == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := append(l.dns[ip], answer{name: name, at: at, ttl: ttl, asker: asker, comm: comm})
	if len(s) > maxPerAddr {
		s = s[len(s)-maxPerAddr:]
	}
	l.dns[ip] = s
}

// Answer is one DNS answer, for loading evidence from an earlier capture.
type Answer struct {
	IP    netip.Addr
	Name  string
	At    time.Time
	TTL   uint32
	Asker int32
	Comm  string
}

// Preload puts answers from an earlier capture in front of what the ledger
// already holds - as a monitor that kept running across both captures would
// have them. Every preloaded answer must predate the ledger's own; the cap
// per address still keeps only the newest.
func (l *Ledger) Preload(prior []Answer) {
	byIP := map[netip.Addr][]answer{}
	for _, a := range prior {
		name := norm(a.Name)
		if !a.IP.IsValid() || name == "" {
			continue
		}
		byIP[a.IP] = append(byIP[a.IP], answer{name: name, at: a.At, ttl: a.TTL, asker: a.Asker, comm: a.Comm})
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, s := range byIP {
		sort.SliceStable(s, func(i, j int) bool { return s[i].at.Before(s[j].at) })
		s = append(s, l.dns[ip]...)
		if len(s) > maxPerAddr {
			s = s[len(s)-maxPerAddr:]
		}
		l.dns[ip] = s
	}
}

// Handshake records that a client announced name while connecting to ip.
func (l *Ledger) Handshake(ip netip.Addr, name string, at time.Time, pid int32) {
	name = norm(name)
	if !ip.IsValid() || name == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := append(l.hs[ip], sighting{name: name, at: at, pid: pid})
	if len(s) > maxPerAddr {
		s = s[len(s)-maxPerAddr:]
	}
	l.hs[ip] = s
}

// Correlation is what a correlating monitor would conclude about a flow that
// opened at a given moment.
type Correlation struct {
	Pick       string
	PickAsker  int32
	PickComm   string
	PickAt     time.Time
	PickTTL    uint32
	Candidates []string // distinct names resolved to the address by then
}

// Stale reports whether the picked answer had expired by its own TTL at t.
func (c Correlation) Stale(t time.Time) bool {
	return c.Pick != "" && c.PickTTL > 0 && t.After(c.PickAt.Add(time.Duration(c.PickTTL)*time.Second))
}

// Correlate answers as a last-answer-wins monitor would at time at, using
// every process's lookups (OpenSnitch, Little Snitch for Linux).
func (l *Ledger) Correlate(ip netip.Addr, at time.Time) Correlation {
	return l.correlate(ip, at, 0)
}

// CorrelateFor answers as a per-process monitor would: only lookups made on
// behalf of pid count (Little Snitch's DNS sniffing, Portmaster's resolver).
// Candidates still lists every name, so fan-in is comparable across strategies.
func (l *Ledger) CorrelateFor(ip netip.Addr, at time.Time, pid int32) Correlation {
	if pid <= 0 {
		return Correlation{Candidates: l.correlate(ip, at, 0).Candidates}
	}
	return l.correlate(ip, at, pid)
}

func (l *Ledger) correlate(ip netip.Addr, at time.Time, pid int32) Correlation {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var c Correlation
	seen := map[string]bool{}
	var best *answer
	cut := at.Add(l.Slack)
	for i := range l.dns[ip] {
		a := &l.dns[ip][i]
		if a.at.After(cut) {
			continue
		}
		if !seen[a.name] {
			seen[a.name] = true
			c.Candidates = append(c.Candidates, a.name)
		}
		if pid > 0 && a.asker != pid {
			continue
		}
		if best == nil || !a.at.Before(best.at) {
			best = a
		}
	}
	if best != nil {
		c.Pick, c.PickAsker, c.PickComm, c.PickAt, c.PickTTL = best.name, best.asker, best.comm, best.at, best.ttl
	}
	sort.Strings(c.Candidates)
	return c
}

// ResolvedBy returns the distinct names pid had resolved to ip by time to,
// other than except. A long h2/h3 connection to an address the same app also
// resolved other names to may be carrying those names too (coalescing), which
// no observer can see without decrypting it.
func (l *Ledger) ResolvedBy(ip netip.Addr, pid int32, to time.Time, except string) []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, a := range l.dns[ip] {
		if a.at.After(to) || (pid > 0 && a.asker != pid) || a.name == except || seen[a.name] {
			continue
		}
		seen[a.name] = true
		out = append(out, a.name)
	}
	sort.Strings(out)
	return out
}

// Peer returns the latest name some other flow announced for this address -
// what a cache keyed by address alone lends a flow that announced nothing.
func (l *Ledger) Peer(ip netip.Addr) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	s := l.hs[ip]
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1].name
}

// Evidence is everything known about one flow's own handshake.
type Evidence struct {
	Handshake string // SNI read from this flow's ClientHello / QUIC Initial
	ECH       bool   // ECH with a known public front: Handshake is the front
	// ECHOffered: the hello carried the ECH extension with a non-front SNI
	// (usually GREASE). Recorded, but the handshake name is graded as read.
	ECHOffered bool
	ALPN       string // "h2", "h3", "h1" or ""
	Unseen     bool   // opened before capture began
	PID        int32
	Opened     time.Time
	LastSeen   time.Time
}

// Verdict is the grade for one flow, with the evidence behind it.
type Verdict struct {
	Class     Class  `json:"class"`
	Handshake string `json:"handshake,omitempty"`
	DNSPick   string `json:"dns_pick,omitempty"`
	FanIn     int    `json:"fan_in,omitempty"`
	// CrossProcess: the correlated answer was looked up for a different app.
	CrossProcess bool   `json:"cross_process,omitempty"`
	PickComm     string `json:"pick_comm,omitempty"`
	Stale        bool   `json:"stale,omitempty"`
	// Reference-validity flags: the handshake name is not the destination
	// (ECH, IP literal) or may not be the only one (coalescing).
	ECH       bool `json:"ech,omitempty"`
	IPLiteral bool `json:"ip_literal,omitempty"`
	// ECHOffered is not a validity flag: the SNI is the real name (GREASE ECH).
	ECHOffered bool     `json:"ech_offered,omitempty"`
	Coalesce   []string `json:"coalesce,omitempty"`
	Cause      Cause    `json:"cause,omitempty"`
}

// Grade classifies a flow against one correlation result.
func Grade(e Evidence, c Correlation, l *Ledger, ip netip.Addr) Verdict {
	h := norm(e.Handshake)
	v := Verdict{Handshake: h, DNSPick: c.Pick, FanIn: len(c.Candidates), PickComm: c.PickComm, ECH: e.ECH,
		ECHOffered: e.ECHOffered}
	if c.Pick != "" && c.PickAsker > 0 && e.PID > 0 && c.PickAsker != e.PID {
		v.CrossProcess = true
	}
	v.Stale = c.Stale(e.Opened)
	if _, err := netip.ParseAddr(h); err == nil && h != "" {
		v.IPLiteral, h = true, ""
	}
	if l != nil && (e.ALPN == "h2" || e.ALPN == "h3") && h != "" {
		end := e.LastSeen
		if end.Before(e.Opened) {
			end = e.Opened
		}
		v.Coalesce = l.ResolvedBy(ip, e.PID, end, h)
	}
	switch {
	case e.ECH && h != "":
		v.Class = ECHOuter
	case h != "" && c.Pick == "":
		v.Class = HandshakeOnly
	case h != "" && h == c.Pick:
		v.Class = Agree
	case h != "" && contains(c.Candidates, h):
		v.Class = Alias
	case h != "":
		hr, pr := enrich.Registrable(h), enrich.Registrable(c.Pick)
		if hr != "" && hr == pr {
			v.Class = SameSite
		} else {
			v.Class = Mismatch
		}
	case c.Pick != "":
		v.Class = DNSOnly
	case e.Unseen:
		v.Class = Unseen
	default:
		v.Class = Neither
	}
	switch {
	case v.Class == HandshakeOnly:
		v.Cause = CauseBypass
	case !v.Class.Wrong():
	case len(v.Coalesce) > 0 && contains(v.Coalesce, c.Pick):
		v.Cause = CauseCoalesced
	case v.Stale:
		v.Cause = CauseStale
	case v.CrossProcess:
		v.Cause = CauseCrossProcess
	case v.FanIn > 1:
		v.Cause = CauseCoHosted
	default:
		v.Cause = CauseOtherName
	}
	return v
}

// Classify is Grade for callers with only a handshake name and a correlation.
func Classify(handshake string, unseen bool, c Correlation, pid int32) Verdict {
	return Grade(Evidence{Handshake: handshake, Unseen: unseen, PID: pid}, c, nil, netip.Addr{})
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func norm(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".") }

// Tally accumulates verdicts in three units - flows, bytes and distinct
// (app, name) pairs - because published baselines mix all three.
type Tally struct {
	Total        int              `json:"total"`
	ByClass      map[Class]int    `json:"by_class"`
	Bytes        map[Class]uint64 `json:"bytes_by_class"`
	Pairs        map[Class]int    `json:"pairs_by_class"`
	ByCause      map[Cause]int    `json:"by_cause"`
	CrossProcess int              `json:"cross_process"`
	Coalesce     int              `json:"coalesce_candidates"`
	IPLiteral    int              `json:"ip_literal"`
	ECHOffered   int              `json:"ech_offered"`
	FanInMax     int              `json:"fan_in_max"`
	pairs        map[Class]map[string]bool
}

func NewTally() *Tally {
	return &Tally{ByClass: map[Class]int{}, Bytes: map[Class]uint64{}, Pairs: map[Class]int{},
		ByCause: map[Cause]int{}, pairs: map[Class]map[string]bool{}}
}

// Add counts a verdict. app and bytes may be zero values.
func (t *Tally) Add(v Verdict) { t.AddFlow(v, "", 0) }

func (t *Tally) AddFlow(v Verdict, app string, bytes uint64) {
	t.Total++
	t.ByClass[v.Class]++
	t.Bytes[v.Class] += bytes
	if v.Cause != CauseNone {
		t.ByCause[v.Cause]++
	}
	name := v.Handshake
	if name == "" {
		name = v.DNSPick
	}
	if t.pairs[v.Class] == nil {
		t.pairs[v.Class] = map[string]bool{}
	}
	if k := app + "\x00" + name; !t.pairs[v.Class][k] {
		t.pairs[v.Class][k] = true
		t.Pairs[v.Class]++
	}
	if v.CrossProcess {
		t.CrossProcess++
	}
	if len(v.Coalesce) > 0 {
		t.Coalesce++
	}
	if v.IPLiteral {
		t.IPLiteral++
	}
	if v.ECHOffered {
		t.ECHOffered++
	}
	if v.FanIn > t.FanInMax {
		t.FanInMax = v.FanIn
	}
}

func (t *Tally) wrong() int { return t.ByClass[Alias] + t.ByClass[SameSite] + t.ByClass[Mismatch] }

// Comparable is the disagreement denominator: flows with both names.
func (t *Tally) Comparable() int { return t.ByClass[Agree] + t.wrong() }

// Readable is every flow whose destination name was in its own handshake.
func (t *Tally) Readable() int { return t.Comparable() + t.ByClass[HandshakeOnly] }

// Disagreement: share of comparable flows where correlation shows another
// name. Defined like Trevisan et al. (TRAC 2016)'s SNI-vs-DNS inconsistency.
func (t *Tally) Disagreement() float64 { return ratio(t.wrong(), t.Comparable()) }

// CorrelationError: share of readable flows correlation names wrongly or not
// at all - the full cost of inferring instead of reading.
func (t *Tally) CorrelationError() float64 {
	return ratio(t.wrong()+t.ByClass[HandshakeOnly], t.Readable())
}

// Wrong returns the count of wrongly named flows.
func (t *Tally) Wrong() int { return t.wrong() }

func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}
