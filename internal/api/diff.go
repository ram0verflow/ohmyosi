package api

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"ohmyosi/internal/enrich"
)

// Comparing two recorded sessions.
//
// The question this answers is the one people actually ask about their own
// machine: "what is it doing today that it wasn't doing yesterday?" A live
// graph cannot answer that - it only ever shows now - and a per-flow diff
// cannot either, because flow IDs are five-tuples and every one of them is new
// tomorrow. Ephemeral ports change, CDN addresses rotate, and a naive diff
// reports several hundred "new connections" every single day, which is the same
// as reporting nothing.
//
// So the unit of comparison here is the *relationship*: which application talks
// to which destination. That is the thing that is genuinely stable day to day,
// and the thing whose change is worth a person's time. Brave reaching a Google
// address is not news. Brave reaching a domain registered last week is.
//
// Nothing here re-derives anything. A recording holds the daemon's own
// conclusions - names, sources, scores, reasons - and the diff compares those
// conclusions as recorded. Two runs of this over the same pair of files give
// the same answer forever, which is what makes it usable as evidence.

// Level says how coarsely a destination could be identified, and therefore how
// much weight a change at that level deserves. A new "domain" is a real new
// relationship. A new "address" inside a network already seen every day is
// usually a rotated CDN node - reported, but marked for what it is.
type Level string

const (
	LevelDomain  Level = "domain"  // registrable domain: cursor.sh
	LevelHost    Level = "host"    // a name, but not one we could reduce: some.internal
	LevelNetwork Level = "network" // no name at all; grouped by the AS that owns the space
	LevelAddress Level = "address" // no name and no AS: the bare address is all there is
)

// Pair is one application-to-destination relationship, summarised over a whole
// session. It is deliberately an aggregate: dozens of flows collapse into one
// row, because "Brave talked to github.com" is one fact however many sockets it
// took.
type Pair struct {
	Key string `json:"key"`

	App   string `json:"app"`             // the outermost bundle, what a person recognises
	Comm  string `json:"comm"`            // the specific process
	PIDs  []int32 `json:"pids,omitempty"` // every pid seen under this name
	Sign  string `json:"signing,omitempty"`

	Dest   string `json:"dest"` // the destination as named at Level
	Level  Level  `json:"level"`
	Org    string `json:"org,omitempty"`
	ASN    uint32 `json:"asn,omitempty"`
	ASNOrg string `json:"asn_org,omitempty"`
	Country string `json:"country,omitempty"`
	Owner  string `json:"owner,omitempty"`   // domain registrant
	AgeDays int   `json:"age_days,omitempty"`
	Addrs  []string `json:"addrs,omitempty"` // every address seen behind this key
	Ports  []uint16 `json:"ports,omitempty"`

	DirectIP bool `json:"direct_ip,omitempty"` // at least one flow never announced a name

	Flows     int     `json:"flows"`
	BytesUp   uint64  `json:"bytes_up"`
	BytesDown uint64  `json:"bytes_down"`
	FirstSeen float64 `json:"first_seen"`
	LastSeen  float64 `json:"last_seen"`

	// The loudest this relationship ever scored, and why. Carried from the
	// recording rather than recomputed.
	PeakScore int      `json:"peak_score"`
	PeakBand  string   `json:"peak_band,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`

	perFlow   map[string][2]uint64
	seenAddrs map[string]bool
	seenPorts map[uint16]bool
	seenPIDs  map[int32]bool
	seenFlows map[string]bool
}

// Session is one recording reduced to the set of relationships it contains.
type Session struct {
	Path     string  `json:"path"`
	Hostname string  `json:"hostname,omitempty"`
	Iface    string  `json:"iface,omitempty"`
	Version  string  `json:"version,omitempty"`
	Start    float64 `json:"start"`
	End      float64 `json:"end"`
	Ticks    int     `json:"ticks"`
	Pairs    map[string]*Pair `json:"pairs"`
}

func (s *Session) Duration() time.Duration {
	if s.End <= s.Start {
		return 0
	}
	return time.Duration((s.End - s.Start) * float64(time.Second))
}

// Apps is the set of application names in the session.
func (s *Session) Apps() map[string]bool {
	out := map[string]bool{}
	for _, p := range s.Pairs {
		out[p.App] = true
	}
	return out
}

// SortedPairs returns the pairs loudest-first, then by bytes, then by key, so
// two runs never disagree about ordering.
func SortedPairs(in []*Pair) []*Pair {
	out := append([]*Pair(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.PeakScore != b.PeakScore {
			return a.PeakScore > b.PeakScore
		}
		if a.BytesUp+a.BytesDown != b.BytesUp+b.BytesDown {
			return a.BytesUp+a.BytesDown > b.BytesUp+b.BytesDown
		}
		return a.Key < b.Key
	})
	return out
}

// destIdentity reduces an endpoint to the coarsest label that is still honest
// about who is on the other end, and says which level it managed.
//
// The ordering matters and is the same principle as everywhere else in this
// tool: who you asked for beats who owns the address space. A domain is the
// thing you can hold someone to. An AS number is a landlord.
func destIdentity(e Endpoint) (string, Level) {
	if e.Domain != "" {
		return e.Domain, LevelDomain
	}
	if e.Host != "" {
		return e.Host, LevelHost
	}
	// No name at all. Grouping by the owning network is the only way a diff
	// survives address rotation - but it is coarse, and the level says so, so
	// nothing downstream can mistake it for identification.
	if e.ASNOrg != "" {
		return fmt.Sprintf("AS%d %s", e.ASN, e.ASNOrg), LevelNetwork
	}
	if e.Org != "" {
		return e.Org, LevelNetwork
	}
	return e.IP, LevelAddress
}

// pairKey identifies a relationship. Ports are excluded on purpose: a browser
// opening a different source port is not a different relationship.
func pairKey(app, dest string) string {
	return app + " → " + dest
}

// Summarize reduces a recording to its relationships.
//
// It replays the recording as fast as the disk allows - the timing in the file
// is for watching, not for analysis - and folds every tick into the pair table.
func Summarize(path string) (*Session, error) {
	s := &Session{Path: path, Pairs: map[string]*Pair{}}
	procs := map[int32]enrich.Proc{}

	err := Play(path, 0, func(e Envelope) {
		s.Ticks++
		if e.Host != nil {
			s.Hostname, s.Iface, s.Version = e.Host.Hostname, e.Host.Iface, e.Host.Version
		}
		if e.T > 0 {
			if s.Start == 0 || e.T < s.Start {
				s.Start = e.T
			}
			if e.T > s.End {
				s.End = e.T
			}
		}
		for _, p := range e.Procs {
			procs[p.PID] = p
		}
		for _, f := range e.Flows {
			s.fold(f, procs)
		}
	})
	if err != nil {
		return nil, err
	}
	if s.Ticks == 0 {
		return nil, fmt.Errorf("%s: no session envelopes - is this an ohmyosi recording?", path)
	}
	for _, p := range s.Pairs {
		p.finish()
	}
	return s, nil
}

// appName picks the label a person would recognise: the outermost bundle if the
// recording resolved one, the kernel's truncated name otherwise, and an honest
// "pid N" rather than a blank when there was no attribution at all.
func appName(f FlowView, procs map[int32]enrich.Proc) (app, comm, signing string) {
	comm = f.Comm
	if p, ok := procs[f.PID]; ok {
		if p.App != "" {
			app = p.App
		} else if p.Name != "" {
			app = p.Name
		}
		if p.Name != "" {
			comm = p.Name
		}
		signing = p.Signing
	}
	if app == "" {
		app = comm
	}
	if app == "" {
		if f.PID > 0 {
			app = fmt.Sprintf("pid %d", f.PID)
		} else {
			app = "unattributed"
		}
	}
	return app, comm, signing
}

func (s *Session) fold(f FlowView, procs map[int32]enrich.Proc) {
	if f.Self {
		return // ohmyosi's own lookups are not the machine's behaviour
	}
	app, comm, signing := appName(f, procs)
	dest, level := destIdentity(f.Remote)
	key := pairKey(app, dest)

	p := s.Pairs[key]
	if p == nil {
		p = &Pair{
			Key: key, App: app, Comm: comm, Sign: signing,
			Dest: dest, Level: level, AgeDays: -1,
			FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
			perFlow: map[string][2]uint64{},
			seenAddrs: map[string]bool{}, seenPorts: map[uint16]bool{},
			seenPIDs: map[int32]bool{}, seenFlows: map[string]bool{},
		}
		s.Pairs[key] = p
	}

	if !p.seenFlows[f.ID] {
		p.seenFlows[f.ID] = true
		p.Flows++
	}
	// Byte counters in a recording are cumulative per flow, so the last value
	// seen for a flow is its total. Summing every tick would multiply a long
	// connection by the number of ticks it lived through.
	p.setFlowBytes(f)

	if f.Remote.IP != "" {
		p.seenAddrs[f.Remote.IP] = true
	}
	if f.Remote.Port != 0 {
		p.seenPorts[f.Remote.Port] = true
	}
	if f.PID > 0 {
		p.seenPIDs[f.PID] = true
	}
	if f.DirectIP {
		p.DirectIP = true
	}
	if signing != "" {
		p.Sign = signing
	}
	// Identity fields fill in as the daemon learns them; later is better.
	r := f.Remote
	if r.Org != "" {
		p.Org = r.Org
	}
	if r.ASN != 0 {
		p.ASN, p.ASNOrg = r.ASN, r.ASNOrg
	}
	if r.Country != "" {
		p.Country = r.Country
	}
	if r.Owner != "" {
		p.Owner = r.Owner
	}
	if r.AgeDays > 0 {
		p.AgeDays = r.AgeDays
	}
	if f.FirstSeen > 0 && (p.FirstSeen == 0 || f.FirstSeen < p.FirstSeen) {
		p.FirstSeen = f.FirstSeen
	}
	if f.LastSeen > p.LastSeen {
		p.LastSeen = f.LastSeen
	}
	if f.Suspicion > p.PeakScore {
		p.PeakScore, p.PeakBand, p.Reasons = f.Suspicion, f.SuspicionBand, f.Reasons
	}
}

// setFlowBytes keeps the latest cumulative counter per flow and rolls the pair
// total from those, rather than adding deltas it was never given.
func (p *Pair) setFlowBytes(f FlowView) {
	if p.perFlow == nil {
		p.perFlow = map[string][2]uint64{}
	}
	p.perFlow[f.ID] = [2]uint64{f.BytesUp, f.BytesDown}
}

func (p *Pair) finish() {
	var up, down uint64
	for _, v := range p.perFlow {
		up += v[0]
		down += v[1]
	}
	p.BytesUp, p.BytesDown = up, down

	for a := range p.seenAddrs {
		p.Addrs = append(p.Addrs, a)
	}
	sort.Strings(p.Addrs)
	for pt := range p.seenPorts {
		p.Ports = append(p.Ports, pt)
	}
	sort.Slice(p.Ports, func(i, j int) bool { return p.Ports[i] < p.Ports[j] })
	for pid := range p.seenPIDs {
		p.PIDs = append(p.PIDs, pid)
	}
	sort.Slice(p.PIDs, func(i, j int) bool { return p.PIDs[i] < p.PIDs[j] })
}

// Diff is what changed between two sessions, in the terms a person cares
// about: relationships that appeared, relationships that stopped, and ones that
// continued but changed character.
type Diff struct {
	A *Session `json:"a"`
	B *Session `json:"b"`

	// Appeared: in B, not in A. This is the list the question was asked about.
	Appeared []*Pair `json:"appeared"`
	// Gone: in A, not in B. Quieter, but a process that stopped calling home is
	// also a change, and hiding it would make this a one-sided report.
	Gone []*Pair `json:"gone"`
	// Changed: present in both, but the score band moved or the traffic volume
	// moved by more than an order of magnitude.
	Changed []Change `json:"changed"`

	// Apps that appeared or disappeared entirely, which is a coarser and often
	// more important signal than any single destination.
	NewApps  []string `json:"new_apps"`
	GoneApps []string `json:"gone_apps"`
}

// Change is one relationship that existed in both sessions but is not behaving
// the same way. Every entry states its own reason, for the same reason scores
// do: a difference you cannot explain is not a finding.
type Change struct {
	Key    string   `json:"key"`
	Before *Pair    `json:"before"`
	After  *Pair    `json:"after"`
	Notes  []string `json:"notes"`
}

// Compare diffs A (the baseline, "yesterday") against B ("today").
func Compare(a, b *Session) Diff {
	d := Diff{A: a, B: b}
	appsA, appsB := a.Apps(), b.Apps()

	for k, pb := range b.Pairs {
		if pa, ok := a.Pairs[k]; !ok {
			d.Appeared = append(d.Appeared, pb)
		} else if notes := comparePair(pa, pb); len(notes) > 0 {
			d.Changed = append(d.Changed, Change{Key: k, Before: pa, After: pb, Notes: notes})
		}
	}
	for k, pa := range a.Pairs {
		if _, ok := b.Pairs[k]; !ok {
			d.Gone = append(d.Gone, pa)
		}
	}
	for app := range appsB {
		if !appsA[app] {
			d.NewApps = append(d.NewApps, app)
		}
	}
	for app := range appsA {
		if !appsB[app] {
			d.GoneApps = append(d.GoneApps, app)
		}
	}

	d.Appeared = SortedPairs(d.Appeared)
	d.Gone = SortedPairs(d.Gone)
	sort.Slice(d.Changed, func(i, j int) bool {
		if d.Changed[i].After.PeakScore != d.Changed[j].After.PeakScore {
			return d.Changed[i].After.PeakScore > d.Changed[j].After.PeakScore
		}
		return d.Changed[i].Key < d.Changed[j].Key
	})
	sort.Strings(d.NewApps)
	sort.Strings(d.GoneApps)
	return d
}

// comparePair reports only differences that mean something. Byte counts always
// differ between two sessions; saying so for every row would bury the rows
// where something actually moved.
func comparePair(a, b *Pair) []string {
	var notes []string
	if a.PeakBand != b.PeakBand && b.PeakScore > a.PeakScore {
		notes = append(notes, fmt.Sprintf("score rose from %d (%s) to %d (%s)",
			a.PeakScore, bandOr(a.PeakBand), b.PeakScore, bandOr(b.PeakBand)))
	}
	if !a.DirectIP && b.DirectIP {
		notes = append(notes, "now connects without announcing a name (no SNI, no DNS we saw)")
	}
	ta, tb := a.BytesUp+a.BytesDown, b.BytesUp+b.BytesDown
	if ta > 0 && tb > ta*10 {
		notes = append(notes, fmt.Sprintf("traffic up %.0fx (%s to %s)", float64(tb)/float64(ta), human(ta), human(tb)))
	}
	// A one-sided upload that was not one-sided before is the shape of data
	// leaving, and is worth naming even when the score did not move.
	if b.BytesUp > 1<<20 && b.BytesUp > b.BytesDown*4 && !(a.BytesUp > a.BytesDown*4) {
		notes = append(notes, fmt.Sprintf("upload now dominates: %s out vs %s in", human(b.BytesUp), human(b.BytesDown)))
	}
	if newAddrs := missing(b.Addrs, a.Addrs); len(newAddrs) > 0 && b.Level == LevelNetwork {
		notes = append(notes, fmt.Sprintf("%d address(es) not seen before inside the same network", len(newAddrs)))
	}
	if newPorts := missingPorts(b.Ports, a.Ports); len(newPorts) > 0 {
		notes = append(notes, "new port(s): "+joinPorts(newPorts))
	}
	return notes
}

func bandOr(s string) string {
	if s == "" {
		return "quiet"
	}
	return s
}

func missing(want, have []string) []string {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	var out []string
	for _, w := range want {
		if !set[w] {
			out = append(out, w)
		}
	}
	return out
}

func missingPorts(want, have []uint16) []uint16 {
	set := map[uint16]bool{}
	for _, h := range have {
		set[h] = true
	}
	var out []uint16
	for _, w := range want {
		if !set[w] {
			out = append(out, w)
		}
	}
	return out
}

func joinPorts(ps []uint16) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		parts = append(parts, fmt.Sprint(p))
	}
	return strings.Join(parts, ", ")
}

func human(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fkB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%dB", b)
}

// Report renders a diff as text meant to be read by a person at a terminal,
// leading with the answer to the question that was asked.
//
// It is deliberately shaped as an argument rather than a table: every line
// carries enough to judge it - who, where, at what level of certainty, and the
// reason it scored what it scored - because a list of differences with no
// justification is just noise with a timestamp.
func (d Diff) Report(w io.Writer, limit int) {
	if limit <= 0 {
		limit = 25
	}
	fmt.Fprintf(w, "session diff\n")
	fmt.Fprintf(w, "  baseline  %s  (%s, %d relationships, %s)\n",
		d.A.Path, stamp(d.A.Start), len(d.A.Pairs), roundDur(d.A.Duration()))
	fmt.Fprintf(w, "  compared  %s  (%s, %d relationships, %s)\n\n",
		d.B.Path, stamp(d.B.Start), len(d.B.Pairs), roundDur(d.B.Duration()))

	if d.A.Hostname != "" && d.B.Hostname != "" && d.A.Hostname != d.B.Hostname {
		fmt.Fprintf(w, "  note: different machines (%s vs %s) - treat every line below as expected\n\n",
			d.A.Hostname, d.B.Hostname)
	}

	if len(d.NewApps) > 0 {
		fmt.Fprintf(w, "applications that were not talking yesterday (%d)\n", len(d.NewApps))
		for _, a := range d.NewApps {
			fmt.Fprintf(w, "  + %s\n", a)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "new relationships (%d)\n", len(d.Appeared))
	if len(d.Appeared) == 0 {
		fmt.Fprintf(w, "  none - every app/destination pair today was also seen in the baseline\n")
	}
	writePairs(w, d.Appeared, limit, "+")
	fmt.Fprintln(w)

	if len(d.Changed) > 0 {
		fmt.Fprintf(w, "relationships that changed character (%d)\n", len(d.Changed))
		n := 0
		for _, c := range d.Changed {
			if n >= limit {
				fmt.Fprintf(w, "  … %d more\n", len(d.Changed)-n)
				break
			}
			fmt.Fprintf(w, "  ~ %s\n", c.Key)
			for _, note := range c.Notes {
				fmt.Fprintf(w, "      %s\n", note)
			}
			n++
		}
		fmt.Fprintln(w)
	}

	if len(d.Gone) > 0 {
		fmt.Fprintf(w, "stopped since the baseline (%d)\n", len(d.Gone))
		writePairs(w, d.Gone, limit, "-")
		fmt.Fprintln(w)
	}
	if len(d.GoneApps) > 0 {
		fmt.Fprintf(w, "applications that went quiet: %s\n\n", strings.Join(d.GoneApps, ", "))
	}

	// The caveat belongs in the output, not in documentation nobody reads. A
	// diff over two short recordings mostly measures what you happened to be
	// doing, and saying so is the difference between a tool and a horoscope.
	fmt.Fprintf(w, "read this carefully: a relationship is \"new\" only relative to the baseline recording.\n")
	fmt.Fprintf(w, "a short baseline makes ordinary traffic look new. entries marked [network] or [address]\n")
	fmt.Fprintf(w, "could not be resolved to a name, so a \"new\" one is often the same service on a rotated address.\n")
}

func writePairs(w io.Writer, ps []*Pair, limit int, mark string) {
	for i, p := range ps {
		if i >= limit {
			fmt.Fprintf(w, "  … %d more\n", len(ps)-i)
			return
		}
		fmt.Fprintf(w, "  %s %s → %s [%s]", mark, p.App, p.Dest, p.Level)
		if p.PeakScore > 0 {
			fmt.Fprintf(w, "  %d/%s", p.PeakScore, bandOr(p.PeakBand))
		}
		fmt.Fprintln(w)

		var meta []string
		if p.Owner != "" {
			meta = append(meta, "registered to "+p.Owner)
		}
		if p.AgeDays >= 0 {
			meta = append(meta, fmt.Sprintf("domain %d days old", p.AgeDays))
		}
		if p.ASNOrg != "" && p.Level != LevelNetwork {
			meta = append(meta, fmt.Sprintf("hosted on AS%d %s", p.ASN, p.ASNOrg))
		}
		if p.Country != "" {
			meta = append(meta, p.Country)
		}
		if p.Sign == "unsigned" || p.Sign == "adhoc" {
			meta = append(meta, "binary is "+p.Sign)
		}
		if p.DirectIP {
			meta = append(meta, "no name announced")
		}
		meta = append(meta, fmt.Sprintf("%d flow(s), %s out / %s in",
			p.Flows, human(p.BytesUp), human(p.BytesDown)))
		if len(p.Ports) > 0 && len(p.Ports) <= 4 {
			meta = append(meta, "port "+joinPorts(p.Ports))
		}
		fmt.Fprintf(w, "      %s\n", strings.Join(meta, " · "))
		for _, r := range p.Reasons {
			fmt.Fprintf(w, "      · %s\n", r)
		}
	}
}

func stamp(t float64) string {
	if t <= 0 {
		return "unknown time"
	}
	return time.Unix(int64(t), 0).Format("Mon 2 Jan 15:04")
}

func roundDur(d time.Duration) string {
	if d <= 0 {
		return "unknown length"
	}
	return d.Round(time.Second).String()
}
