// Package eval runs a whole capture through the same decode → flow → naming
// pipeline the daemon uses, and measures how often each way of naming a
// connection gets it wrong.
//
// Two modes. Field: any pktap capture, no ground truth; the handshake name is
// the reference, because it is what the client asked for and what a monitor
// can see - with ECH, IP-literal and possibly-coalesced flows flagged, since
// for those the handshake name is not (or not only) the destination.
// Lab: a capture from cmd/acn-lab plus its truth file, which says what every
// flow was really for, so every strategy can be scored against fact.
//
// Strategies are modelled on what each tool documents, not lumped together:
//
//	last-answer   latest answer from any process   (OpenSnitch, Little Snitch for Linux)
//	per-process   latest answer this app asked for  (Little Snitch DNS sniffing, Portmaster)
//	header-first  handshake name, else per-process  (Little Snitch on macOS)
//	address-cache any name cached for the address   (ohmyosi v0.1)
//	read-first    own handshake as read; else per-process, labelled a guess (ohmyosi now)
package eval

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ohmyosi/internal/audit"
	"ohmyosi/internal/decode"
	"ohmyosi/internal/enrich"
	"ohmyosi/internal/flow"
	"ohmyosi/internal/naming"
	"ohmyosi/internal/pktap"
)

// Truth is the lab's answer key: flow key → the name the app really wanted.
type Truth map[string]TruthEntry

type TruthEntry struct {
	App  string `json:"app"`
	Name string `json:"name"` // "" when the flow genuinely has no name
	Note string `json:"note,omitempty"`
}

// Key identifies a flow in a truth file: "tcp 192.168.1.3:50001>104.18.32.7:443".
func Key(proto string, local, remote netip.AddrPort) string {
	return proto + " " + local.String() + ">" + remote.String()
}

// Strategy names, in report order.
const (
	StratLastAnswer  = "last-answer"
	StratPerProcess  = "per-process"
	StratHeaderFirst = "header-first"
	StratAddrCache   = "address-cache"
	StratRead        = "read-first"
	// Little Snitch on macOS by its documented steps (littlesnitch.go), with
	// its default "Verify server names asserted by process" on and off.
	StratLittleSnitch         = "littlesnitch-mac"
	StratLittleSnitchNoVerify = "littlesnitch-mac-noverify"
)

var Strategies = []string{StratLastAnswer, StratPerProcess, StratHeaderFirst, StratLittleSnitch, StratLittleSnitchNoVerify, StratAddrCache, StratRead}

// Correlators are the strategies that name flows from DNS alone, and so can be
// graded against the handshake name without ground truth.
var Correlators = []string{StratLastAnswer, StratPerProcess}

// Shown is one strategy's output for a flow.
type Shown struct {
	Name string `json:"name"`
	// Claim: "read" when presented as the connection's own name, "inferred"
	// when labelled a guess, "" when nothing is shown.
	Claim string `json:"claim"`
}

// FlowResult is one flow's evidence and grades.
type FlowResult struct {
	Key      string     `json:"key"`
	Comm     string     `json:"comm"`
	PID      int32      `json:"pid"`
	Unseen   bool       `json:"unseen,omitempty"`
	Remote   netip.Addr `json:"remote"`
	Bytes    uint64     `json:"bytes"`
	ALPN     string     `json:"alpn,omitempty"`
	Answered bool       `json:"answered"`
	// Verdicts: one grade per correlating strategy, keyed by strategy name.
	Verdicts map[string]naming.Verdict `json:"verdicts"`
	Shown    map[string]Shown          `json:"shown"`
	Truth    *TruthEntry               `json:"truth,omitempty"`
	// LSStep is the step of the modelled Little Snitch (default settings)
	// that named this flow; LSRejected marks a handshake name it refused.
	LSStep     int  `json:"ls_step,omitempty"`
	LSRejected bool `json:"ls_rejected,omitempty"`
	// Opened, Site and Lane place the flow in a workload's visit log, when
	// the run recorded one, for per-site statistics.
	Opened time.Time `json:"opened"`
	Site   string    `json:"site,omitempty"`
	Lane   string    `json:"lane,omitempty"`
}

// V is the last-answer verdict, the one comparable to published baselines.
func (r FlowResult) V() naming.Verdict { return r.Verdicts[StratLastAnswer] }

// Score is one strategy's performance over flows with known truth.
type Score struct {
	Strategy string `json:"strategy"`
	Flows    int    `json:"flows"`
	Correct  int    `json:"correct"`
	Wrong    int    `json:"wrong"`
	Missing  int    `json:"missing"`
	// Misled: wrong names presented as read off the connection.
	Misled int `json:"misled"`
	// DomainLevel: counted correct, but only at the registrable domain (Little
	// Snitch's step 4 shows a common domain rather than a host).
	DomainLevel int `json:"domain_level,omitempty"`
}

// ProcRow breaks results down per process.
type ProcRow struct {
	Comm     string               `json:"comm"`
	Flows    int                  `json:"flows"`
	ByClass  map[naming.Class]int `json:"by_class"`
	Readable int                  `json:"readable"`
	// Errors per correlating strategy: wrong or blank, over readable flows.
	Errors map[string]int `json:"errors"`
}

// DNSCoverage says how many DNS answers pktap attributed to the app that asked
// rather than to mDNSResponder - the precondition for per-process strategies
// and for every cross-process number. Verify it per macOS version.
type DNSCoverage struct {
	Answers   int `json:"answers"`
	Effective int `json:"effective"` // carried an effective PID distinct from the socket owner
}

// Options controls a run.
type Options struct {
	Truth   Truth
	Blocked []string
	// Slack is how far after a flow opened a DNS answer may be timestamped and
	// still count; capture order across interfaces is not causal order.
	Slack time.Duration
	// Prior is an earlier capture whose DNS answers are preloaded, as a monitor
	// running across both would hold them (prior.go). Used for warm passes.
	Prior string
}

// Report is the whole evaluation.
type Report struct {
	Source      string                   `json:"source"`
	Manifest    map[string]any           `json:"manifest,omitempty"`
	SlackMS     int64                    `json:"slack_ms"`
	Packets     int                      `json:"packets"`
	Flows       int                      `json:"flows"`
	WithProcess int                      `json:"with_process"`
	DNS         DNSCoverage              `json:"dns"`
	Tallies     map[string]*naming.Tally `json:"tallies"` // per correlating strategy
	FanIn       map[int]int              `json:"fan_in"`
	PerProcess  []ProcRow                `json:"per_process"`
	Examples    []FlowResult             `json:"examples"`
	Scores      []Score                  `json:"scores,omitempty"`
	Evasions    []audit.Evasion          `json:"evasions,omitempty"`
	Results     []FlowResult             `json:"results"`
	Prior       *PriorStats              `json:"prior,omitempty"`
}

// Tally is the last-answer tally, the baseline-comparable one.
func (r *Report) Tally() *naming.Tally { return r.Tallies[StratLastAnswer] }

// Run evaluates a capture file.
func Run(path string, opt Options) (*Report, error) {
	src, err := pktap.OpenFile(path)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	dec := decode.New()
	table := flow.NewTable(-1)
	table.IdleTimeout = 1 << 62 // keep every flow: this is an audit, not a live view
	ledger := naming.NewLedger()
	ledger.Slack = opt.Slack
	rep := &Report{Source: path, SlackMS: opt.Slack.Milliseconds(), FanIn: map[int]int{},
		Tallies: map[string]*naming.Tally{}, Manifest: loadManifest(path)}
	for _, s := range Correlators {
		rep.Tallies[s] = naming.NewTally()
	}
	// Process name -> PIDs that started something in this capture (a connection,
	// a QUIC Initial, a handshake, a DNS lookup), for re-keying prior answers.
	// Only starters count: an app that has exited still shows up while the
	// kernel closes its leftover sockets, under its old PID.
	procs := map[string]map[int32]bool{}
	seenProc := func(comm string, pid int32) {
		if comm == "" || pid <= 0 {
			return
		}
		if procs[comm] == nil {
			procs[comm] = map[int32]bool{}
		}
		procs[comm][pid] = true
	}

	for {
		p, err := src.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if p == nil {
			continue
		}
		rep.Packets++
		o := dec.Decode(p)
		if o == nil {
			continue
		}
		asker, comm := o.PID, o.Comm
		if o.EPID > 0 {
			asker, comm = o.EPID, o.EComm
		}
		if len(o.DNS) > 0 || o.SNI != "" ||
			(o.Dir == pktap.DirOut && ((o.SYN && !o.FIN && !o.RST) || o.QUICLong)) {
			seenProc(comm, asker)
		}
		if len(o.DNS) > 0 {
			rep.DNS.Answers++
			if o.EPID > 0 && o.EPID != o.PID {
				rep.DNS.Effective++
			}
		}
		for _, r := range o.DNS {
			ledger.DNS(r.IP, r.Name, o.Ts, r.TTL, asker, comm)
		}
		if o.SNI != "" && !o.ECH {
			ledger.Handshake(o.Dst, o.SNI, o.Ts, asker)
		}
		table.Observe(o)
	}

	// Grading starts only now, so the earlier capture's answers can still go
	// in front of this one's.
	if opt.Prior != "" {
		prior, err := readAnswers(opt.Prior)
		if err != nil {
			return nil, fmt.Errorf("prior capture %s: %w", opt.Prior, err)
		}
		st := &PriorStats{File: opt.Prior, Answers: len(prior)}
		rekey(prior, procs, st)
		ledger.Preload(prior)
		rep.Prior = st
	}

	rows := map[string]*ProcRow{}
	for _, f := range table.All() {
		ra := f.Remote.Addr()
		if f.Self || local(ra) || f.Remote.Port() == 53 {
			continue
		}
		rep.Flows++
		pid := f.DisplayPID()
		if pid > 0 {
			rep.WithProcess++
		}
		// Match the flow to lookups by the same identity the ledger files DNS
		// answers under (above): the effective process when pktap gives one.
		// Safari's connections are owned by com.apple.WebKit.Networking with
		// Safari as effective process, and mDNSResponder's answers carry Safari
		// too; keying the flow by its owner would call every one of them
		// cross-process.
		app, appComm := pid, f.DisplayComm()
		if f.EPID > 0 {
			app = f.EPID
			if f.EComm != "" {
				appComm = f.EComm
			}
		}
		ev := naming.Evidence{Handshake: f.SNI, ECH: f.ECH, ECHOffered: f.ECHOffered, ALPN: f.ALPN, Unseen: f.PreExisting,
			PID: app, Comm: appComm, Opened: f.FirstSeen, LastSeen: f.LastSeen}
		global := ledger.Correlate(ra, f.FirstSeen)
		perProc := ledger.CorrelateFor(ra, f.FirstSeen, app)
		r := FlowResult{
			Key: Key(string(f.Proto), f.Local, f.Remote), Comm: f.DisplayComm(), PID: pid,
			Unseen: f.PreExisting, Remote: ra, Bytes: f.BytesUp + f.BytesDown, ALPN: f.ALPN,
			Answered: f.PktsDown > 0, Shown: map[string]Shown{}, Opened: f.FirstSeen,
			Verdicts: map[string]naming.Verdict{
				StratLastAnswer: naming.Grade(ev, global, ledger, ra),
				StratPerProcess: naming.Grade(ev, perProc, ledger, ra),
			},
		}
		v := r.V()
		for _, s := range Correlators {
			rep.Tallies[s].AddFlow(r.Verdicts[s], r.Comm, r.Bytes)
		}
		rep.FanIn[v.FanIn]++

		// What each design would put on screen.
		own := ""
		if !v.IPLiteral && f.SNI != "" {
			own = f.SNI
		}
		ownTrusted := own != "" && !f.ECH
		r.Shown[StratLastAnswer] = shown(global.Pick, "read")
		r.Shown[StratPerProcess] = shown(perProc.Pick, "read")
		if own != "" { // Little Snitch reads the SNI header, ECH outer name included
			r.Shown[StratHeaderFirst] = Shown{own, "read"}
		} else {
			r.Shown[StratHeaderFirst] = shown(perProc.Pick, "read")
		}
		// Little Snitch reads the SNI as sent, the ECH outer name included.
		ls := littleSnitch(ledger, ra, f.FirstSeen, app, own, true)
		r.Shown[StratLittleSnitch] = shownLS(ls)
		r.LSStep, r.LSRejected = ls.Step, ls.Rejected
		r.Shown[StratLittleSnitchNoVerify] = shownLS(littleSnitch(ledger, ra, f.FirstSeen, app, own, false))
		switch {
		case own != "":
			r.Shown[StratAddrCache] = Shown{own, "read"}
		case ledger.Peer(ra) != "":
			r.Shown[StratAddrCache] = Shown{ledger.Peer(ra), "read"}
		default:
			r.Shown[StratAddrCache] = shown(global.Pick, "inferred")
		}
		switch {
		case ownTrusted:
			r.Shown[StratRead] = Shown{own, "read"}
		case perProc.Pick != "":
			r.Shown[StratRead] = Shown{perProc.Pick, "inferred"}
		default:
			r.Shown[StratRead] = shown(global.Pick, "inferred")
		}
		if opt.Truth != nil {
			if t, ok := opt.Truth[r.Key]; ok {
				tt := t
				r.Truth = &tt
			}
		}
		rep.Results = append(rep.Results, r)
		if e, ok := audit.Check(r.Key, r.Comm, r.PID, ra, r.Answered, v, opt.Blocked); ok && !f.ECH {
			rep.Evasions = append(rep.Evasions, e)
		}

		c := r.Comm
		if c == "" {
			c = "(unattributed)"
		}
		row := rows[c]
		if row == nil {
			row = &ProcRow{Comm: c, ByClass: map[naming.Class]int{}, Errors: map[string]int{}}
			rows[c] = row
		}
		row.Flows++
		row.ByClass[v.Class]++
		if v.Class.Comparable() || v.Class == naming.HandshakeOnly {
			row.Readable++
			for _, s := range Correlators {
				if vc := r.Verdicts[s].Class; vc.Wrong() || vc == naming.HandshakeOnly {
					row.Errors[s]++
				}
			}
		}
	}
	sort.Slice(rep.Results, func(i, j int) bool { return rep.Results[i].Key < rep.Results[j].Key })

	for _, row := range rows {
		rep.PerProcess = append(rep.PerProcess, *row)
	}
	sort.Slice(rep.PerProcess, func(i, j int) bool {
		if rep.PerProcess[i].Flows != rep.PerProcess[j].Flows {
			return rep.PerProcess[i].Flows > rep.PerProcess[j].Flows
		}
		return rep.PerProcess[i].Comm < rep.PerProcess[j].Comm
	})

	rank := map[naming.Class]int{naming.Mismatch: 0, naming.Alias: 1, naming.SameSite: 2, naming.HandshakeOnly: 3}
	for _, r := range rep.Results {
		if _, ok := rank[r.V().Class]; ok {
			rep.Examples = append(rep.Examples, r)
		}
	}
	sort.SliceStable(rep.Examples, func(i, j int) bool {
		return rank[rep.Examples[i].V().Class] < rank[rep.Examples[j].V().Class]
	})
	if len(rep.Examples) > 15 {
		rep.Examples = rep.Examples[:15]
	}

	if opt.Truth != nil {
		for _, s := range Strategies {
			sc := Score{Strategy: s}
			for _, r := range rep.Results {
				if r.Truth == nil {
					continue
				}
				sc.Flows++
				got, want := r.Shown[s], r.Truth.Name
				switch {
				case got.Name == want:
					sc.Correct++
				case got.Claim == "domain" && want != "" && enrich.Registrable(want) == got.Name:
					sc.Correct++
					sc.DomainLevel++
				case got.Name == "":
					sc.Missing++
				default:
					sc.Wrong++
					if got.Claim == "read" {
						sc.Misled++
					}
				}
			}
			rep.Scores = append(rep.Scores, sc)
		}
	}
	return rep, nil
}

func shown(name, claim string) Shown {
	if name == "" {
		return Shown{}
	}
	return Shown{name, claim}
}

func local(a netip.Addr) bool {
	return !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsLinkLocalMulticast() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

// loadManifest reads <capture>.manifest.json if the workload wrote one.
func loadManifest(path string) map[string]any {
	base := strings.TrimSuffix(path, ".pcapng")
	base = strings.TrimSuffix(base, ".pcap")
	b, err := os.ReadFile(base + ".manifest.json")
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// LoadTruth reads a lab truth file.
func LoadTruth(path string) (Truth, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Truth
	return t, json.Unmarshal(b, &t)
}

// Wilson is the 95% Wilson score interval for k successes in n trials - honest
// at small n and near 0 or 1, where the normal approximation is not.
func Wilson(k, n int) (lo, hi float64) {
	if n == 0 {
		return 0, 1
	}
	const z = 1.959964
	p := float64(k) / float64(n)
	nn := float64(n)
	den := 1 + z*z/nn
	mid := (p + z*z/(2*nn)) / den
	half := z * math.Sqrt(p*(1-p)/nn+z*z/(4*nn*nn)) / den
	return math.Max(0, mid-half), math.Min(1, mid+half)
}

func pct(n, d int) string {
	if d == 0 {
		return "   -  "
	}
	return fmt.Sprintf("%5.1f%%", 100*float64(n)/float64(d))
}

// PctCI renders k/n with its Wilson interval.
func PctCI(k, n int) string {
	if n == 0 {
		return "-"
	}
	lo, hi := Wilson(k, n)
	return fmt.Sprintf("%.1f%% [%.1f-%.1f]", 100*float64(k)/float64(n), 100*lo, 100*hi)
}

// Print writes the report for a person.
func (r *Report) Print(w io.Writer) {
	t := r.Tally()
	fmt.Fprintf(w, "ohmyosi eval: %s  (slack %d ms)\n", r.Source, r.SlackMS)
	if len(r.Manifest) > 0 {
		keys := make([]string, 0, len(r.Manifest))
		for k := range r.Manifest {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, r.Manifest[k]))
		}
		fmt.Fprintf(w, "run: %s\n", strings.Join(parts, " "))
	}
	fmt.Fprintf(w, "system resolver: %s\n", ResolverLine(r.Manifest))
	if p := r.Prior; p != nil {
		fmt.Fprintf(w, "preloaded %d DNS answers from %s (%d re-keyed to a relaunched process, %d with an ambiguous name)\n",
			p.Answers, filepath.Base(p.File), p.Remapped, p.Unknown)
	}
	if s := ResolverWarning(r.Manifest); s != "" {
		fmt.Fprintln(w, s)
	}
	fmt.Fprintf(w, "%d packets, %d external flows, %s attributed to a process\n",
		r.Packets, r.Flows, pct(r.WithProcess, r.Flows))
	fmt.Fprintf(w, "DNS answers: %d, %s carried the asking app (effective PID)\n\n",
		r.DNS.Answers, pct(r.DNS.Effective, r.DNS.Answers))

	fmt.Fprintln(w, "HEADLINE (95% Wilson intervals)")
	fmt.Fprintf(w, "  readable: name in the flow's own handshake   %6d  %s of flows\n", t.Readable(), pct(t.Readable(), r.Flows))
	fmt.Fprintf(w, "  comparable: handshake AND a DNS answer       %6d\n", t.Comparable())
	for _, s := range Correlators {
		st := r.Tallies[s]
		fmt.Fprintf(w, "  %-12s disagreement   %-22s  correlation error %s\n", s,
			PctCI(st.Wrong(), st.Comparable()), PctCI(st.Wrong()+st.ByClass[naming.HandshakeOnly], st.Readable()))
	}
	fmt.Fprintf(w, "  correlated name came from another app's lookup  %d flows\n", t.CrossProcess)
	fmt.Fprintf(w, "  reference flags: ech-outer %d, ip-literal %d, coalescing candidates %d\n",
		t.ByClass[naming.ECHOuter], t.IPLiteral, t.Coalesce)
	fmt.Fprintf(w, "  ech offered with a real SNI (usually GREASE; graded normally)  %d flows\n", t.ECHOffered)
	fmt.Fprintf(w, "  ech-outer = ECH extension and SNI in the front list: %s\n", strings.Join(decode.ECHFronts, ", "))
	fmt.Fprintln(w, "  disagreement is defined as Trevisan et al. 2016's SNI-vs-DNS inconsistency (6% in-network)")

	fmt.Fprintln(w, "\nCLASSES (last-answer)        flows            bytes   app+name pairs")
	for _, c := range naming.Classes {
		fmt.Fprintf(w, "  %-15s %6d %s %14d %8d\n", c, t.ByClass[c], pct(t.ByClass[c], t.Total), t.Bytes[c], t.Pairs[c])
	}

	fmt.Fprintln(w, "\nCAUSES of wrong or blank names")
	fmt.Fprintf(w, "  %-14s %12s %12s\n", "cause", StratLastAnswer, StratPerProcess)
	for _, c := range naming.Causes {
		fmt.Fprintf(w, "  %-14s %12d %12d\n", c, r.Tallies[StratLastAnswer].ByCause[c], r.Tallies[StratPerProcess].ByCause[c])
	}

	fmt.Fprintln(w, "\nFAN-IN (distinct names resolved to the flow's address)")
	var ks []int
	for k := range r.FanIn {
		ks = append(ks, k)
	}
	sort.Ints(ks)
	for _, k := range ks {
		fmt.Fprintf(w, "  %3d name(s)  %6d flows\n", k, r.FanIn[k])
	}

	fmt.Fprintln(w, "\nPER PROCESS (correlation error over readable flows)")
	fmt.Fprintf(w, "  %-18s %5s %5s  %-24s %-24s\n", "process", "flows", "read", StratLastAnswer, StratPerProcess)
	for i, p := range r.PerProcess {
		if i == 25 {
			fmt.Fprintf(w, "  ... %d more\n", len(r.PerProcess)-25)
			break
		}
		fmt.Fprintf(w, "  %-18s %5d %5d  %-24s %-24s\n", trunc(p.Comm, 18), p.Flows, p.Readable,
			PctCI(p.Errors[StratLastAnswer], p.Readable), PctCI(p.Errors[StratPerProcess], p.Readable))
	}

	if len(r.Examples) > 0 {
		fmt.Fprintln(w, "\nWHERE LAST-ANSWER CORRELATION GETS IT WRONG")
		for _, e := range r.Examples {
			v := e.V()
			pick := v.DNSPick
			if pick == "" {
				pick = "<bare address>"
			}
			fmt.Fprintf(w, "  %-14s %-16s asked for %-28s correlation says %-24s [%s]\n",
				v.Class, trunc(e.Comm, 16), v.Handshake, pick, v.Cause)
		}
	}

	if len(r.Evasions) > 0 {
		fmt.Fprintln(w, "\nBLOCK EVASIONS (blocked name in a handshake that got an answer)")
		for _, e := range r.Evasions {
			fmt.Fprintf(w, "  %-16s %s (rule %s) at %s\n      %s\n", trunc(e.Comm, 16), e.Name, e.Rule, e.Addr, e.Route)
		}
	}

	if len(r.Scores) > 0 {
		fmt.Fprintln(w, "\nAGAINST GROUND TRUTH")
		fmt.Fprintf(w, "  %-26s %5s %8s %6s %8s %7s\n", "strategy", "flows", "correct", "wrong", "missing", "misled")
		for _, s := range r.Scores {
			fmt.Fprintf(w, "  %-26s %5d %8s %6d %8d %7d\n", s.Strategy, s.Flows, pct(s.Correct, s.Flows), s.Wrong, s.Missing, s.Misled)
		}
		fmt.Fprintln(w, "  misled = a wrong name presented as read off the connection")
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Markdown renders the headline tables for a paper or README.
func (r *Report) Markdown() string {
	var b strings.Builder
	t := r.Tally()
	fmt.Fprintf(&b, "| class | flows | share | bytes | app+name pairs |\n|---|---:|---:|---:|---:|\n")
	for _, c := range naming.Classes {
		fmt.Fprintf(&b, "| %s | %d | %s | %d | %d |\n", c, t.ByClass[c], strings.TrimSpace(pct(t.ByClass[c], t.Total)), t.Bytes[c], t.Pairs[c])
	}
	if len(r.Scores) > 0 {
		fmt.Fprintf(&b, "\n| strategy | correct | wrong | missing | misled |\n|---|---:|---:|---:|---:|\n")
		for _, s := range r.Scores {
			fmt.Fprintf(&b, "| %s | %s | %d | %d | %d |\n", s.Strategy, strings.TrimSpace(pct(s.Correct, s.Flows)), s.Wrong, s.Missing, s.Misled)
		}
	}
	return b.String()
}
