package eval

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"ohmyosi/internal/decode"
	"ohmyosi/internal/enrich"
	"ohmyosi/internal/naming"
)

// Counts is the arithmetic of one group of flows. Rates are always derived
// from these, never averaged, so pooling runs is just adding Counts.
type Counts struct {
	Flows        int                  `json:"flows"`
	Bytes        uint64               `json:"bytes"`
	Readable     int                  `json:"readable"`   // trusted handshake name present
	Comparable   int                  `json:"comparable"` // ... and a last-answer DNS pick
	Wrong        map[string]int       `json:"wrong"`      // per correlating strategy
	Blind        map[string]int       `json:"blind"`      // readable, but strategy showed nothing
	CrossProcess int                  `json:"cross_process"`
	ECHOuter     int                  `json:"ech_outer"`
	ECHOffered   int                  `json:"ech_offered"` // ECH extension, real SNI (GREASE); graded normally
	Coalesce     int                  `json:"coalesce_candidates"`
	IPLiteral    int                  `json:"ip_literal"`
	Causes       map[naming.Cause]int `json:"causes"` // last-answer
	// Sibling: the correlated answer came from another process of the SAME
	// app (two instances of one browser): not counted as cross-process.
	Sibling int `json:"sibling_process"`

	// Every strategy's displayed name graded against the flow's own
	// handshake name, over readable flows: wrong (another name shown) and
	// blind (nothing shown). Covers the Little Snitch models too.
	SWrong map[string]int `json:"shown_wrong"`
	SBlind map[string]int `json:"shown_blind"`

	// The same, restricted to flows that are NOT coalescing candidates. An
	// h2/h3 connection may legitimately carry several names (RFC 9113
	// 9.1.1), so its "wrong" name is ambiguous, not necessarily an error.
	// Coalescing-only figures are the difference between the two.
	ReadableNC   int            `json:"readable_no_coalesce"`
	ComparableNC int            `json:"comparable_no_coalesce"`
	SWrongNC     map[string]int `json:"shown_wrong_no_coalesce"`
	SBlindNC     map[string]int `json:"shown_blind_no_coalesce"`

	// Little Snitch model (default settings), readable flows: which step
	// named them, how often step 2's DNS-only name disagreed with the
	// handshake, and how many handshake names step 3 refused.
	LSSteps      map[int]int `json:"ls_steps"`
	LSStep2Wrong int         `json:"ls_step2_wrong"`
	LSRejected   int         `json:"ls_rejected"`
	// RealGraded: readable flows each real tool's log covered - the
	// denominator for its rates (flows it never logged are excluded).
	RealGraded map[string]int `json:"real_graded,omitempty"`
}

// RealError is a real tool's wrong-or-blank over the readable flows its log covered.
func (c Counts) RealError(s string) (int, int) { return c.SWrong[s] + c.SBlind[s], c.RealGraded[s] }

// realStrategies lists the real tools seen in c, sorted.
func (c Counts) realStrategies() []string {
	var out []string
	for s := range c.RealGraded {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func newCounts() Counts {
	return Counts{Wrong: map[string]int{}, Blind: map[string]int{}, Causes: map[naming.Cause]int{},
		SWrong: map[string]int{}, SBlind: map[string]int{}, SWrongNC: map[string]int{}, SBlindNC: map[string]int{},
		LSSteps: map[int]int{}}
}

// shownOutcome grades what strategy s displayed for a readable flow against
// the flow's own handshake name: "agree", "wrong", "blind", or "" when the
// flow has no trustworthy handshake name to grade against.
func shownOutcome(r FlowResult, s string) string {
	if r.Unlogged[s] {
		return ""
	}
	v := r.V()
	if !(v.Class.Comparable() || v.Class == naming.HandshakeOnly) || v.Handshake == "" {
		return ""
	}
	got := r.Shown[s]
	switch {
	case got.Name == "":
		return "blind"
	case got.Name == v.Handshake:
		return "agree"
	case got.Claim == "domain" && enrich.Registrable(v.Handshake) == got.Name:
		return "agree"
	}
	return "wrong"
}

func (c *Counts) add(r FlowResult) {
	v := r.V()
	c.Flows++
	c.Bytes += r.Bytes
	if v.Class.Comparable() || v.Class == naming.HandshakeOnly {
		c.Readable++
	}
	if v.Class.Comparable() {
		c.Comparable++
	}
	for _, s := range Correlators {
		switch vc := r.Verdicts[s].Class; {
		case vc.Wrong():
			c.Wrong[s]++
		case vc == naming.HandshakeOnly:
			c.Blind[s]++
		}
	}
	if v.CrossProcess && v.Class.Wrong() {
		c.CrossProcess++
	}
	if v.SiblingProcess && v.Class.Wrong() {
		c.Sibling++
	}
	coal := len(v.Coalesce) > 0
	readable := v.Class.Comparable() || v.Class == naming.HandshakeOnly
	if readable && !coal {
		c.ReadableNC++
		if v.Class.Comparable() {
			c.ComparableNC++
		}
	}
	for _, s := range StrategiesOf(r) {
		if strings.HasPrefix(s, RealPrefix) && !r.Unlogged[s] && shownOutcome(r, s) != "" {
			if c.RealGraded == nil {
				c.RealGraded = map[string]int{}
			}
			c.RealGraded[s]++
		}
		switch shownOutcome(r, s) {
		case "wrong":
			c.SWrong[s]++
			if !coal {
				c.SWrongNC[s]++
			}
		case "blind":
			c.SBlind[s]++
			if !coal {
				c.SBlindNC[s]++
			}
		}
	}
	if readable && r.LSStep > 0 {
		c.LSSteps[r.LSStep]++
		if r.LSStep == LSStepDNS && shownOutcome(r, StratLittleSnitch) == "wrong" {
			c.LSStep2Wrong++
		}
		if r.LSRejected {
			c.LSRejected++
		}
	}
	if v.Class == naming.ECHOuter {
		c.ECHOuter++
	}
	if v.ECHOffered {
		c.ECHOffered++
	}
	if len(v.Coalesce) > 0 {
		c.Coalesce++
	}
	if v.IPLiteral {
		c.IPLiteral++
	}
	if v.Cause != naming.CauseNone {
		c.Causes[v.Cause]++
	}
}

func (c *Counts) merge(o Counts) {
	c.Flows += o.Flows
	c.Bytes += o.Bytes
	c.Readable += o.Readable
	c.Comparable += o.Comparable
	for k, v := range o.Wrong {
		c.Wrong[k] += v
	}
	for k, v := range o.Blind {
		c.Blind[k] += v
	}
	for k, v := range o.Causes {
		c.Causes[k] += v
	}
	c.CrossProcess += o.CrossProcess
	c.Sibling += o.Sibling
	c.ReadableNC += o.ReadableNC
	c.ComparableNC += o.ComparableNC
	for _, m := range []struct{ dst, src map[string]int }{{c.SWrong, o.SWrong}, {c.SBlind, o.SBlind}, {c.SWrongNC, o.SWrongNC}, {c.SBlindNC, o.SBlindNC}} {
		for k, v := range m.src {
			m.dst[k] += v
		}
	}
	for k, v := range o.LSSteps {
		c.LSSteps[k] += v
	}
	for k, v := range o.RealGraded {
		if c.RealGraded == nil {
			c.RealGraded = map[string]int{}
		}
		c.RealGraded[k] += v
	}
	c.LSStep2Wrong += o.LSStep2Wrong
	c.LSRejected += o.LSRejected
	c.ECHOuter += o.ECHOuter
	c.ECHOffered += o.ECHOffered
	c.Coalesce += o.Coalesce
	c.IPLiteral += o.IPLiteral
}

// Error is wrong-or-blank over readable flows for strategy s.
func (c Counts) Error(s string) (int, int) { return c.Wrong[s] + c.Blind[s], c.Readable }

// Disagreement is wrong over comparable flows (last-answer), as Trevisan 2016.
func (c Counts) Disagreement() (int, int) { return c.Wrong[StratLastAnswer], c.Comparable }

// DisagreementNC is Disagreement over flows that are not coalescing candidates.
func (c Counts) DisagreementNC() (int, int) { return c.SWrongNC[StratLastAnswer], c.ComparableNC }

// ShownError is wrong-or-blank over readable flows for any strategy s.
func (c Counts) ShownError(s string) (int, int) { return c.SWrong[s] + c.SBlind[s], c.Readable }

// ShownErrorNC is ShownError over flows that are not coalescing candidates.
func (c Counts) ShownErrorNC(s string) (int, int) { return c.SWrongNC[s] + c.SBlindNC[s], c.ReadableNC }

// RunSummary is one capture: its conditions and the counts for the process
// family the workload drove ("focus") and for everything else on the machine.
type RunSummary struct {
	File     string         `json:"file"`
	Manifest map[string]any `json:"manifest,omitempty"`
	Subject  string         `json:"subject"` // browser or app the run exercised
	Focus    Counts         `json:"focus"`
	Other    Counts         `json:"other"`
	DNS      DNSCoverage    `json:"dns"`
	// Prior: a warm run evaluated with its cold capture's DNS answers preloaded.
	Prior *PriorStats `json:"prior,omitempty"`
	// NoPrior: a warm run whose cold capture was not found; evaluated alone.
	NoPrior bool `json:"no_prior,omitempty"`
	// Sites holds focus counts per visited site, when the run logged visits
	// (<capture>.visits.tsv): hundreds of flows from one site are not
	// hundreds of independent observations, so rates are also given per site.
	Sites map[string]*Counts `json:"sites,omitempty"`
}

func (r RunSummary) m(k string) string {
	if v, ok := r.Manifest[k]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

// Group is the key runs are pooled by: same workload, subject and conditions,
// across repeats and networks.
func (r RunSummary) Group() string {
	w := r.m("workload")
	if w == "" {
		return "field: " + filepath.Base(r.File)
	}
	if w == "app-launch" {
		return "app " + r.Subject
	}
	return fmt.Sprintf("%s doh=%s %s", r.Subject, r.m("doh"), r.m("cache"))
}

// families maps a workload subject to the process names that carry its
// traffic. Browsers do their networking in helper processes, and pktap
// carries names truncated to 15 characters: com.apple.WebKit.Networking
// arrives as "com.apple.WebKi".
var families = map[string][]string{
	"safari":  {"safari", "com.apple.webki"},
	"chrome":  {"chrome"},
	"firefox": {"firefox", "plugin-container"},
}

func inFamily(subject, comm string) bool {
	if subject == "" {
		return true
	}
	c := strings.ToLower(comm)
	if keys, ok := families[subject]; ok {
		for _, k := range keys {
			if strings.Contains(c, k) {
				return true
			}
		}
		return false
	}
	// An app: match its first word ("Microsoft Teams" -> "teams" too).
	for _, w := range strings.Fields(strings.ToLower(subject)) {
		w = strings.TrimSuffix(w, ".us")
		if len(w) >= 4 && w != "microsoft" && strings.Contains(c, w) {
			return true
		}
	}
	return false
}

// Summarize evaluates every capture in dir.
func Summarize(dir string, slack time.Duration, progress io.Writer) ([]RunSummary, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcapng"))
	more, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	files = append(files, more...)
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no .pcapng captures in %s", dir)
	}
	var out []RunSummary
	for _, f := range files {
		if progress != nil {
			fmt.Fprintf(progress, "measuring %s\n", filepath.Base(f))
		}
		m := loadManifest(f)
		cold := coldSibling(f, m)
		rep, err := Run(f, Options{Slack: slack, Prior: cold})
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", f, err)
			continue
		}
		// A parallel run holds several browsers in one capture: it becomes one
		// summary per browser, each focused on that browser's processes.
		subjects := []string{strings.ToLower(mstr(m, "browser"))}
		if bs := mstr(m, "browsers"); bs != "" {
			subjects = strings.Split(strings.ToLower(bs), ",")
		}
		visits, lanes := loadVisits(f, m)
		for _, subject := range subjects {
			man := rep.Manifest
			if len(subjects) > 1 {
				man = map[string]any{}
				for k, v := range rep.Manifest {
					man[k] = v
				}
				man["browser"] = subject
				man["browser_version"] = rep.Manifest[subject+"_version"]
			}
			s := RunSummary{File: f, Manifest: man, Focus: newCounts(), Other: newCounts(), DNS: rep.DNS,
				Prior: rep.Prior, NoPrior: mstr(m, "cache") == "warm" && cold == ""}
			s.Subject = subject
			if s.Subject == "" {
				s.Subject = s.m("app")
			}
			fallback := onlyLane(m, subject)
			for _, r := range rep.Results {
				if inFamily(s.Subject, r.Comm) {
					s.Focus.add(r)
					if site := siteOf(visits, lanes, fallback, r); site != "" {
						if s.Sites == nil {
							s.Sites = map[string]*Counts{}
						}
						if s.Sites[site] == nil {
							c := newCounts()
							s.Sites[site] = &c
						}
						s.Sites[site].add(r)
					}
				} else {
					s.Other.add(r)
				}
			}
			out = append(out, s)
		}
	}
	return out, nil
}

// spread is the lowest and highest per-run rate in a group - run-to-run
// variation, reported beside the pooled interval rather than hidden in it.
func spread(runs []RunSummary, f func(Counts) (int, int)) string {
	lo, hi, n := 2.0, -1.0, 0
	for _, r := range runs {
		k, d := f(r.Focus)
		if d == 0 {
			continue
		}
		p := float64(k) / float64(d)
		n++
		if p < lo {
			lo = p
		}
		if p > hi {
			hi = p
		}
	}
	if n < 2 {
		return ""
	}
	return fmt.Sprintf("runs %.0f-%.0f%%", 100*lo, 100*hi)
}

// Baselines are the published figures the field study is compared against.
// Units differ between them; each line says which unit it is in.
var Baselines = []struct{ Source, Metric, Value, Ours string }{
	{"Trevisan et al., TRAC 2016 (in-network, ISP+campus)", "SNI vs DNS inconsistency, flows", "6%", "disagreement"},
	{"Bermudez et al., IMC 2012 (DN-Hunter)", "possible label confusion, flows (estimate)", "<4%", "disagreement"},
	{"Allman, IMC 2020 (residential)", "connections with no DNS", "7.2%", "handshake-only"},
	{"Yu et al., DNS-OARC 41, 2023 (residential, talk)", "connections with no DNS", "27%", "handshake-only"},
}

// PrintSummary writes the per-run and pooled tables.
func PrintSummary(w io.Writer, runs []RunSummary) {
	printResolvers(w, runs)
	fmt.Fprintln(w, "PER RUN (focus = the browser or app the run drove)")
	fmt.Fprintf(w, "  %-52s %6s %6s  %-20s %-20s %5s %6s %6s\n", "run", "flows", "read", "last-answer err", "per-process err", "xproc", "echout", "echoff")
	for _, r := range runs {
		f := r.Focus
		label := strings.TrimSuffix(filepath.Base(r.File), ".pcapng")
		if r.m("browsers") != "" {
			label += " [" + r.Subject + "]"
		}
		fmt.Fprintf(w, "  %-52s %6d %6d  %-20s %-20s %5d %6d %6d\n", trunc(label, 52),
			f.Flows, f.Readable, PctCI(f.Error(StratLastAnswer)), PctCI(f.Error(StratPerProcess)), f.CrossProcess, f.ECHOuter, f.ECHOffered)
	}
	fmt.Fprintln(w, "  echout = ECH with a known front (excluded); echoff = ECH extension with a real SNI (GREASE; graded)")
	for _, r := range runs {
		name := strings.TrimSuffix(filepath.Base(r.File), ".pcapng")
		switch {
		case r.Prior != nil:
			fmt.Fprintf(w, "  %s: preloaded %d DNS answers from its cold capture (%d re-keyed to the relaunched process, %d ambiguous)\n",
				name, r.Prior.Answers, r.Prior.Remapped, r.Prior.Unknown)
		case r.NoPrior:
			fmt.Fprintf(w, "  WARNING: %s is a warm run without its cold capture: evaluated alone, so cached lookups count as bypass\n", name)
		}
	}

	groups := map[string][]RunSummary{}
	var keys []string
	for _, r := range runs {
		g := r.Group()
		if groups[g] == nil {
			keys = append(keys, g)
		}
		groups[g] = append(groups[g], r)
	}
	sort.Strings(keys)

	fmt.Fprintln(w, "\nPOOLED BY CONDITION (95% Wilson; run-to-run spread where >1 run)")
	fmt.Fprintf(w, "  %-28s %4s %6s  %-28s %-28s %-24s\n", "condition", "runs", "read", "disagreement (last-answer)", "error: last-answer", "error: per-process")
	total := newCounts()
	var all []RunSummary
	for _, k := range keys {
		c := newCounts()
		for _, r := range groups[k] {
			c.merge(r.Focus)
		}
		total.merge(c)
		all = append(all, groups[k]...)
		fmt.Fprintf(w, "  %-28s %4d %6d  %-28s %-28s %-24s\n", trunc(k, 28), len(groups[k]), c.Readable,
			PctCI(c.Disagreement()), PctCI(c.Error(StratLastAnswer)), PctCI(c.Error(StratPerProcess)))
		if s := spread(groups[k], func(c Counts) (int, int) { return c.Error(StratLastAnswer) }); s != "" {
			fmt.Fprintf(w, "  %-28s %4s %6s  %-28s %-28s\n", "", "", "", "", s)
		}
	}

	fmt.Fprintln(w, "\nCOALESCING SPLIT (last-answer disagreement; h2/h3 reuse may legitimately carry several names)")
	fmt.Fprintf(w, "  %-28s %-26s %-26s %-22s\n", "condition", "all comparable", "excluding coalescing", "coalescing only")
	for _, k := range keys {
		c := newCounts()
		for _, r := range groups[k] {
			c.merge(r.Focus)
		}
		kw, kd := c.Disagreement()
		nw, nd := c.DisagreementNC()
		fmt.Fprintf(w, "  %-28s %-26s %-26s %-22s\n", trunc(k, 28), PctCI(kw, kd), PctCI(nw, nd), PctCI(kw-nw, kd-nd))
	}

	fmt.Fprintln(w, "\nEVERY STRATEGY vs THE HANDSHAKE NAME (all focus flows; error = wrong or blank over readable)")
	fmt.Fprintf(w, "  %-26s %-24s %-24s %8s %8s\n", "strategy", "error", "error excl. coalescing", "wrong", "blank")
	for _, st := range Strategies {
		fmt.Fprintf(w, "  %-26s %-24s %-24s %8d %8d\n", st, PctCI(total.ShownError(st)), PctCI(total.ShownErrorNC(st)),
			total.SWrong[st], total.SBlind[st])
	}
	for _, st := range total.realStrategies() {
		fmt.Fprintf(w, "  %-26s %-24s %-24s %8d %8d   (over the %d readable flows its log covered)\n", st,
			PctCI(total.RealError(st)), "", total.SWrong[st], total.SBlind[st], total.RealGraded[st])
	}

	fmt.Fprintln(w, "\nLITTLE SNITCH MODEL (macOS, documented steps, default verification; readable focus flows)")
	fmt.Fprintln(w, "  step 1 (name from the Network Extension framework) is not observable: these figures bound its error from above")
	ls := total.LSSteps[LSStepDNS] + total.LSSteps[LSStepSNI] + total.LSSteps[LSStepDomain] + total.LSSteps[LSStepAddress]
	fmt.Fprintf(w, "  named at step 2 (app's single DNS name, handshake not checked) %s\n", PctCI(total.LSSteps[LSStepDNS], ls))
	fmt.Fprintf(w, "    of which disagree with the handshake name                  %s\n", PctCI(total.LSStep2Wrong, total.LSSteps[LSStepDNS]))
	fmt.Fprintf(w, "  named at step 3 (handshake name, verified against DNS)       %s\n", PctCI(total.LSSteps[LSStepSNI], ls))
	fmt.Fprintf(w, "  common domain only (step 4)                                  %s\n", PctCI(total.LSSteps[LSStepDomain], ls))
	fmt.Fprintf(w, "  address only                                                 %s\n", PctCI(total.LSSteps[LSStepAddress], ls))
	fmt.Fprintf(w, "  readable handshake names refused by verification             %s\n", PctCI(total.LSRejected, ls))
	fmt.Fprintf(w, "  borrowed between processes of the same app (not counted as cross-process): %d\n", total.Sibling)

	printSites(w, keys, groups)

	fmt.Fprintln(w, "\nCAUSES (last-answer, all focus flows)")
	errs := 0
	for _, c := range naming.Causes {
		errs += total.Causes[c]
	}
	for _, c := range naming.Causes {
		fmt.Fprintf(w, "  %-14s %6d  %s\n", c, total.Causes[c], strings.TrimSpace(pct(total.Causes[c], errs)))
	}
	fmt.Fprintf(w, "  reference flags: ech-outer %d, ip-literal %d, coalescing candidates %d (of %d flows)\n",
		total.ECHOuter, total.IPLiteral, total.Coalesce, total.Flows)
	fmt.Fprintf(w, "  ech-outer = ECH extension and SNI in the front list: %s\n", strings.Join(decode.ECHFronts, ", "))

	var dnsA, dnsE int
	for _, r := range all {
		dnsA += r.DNS.Answers
		dnsE += r.DNS.Effective
	}
	fmt.Fprintf(w, "  DNS answers attributed to the asking app (effective PID): %s\n", PctCI(dnsE, dnsA))

	fmt.Fprintln(w, "\nECH BY SUBJECT (focus flows, all runs)")
	fmt.Fprintf(w, "  %-20s %6s  %-10s %s\n", "subject", "flows", "ech-outer", "ech offered (GREASE)")
	bySubj := map[string]*Counts{}
	var subjects []string
	for _, r := range all {
		if bySubj[r.Subject] == nil {
			c := newCounts()
			bySubj[r.Subject] = &c
			subjects = append(subjects, r.Subject)
		}
		bySubj[r.Subject].merge(r.Focus)
	}
	sort.Strings(subjects)
	for _, sub := range subjects {
		c := bySubj[sub]
		name := sub
		if name == "" {
			name = "(field)"
		}
		fmt.Fprintf(w, "  %-20s %6d  %-10d %-24s\n", trunc(name, 20), c.Flows, c.ECHOuter,
			fmt.Sprintf("%d  %s", c.ECHOffered, strings.TrimSpace(pct(c.ECHOffered, c.Flows))))
	}

	fmt.Fprintln(w, "\nAGAINST PUBLISHED BASELINES (units differ; see each line)")
	k, d := total.Disagreement()
	ho := total.Blind[StratLastAnswer]
	for _, b := range Baselines {
		ours := PctCI(k, d) + " of comparable flows"
		if b.Ours == "handshake-only" {
			ours = PctCI(ho, total.Flows) + " of flows"
		}
		fmt.Fprintf(w, "  %-52s %-44s %-5s  ours: %s\n", b.Source, b.Metric, b.Value, ours)
	}
	fmt.Fprintln(w, "\nScope: one machine. Per-app, per-version results are reproducible with")
	fmt.Fprintln(w, "tools/workload; population prevalence is not claimed.")
}

// WriteCSV writes one row per run for plotting.
func WriteCSV(w io.Writer, runs []RunSummary) error {
	cw := csv.NewWriter(w)
	head := []string{"file", "workload", "subject", "version", "doh", "cache", "network", "repeat",
		"flows", "bytes", "readable", "comparable", "wrong_last_answer", "blind_last_answer",
		"wrong_per_process", "blind_per_process", "cross_process", "ech_outer", "ech_offered", "coalesce", "ip_literal",
		"dns_answers", "dns_effective", "resolver", "resolver_ddr", "resolver_encrypted", "prior_dns_answers",
		"readable_no_coalesce", "comparable_no_coalesce", "wrong_last_answer_no_coalesce", "sibling_process",
		"ls_step2", "ls_step3", "ls_step4", "ls_address", "ls_step2_wrong", "ls_rejected", "sites"}
	for _, st := range Strategies {
		head = append(head, "shown_wrong_"+st, "shown_blind_"+st)
	}
	for _, c := range naming.Causes {
		head = append(head, "cause_"+string(c))
	}
	if err := cw.Write(head); err != nil {
		return err
	}
	for _, r := range runs {
		f := r.Focus
		ver := r.m("browser_version")
		if ver == "" {
			ver = r.m("app_version")
		}
		row := []string{filepath.Base(r.File), r.m("workload"), r.Subject, ver, r.m("doh"), r.m("cache"),
			r.m("network"), r.m("repeat"), itoa(f.Flows), strconv.FormatUint(f.Bytes, 10), itoa(f.Readable),
			itoa(f.Comparable), itoa(f.Wrong[StratLastAnswer]), itoa(f.Blind[StratLastAnswer]),
			itoa(f.Wrong[StratPerProcess]), itoa(f.Blind[StratPerProcess]), itoa(f.CrossProcess),
			itoa(f.ECHOuter), itoa(f.ECHOffered), itoa(f.Coalesce), itoa(f.IPLiteral), itoa(r.DNS.Answers), itoa(r.DNS.Effective),
			r.m("resolver"), r.m("resolver_ddr"), r.m("resolver_encrypted"), priorCell(r),
			itoa(f.ReadableNC), itoa(f.ComparableNC), itoa(f.SWrongNC[StratLastAnswer]), itoa(f.Sibling),
			itoa(f.LSSteps[LSStepDNS]), itoa(f.LSSteps[LSStepSNI]), itoa(f.LSSteps[LSStepDomain]), itoa(f.LSSteps[LSStepAddress]),
			itoa(f.LSStep2Wrong), itoa(f.LSRejected), itoa(len(r.Sites))}
		for _, st := range Strategies {
			row = append(row, itoa(f.SWrong[st]), itoa(f.SBlind[st]))
		}
		for _, c := range naming.Causes {
			row = append(row, itoa(f.Causes[c]))
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func itoa(n int) string { return strconv.Itoa(n) }

// priorCell is the CSV value for preloaded answers: empty when none were.
func priorCell(r RunSummary) string {
	if r.Prior == nil {
		return ""
	}
	return itoa(r.Prior.Answers)
}

// InFamily reports whether a process name belongs to a workload subject.
func InFamily(subject, comm string) bool { return inFamily(subject, comm) }
