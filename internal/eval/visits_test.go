package eval

import (
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"ohmyosi/internal/naming"
)

func TestSiteOf(t *testing.T) {
	log := "1000\tchrome-1\ta.example\n1000\tchrome-2\tb.example\n7000\tchrome-1\tc.example\nbad line\n"
	visits := parseVisits(strings.NewReader(log))
	if len(visits) != 3 {
		t.Fatalf("parsed %d visits", len(visits))
	}
	lanes := lanePIDs(map[string]any{"lanes": []any{
		map[string]any{"id": "chrome-1", "pids": []any{float64(11), float64(12)}},
		map[string]any{"id": "chrome-2", "pids": []any{float64(21)}},
	}})
	at := func(ms int64) time.Time { return time.UnixMilli(ms) }
	cases := []struct {
		pid  int32
		ms   int64
		want string
	}{
		{11, 2000, "a.example"},  // lane 1, first visit
		{21, 8000, "b.example"},  // lane 2 never moved on
		{12, 7500, "c.example"},  // lane 1 helper, second visit
		{99, 2000, ""},           // outside every lane: background
		{11, 500, ""},            // before any visit
		{21, 1000 + 3*60000, ""}, // long after its visit
	}
	for _, c := range cases {
		if got := siteOf(visits, lanes, "", FlowResult{PID: c.pid, Opened: at(c.ms)}); got != c.want {
			t.Errorf("pid %d at %d: %q, want %q", c.pid, c.ms, got, c.want)
		}
	}
	// A PID in no lane falls back to the only lane of its browser (Safari).
	if got := siteOf(visits, lanes, "chrome-2", FlowResult{PID: 99, Opened: at(2000)}); got != "b.example" {
		t.Errorf("fallback: %q", got)
	}
	m := map[string]any{"lanes": []any{map[string]any{"id": "safari-1", "browser": "safari"}, map[string]any{"id": "chrome-1", "browser": "chrome"}, map[string]any{"id": "chrome-2", "browser": "chrome"}}}
	if onlyLane(m, "safari") != "safari-1" || onlyLane(m, "chrome") != "" {
		t.Errorf("onlyLane")
	}
	// No lanes: one sequential lane.
	if got := siteOf(visits, nil, "", FlowResult{PID: 99, Opened: at(7100)}); got != "c.example" {
		t.Errorf("sequential: %q", got)
	}
}

func TestPerSite(t *testing.T) {
	mk := func(k, d int) *Counts {
		c := newCounts()
		c.Readable, c.SWrong[StratLastAnswer] = d, k
		return &c
	}
	r := perSite([]*Counts{mk(0, 4), mk(1, 4), mk(2, 4), mk(4, 4), mk(1, 2)}, func(c *Counts) (int, int) { return c.ShownError(StratLastAnswer) })
	if r.N != 4 { // the 2-flow site is below the minimum
		t.Fatalf("n %d", r.N)
	}
	if math.Abs(r.Median-0.375) > 1e-9 || math.Abs(r.Q1-0.1875) > 1e-9 || math.Abs(r.Q3-0.625) > 1e-9 {
		t.Fatalf("quartiles %+v", r)
	}
}

func readable(h, pick string, coalesce []string) FlowResult {
	v := naming.Verdict{Class: naming.Agree, Handshake: h, DNSPick: pick, Coalesce: coalesce}
	if h != pick {
		v.Class = naming.Mismatch
	}
	return FlowResult{Verdicts: map[string]naming.Verdict{StratLastAnswer: v, StratPerProcess: v},
		Shown: map[string]Shown{StratLastAnswer: {pick, "read"}, StratLittleSnitch: {"example.com", "domain"}}}
}

func TestCoalescingSplit(t *testing.T) {
	c := newCounts()
	c.add(readable("a.example.com", "a.example.com", nil))
	c.add(readable("a.example.com", "x.other.net", nil))
	c.add(readable("www.gstatic.com", "fonts.gstatic.com", []string{"fonts.gstatic.com"}))
	if k, d := c.Disagreement(); k != 2 || d != 3 {
		t.Fatalf("all %d/%d", k, d)
	}
	if k, d := c.DisagreementNC(); k != 1 || d != 2 {
		t.Fatalf("excluding coalescing %d/%d", k, d)
	}
	// A domain-level name agrees when it is the handshake's registrable domain.
	if got := shownOutcome(readable("a.example.com", "a.example.com", nil), StratLittleSnitch); got != "agree" {
		t.Fatalf("domain-level outcome %q", got)
	}
}

func TestSiblingIsNotCrossProcess(t *testing.T) {
	ledger := naming.NewLedger()
	ip := mustAddr("104.18.32.7")
	t0 := time.Unix(1_700_000_000, 0)
	ledger.DNS(ip, "a.example.com", t0, 300, 501, "Google Chrome He")
	c := ledger.Correlate(ip, t0.Add(time.Second))
	sib := naming.Grade(naming.Evidence{Handshake: "b.example.com", PID: 777, Comm: "Google Chrome He", Opened: t0.Add(time.Second)}, c, ledger, ip)
	if sib.CrossProcess || !sib.SiblingProcess {
		t.Fatalf("two Chrome instances: %+v", sib)
	}
	x := naming.Grade(naming.Evidence{Handshake: "b.example.com", PID: 888, Comm: "Slack Helper", Opened: t0.Add(time.Second)}, c, ledger, ip)
	if !x.CrossProcess || x.SiblingProcess {
		t.Fatalf("Slack borrowing Chrome's lookup: %+v", x)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
