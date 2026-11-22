package naming

import (
	"net/netip"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

func at(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

func TestClassify(t *testing.T) {
	cdn := netip.MustParseAddr("104.18.32.7")
	l := NewLedger()
	l.DNS(cdn, "notion.so.", at(0), 300, 10, "Notion")
	l.DNS(cdn, "tracker.example", at(5), 300, 20, "Brave")
	l.DNS(cdn, "api.notion.so", at(6), 300, 10, "Notion")

	cases := []struct {
		name      string
		handshake string
		unseen    bool
		when      int
		pid       int32
		ip        netip.Addr
		want      Class
		cross     bool
	}{
		{"latest answer matches", "api.notion.so", false, 10, 10, cdn, Agree, false},
		{"answered earlier, not latest", "tracker.example", false, 10, 20, cdn, Alias, true},
		{"same registrable domain", "www.notion.so", false, 10, 10, cdn, SameSite, false},
		{"different organisation", "evil.example.net", false, 10, 30, cdn, Mismatch, true},
		{"before any later answer", "notion.so", false, 1, 10, cdn, Agree, false},
		{"no dns at all", "doh-only.example", false, 10, 10, netip.MustParseAddr("1.2.3.4"), HandshakeOnly, false},
		{"no handshake, dns exists", "", false, 10, 10, cdn, DNSOnly, false},
		{"predates capture", "", true, 10, 10, netip.MustParseAddr("1.2.3.4"), Unseen, false},
		{"direct to ip", "", false, 10, 10, netip.MustParseAddr("1.2.3.4"), Neither, false},
	}
	for _, c := range cases {
		v := Classify(c.handshake, c.unseen, l.Correlate(c.ip, at(c.when)), c.pid)
		if v.Class != c.want {
			t.Errorf("%s: class %s, want %s (%+v)", c.name, v.Class, c.want, v)
		}
		if v.CrossProcess != c.cross {
			t.Errorf("%s: cross %v, want %v", c.name, v.CrossProcess, c.cross)
		}
	}
}

// A DNS answer that arrives after the connection opened cannot have informed a
// monitor's decision at connect time, beyond capture-ordering slack.
func TestCorrelateIgnoresFuture(t *testing.T) {
	ip := netip.MustParseAddr("9.9.9.9")
	l := NewLedger()
	l.DNS(ip, "later.example", at(30), 300, 1, "")
	if c := l.Correlate(ip, at(10)); c.Pick != "" {
		t.Fatalf("picked a future answer: %+v", c)
	}
	if c := l.Correlate(ip, at(29)); c.Pick != "" {
		t.Fatalf("picked an answer a second in the future: %+v", c)
	}
	if c := l.Correlate(ip, at(30).Add(-50*time.Millisecond)); c.Pick != "later.example" {
		t.Fatalf("slack not applied: %+v", c)
	}
}

func TestTally(t *testing.T) {
	tl := NewTally()
	for _, c := range []Class{Agree, Agree, Mismatch, Alias, HandshakeOnly, DNSOnly, Unseen} {
		tl.Add(Verdict{Class: c})
	}
	if tl.Comparable() != 4 || tl.Readable() != 5 {
		t.Fatalf("comparable %d readable %d", tl.Comparable(), tl.Readable())
	}
	if d := tl.Disagreement(); d != 0.5 {
		t.Fatalf("disagreement %v", d)
	}
	if e := tl.CorrelationError(); e != 0.6 {
		t.Fatalf("correlation error %v", e)
	}
}

func TestBounded(t *testing.T) {
	ip := netip.MustParseAddr("1.1.1.1")
	l := NewLedger()
	for i := 0; i < 500; i++ {
		l.DNS(ip, "n.example", at(i), 300, 0, "")
		l.Handshake(ip, "n.example", at(i), 0)
	}
	if len(l.dns[ip]) != maxPerAddr || len(l.hs[ip]) != maxPerAddr {
		t.Fatalf("unbounded: %d %d", len(l.dns[ip]), len(l.hs[ip]))
	}
}

func TestPerProcessAndCauses(t *testing.T) {
	cdn := netip.MustParseAddr("104.18.32.7")
	l := NewLedger()
	l.DNS(cdn, "www.notion.so", at(0), 300, 10, "Notion")
	l.DNS(cdn, "ads.example", at(5), 300, 20, "Brave")

	// Global last-answer borrows Brave's lookup for Notion's connection.
	e := Evidence{Handshake: "www.notion.so", PID: 10, Opened: at(6)}
	g := Grade(e, l.Correlate(cdn, at(6)), l, cdn)
	if g.Class != Alias || g.Cause != CauseCrossProcess {
		t.Fatalf("global: %+v", g)
	}
	// Per-process correlation only consults Notion's own lookup and is right.
	p := Grade(e, l.CorrelateFor(cdn, at(6), 10), l, cdn)
	if p.Class != Agree || p.FanIn != 2 {
		t.Fatalf("per-process: %+v", p)
	}

	// Stale: the only answer expired by TTL long before the flow opened.
	old := netip.MustParseAddr("34.120.5.5")
	l.DNS(old, "old.example", at(0), 60, 30, "Safari")
	s := Grade(Evidence{Handshake: "new.example", PID: 30, Opened: at(600)}, l.Correlate(old, at(600)), l, old)
	if s.Class != Mismatch || s.Cause != CauseStale || !s.Stale {
		t.Fatalf("stale: %+v", s)
	}

	// ECH: the outer name is not the destination and is not compared.
	ech := Grade(Evidence{Handshake: "cloudflare-ech.com", ECH: true, PID: 10, Opened: at(6)}, l.Correlate(cdn, at(6)), l, cdn)
	if ech.Class != ECHOuter || ech.Cause != CauseNone {
		t.Fatalf("ech: %+v", ech)
	}

	// IP literal in SNI is not a name.
	lit := Grade(Evidence{Handshake: "104.18.32.7", PID: 10, Opened: at(6)}, l.Correlate(cdn, at(6)), l, cdn)
	if lit.Class != DNSOnly || !lit.IPLiteral {
		t.Fatalf("ip literal: %+v", lit)
	}

	// Coalescing: an h2 connection Brave opened for ads.example, to an address
	// Brave also resolved another name to; correlation's pick is that name.
	l.DNS(cdn, "cdn.brave-assets.example", at(7), 300, 20, "Brave")
	co := Grade(Evidence{Handshake: "ads.example", ALPN: "h2", PID: 20, Opened: at(8), LastSeen: at(60)},
		l.Correlate(cdn, at(8)), l, cdn)
	if co.Cause != CauseCoalesced || len(co.Coalesce) != 1 {
		t.Fatalf("coalesce: %+v", co)
	}
	// Bypass: no DNS at all.
	by := Grade(Evidence{Handshake: "doh.example", PID: 1, Opened: at(1)}, l.Correlate(netip.MustParseAddr("9.9.9.9"), at(1)), l, netip.MustParseAddr("9.9.9.9"))
	if by.Class != HandshakeOnly || by.Cause != CauseBypass {
		t.Fatalf("bypass: %+v", by)
	}
}

func TestTallyUnits(t *testing.T) {
	tl := NewTally()
	tl.AddFlow(Verdict{Class: Agree, Handshake: "a.example"}, "Safari", 100)
	tl.AddFlow(Verdict{Class: Agree, Handshake: "a.example"}, "Safari", 50)
	tl.AddFlow(Verdict{Class: Agree, Handshake: "a.example"}, "Chrome", 10)
	if tl.ByClass[Agree] != 3 || tl.Bytes[Agree] != 160 || tl.Pairs[Agree] != 2 {
		t.Fatalf("%+v", tl)
	}
}
