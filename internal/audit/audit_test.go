package audit

import (
	"net/netip"
	"strings"
	"testing"

	"ohmyosi/internal/naming"
)

var blocked = []string{"doubleclick.net", "telemetry.example"}

func TestBlockedBy(t *testing.T) {
	for name, want := range map[string]string{
		"ad.doubleclick.net":   "doubleclick.net",
		"doubleclick.net.":     "doubleclick.net",
		"notdoubleclick.net":   "",
		"v1.telemetry.example": "telemetry.example",
		"":                     "",
	} {
		if got := BlockedBy(name, blocked); got != want {
			t.Errorf("%q: %q want %q", name, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	ip := netip.MustParseAddr("142.250.1.1")
	doh := naming.Verdict{Class: naming.HandshakeOnly, Handshake: "ad.doubleclick.net"}
	e, ok := Check("f1", "Brave", 42, ip, true, doh, blocked)
	if !ok || e.Rule != "doubleclick.net" || !strings.Contains(e.Route, "DoH") {
		t.Fatalf("missed evasion: %+v %v", e, ok)
	}
	// No reply: the block (or something) worked - not an evasion.
	if _, ok := Check("f1", "Brave", 42, ip, false, doh, blocked); ok {
		t.Fatal("unanswered handshake counted as evasion")
	}
	// Sinkholed: the hosts file sent it to 0.0.0.0.
	if _, ok := Check("f1", "Brave", 42, netip.MustParseAddr("0.0.0.0"), true, doh, blocked); ok {
		t.Fatal("sinkhole counted as evasion")
	}
	// Unblocked names are none of our business.
	if _, ok := Check("f1", "Brave", 42, ip, true, naming.Verdict{Handshake: "example.org"}, blocked); ok {
		t.Fatal("unblocked name flagged")
	}
}

func TestLoopVerifiedSkipsShared(t *testing.T) {
	l := NewLoop()
	a := Evasion{FlowID: "a", Comm: "x", Name: "t.telemetry.example", Rule: "telemetry.example", Addr: "203.0.113.5", Shared: 1}
	b := Evasion{FlowID: "b", Comm: "y", Name: "ad.doubleclick.net", Rule: "doubleclick.net", Addr: "104.18.0.1", Shared: 40}
	if !l.Observe(a) || !l.Observe(b) || l.Observe(a) {
		t.Fatal("dedup by flow broken")
	}
	if got := l.Verified(false); len(got) != 1 || got[0].String() != "203.0.113.5" {
		t.Fatalf("verified %v", got)
	}
	if got := l.Verified(true); len(got) != 2 {
		t.Fatalf("verified with shared %v", got)
	}
	tbl := RenderTable(l.Verified(false))
	if !strings.Contains(tbl, "<ohmyosi_verified> persist { 203.0.113.5 }") || !strings.Contains(tbl, "block return out quick") {
		t.Fatalf("table:\n%s", tbl)
	}
}

func TestAuditHosts(t *testing.T) {
	good := "127.0.0.1 localhost\n0.0.0.0 doubleclick.net\n0.0.0.0 telemetry.example\n"
	if p := AuditHosts(good, blocked); p != nil {
		t.Fatalf("false alarm: %v", p)
	}
	tampered := "127.0.0.1 localhost\n# 0.0.0.0 doubleclick.net\n0.0.0.0 telemetry.example\n"
	if p := AuditHosts(tampered, blocked); len(p) != 1 || !strings.Contains(p[0].Detail, "doubleclick.net") {
		t.Fatalf("missed tamper: %v", p)
	}
}

func TestAuditPF(t *testing.T) {
	if p := AuditPF("Status: Enabled for 0 days", "block drop quick ...", true); p != nil {
		t.Fatalf("false alarm %v", p)
	}
	if p := AuditPF("Status: Disabled", "", true); len(p) != 2 {
		t.Fatalf("want 2 problems, got %v", p)
	}
}
