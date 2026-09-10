package rules

import (
	"path/filepath"
	"testing"
)

func newSet(t *testing.T) *Set {
	s := New(filepath.Join(t.TempDir(), "rules.json"))
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDefaultAllow(t *testing.T) {
	s := newSet(t)
	d := s.Decide(Target{App: "Brave", Domain: "google.com", IP: "1.1.1.1", Port: 443})
	if d.Action != Allow || d.Rule != nil {
		t.Fatalf("no rules should mean default allow, got %+v", d)
	}
	if d.Blocked() {
		t.Error("default-allow must not report as blocked")
	}
}

func TestAppBlock(t *testing.T) {
	s := newSet(t)
	s.Add(Rule{Scope: ScopeApp, Match: "spotify", Action: Block, Enabled: true})

	// The named app is blocked...
	if d := s.Decide(Target{App: "Spotify", IP: "2.2.2.2", Port: 443}); !d.Blocked() {
		t.Errorf("Spotify should be blocked, got %+v", d)
	}
	// ...but a different app to the same address is not - the whole point of
	// per-app control.
	if d := s.Decide(Target{App: "Brave Browser", IP: "2.2.2.2", Port: 443}); d.Blocked() {
		t.Errorf("Brave should not be caught by a Spotify rule, got %+v", d)
	}
}

func TestDomainSubdomainMatch(t *testing.T) {
	s := newSet(t)
	s.Add(Rule{Scope: ScopeDomain, Match: "doubleclick.net", Action: Block, Enabled: true})

	cases := map[string]bool{
		"doubleclick.net":          true,
		"ad.g.doubleclick.net":     true,
		"notdoubleclick.net":       false,
		"doubleclick.net.evil.com": false,
	}
	for host, want := range cases {
		got := s.Decide(Target{Host: host}).Blocked()
		if got != want {
			t.Errorf("host %q: blocked=%v, want %v", host, got, want)
		}
	}
}

func TestAllowBeatsBlock(t *testing.T) {
	s := newSet(t)
	s.Add(Rule{Scope: ScopeApp, Match: "curl", Action: Block, Enabled: true})
	s.Add(Rule{Scope: ScopeDomain, Match: "github.com", Action: Allow, Enabled: true})

	// curl is blocked in general...
	if d := s.Decide(Target{Comm: "curl", Domain: "evil.test"}); !d.Blocked() {
		t.Errorf("curl should be blocked by default, got %+v", d)
	}
	// ...except to an explicitly allowed domain.
	if d := s.Decide(Target{Comm: "curl", Domain: "github.com"}); d.Blocked() {
		t.Errorf("allow rule for github.com must win over the curl block, got %+v", d)
	}
}

func TestDestAndPort(t *testing.T) {
	s := newSet(t)
	s.Add(Rule{Scope: ScopeDest, Match: "9.9.9.9:853", Action: Block, Enabled: true})
	s.Add(Rule{Scope: ScopePort, Match: "23", Action: Block, Enabled: true})

	if d := s.Decide(Target{IP: "9.9.9.9", Port: 853}); !d.Blocked() {
		t.Error("ip:port dest rule should block")
	}
	if d := s.Decide(Target{IP: "9.9.9.9", Port: 443}); d.Blocked() {
		t.Error("ip:port rule must not block a different port")
	}
	if d := s.Decide(Target{IP: "5.5.5.5", Port: 23}); !d.Blocked() {
		t.Error("telnet port rule should block regardless of host")
	}
}

// IPv6 addresses are full of colons, so a bare v6 dest rule must not be parsed
// as host:port. This is a regression test for exactly that bug.
func TestDestIPv6(t *testing.T) {
	s := newSet(t)
	s.Add(Rule{Scope: ScopeDest, Match: "2607:6bc0::10", Action: Block, Enabled: true})
	s.Add(Rule{Scope: ScopeDest, Match: "[2a02:26f7::1]:853", Action: Block, Enabled: true})

	if d := s.Decide(Target{IP: "2607:6bc0::10", Port: 443}); !d.Blocked() {
		t.Error("bare IPv6 dest rule should block on any port")
	}
	if d := s.Decide(Target{IP: "2a02:26f7::1", Port: 853}); !d.Blocked() {
		t.Error("bracketed IPv6:port dest rule should block")
	}
	if d := s.Decide(Target{IP: "2a02:26f7::1", Port: 443}); d.Blocked() {
		t.Error("IPv6:port rule must not block a different port")
	}
}

func TestDisabledRuleIgnored(t *testing.T) {
	s := newSet(t)
	s.Add(Rule{Scope: ScopeApp, Match: "spotify", Action: Block, Enabled: false})
	if d := s.Decide(Target{App: "Spotify"}); d.Blocked() {
		t.Error("a disabled rule must not take effect")
	}
}

func TestPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	s1 := New(path)
	if err := s1.Load(); err != nil {
		t.Fatal(err)
	}
	r, _ := s1.Add(Rule{Scope: ScopeDomain, Match: "ads.example", Action: Block, Enabled: true})

	s2 := New(path)
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	if len(s2.List()) != 1 {
		t.Fatalf("rule did not persist: %d rules", len(s2.List()))
	}
	if ok, _ := s2.Remove(r.ID); !ok {
		t.Error("remove reported nothing removed")
	}
	if len(s2.List()) != 0 {
		t.Error("rule not removed")
	}
}

func TestRemoveByNote(t *testing.T) {
	s := newSet(t)
	s.AddMany(BlocklistRules([]string{"a.test", "b.test", "c.test"}, "adult"))
	s.Add(Rule{Scope: ScopeApp, Match: "curl", Action: Block, Enabled: true, Note: "added in app"})

	n, err := s.RemoveByNote("blocklist: adult")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("removed %d, want 3", n)
	}
	// The hand-made rule with a different note survives.
	if len(s.List()) != 1 || s.List()[0].Match != "curl" {
		t.Errorf("bulk delete took the wrong rules: %+v", s.List())
	}
}

func TestBlockedDomains(t *testing.T) {
	s := newSet(t)
	s.Add(Rule{Scope: ScopeDomain, Match: "a.test", Action: Block, Enabled: true})
	s.Add(Rule{Scope: ScopeDomain, Match: "b.test", Action: Block, Enabled: false}) // disabled
	s.Add(Rule{Scope: ScopeApp, Match: "x", Action: Block, Enabled: true})          // not a domain
	got := s.BlockedDomains()
	if len(got) != 1 || got[0] != "a.test" {
		t.Errorf("BlockedDomains = %v, want [a.test]", got)
	}
}
