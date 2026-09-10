package rules

import (
	"strings"
	"testing"
)

func TestParseHostsBlocklist(t *testing.T) {
	in := `# Title: test blocklist
# comment line
127.0.0.1 localhost
255.255.255.255 broadcasthost
0.0.0.0 ads.example
0.0.0.0 ADS.EXAMPLE     # duplicate, different case, inline comment
0.0.0.0 tracker.test
bare-domain.test
0.0.0.0 adult.example.com
not a domain
0.0.0.0 1.2.3.4
http://someurl.test/path
0.0.0.0 has.trailing.dot.

`
	got := ParseHostsBlocklist(strings.NewReader(in))
	want := map[string]bool{
		"ads.example": true, "tracker.test": true, "bare-domain.test": true,
		"adult.example.com": true, "has.trailing.dot": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d domains %v, want %d", len(got), got, len(want))
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("unexpected domain %q", d)
		}
	}
	// localhost/broadcasthost/IPs/URLs must all be rejected.
	for _, d := range got {
		if d == "localhost" || d == "1.2.3.4" || strings.Contains(d, "/") {
			t.Errorf("junk leaked through: %q", d)
		}
	}
}

func TestBlocklistRules(t *testing.T) {
	rs := BlocklistRules([]string{"a.test", "b.test"}, "adult")
	if len(rs) != 2 {
		t.Fatalf("got %d rules", len(rs))
	}
	for _, r := range rs {
		if r.Scope != ScopeDomain || r.Action != Block || !r.Enabled {
			t.Errorf("bad rule: %+v", r)
		}
		if !strings.Contains(r.Note, "adult") {
			t.Errorf("rule missing source tag: %+v", r)
		}
	}
}
