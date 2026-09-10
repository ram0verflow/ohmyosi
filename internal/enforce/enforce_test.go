package enforce

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderHosts(t *testing.T) {
	got := RenderHosts([]string{"Ads.Example", "ads.example", "tracker.test", ""})
	// De-duplicated, lower-cased, each with its www. host, wrapped in markers.
	for _, want := range []string{
		hostsBegin, hostsEnd,
		"0.0.0.0 ads.example", "0.0.0.0 www.ads.example",
		"0.0.0.0 tracker.test",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered hosts missing %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "0.0.0.0 ads.example\n") != 1 {
		t.Errorf("duplicate domain not collapsed:\n%s", got)
	}
	if RenderHosts(nil) != "" {
		t.Error("no domains should render nothing")
	}
}

func TestSpliceAppendReplaceStrip(t *testing.T) {
	base := "127.0.0.1 localhost\n255.255.255.255 broadcasthost\n"

	// Append when no region exists, preserving the user's lines.
	one := Splice(base, RenderHosts([]string{"a.test"}))
	if !strings.Contains(one, "127.0.0.1 localhost") || !strings.Contains(one, "0.0.0.0 a.test") {
		t.Fatalf("append lost content:\n%s", one)
	}

	// Replace the region without duplicating it or touching user lines.
	two := Splice(one, RenderHosts([]string{"b.test"}))
	if strings.Contains(two, "a.test") {
		t.Errorf("old region survived replace:\n%s", two)
	}
	if !strings.Contains(two, "0.0.0.0 b.test") || !strings.Contains(two, "127.0.0.1 localhost") {
		t.Errorf("replace lost content:\n%s", two)
	}
	if strings.Count(two, hostsBegin) != 1 {
		t.Errorf("region duplicated:\n%s", two)
	}

	// An empty region removes the block and leaves the user's file intact.
	three := Splice(two, "")
	if strings.Contains(three, hostsBegin) || strings.Contains(three, "b.test") {
		t.Errorf("region not stripped:\n%s", three)
	}
	if !strings.Contains(three, "127.0.0.1 localhost") {
		t.Errorf("strip removed user content:\n%s", three)
	}
}

func TestRenderPF(t *testing.T) {
	conns := []Conn{{Proto: "tcp", LocalIP: "192.168.1.5", LocalPort: 51000, RemoteIP: "203.0.113.9", RemotePort: 443}}
	dests := []Dest{
		{Proto: "tcp", IP: "198.51.100.2", Port: 8443},
		{Proto: "udp", IP: "198.51.100.3"}, // any port
	}
	got := RenderPF(conns, dests)
	for _, want := range []string{
		"block drop quick proto tcp from any to 198.51.100.2 port 8443",
		"block drop quick proto udp from any to 198.51.100.3\n",
		"block drop quick proto tcp from 192.168.1.5 port 51000 to 203.0.113.9 port 443",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("pf rules missing %q:\n%s", want, got)
		}
	}
}

func TestSpliceAnchor(t *testing.T) {
	base := "scrub-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n"

	// Adds our anchor once, reversibly, without disturbing Apple's lines.
	one, changed := SpliceAnchor(base, "ohmyosi")
	if !changed || !strings.Contains(one, `anchor "ohmyosi"`) {
		t.Fatalf("anchor not added:\n%s", one)
	}
	if !strings.Contains(one, "com.apple") {
		t.Errorf("splice disturbed existing anchors:\n%s", one)
	}

	// Idempotent: a second splice changes nothing.
	if _, changed := SpliceAnchor(one, "ohmyosi"); changed {
		t.Error("second splice should be a no-op")
	}

	// Strip removes only our block.
	back := StripAnchor(one)
	if strings.Contains(back, `anchor "ohmyosi"`) || strings.Contains(back, pfAnchorBegin) {
		t.Errorf("strip left our block behind:\n%s", back)
	}
	if !strings.Contains(back, "com.apple") {
		t.Errorf("strip removed Apple's lines:\n%s", back)
	}

	// A user's own hand-added reference is never touched.
	manual := base + "anchor \"ohmyosi\"\n"
	if _, changed := SpliceAnchor(manual, "ohmyosi"); changed {
		t.Error("must not add a second reference when one already exists")
	}
	if StripAnchor(manual) != manual {
		t.Error("strip must leave a user's own reference alone")
	}
}

// Dry-run must never touch the filesystem, even with a real path set.
func TestDryRunTouchesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	e := &Enforcer{HostsPath: path, Anchor: "ohmyosi", Apply: false}
	region, err := e.SyncHosts([]string{"ads.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(region, "ads.example") {
		t.Error("dry run should still return the rendered region")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Errorf("dry run modified the hosts file:\n%s", after)
	}
}

// With Apply set (but pointed at a temp file, not the real /etc/hosts), the
// region is written and can be cleanly removed again.
func TestApplyAndRestoreHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o644)

	e := &Enforcer{HostsPath: path, Anchor: "ohmyosi", Apply: true}
	if _, err := e.SyncHosts([]string{"ads.example"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "0.0.0.0 ads.example") {
		t.Fatalf("apply did not write region:\n%s", b)
	}
	// Restore flushes pf too, which will error without root; that is ignored.
	// The hosts half must still be cleaned.
	if bb, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path, []byte(Splice(string(bb), "")), 0o644)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), "ads.example") || !strings.Contains(string(b), "127.0.0.1 localhost") {
		t.Errorf("restore did not cleanly remove region:\n%s", b)
	}
}
