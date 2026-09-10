package api

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ohmyosi/internal/enrich"
)

// writeRecording lays down an NDJSON recording the way the Recorder does, so
// the tests exercise the same path a real file takes.
func writeRecording(t *testing.T, name string, envs []Envelope) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	r, err := NewRecorder(path, "test", "testhost", "pktap,all")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range envs {
		r.Write(e)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func flowTo(id, comm string, pid int32, host, domain, ip string, port uint16) FlowView {
	return FlowView{
		ID: id, Proto: "tcp", PID: pid, Comm: comm,
		Remote:    Endpoint{IP: ip, Port: port, Host: host, Domain: domain},
		BytesUp:   1000,
		BytesDown: 2000,
		FirstSeen: 100, LastSeen: 200, State: "active",
	}
}

func TestSummarizeCollapsesFlowsIntoRelationships(t *testing.T) {
	// Three sockets to the same site from the same app is one relationship,
	// not three. That collapse is the whole reason a day-over-day diff is
	// readable at all.
	path := writeRecording(t, "a.ndjson", []Envelope{
		{Type: "hello", T: 100, Host: &Host{Hostname: "testhost", Iface: "pktap,all"},
			Procs: []enrich.Proc{{PID: 40, Name: "Brave Browser Helper", App: "Brave Browser", Signing: "developer-id"}},
			Flows: []FlowView{
				flowTo("f1", "Brave Helper", 40, "www.github.com", "github.com", "140.82.1.1", 443),
				flowTo("f2", "Brave Helper", 40, "api.github.com", "github.com", "140.82.1.2", 443),
			}},
		{Type: "tick", T: 101, Flows: []FlowView{
			flowTo("f3", "Brave Helper", 40, "codeload.github.com", "github.com", "140.82.1.3", 443),
		}},
	})

	s, err := Summarize(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Pairs) != 1 {
		t.Fatalf("want 1 relationship, got %d: %v", len(s.Pairs), keysOf(s))
	}
	p := s.Pairs["Brave Browser → github.com"]
	if p == nil {
		t.Fatalf("relationship keyed by app bundle and domain not found: %v", keysOf(s))
	}
	if p.Flows != 3 {
		t.Errorf("want 3 flows folded in, got %d", p.Flows)
	}
	if p.Level != LevelDomain {
		t.Errorf("want domain-level identification, got %q", p.Level)
	}
	if len(p.Addrs) != 3 {
		t.Errorf("want all 3 addresses kept, got %v", p.Addrs)
	}
	if p.Sign != "developer-id" {
		t.Errorf("signing verdict lost: %q", p.Sign)
	}
}

func TestSummarizeDoesNotMultiplyBytesByTicks(t *testing.T) {
	// Recorded byte counters are cumulative per flow. Summing them every tick
	// would report a long-lived connection as hundreds of times its real size,
	// which would make every "traffic up 10x" note a lie.
	f := flowTo("f1", "curl", 9, "example.com", "example.com", "93.184.216.34", 443)
	f.BytesUp, f.BytesDown = 500, 1500
	f2 := f
	f2.BytesUp, f2.BytesDown = 900, 4000 // same flow, later tick

	path := writeRecording(t, "b.ndjson", []Envelope{
		{Type: "hello", T: 10, Flows: []FlowView{f}},
		{Type: "tick", T: 11, Flows: []FlowView{f2}},
		{Type: "tick", T: 12, Flows: []FlowView{f2}},
	})
	s, err := Summarize(path)
	if err != nil {
		t.Fatal(err)
	}
	p := s.Pairs["curl → example.com"]
	if p == nil {
		t.Fatalf("missing pair: %v", keysOf(s))
	}
	if p.BytesUp != 900 || p.BytesDown != 4000 {
		t.Errorf("want the last cumulative counters (900/4000), got %d/%d", p.BytesUp, p.BytesDown)
	}
	if p.Flows != 1 {
		t.Errorf("one flow seen three times is still one flow, got %d", p.Flows)
	}
}

func TestDestIdentityPrefersWhoYouAskedForOverWhoOwnsTheAddress(t *testing.T) {
	cases := []struct {
		name string
		in   Endpoint
		want string
		lvl  Level
	}{
		{"domain wins over everything",
			Endpoint{IP: "1.2.3.4", Host: "api.cursor.sh", Domain: "cursor.sh", ASN: 16509, ASNOrg: "AMAZON-02", Org: "AWS"},
			"cursor.sh", LevelDomain},
		{"a name with no registrable domain is still a name",
			Endpoint{IP: "10.0.0.5", Host: "nas.local"},
			"nas.local", LevelHost},
		{"no name at all falls back to the owning network, and says so",
			Endpoint{IP: "52.1.2.3", ASN: 16509, ASNOrg: "AMAZON-02"},
			"AS16509 AMAZON-02", LevelNetwork},
		{"nothing known leaves the bare address",
			Endpoint{IP: "203.0.113.9"},
			"203.0.113.9", LevelAddress},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, lvl := destIdentity(c.in)
			if got != c.want || lvl != c.lvl {
				t.Errorf("got %q/%s, want %q/%s", got, lvl, c.want, c.lvl)
			}
		})
	}
}

func TestCompareReportsAppearedGoneAndChanged(t *testing.T) {
	base := writeRecording(t, "base.ndjson", []Envelope{
		{Type: "hello", T: 1000, Host: &Host{Hostname: "testhost"},
			Procs: []enrich.Proc{{PID: 40, Name: "Brave Browser Helper", App: "Brave Browser"}},
			Flows: []FlowView{
				flowTo("f1", "Brave Helper", 40, "www.github.com", "github.com", "140.82.1.1", 443),
			}},
	})

	loud := flowTo("f9", "updater", 77, "", "", "45.61.2.3", 8443)
	loud.DirectIP = true
	loud.Suspicion, loud.SuspicionBand = 62, "unusual"
	loud.Reasons = []string{"connects straight to an address with no name announced", "destination is in no published allocation list"}

	grew := flowTo("f1", "Brave Helper", 40, "www.github.com", "github.com", "140.82.1.1", 443)
	grew.BytesUp, grew.BytesDown = 50_000_000, 1000

	today := writeRecording(t, "today.ndjson", []Envelope{
		{Type: "hello", T: 90000, Host: &Host{Hostname: "testhost"},
			Procs: []enrich.Proc{
				{PID: 40, Name: "Brave Browser Helper", App: "Brave Browser"},
				{PID: 77, Name: "updater", Signing: "unsigned"},
			},
			Flows: []FlowView{grew, loud}},
	})

	a, err := Summarize(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Summarize(today)
	if err != nil {
		t.Fatal(err)
	}
	d := Compare(a, b)

	if len(d.Appeared) != 1 || d.Appeared[0].App != "updater" {
		t.Fatalf("want the unsigned updater as the one new relationship, got %+v", d.Appeared)
	}
	if d.Appeared[0].Level != LevelAddress {
		t.Errorf("an unnamed destination must be marked as address-level, got %s", d.Appeared[0].Level)
	}
	if len(d.NewApps) != 1 || d.NewApps[0] != "updater" {
		t.Errorf("want updater as a newly-talking app, got %v", d.NewApps)
	}
	if len(d.Gone) != 0 {
		t.Errorf("nothing stopped, got %+v", d.Gone)
	}
	if len(d.Changed) != 1 {
		t.Fatalf("want the github relationship flagged as changed, got %+v", d.Changed)
	}
	notes := strings.Join(d.Changed[0].Notes, " | ")
	if !strings.Contains(notes, "traffic up") || !strings.Contains(notes, "upload now dominates") {
		t.Errorf("changed notes must name what changed, got %q", notes)
	}

	// The report has to carry the reasons, not just the verdict.
	var buf bytes.Buffer
	d.Report(&buf, 25)
	out := buf.String()
	for _, want := range []string{
		"new relationships (1)",
		"updater → 45.61.2.3",
		"[address]",
		"62/unusual",
		"no name announced",
		"binary is unsigned",
		"connects straight to an address with no name announced",
		"relationships that changed character (1)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n---\n%s", want, out)
		}
	}
}

func TestCompareIsSymmetricAboutDisappearance(t *testing.T) {
	a := writeRecording(t, "a.ndjson", []Envelope{
		{Type: "hello", T: 1, Flows: []FlowView{
			flowTo("f1", "backupd", 5, "s3.amazonaws.com", "amazonaws.com", "52.1.1.1", 443)}},
	})
	b := writeRecording(t, "b.ndjson", []Envelope{
		{Type: "hello", T: 2, Flows: []FlowView{
			flowTo("f2", "mDNSResponder", 6, "one.one.one.one", "one.one", "1.1.1.1", 53)}},
	})
	sa, _ := Summarize(a)
	sb, _ := Summarize(b)
	d := Compare(sa, sb)
	if len(d.Appeared) != 1 || len(d.Gone) != 1 {
		t.Fatalf("want one appeared and one gone, got %d/%d", len(d.Appeared), len(d.Gone))
	}
	if len(d.GoneApps) != 1 || d.GoneApps[0] != "backupd" {
		t.Errorf("a process that stopped calling home is a finding too, got %v", d.GoneApps)
	}
}

func TestSummarizeRejectsAFileThatIsNotARecording(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("this is not a recording\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Summarize(path); err == nil {
		t.Fatal("want an error naming the file, got none")
	}
}

func TestSelfTrafficIsNotTheMachinesBehaviour(t *testing.T) {
	// ohmyosi's own RDAP and reverse-DNS lookups would otherwise show up as a
	// new relationship on any day the user turned those flags on.
	f := flowTo("f1", "ohmyosi", 1, "rdap.org", "rdap.org", "1.2.3.4", 443)
	f.Self = true
	path := writeRecording(t, "self.ndjson", []Envelope{{Type: "hello", T: 5, Flows: []FlowView{f}}})
	s, err := Summarize(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Pairs) != 0 {
		t.Errorf("self traffic must not become a relationship, got %v", keysOf(s))
	}
}

func keysOf(s *Session) []string {
	var out []string
	for k := range s.Pairs {
		out = append(out, k)
	}
	return out
}
