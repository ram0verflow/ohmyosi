package score

import (
	"strings"
	"testing"
	"time"
)

// Ordinary traffic must score near zero. A detector that flags everything is
// the same as no detector, and it is the failure mode this design invites.
func TestOrdinaryTrafficIsQuiet(t *testing.T) {
	r := Evaluate(Input{
		DirectIP: false, HasName: true, HasOrg: true,
		RemotePort: 443, Proto: "tcp",
		ExecPath:      "/Applications/Safari.app/Contents/MacOS/Safari",
		DomainAgeDays: 4000,
	})
	if r.Score != 0 || r.Band != "quiet" {
		t.Fatalf("ordinary traffic scored %d (%s): %#v", r.Score, r.Band, r.Signals)
	}
}

// A browser talking to an unnamed Cloudflare address over QUIC is extremely
// common and must not be loud just because the name is missing.
func TestUnnamedButKnownHostIsOnlyNotable(t *testing.T) {
	r := Evaluate(Input{
		DirectIP: true, HasName: false, HasOrg: true,
		RemotePort:    443,
		ExecPath:      "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		DomainAgeDays: -1,
	})
	if r.Band != "notable" {
		t.Fatalf("expected notable, got %d (%s)", r.Score, r.Band)
	}
}

// The shape we actually care about: a binary somewhere unusual, dialling a
// bare address on an odd port, at a metronome cadence.
func TestBeaconShapeIsLoud(t *testing.T) {
	r := Evaluate(Input{
		DirectIP: true, HasName: false, HasOrg: false,
		RemotePort:       8443,
		ExecPath:         "/tmp/updater",
		DomainAgeDays:    -1,
		BeaconRegularity: 0.96, BeaconSamples: 9,
	})
	if r.Band != "loud" {
		t.Fatalf("expected loud, got %d (%s)", r.Score, r.Band)
	}
	if len(r.Signals) < 4 {
		t.Fatalf("a loud score must be able to justify itself: %#v", r.Signals)
	}
}

// Every point must come with a sentence. A score that cannot explain itself is
// the thing this package exists to avoid.
func TestEveryPointIsExplained(t *testing.T) {
	r := Evaluate(Input{
		DirectIP: true, RemotePort: 4444, ExecPath: "/tmp/x",
		BeaconRegularity: 0.95, BeaconSamples: 6, DomainAgeDays: 3,
	})
	sum := 0
	for _, s := range r.Signals {
		if s.Reason == "" {
			t.Error("a signal with no reason")
		}
		if s.Points <= 0 {
			t.Errorf("signal %q contributed %d", s.Reason, s.Points)
		}
		sum += s.Points
	}
	if r.Score != min(sum, 100) {
		t.Fatalf("score %d does not equal the sum of its reasons %d", r.Score, sum)
	}
}

// ohmyosi's own traffic must never be scored; it would flag its own reverse
// DNS lookups as direct-IP contacts forever.
func TestSelfIsNeverScored(t *testing.T) {
	r := Evaluate(Input{IsSelf: true, DirectIP: true, ExecPath: "/tmp/x", RemotePort: 9999})
	if r.Score != 0 || len(r.Signals) != 0 {
		t.Fatalf("self traffic scored %d: %#v", r.Score, r.Signals)
	}
}

// Regularity: evenly spaced connections score high, bursty ones do not.
func TestBeaconRegularity(t *testing.T) {
	base := time.Now().Add(-10 * time.Minute)

	steady := NewTracker()
	for i := 0; i < 8; i++ {
		steady.Observe("k", base.Add(time.Duration(i)*30*time.Second))
	}
	reg, n := steady.Regularity("k")
	if n != 8 || reg < 0.95 {
		t.Fatalf("metronome cadence scored %.2f over %d samples", reg, n)
	}

	// Human-driven traffic: clustered, then a gap, then clustered.
	bursty := NewTracker()
	offsets := []time.Duration{0, 4, 9, 15, 240, 246, 251, 258}
	for _, o := range offsets {
		bursty.Observe("k", base.Add(o*time.Second))
	}
	reg, _ = bursty.Regularity("k")
	if reg >= 0.80 {
		t.Fatalf("bursty traffic scored %.2f, high enough to be called a beacon", reg)
	}
}

// Too few samples proves nothing, and a cadence outside a plausible check-in
// range (sub-second, or hours apart) is not evidence either.
func TestBeaconNeedsEnoughEvidence(t *testing.T) {
	few := NewTracker()
	base := time.Now()
	for i := 0; i < 3; i++ {
		few.Observe("k", base.Add(time.Duration(i)*30*time.Second))
	}
	if reg, n := few.Regularity("k"); reg != 0 || n != 3 {
		t.Fatalf("three samples yielded regularity %.2f", reg)
	}

	slow := NewTracker()
	for i := 0; i < 8; i++ {
		slow.Observe("k", base.Add(time.Duration(i)*3*time.Hour))
	}
	if reg, _ := slow.Regularity("k"); reg != 0 {
		t.Fatalf("a three-hourly cadence scored %.2f; outside the beacon range", reg)
	}
}

// A burst of connections in the same instant is one event, not several.
func TestBurstsCollapse(t *testing.T) {
	tr := NewTracker()
	now := time.Now()
	for i := 0; i < 6; i++ {
		tr.Observe("k", now.Add(time.Duration(i)*100*time.Millisecond))
	}
	if _, n := tr.Regularity("k"); n != 1 {
		t.Fatalf("a sub-second burst counted as %d check-ins", n)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// A router, a printer or an AirPlay speaker has no public DNS, appears in no
// allocation list, and often listens on an arbitrary port. Before this, every
// one of them scored "unusual" the moment it was seen, which put a list of the
// user's own household at the top of the panel and taught them to ignore it.
func TestLocalNetworkPeersDoNotTripTheAnonymitySignals(t *testing.T) {
	lan := Input{
		DirectIP: true, HasName: false, HasOrg: false,
		RemotePort: 7000, Proto: "tcp", RemoteIsLocal: true,
		ExecPath: "/usr/libexec/rapportd", Signing: "apple",
		DomainAgeDays: -1,
	}
	got := Evaluate(lan)
	if got.Score != 0 {
		t.Errorf("a LAN peer with nothing else against it should score 0, got %d: %+v", got.Score, got.Signals)
	}

	// The waiver must be visible. A signal that silently vanishes is worse than
	// one that never fired: you cannot tell "checked and fine" from "never
	// looked", and this whole tool is an argument against that.
	var explained bool
	for _, s := range got.Signals {
		if strings.Contains(s.Reason, "your own network") {
			explained = true
			if s.Points != 0 {
				t.Errorf("the waiver must carry 0 points, got %d", s.Points)
			}
		}
	}
	if !explained {
		t.Error("the row must still say why the anonymity signals did not apply")
	}
}

func TestLocalIsNotABlanketPardon(t *testing.T) {
	// Everything that is about the *process* or the *shape* of the traffic still
	// counts on a LAN. An unsigned binary in /tmp beaconing to another machine
	// on the same network is exactly as interesting as one beaconing outward.
	in := Input{
		DirectIP: true, RemoteIsLocal: true, RemotePort: 4444,
		ExecPath: "/tmp/.hidden/agent", Signing: "unsigned",
		DomainAgeDays:    -1,
		BeaconRegularity: 0.95, BeaconSamples: 12,
	}
	got := Evaluate(in)
	if got.Score < 45 {
		t.Errorf("an unsigned beaconing binary in /tmp must still score loudly on a LAN, got %d: %+v", got.Score, got.Signals)
	}
	sum := 0
	for _, s := range got.Signals {
		sum += s.Points
	}
	if sum != got.Score {
		t.Errorf("score %d must equal the sum of its stated reasons %d", got.Score, sum)
	}
}

func TestPublicAddressesAreUnaffectedByTheLocalWaiver(t *testing.T) {
	pub := Input{DirectIP: true, RemotePort: 8443, Proto: "tcp", DomainAgeDays: -1}
	if Evaluate(pub).Score == 0 {
		t.Error("an unnamed public destination must still score")
	}
}
