package score

import "testing"

func hasReasonContaining(r Result, substr string) bool {
	for _, s := range r.Signals {
		if contains(s.Reason, substr) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestExfilShape(t *testing.T) {
	// Large one-sided upload to a far end with no name: the exfil shape fires.
	up := Evaluate(Input{BytesUp: 5 << 20, BytesDown: 4096, HasName: false})
	if !hasReasonContaining(up, "sent") {
		t.Errorf("expected an exfil signal, got %+v", up.Signals)
	}

	// The same volume to a NAMED destination does not: a big upload to a known
	// service is a backup, not a leak.
	named := Evaluate(Input{BytesUp: 5 << 20, BytesDown: 4096, HasName: true})
	if hasReasonContaining(named, "sent") {
		t.Errorf("named destination should not raise the exfil signal: %+v", named.Signals)
	}

	// A balanced transfer (download-heavy) does not fire either.
	balanced := Evaluate(Input{BytesUp: 5 << 20, BytesDown: 5 << 20, HasName: false})
	if hasReasonContaining(balanced, "sent") {
		t.Errorf("balanced transfer should not raise the exfil signal: %+v", balanced.Signals)
	}

	// Below the floor, a one-sided trickle is noise, not a signal.
	small := Evaluate(Input{BytesUp: 1000, BytesDown: 1, HasName: false})
	if hasReasonContaining(small, "sent") {
		t.Errorf("sub-floor upload should not raise the exfil signal: %+v", small.Signals)
	}
}

func TestSigningSignal(t *testing.T) {
	// A neutral baseline that scores nothing on its own, so only the signing
	// verdict moves the number. (DomainAgeDays must be -1: zero would read as a
	// domain registered today.)
	base := func(signing string) Input {
		return Input{HasName: true, HasOrg: true, RemotePort: 443,
			DomainAgeDays: -1, Signing: signing}
	}
	if r := Evaluate(base("unsigned")); !hasReasonContaining(r, "no code signature") {
		t.Errorf("unsigned binary should be flagged: %+v", r.Signals)
	}
	if r := Evaluate(base("adhoc")); !hasReasonContaining(r, "ad-hoc") {
		t.Errorf("ad-hoc binary should be flagged: %+v", r.Signals)
	}
	// Attestable provenance earns no points.
	for _, s := range []string{"apple", "developer-id", "signed", "", "unknown"} {
		if r := Evaluate(base(s)); r.Score != 0 {
			t.Errorf("signing %q scored %d, want 0", s, r.Score)
		}
	}
}

func TestFirstContactSignal(t *testing.T) {
	with := Evaluate(Input{FirstContact: true})
	without := Evaluate(Input{FirstContact: false})
	if with.Score <= without.Score {
		t.Errorf("first contact should add weight: %d vs %d", with.Score, without.Score)
	}
	if !hasReasonContaining(with, "not been seen") {
		t.Errorf("first contact should carry a reason: %+v", with.Signals)
	}
}

func TestTrustedAppNotPenalisedForUnnamedDestination(t *testing.T) {
	// A signed app in a normal location talking to an address it never named
	// (push, QUIC, ECH) is ordinary and must stay quiet - this is the "legit
	// apps scoring 40+" regression.
	legit := Evaluate(Input{
		DirectIP: true, HasName: false, HasOrg: false, RemotePort: 443,
		ExecPath: "/Applications/Some.app/Contents/MacOS/Some",
		Signing:  "developer-id", DomainAgeDays: -1,
	})
	if legit.Score != 0 {
		t.Errorf("signed app with an unnamed destination scored %d (%v), want 0", legit.Score, legit.Signals)
	}

	// The exact same shape from an unsigned binary in a scratch location keeps
	// full weight - the waiver is about provenance, not about the destination.
	shady := Evaluate(Input{
		DirectIP: true, HasName: false, HasOrg: false, RemotePort: 443,
		ExecPath: "/tmp/x", Signing: "unsigned", DomainAgeDays: -1,
	})
	if shady.Score < 45 {
		t.Errorf("unsigned binary with an unnamed destination scored %d, expected it to remain loud/unusual", shady.Score)
	}

	// A trusted app still gets flagged for a genuinely suspicious shape (a
	// steady beacon), so the waiver does not blind the scorer.
	beaconing := Evaluate(Input{
		DirectIP: true, HasName: false, RemotePort: 443,
		ExecPath: "/Applications/Some.app/Contents/MacOS/Some", Signing: "apple",
		DomainAgeDays: -1, BeaconRegularity: 0.95, BeaconSamples: 8,
	})
	if beaconing.Score == 0 {
		t.Error("a trusted app that beacons should still be scored")
	}
}

func TestSelfIsAlwaysQuiet(t *testing.T) {
	// ohmyosi's own traffic must never score, whatever else is set.
	r := Evaluate(Input{IsSelf: true, DirectIP: true, Signing: "unsigned",
		BytesUp: 100 << 20, HasName: false, FirstContact: true})
	if r.Score != 0 || r.Band != "quiet" {
		t.Errorf("self traffic scored %d (%s), want 0 quiet", r.Score, r.Band)
	}
}
