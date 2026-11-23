package eval_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ohmyosi/internal/eval"
	"ohmyosi/internal/lab"
	"ohmyosi/internal/naming"
)

func buildLab(t *testing.T) (string, eval.Truth) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lab.pcapng")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	truth, err := lab.Build(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	return path, truth
}

// The lab is the controlled experiment behind the project's claims. These are
// its results, pinned: if a change to decoding, flow orientation or the
// classifier moves them, the claim moved and somebody should look.
func TestLabResults(t *testing.T) {
	path, truth := buildLab(t)
	rep, err := eval.Run(path, eval.Options{Truth: truth, Blocked: []string{"telemetry-vendor.example"}, Slack: naming.DefaultSlack})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Flows != len(truth) {
		t.Fatalf("eval saw %d flows, lab built %d - orientation or keying broke", rep.Flows, len(truth))
	}
	if rep.WithProcess != rep.Flows || rep.DNS.Effective != rep.DNS.Answers {
		t.Errorf("attribution: %d/%d flows, %d/%d dns", rep.WithProcess, rep.Flows, rep.DNS.Effective, rep.DNS.Answers)
	}

	la := rep.Tally()
	want := map[naming.Class]int{
		naming.Agree: 12, naming.Alias: 3, naming.Mismatch: 4, naming.HandshakeOnly: 4,
		naming.ECHOuter: 1, naming.DNSOnly: 2, naming.Neither: 1,
	}
	for c, n := range want {
		if la.ByClass[c] != n {
			t.Errorf("%s: %d, want %d", c, la.ByClass[c], n)
		}
	}
	causes := map[naming.Cause]int{
		naming.CauseBypass: 4, naming.CauseCoalesced: 1, naming.CauseStale: 1,
		naming.CauseCrossProcess: 4, naming.CauseOtherName: 1,
	}
	for c, n := range causes {
		if la.ByCause[c] != n {
			t.Errorf("cause %s: %d, want %d", c, la.ByCause[c], n)
		}
	}
	// Per-process correlation removes cross-process borrowing entirely.
	if pp := rep.Tallies[eval.StratPerProcess]; pp.ByCause[naming.CauseCrossProcess] != 0 || pp.Wrong() >= la.Wrong() {
		t.Errorf("per-process should be wrong less often: %d vs %d", pp.Wrong(), la.Wrong())
	}

	scores := map[string]eval.Score{}
	for _, s := range rep.Scores {
		scores[s.Strategy] = s
	}
	check := func(name string, correct, misled int) {
		if s := scores[name]; s.Correct != correct || s.Misled != misled {
			t.Errorf("%s: %+v, want correct %d misled %d", name, s, correct, misled)
		}
	}
	check(eval.StratLastAnswer, 14, 9)
	check(eval.StratPerProcess, 16, 3)
	check(eval.StratHeaderFirst, 24, 1) // misled once: reports the ECH front as the destination
	check(eval.StratAddrCache, 24, 3)
	check(eval.StratRead, 25, 0) // never claims to have read a name it guessed
	// Little Snitch by its documented steps. Default verification refuses every
	// handshake name no lookup backs (DoH, cached, hardcoded, reused address),
	// so it shows a bare address there; step 2 trusts the app's one lookup and
	// is fooled by the shared Google edge and the same-site Notion host.
	check(eval.StratLittleSnitch, 17, 2)
	check(eval.StratLittleSnitchNoVerify, 23, 2)

	// S9: an ECH extension with a real SNI (GREASE) is graded as read, not
	// excluded as a front. Only S7's cloudflare-ech.com is ech-outer.
	if la.ECHOffered != 1 {
		t.Errorf("ech offered: %d, want 1 (S9)", la.ECHOffered)
	}
	for _, r := range rep.Results {
		if v := r.V(); v.Handshake == "search.brave.example" && (v.Class != naming.Agree || !v.ECHOffered || v.ECH) {
			t.Errorf("S9 GREASE ECH: %+v, want agree with ech_offered", v)
		}
	}

	if len(rep.Evasions) != 1 || rep.Evasions[0].Comm != "AcmeUpdater" {
		t.Errorf("evasions %+v", rep.Evasions)
	}
}

// Slack is a parameter, so results are reported across it. With no slack at
// all, nothing in the lab should change: every answer precedes its flow.
func TestLabSlackSensitivity(t *testing.T) {
	path, truth := buildLab(t)
	var wrong []int
	for _, s := range []time.Duration{0, naming.DefaultSlack, 500 * time.Millisecond} {
		rep, err := eval.Run(path, eval.Options{Truth: truth, Slack: s})
		if err != nil {
			t.Fatal(err)
		}
		wrong = append(wrong, rep.Tally().Wrong())
	}
	if wrong[0] != wrong[1] {
		t.Errorf("0ms vs 100ms differ: %v", wrong)
	}
	// Wider slack admits answers that arrived after the flow opened. That can
	// only add candidates for correlation to pick wrongly, never remove them.
	if wrong[2] < wrong[1] {
		t.Errorf("wider slack reduced errors: %v", wrong)
	}
}

func TestWilson(t *testing.T) {
	lo, hi := eval.Wilson(0, 10)
	if lo != 0 || hi < 0.27 || hi > 0.32 {
		t.Fatalf("0/10: %v %v", lo, hi)
	}
	lo, hi = eval.Wilson(50, 100)
	if lo < 0.40 || lo > 0.41 || hi < 0.59 || hi > 0.60 {
		t.Fatalf("50/100: %v %v", lo, hi)
	}
}
