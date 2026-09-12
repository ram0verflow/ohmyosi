package identityeval

import (
	"os"
	"strings"
	"testing"
)

func TestSharedIPFixture(t *testing.T) {
	f, err := os.Open("../../research/fixtures/shared-ip.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	report := Evaluate(events)
	want := map[string][3]int{
		"dns-latest":        {2, 2, 2},
		"dns-unique":        {1, 0, 5},
		"flow-first-no-ttl": {4, 1, 1},
		"flow-first":        {4, 1, 1},
		"flow-first-safe":   {4, 0, 2},
		"flow-only":         {3, 0, 3},
	}
	for _, got := range report.Methods {
		w, ok := want[got.Method]
		if !ok {
			t.Fatalf("unexpected method %q", got.Method)
		}
		if got.Correct != w[0] || got.Wrong != w[1] || got.Abstained != w[2] {
			t.Errorf("%s: got correct/wrong/abstain %d/%d/%d, want %d/%d/%d",
				got.Method, got.Correct, got.Wrong, got.Abstained, w[0], w[1], w[2])
		}
	}
}

func TestRejectsTruthDerivedFromSignalUnderTest(t *testing.T) {
	input := `{"type":"flow","at":1,"ip":"203.0.113.1","flow_id":"f","truth":"x.test","truth_source":"sni","sni":"x.test"}`
	if _, err := Load(strings.NewReader(input)); err == nil {
		t.Fatal("expected signal-derived truth to be rejected")
	}
}

func TestRejectsUnknownFixtureField(t *testing.T) {
	input := `{"type":"dns","at":1,"ip":"203.0.113.1","name":"x.test","ttl":60,"tll":60}`
	if _, err := Load(strings.NewReader(input)); err == nil {
		t.Fatal("expected misspelled fixture field to be rejected")
	}
}

func TestDNSExpiry(t *testing.T) {
	input := strings.Join([]string{
		`{"type":"dns","at":1,"ip":"203.0.113.1","name":"old.test","ttl":2}`,
		`{"type":"flow","at":4,"ip":"203.0.113.1","flow_id":"f","truth":"new.test","truth_source":"server_log"}`,
	}, "\n")
	events, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	for _, report := range Evaluate(events).Methods {
		switch report.Method {
		case "dns-latest", "flow-first":
			if report.Abstained != 1 {
				t.Fatalf("%s used an expired DNS answer: %+v", report.Method, report)
			}
		case "flow-first-no-ttl":
			if report.Wrong != 1 {
				t.Fatalf("current product model did not expose stale-cache error: %+v", report)
			}
		}
	}
}

func TestDNSZeroTTLWithdrawsPriorAnswer(t *testing.T) {
	input := strings.Join([]string{
		`{"type":"dns","at":1,"ip":"203.0.113.1","name":"old.test","ttl":60}`,
		`{"type":"dns","at":2,"ip":"203.0.113.1","name":"old.test","ttl":0}`,
		`{"type":"flow","at":3,"ip":"203.0.113.1","flow_id":"f","truth":"old.test","truth_source":"server_log"}`,
	}, "\n")
	events, err := Load(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	for _, report := range Evaluate(events).Methods {
		if report.Method == "dns-latest" && report.Abstained != 1 {
			t.Fatalf("withdrawn answer remained active: %+v", report)
		}
	}
}
