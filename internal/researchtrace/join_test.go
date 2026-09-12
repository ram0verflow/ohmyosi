package researchtrace

import (
	"strings"
	"testing"
)

func TestLoadAndJoinExactTuple(t *testing.T) {
	traceText := strings.Join([]string{
		`{"type":"research-trace","version":"test","hostname":"lab","iface":"lo0","started":"now"}`,
		`{"type":"dns","at":1,"ip":"127.0.0.2","name":"alpha.test","ttl":60}`,
		`{"type":"dns","at":1,"ip":"203.0.113.9","name":"unrelated.test","ttl":60}`,
		`{"type":"flow","at":2,"flow_id":"product-id","proto":"tcp","local_ip":"127.0.0.1","local_port":50000,"remote_ip":"127.0.0.2","remote_port":443}`,
		`{"type":"flow","at":3,"flow_id":"product-id","proto":"tcp","local_ip":"127.0.0.1","local_port":50000,"remote_ip":"127.0.0.2","remote_port":443,"sni":"alpha.test","pre_existing":true}`,
	}, "\n")
	truthText := `{"type":"truth","at":2,"flow_id":"run-alpha","proto":"tcp","local_ip":"127.0.0.1","local_port":50000,"remote_ip":"127.0.0.2","remote_port":443,"truth":"alpha.test","truth_source":"workload_manifest","condition":"tls"}`
	trace, err := LoadTrace(strings.NewReader(traceText))
	if err != nil {
		t.Fatal(err)
	}
	truths, err := LoadTruth(strings.NewReader(truthText))
	if err != nil {
		t.Fatal(err)
	}
	got := Join(trace, truths)
	if got.Matched != 1 || len(got.Excluded) != 0 {
		t.Fatalf("join = %+v", got)
	}
	if len(got.Events) != 2 {
		t.Fatalf("got %d joined events, want DNS plus flow", len(got.Events))
	}
	flow := got.Events[1]
	if flow.FlowID != "run-alpha" || flow.SNI != "alpha.test" || !flow.PreExisting || flow.Condition != "tls" {
		t.Fatalf("joined flow = %+v", flow)
	}
}

func TestJoinPreservesUnmatchedTruthAsExclusion(t *testing.T) {
	truths := []TruthFlow{{
		Type: "truth", FlowID: "missing", Proto: "udp", LocalIP: "127.0.0.1", LocalPort: 50001,
		RemoteIP: "127.0.0.2", RemotePort: 443, Truth: "missing.test", TruthSource: "server_log", Condition: "preexisting",
	}}
	got := Join(nil, truths)
	if got.Matched != 0 || len(got.Excluded) != 1 || got.Excluded[0].FlowID != "missing" || got.Excluded[0].Condition != "preexisting" {
		t.Fatalf("join = %+v", got)
	}
}

func TestWriteExclusions(t *testing.T) {
	var out strings.Builder
	if err := WriteExclusions(&out, []Exclusion{{FlowID: "f", Condition: "snaplen", Reason: "not captured"}}); err != nil {
		t.Fatal(err)
	}
	if want := `{"flow_id":"f","condition":"snaplen","reason":"not captured"}`; strings.TrimSpace(out.String()) != want {
		t.Fatalf("exclusion = %q, want %q", out.String(), want)
	}
}

func TestRejectsSignalDerivedTruth(t *testing.T) {
	input := `{"type":"truth","at":1,"flow_id":"f","proto":"tcp","local_ip":"127.0.0.1","local_port":50000,"remote_ip":"127.0.0.2","remote_port":443,"truth":"x.test","truth_source":"sni"}`
	if _, err := LoadTruth(strings.NewReader(input)); err == nil {
		t.Fatal("expected non-independent truth to be rejected")
	}
}

func TestTraceAllowsDNSWithdrawal(t *testing.T) {
	input := `{"type":"dns","at":1,"ip":"127.0.0.2","name":"x.test","ttl":0}`
	if _, err := LoadTrace(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
}

func TestTraceAllowsNonTransportFlowWithoutPorts(t *testing.T) {
	input := `{"type":"flow","at":1,"flow_id":"icmp","proto":"icmp","local_ip":"127.0.0.1","remote_ip":"127.0.0.2"}`
	if _, err := LoadTrace(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
}
