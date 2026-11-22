package eval_test

import (
	"bytes"
	"strings"
	"testing"

	"ohmyosi/internal/eval"
)

func TestResolverWarning(t *testing.T) {
	for _, c := range []struct {
		m    map[string]any
		warn bool
	}{
		{map[string]any{"resolver": "8.8.8.8 8.8.4.4", "resolver_ddr": "yes", "resolver_encrypted": "likely"}, true},
		{map[string]any{"resolver": "2606:4700:4700::1111"}, true},                                           // public, probe missing
		{map[string]any{"resolver": "192.168.1.1", "resolver_ddr": "no", "resolver_encrypted": "yes"}, true}, // observed DoH
		{map[string]any{"resolver": "fe80::1%en0 192.168.1.1", "resolver_ddr": "no", "resolver_encrypted": "no"}, false},
		{nil, false}, // not recorded: no claim either way
	} {
		if got := eval.ResolverWarning(c.m) != ""; got != c.warn {
			t.Errorf("%v: warning %v, want %v", c.m, got, c.warn)
		}
	}
	if l := eval.ResolverLine(nil); l != "not recorded" {
		t.Errorf("line for no manifest: %q", l)
	}
}

func TestSummaryPrintsResolverAndFronts(t *testing.T) {
	runs := []eval.RunSummary{
		{File: "a.pcapng", Subject: "chrome", Manifest: map[string]any{"workload": "tranco-browse", "resolver": "8.8.8.8", "resolver_ddr": "yes", "resolver_encrypted": "likely"}},
		{File: "b.pcapng", Subject: "safari", Manifest: map[string]any{"workload": "tranco-browse", "resolver": "192.168.1.1", "resolver_ddr": "no", "resolver_encrypted": "no"}},
	}
	var out bytes.Buffer
	eval.PrintSummary(&out, runs)
	for _, want := range []string{"SYSTEM RESOLVER", "WARNING: system resolver 8.8.8.8", "192.168.1.1 (ddr no, encrypted no)",
		"ECH BY SUBJECT", "front list: cloudflare-ech.com", "echoff"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Count(out.String(), "WARNING") != 1 {
		t.Errorf("want exactly one warning:\n%s", out.String())
	}
}
