package eval_test

import (
	"bytes"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ohmyosi/internal/eval"
	"ohmyosi/internal/lab"
	"ohmyosi/internal/naming"
)

func TestSummarize(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"r1-app-notion", "r2-app-notion", "field"} {
		f, err := os.Create(filepath.Join(dir, name+".pcapng"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lab.Build(f); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if name != "field" {
			os.WriteFile(filepath.Join(dir, name+".manifest.json"),
				[]byte(`{"workload":"app-launch","app":"Notion","app_version":"4.1","repeat":1,"network":"lab"}`), 0o644)
		}
	}
	runs, err := eval.Summarize(dir, naming.DefaultSlack, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Fatalf("%d runs", len(runs))
	}
	byName := map[string]eval.RunSummary{}
	for _, r := range runs {
		byName[strings.TrimSuffix(filepath.Base(r.File), ".pcapng")] = r
	}
	n := byName["r1-app-notion"]
	// The lab has two Notion flows; both are readable, and last-answer gets
	// both wrong (another app's lookup came last), per-process neither.
	if n.Focus.Flows != 2 || n.Focus.Readable != 2 || n.Focus.Wrong[eval.StratLastAnswer] != 2 {
		t.Fatalf("notion focus %+v", n.Focus)
	}
	if n.Focus.Flows+n.Other.Flows != 27 || byName["field"].Focus.Flows != 27 {
		t.Fatalf("split %d+%d, field %d", n.Focus.Flows, n.Other.Flows, byName["field"].Focus.Flows)
	}
	if n.Group() != "app Notion" || byName["field"].Group() != "field: field.pcapng" {
		t.Fatalf("groups %q %q", n.Group(), byName["field"].Group())
	}

	var out bytes.Buffer
	eval.PrintSummary(&out, runs)
	for _, want := range []string{"POOLED BY CONDITION", "app Notion", "Trevisan", "runs 100-100%"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, out.String())
		}
	}
	var c bytes.Buffer
	if err := eval.WriteCSV(&c, runs); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&c).ReadAll()
	if err != nil || len(rows) != 4 || rows[2][2] != "Notion" || rows[1][1] != "" {
		t.Fatalf("csv %v %v", rows, err)
	}
}

func TestFamilies(t *testing.T) {
	cases := []struct {
		subject, comm string
		want          bool
	}{
		{"chrome", "Google Chrome He", true},
		{"safari", "com.apple.WebKi", true},
		{"firefox", "firefox", true},
		{"chrome", "Slack Helper", false},
		{"Microsoft Teams", "MSTeams", true},
		{"zoom.us", "zoom.us", true},
	}
	for _, c := range cases {
		if got := eval.InFamily(c.subject, c.comm); got != c.want {
			t.Errorf("%s/%s: %v", c.subject, c.comm, got)
		}
	}
}
