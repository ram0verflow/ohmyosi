// identity-eval compares destination identity strategies on an independently
// labelled NDJSON fixture. It is a research instrument, not the product path.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"ohmyosi/internal/identityeval"
	"ohmyosi/internal/researchtrace"
)

func main() {
	input := flag.String("input", "", "NDJSON evaluation fixture")
	trace := flag.String("trace", "", "raw evidence NDJSON written by ohmyosi -research-trace")
	truth := flag.String("truth", "", "independent workload truth NDJSON")
	fixtureOut := flag.String("fixture-out", "", "write the joined evaluation fixture for audit and reuse")
	exclusionsOut := flag.String("exclusions-out", "", "write unmatched truth flows and reasons as NDJSON")
	jsonOut := flag.Bool("json", false, "emit the complete machine-readable report")
	flag.Parse()
	direct := *input != ""
	joined := *trace != "" || *truth != ""
	if direct == joined || (joined && (*trace == "" || *truth == "")) {
		fmt.Fprintln(os.Stderr, "identity-eval: use either -input FILE or both -trace FILE -truth FILE")
		os.Exit(2)
	}
	var events []identityeval.Event
	var exclusions []researchtrace.Exclusion
	joinedMatched, joinedTruth := 0, 0
	if direct {
		f, err := os.Open(*input)
		if err != nil {
			fatal(err)
		}
		events, err = identityeval.Load(f)
		f.Close()
		if err != nil {
			fatal(err)
		}
	} else {
		traceFile, err := os.Open(*trace)
		if err != nil {
			fatal(err)
		}
		traceEvents, err := researchtrace.LoadTrace(traceFile)
		traceFile.Close()
		if err != nil {
			fatal(err)
		}
		truthFile, err := os.Open(*truth)
		if err != nil {
			fatal(err)
		}
		truthFlows, err := researchtrace.LoadTruth(truthFile)
		truthFile.Close()
		if err != nil {
			fatal(err)
		}
		result := researchtrace.Join(traceEvents, truthFlows)
		exclusions = result.Excluded
		joinedMatched, joinedTruth = result.Matched, len(truthFlows)
		for _, excluded := range result.Excluded {
			fmt.Fprintf(os.Stderr, "excluded %s: %s\n", excluded.FlowID, excluded.Reason)
		}
		fmt.Fprintf(os.Stderr, "joined %d/%d truth flows by exact 5-tuple\n", result.Matched, len(truthFlows))
		events = result.Events
	}
	if *exclusionsOut != "" {
		f, err := os.Create(*exclusionsOut)
		if err != nil {
			fatal(err)
		}
		if err := researchtrace.WriteExclusions(f, exclusions); err != nil {
			f.Close()
			fatal(err)
		}
		if err := f.Close(); err != nil {
			fatal(err)
		}
	}
	if joined && joinedMatched == 0 {
		fatal(fmt.Errorf("no truth flow matched the trace (%d excluded)", joinedTruth))
	}
	if *fixtureOut != "" {
		f, err := os.Create(*fixtureOut)
		if err != nil {
			fatal(err)
		}
		if err := researchtrace.WriteFixture(f, events); err != nil {
			f.Close()
			fatal(err)
		}
		if err := f.Close(); err != nil {
			fatal(err)
		}
	}
	report := identityeval.Evaluate(events)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal(err)
		}
		return
	}

	fmt.Printf("destination identity evaluation: %d independently labelled flows\n\n", report.Flows)
	fmt.Printf("%-17s %7s %7s %8s %9s %10s %12s\n", "method", "correct", "wrong", "abstain", "coverage", "accuracy", "correct rate")
	for _, r := range report.Methods {
		fmt.Printf("%-17s %7d %7d %8d %8.1f%% %9.1f%% %11.1f%%\n",
			r.Method, r.Correct, r.Wrong, r.Abstained,
			r.Coverage*100, r.AccuracyAnswered*100, r.CorrectRate*100)
	}
	for _, r := range report.Methods {
		wrong := identityeval.WrongPredictions(r)
		if len(wrong) == 0 {
			continue
		}
		fmt.Printf("\n%s wrong labels:\n", r.Method)
		for _, p := range wrong {
			fmt.Printf("  %s: predicted %s via %s; truth %s via %s\n",
				p.FlowID, p.Label, p.Evidence, p.Truth, p.TruthSource)
		}
	}
	for _, r := range report.Methods {
		if len(r.Conditions) == 0 {
			continue
		}
		fmt.Printf("\n%s by condition:\n", r.Method)
		for _, c := range r.Conditions {
			fmt.Printf("  %-26s %d correct, %d wrong, %d abstain (coverage %.1f%%)\n",
				c.Condition, c.Correct, c.Wrong, c.Abstained, c.Coverage*100)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "identity-eval:", err)
	os.Exit(1)
}
