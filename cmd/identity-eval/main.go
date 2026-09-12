// identity-eval compares destination identity strategies on an independently
// labelled NDJSON fixture. It is a research instrument, not the product path.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"ohmyosi/internal/identityeval"
)

func main() {
	input := flag.String("input", "", "NDJSON evaluation fixture")
	jsonOut := flag.Bool("json", false, "emit the complete machine-readable report")
	flag.Parse()
	if *input == "" {
		fmt.Fprintln(os.Stderr, "identity-eval: -input is required")
		os.Exit(2)
	}
	f, err := os.Open(*input)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	events, err := identityeval.Load(f)
	if err != nil {
		fatal(err)
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
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "identity-eval:", err)
	os.Exit(1)
}
