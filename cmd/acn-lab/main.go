// acn-lab writes a pktap-format capture with known ground truth, for
// evaluating how each naming strategy performs against fact.
//
// A field capture can only grade correlation against the handshake name, and
// says nothing about flows that announce no name at all. The lab fixes that:
// every flow here is built from a scenario that says which app wanted which
// name, so `ohmyosi -eval lab.pcapng -truth lab.truth.json` can score
// dns-correlation, the old address cache and read-first on the same packets.
//
// The scenarios are the failure modes, one each, plus an ordinary baseline.
// They are not a sample of real traffic and their proportions mean nothing:
// prevalence comes from a field capture. What the lab shows is mechanism -
// that each failure exists, which strategy it fools, and whether the fool is
// presented as fact.
//
//	go run ./cmd/acn-lab -o lab.pcapng
//	ohmyosi -eval lab.pcapng -truth lab.truth.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"ohmyosi/internal/lab"
)

func main() {
	out := flag.String("o", "lab.pcapng", "capture to write; the truth file goes next to it as <name>.truth.json")
	flag.Parse()
	f, err := os.Create(*out)
	if err != nil {
		fatal(err)
	}
	truth, err := lab.Build(f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fatal(err)
	}
	tp := strings.TrimSuffix(*out, ".pcapng") + ".truth.json"
	b, _ := json.MarshalIndent(truth, "", "  ")
	if err := os.WriteFile(tp, b, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s (%d flows) and %s\n", *out, len(truth), tp)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "acn-lab:", err)
	os.Exit(1)
}
