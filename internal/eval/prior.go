package eval

import (
	"errors"
	"io"
	"os"
	"strings"

	"ohmyosi/internal/decode"
	"ohmyosi/internal/naming"
	"ohmyosi/internal/pktap"
)

// Warm captures and the cold capture before them.
//
// The workload captures each pass to its own file. On the warm pass system DNS
// is warm, so most lookups are answered from mDNSResponder's cache and never
// cross the wire: the answers are in the cold pass's file. Evaluated alone, a
// warm capture models a monitor started between the passes and calls nearly
// every flow "bypass". A real monitor runs throughout, so a warm capture is
// evaluated with its cold capture's DNS answers preloaded - with their own
// times and TTLs, so answers that expired in between show up as stale.
//
// The browser is quit and relaunched between passes, so its PIDs change.
// A preloaded answer is re-keyed to the process of the same name in the warm
// capture when exactly one process of that name starts something there
// (connects, sends a handshake or QUIC Initial, or has a lookup answered) -
// an exited process still appears while its old sockets close, and must not
// count. If several do, the asker becomes unknown (0): no per-process match
// and no cross-process claim. A process starting nothing keeps its PID.
//
// Not carried over: handshake sightings (the address-cache strategy sees only
// the warm capture's own), and anything in the seconds between the captures.

// PriorStats says what was carried over from an earlier capture.
type PriorStats struct {
	File     string `json:"file"`
	Answers  int    `json:"answers"`  // DNS answers preloaded
	Remapped int    `json:"remapped"` // re-keyed to the relaunched process of the same name
	Unknown  int    `json:"unknown"`  // name ambiguous in this capture: asker unknown
}

// readAnswers returns every DNS answer in a capture, attributed as Run does.
func readAnswers(path string) ([]naming.Answer, error) {
	src, err := pktap.OpenFile(path)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	dec := decode.New()
	var out []naming.Answer
	for {
		p, err := src.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		if p == nil {
			continue
		}
		o := dec.Decode(p)
		if o == nil || len(o.DNS) == 0 {
			continue
		}
		asker, comm := o.PID, o.Comm
		if o.EPID > 0 {
			asker, comm = o.EPID, o.EComm
		}
		for _, r := range o.DNS {
			out = append(out, naming.Answer{IP: r.IP, Name: r.Name, At: o.Ts, TTL: r.TTL, Asker: asker, Comm: comm})
		}
	}
}

// rekey moves each answer's asker to the process of the same name in this
// capture (procs: name -> PIDs seen), following the rule above.
func rekey(prior []naming.Answer, procs map[string]map[int32]bool, st *PriorStats) {
	for i := range prior {
		a := &prior[i]
		pids := procs[a.Comm]
		if a.Comm == "" || len(pids) == 0 || pids[a.Asker] {
			continue // unnamed, not running now, or the same process still running
		}
		if len(pids) == 1 {
			for pid := range pids {
				a.Asker = pid
			}
			st.Remapped++
			continue
		}
		a.Asker = 0
		st.Unknown++
	}
}

// coldSibling returns the cold capture a warm one follows, or "". The
// workload names them <stamp>-<network>-r<n>-<browser>-doh<x>-{cold,warm}.
func coldSibling(path string, manifest map[string]any) string {
	if mstr(manifest, "cache") != "warm" || !strings.HasSuffix(path, "-warm.pcapng") {
		return ""
	}
	cold := strings.TrimSuffix(path, "-warm.pcapng") + "-cold.pcapng"
	if _, err := os.Stat(cold); err != nil {
		return ""
	}
	m := loadManifest(cold)
	for _, k := range []string{"browser", "doh", "repeat", "network", "tranco_list"} {
		if mstr(m, k) != mstr(manifest, k) {
			return ""
		}
	}
	if mstr(m, "cache") != "cold" {
		return ""
	}
	return cold
}
