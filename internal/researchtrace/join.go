package researchtrace

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"

	"ohmyosi/internal/identityeval"
)

// TruthFlow is written by a controlled workload before its intended identity
// is compared with any packet-derived signal.
type TruthFlow struct {
	Type        string `json:"type"`
	At          int64  `json:"at"`
	Run         int    `json:"run,omitempty"`
	Seed        int64  `json:"seed,omitempty"`
	FlowID      string `json:"flow_id"`
	Proto       string `json:"proto"`
	LocalIP     string `json:"local_ip"`
	LocalPort   uint16 `json:"local_port"`
	RemoteIP    string `json:"remote_ip"`
	RemotePort  uint16 `json:"remote_port"`
	Truth       string `json:"truth"`
	TruthSource string `json:"truth_source"`
	Condition   string `json:"condition,omitempty"`
}

type JoinResult struct {
	Events   []identityeval.Event
	Matched  int
	Excluded []Exclusion
}

type Exclusion struct {
	FlowID    string `json:"flow_id"`
	Condition string `json:"condition,omitempty"`
	Reason    string `json:"reason"`
}

type tuple struct {
	proto                 string
	localIP, remoteIP     string
	localPort, remotePort uint16
}

func eventTuple(e Event) tuple {
	return tuple{e.Proto, e.LocalIP, e.RemoteIP, e.LocalPort, e.RemotePort}
}

func truthTuple(t TruthFlow) tuple {
	return tuple{t.Proto, t.LocalIP, t.RemoteIP, t.LocalPort, t.RemotePort}
}

func LoadTrace(r io.Reader) ([]Event, error) {
	var events []Event
	err := scanNDJSON(r, func(line int, raw []byte) error {
		// The first line is recorder metadata, not an evidence event. Inspect
		// only its discriminator before applying strict event validation so
		// metadata can evolve without weakening checks on evidence rows.
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return fmt.Errorf("trace line %d: %w", line, err)
		}
		if envelope.Type == "research-trace" {
			return nil
		}
		var e Event
		if err := strictJSON(raw, &e); err != nil {
			return fmt.Errorf("trace line %d: %w", line, err)
		}
		switch e.Type {
		case "dns":
			if _, err := netip.ParseAddr(e.IP); err != nil || e.Name == "" {
				return fmt.Errorf("trace line %d: invalid DNS event", line)
			}
		case "flow":
			if e.FlowID == "" || e.Proto == "" {
				return fmt.Errorf("trace line %d: incomplete flow event", line)
			}
			if (e.Proto == "tcp" || e.Proto == "udp") && (e.LocalPort == 0 || e.RemotePort == 0) {
				return fmt.Errorf("trace line %d: incomplete transport flow event", line)
			}
			if _, err := netip.ParseAddr(e.LocalIP); err != nil {
				return fmt.Errorf("trace line %d: invalid local ip", line)
			}
			if _, err := netip.ParseAddr(e.RemoteIP); err != nil {
				return fmt.Errorf("trace line %d: invalid remote ip", line)
			}
		default:
			return fmt.Errorf("trace line %d: unknown type %q", line, e.Type)
		}
		events = append(events, e)
		return nil
	})
	return events, err
}

func LoadTruth(r io.Reader) ([]TruthFlow, error) {
	var truths []TruthFlow
	ids := map[string]bool{}
	err := scanNDJSON(r, func(line int, raw []byte) error {
		var t TruthFlow
		if err := strictJSON(raw, &t); err != nil {
			return fmt.Errorf("truth line %d: %w", line, err)
		}
		if t.Type != "truth" || t.FlowID == "" || ids[t.FlowID] || t.Truth == "" {
			return fmt.Errorf("truth line %d: invalid or duplicate truth flow", line)
		}
		ids[t.FlowID] = true
		if t.TruthSource != "workload_manifest" && t.TruthSource != "server_log" && t.TruthSource != "application_log" {
			return fmt.Errorf("truth line %d: source %q is not independent", line, t.TruthSource)
		}
		if _, err := netip.ParseAddr(t.LocalIP); err != nil {
			return fmt.Errorf("truth line %d: invalid local ip", line)
		}
		if _, err := netip.ParseAddr(t.RemoteIP); err != nil {
			return fmt.Errorf("truth line %d: invalid remote ip", line)
		}
		if t.Proto == "" || t.LocalPort == 0 || t.RemotePort == 0 {
			return fmt.Errorf("truth line %d: incomplete tuple", line)
		}
		truths = append(truths, t)
		return nil
	})
	return truths, err
}

func Join(trace []Event, truths []TruthFlow) JoinResult {
	latest := map[tuple]Event{}
	wantedIPs := map[string]bool{}
	for _, t := range truths {
		wantedIPs[t.RemoteIP] = true
	}
	for _, e := range trace {
		if e.Type != "flow" {
			continue
		}
		k := eventTuple(e)
		prior, ok := latest[k]
		if !ok || e.At >= prior.At {
			// Keep earlier evidence if a later update only changes another field.
			if e.SNI == "" {
				e.SNI = prior.SNI
			}
			if e.HTTPHost == "" {
				e.HTTPHost = prior.HTTPHost
			}
			if prior.PreExisting {
				e.PreExisting = true
			}
			latest[k] = e
		}
	}

	var out JoinResult
	for _, e := range trace {
		if e.Type == "dns" && wantedIPs[e.IP] {
			out.Events = append(out.Events, identityeval.Event{
				Type: "dns", At: e.At, IP: e.IP, Name: e.Name, TTL: int64(e.TTL),
			})
		}
	}
	for _, truth := range truths {
		observed, ok := latest[truthTuple(truth)]
		if !ok {
			out.Excluded = append(out.Excluded, Exclusion{FlowID: truth.FlowID, Condition: truth.Condition, Reason: "no exact 5-tuple in trace"})
			continue
		}
		out.Matched++
		out.Events = append(out.Events, identityeval.Event{
			Type: "flow", At: observed.At, IP: observed.RemoteIP,
			FlowID: truth.FlowID, Truth: truth.Truth, TruthSource: truth.TruthSource,
			SNI: observed.SNI, HTTPHost: observed.HTTPHost, PreExisting: observed.PreExisting, Condition: truth.Condition,
		})
	}
	sort.SliceStable(out.Events, func(i, j int) bool {
		if out.Events[i].At != out.Events[j].At {
			return out.Events[i].At < out.Events[j].At
		}
		return out.Events[i].Type == "dns" && out.Events[j].Type != "dns"
	})
	sort.Slice(out.Excluded, func(i, j int) bool { return out.Excluded[i].FlowID < out.Excluded[j].FlowID })
	return out
}

func WriteFixture(w io.Writer, events []identityeval.Event) error {
	enc := json.NewEncoder(w)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

func WriteExclusions(w io.Writer, exclusions []Exclusion) error {
	enc := json.NewEncoder(w)
	for _, exclusion := range exclusions {
		if err := enc.Encode(exclusion); err != nil {
			return err
		}
	}
	return nil
}

func scanNDJSON(r io.Reader, fn func(int, []byte) error) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for line := 1; s.Scan(); line++ {
		raw := bytes.TrimSpace(s.Bytes())
		if len(raw) == 0 || strings.HasPrefix(string(raw), "#") {
			continue
		}
		if err := fn(line, raw); err != nil {
			return err
		}
	}
	return s.Err()
}

func strictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON content")
	}
	return nil
}
