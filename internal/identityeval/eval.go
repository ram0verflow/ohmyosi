// Package identityeval compares destination-labelling strategies against
// independently supplied ground truth. It is deliberately separate from the
// live product path: an evaluator that derives truth from the signal under test
// can only confirm itself.
package identityeval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

type Event struct {
	Type string `json:"type"`
	At   int64  `json:"at"`

	IP   string `json:"ip"`
	Name string `json:"name,omitempty"`
	TTL  int64  `json:"ttl,omitempty"`

	FlowID      string `json:"flow_id,omitempty"`
	Truth       string `json:"truth,omitempty"`
	TruthSource string `json:"truth_source,omitempty"`
	SNI         string `json:"sni,omitempty"`
	HTTPHost    string `json:"http_host,omitempty"`
	Condition   string `json:"condition,omitempty"`
}

type Outcome string

const (
	Correct Outcome = "correct"
	Wrong   Outcome = "wrong"
	Abstain Outcome = "abstain"
)

type Prediction struct {
	FlowID      string  `json:"flow_id"`
	Truth       string  `json:"truth"`
	TruthSource string  `json:"truth_source"`
	Condition   string  `json:"condition,omitempty"`
	Label       string  `json:"label,omitempty"`
	Evidence    string  `json:"evidence,omitempty"`
	Outcome     Outcome `json:"outcome"`
}

type MethodReport struct {
	Method           string            `json:"method"`
	Total            int               `json:"total"`
	Correct          int               `json:"correct"`
	Wrong            int               `json:"wrong"`
	Abstained        int               `json:"abstained"`
	Coverage         float64           `json:"coverage"`
	AccuracyAnswered float64           `json:"accuracy_answered"`
	CorrectRate      float64           `json:"correct_rate"`
	Predictions      []Prediction      `json:"predictions"`
	Conditions       []ConditionReport `json:"conditions,omitempty"`
}

type ConditionReport struct {
	Condition        string  `json:"condition"`
	Total            int     `json:"total"`
	Correct          int     `json:"correct"`
	Wrong            int     `json:"wrong"`
	Abstained        int     `json:"abstained"`
	Coverage         float64 `json:"coverage"`
	AccuracyAnswered float64 `json:"accuracy_answered"`
	CorrectRate      float64 `json:"correct_rate"`
}

type Report struct {
	Flows   int            `json:"flows"`
	Methods []MethodReport `json:"methods"`
}

// Load reads newline-delimited evaluation events. Line order is the observed
// order and At must be nondecreasing, which makes DNS TTL and recency explicit.
func Load(r io.Reader) ([]Event, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	var events []Event
	var lastAt int64
	ids := map[string]bool{}
	for line := 1; s.Scan(); line++ {
		raw := strings.TrimSpace(s.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		var e Event
		dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			return nil, fmt.Errorf("line %d: trailing JSON content", line)
		}
		if len(events) > 0 && e.At < lastAt {
			return nil, fmt.Errorf("line %d: at=%d precedes prior event at=%d", line, e.At, lastAt)
		}
		lastAt = e.At
		if _, err := netip.ParseAddr(e.IP); err != nil {
			return nil, fmt.Errorf("line %d: invalid ip %q", line, e.IP)
		}
		switch e.Type {
		case "dns":
			e.Name = normalize(e.Name)
			if e.Name == "" {
				return nil, fmt.Errorf("line %d: dns event needs name", line)
			}
			if e.TTL < 0 {
				return nil, fmt.Errorf("line %d: dns event needs a non-negative ttl", line)
			}
		case "flow":
			if e.FlowID == "" || ids[e.FlowID] {
				return nil, fmt.Errorf("line %d: flow_id must be non-empty and unique", line)
			}
			ids[e.FlowID] = true
			e.Truth, e.SNI, e.HTTPHost = normalize(e.Truth), normalize(e.SNI), normalize(e.HTTPHost)
			if e.Truth == "" {
				return nil, fmt.Errorf("line %d: flow needs truth", line)
			}
			if !independentTruthSource(e.TruthSource) {
				return nil, fmt.Errorf("line %d: truth_source %q is absent or derived from a signal under test", line, e.TruthSource)
			}
		default:
			return nil, fmt.Errorf("line %d: unknown event type %q", line, e.Type)
		}
		events = append(events, e)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func independentTruthSource(src string) bool {
	switch src {
	case "workload_manifest", "server_log", "application_log":
		return true
	default:
		return false
	}
}

func normalize(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

type dnsAnswer struct {
	name      string
	observed  int64
	expiresAt int64
}

type dnsState map[string][]dnsAnswer

func (d dnsState) learn(e Event) {
	// A zero TTL explicitly withdraws this name. Retaining the prior positive
	// answer would make the evaluator disagree with the product's DNS cache.
	if e.TTL == 0 {
		prior := d[e.IP]
		kept := prior[:0]
		for _, a := range prior {
			if a.name != e.Name {
				kept = append(kept, a)
			}
		}
		d[e.IP] = kept
		return
	}
	d[e.IP] = append(d[e.IP], dnsAnswer{name: e.Name, observed: e.At, expiresAt: e.At + e.TTL})
}

func (d dnsState) active(ip string, at int64) []dnsAnswer {
	var out []dnsAnswer
	for _, a := range d[ip] {
		if a.observed <= at && at < a.expiresAt {
			out = append(out, a)
		}
	}
	return out
}

func latest(answers []dnsAnswer) string {
	if len(answers) == 0 {
		return ""
	}
	return answers[len(answers)-1].name
}

func unique(answers []dnsAnswer) string {
	seen := map[string]bool{}
	for _, a := range answers {
		seen[a.name] = true
	}
	if len(seen) != 1 {
		return ""
	}
	for name := range seen {
		return name
	}
	return ""
}

type dnsView struct {
	active   []dnsAnswer
	observed []dnsAnswer
}

type predictor func(Event, dnsView) (label, evidence string)

var methods = []struct {
	name string
	fn   predictor
}{
	{"dns-latest", func(_ Event, dns dnsView) (string, string) { return dnsLatest(dns.active) }},
	{"dns-unique", func(_ Event, dns dnsView) (string, string) { return dnsUnique(dns.active) }},
	{"flow-first-no-ttl", func(e Event, dns dnsView) (string, string) {
		if e.SNI != "" {
			return e.SNI, "sni"
		}
		if e.HTTPHost != "" {
			return e.HTTPHost, "http"
		}
		// Frozen model of the original single-value product cache. Keep it as a
		// regression baseline after the product itself improves.
		if label := latest(dns.observed); label != "" {
			return label, "dns-latest-no-ttl"
		}
		return "", "no-dns"
	}},
	{"flow-first", func(e Event, dns dnsView) (string, string) {
		if e.SNI != "" {
			return e.SNI, "sni"
		}
		if e.HTTPHost != "" {
			return e.HTTPHost, "http"
		}
		return dnsLatest(dns.active)
	}},
	{"flow-first-safe", func(e Event, dns dnsView) (string, string) {
		if e.SNI != "" {
			return e.SNI, "sni"
		}
		if e.HTTPHost != "" {
			return e.HTTPHost, "http"
		}
		return dnsUnique(dns.active)
	}},
	{"flow-only", func(e Event, _ dnsView) (string, string) {
		if e.SNI != "" {
			return e.SNI, "sni"
		}
		if e.HTTPHost != "" {
			return e.HTTPHost, "http"
		}
		return "", ""
	}},
}

func dnsLatest(answers []dnsAnswer) (string, string) {
	if label := latest(answers); label != "" {
		return label, "dns-latest"
	}
	return "", "no-dns"
}

func dnsUnique(answers []dnsAnswer) (string, string) {
	if label := unique(answers); label != "" {
		return label, "dns-unique"
	}
	if len(answers) > 0 {
		return "", "dns-ambiguous"
	}
	return "", "no-dns"
}

func Evaluate(events []Event) Report {
	reports := make([]MethodReport, len(methods))
	for i, m := range methods {
		reports[i].Method = m.name
	}
	dns := dnsState{}
	for _, e := range events {
		if e.Type == "dns" {
			dns.learn(e)
			continue
		}
		view := dnsView{active: dns.active(e.IP, e.At), observed: dns[e.IP]}
		for i, m := range methods {
			label, evidence := m.fn(e, view)
			p := Prediction{FlowID: e.FlowID, Truth: e.Truth, TruthSource: e.TruthSource, Condition: e.Condition, Label: label, Evidence: evidence}
			switch {
			case label == "":
				p.Outcome = Abstain
				reports[i].Abstained++
			case label == e.Truth:
				p.Outcome = Correct
				reports[i].Correct++
			default:
				p.Outcome = Wrong
				reports[i].Wrong++
			}
			reports[i].Total++
			reports[i].Predictions = append(reports[i].Predictions, p)
		}
	}
	flows := 0
	for i := range reports {
		r := &reports[i]
		r.Coverage, r.AccuracyAnswered, r.CorrectRate = metrics(r.Correct, r.Wrong, r.Total)
		byCondition := map[string]*ConditionReport{}
		for _, p := range r.Predictions {
			if p.Condition == "" {
				continue
			}
			c := byCondition[p.Condition]
			if c == nil {
				c = &ConditionReport{Condition: p.Condition}
				byCondition[p.Condition] = c
			}
			c.Total++
			switch p.Outcome {
			case Correct:
				c.Correct++
			case Wrong:
				c.Wrong++
			case Abstain:
				c.Abstained++
			}
		}
		conditionNames := make([]string, 0, len(byCondition))
		for name := range byCondition {
			conditionNames = append(conditionNames, name)
		}
		sort.Strings(conditionNames)
		for _, name := range conditionNames {
			c := byCondition[name]
			c.Coverage, c.AccuracyAnswered, c.CorrectRate = metrics(c.Correct, c.Wrong, c.Total)
			r.Conditions = append(r.Conditions, *c)
		}
		flows = r.Total
	}
	return Report{Flows: flows, Methods: reports}
}

func metrics(correct, wrong, total int) (coverage, accuracyAnswered, correctRate float64) {
	answered := correct + wrong
	return ratio(answered, total), ratio(correct, answered), ratio(correct, total)
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// WrongPredictions returns a stable audit list for a method.
func WrongPredictions(r MethodReport) []Prediction {
	var out []Prediction
	for _, p := range r.Predictions {
		if p.Outcome == Wrong {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FlowID < out[j].FlowID })
	return out
}
