package eval

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A workload logs each page visit as one line of <capture>.visits.tsv:
//
//	<unix milliseconds> \t <lane> \t <site>
//
// Lanes are independent browser instances running in parallel; the manifest
// maps each lane to the PIDs of its process tree:
//
//	"lanes": [{"id": "chrome-1", "pids": [5012, 5013, ...]}, ...]
//
// A run with no lanes is one sequential lane. A flow belongs to the latest
// visit of its lane that started at or before the flow opened, within
// maxVisitGap - so background traffic long after a visit is not pinned on it.

const maxVisitGap = 2 * time.Minute

type visit struct {
	at   time.Time
	lane string
	site string
}

// loadVisits reads the visit log and lane map for a capture, if any.
func loadVisits(pcap string, m map[string]any) ([]visit, map[int32]string) {
	base := strings.TrimSuffix(strings.TrimSuffix(pcap, ".pcapng"), ".pcap")
	f, err := os.Open(base + ".visits.tsv")
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	visits := parseVisits(f)
	return visits, lanePIDs(m)
}

func parseVisits(r io.Reader) []visit {
	var out []visit
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), "\t")
		if len(parts) != 3 {
			continue
		}
		ms, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || parts[2] == "" {
			continue
		}
		out = append(out, visit{at: time.UnixMilli(ms), lane: parts[1], site: parts[2]})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].at.Before(out[j].at) })
	return out
}

// lanePIDs reads the manifest's lane → PIDs map, inverted.
func lanePIDs(m map[string]any) map[int32]string {
	raw, ok := m["lanes"].([]any)
	if !ok {
		return nil
	}
	out := map[int32]string{}
	for _, l := range raw {
		lm, ok := l.(map[string]any)
		if !ok {
			continue
		}
		id := fmt.Sprint(lm["id"])
		pids, _ := lm["pids"].([]any)
		for _, p := range pids {
			if f, ok := p.(float64); ok {
				out[int32(f)] = id
			}
		}
	}
	return out
}

// onlyLane returns the lane id when the manifest has exactly one lane for
// browser, else "". Safari is started by launchd, not by safaridriver, so
// its processes are never in its lane's PID list; with one Safari lane there
// is no ambiguity about where its flows belong.
func onlyLane(m map[string]any, browser string) string {
	raw, _ := m["lanes"].([]any)
	id := ""
	for _, l := range raw {
		lm, _ := l.(map[string]any)
		if strings.EqualFold(fmt.Sprint(lm["browser"]), browser) {
			if id != "" {
				return ""
			}
			id = fmt.Sprint(lm["id"])
		}
	}
	return id
}

// siteOf places a flow on the visit that caused it, or "" when it can't.
// fallback is the lane to use when the flow's PID is in no lane's list.
func siteOf(visits []visit, lanes map[int32]string, fallback string, r FlowResult) string {
	if len(visits) == 0 || r.Opened.IsZero() {
		return ""
	}
	lane := ""
	if len(lanes) > 0 {
		lane = lanes[r.PID]
		if lane == "" {
			lane = fallback
		}
		if lane == "" {
			return "" // a process outside every lane: background traffic
		}
	}
	best := -1
	for i, v := range visits {
		if v.at.After(r.Opened) {
			break
		}
		if lane != "" && v.lane != lane {
			continue
		}
		best = i
	}
	if best < 0 || r.Opened.Sub(visits[best].at) > maxVisitGap {
		return ""
	}
	return visits[best].site
}

// siteRates is the distribution of per-site rates for one metric, over sites
// with at least minPerSite readable flows: n sites, median, quartiles.
type siteRates struct {
	N              int
	Median, Q1, Q3 float64
}

const minPerSite = 3

func perSite(sites []*Counts, f func(*Counts) (int, int)) siteRates {
	var rates []float64
	for _, c := range sites {
		k, d := f(c)
		if d < minPerSite {
			continue
		}
		rates = append(rates, float64(k)/float64(d))
	}
	sort.Float64s(rates)
	if len(rates) == 0 {
		return siteRates{}
	}
	q := func(p float64) float64 {
		i := p * float64(len(rates)-1)
		lo := int(i)
		if lo+1 >= len(rates) {
			return rates[lo]
		}
		return rates[lo] + (i-float64(lo))*(rates[lo+1]-rates[lo])
	}
	return siteRates{N: len(rates), Median: q(0.5), Q1: q(0.25), Q3: q(0.75)}
}

func (s siteRates) String() string {
	if s.N == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%% [IQR %.1f-%.1f] n=%d", 100*s.Median, 100*s.Q1, 100*s.Q3, s.N)
}

// printSites writes per-site medians next to the pooled rates, per condition.
func printSites(w io.Writer, keys []string, groups map[string][]RunSummary) {
	any := false
	for _, k := range keys {
		for _, r := range groups[k] {
			if len(r.Sites) > 0 {
				any = true
			}
		}
	}
	if !any {
		return
	}
	fmt.Fprintf(w, "\nPER SITE (median across sites with >= %d readable flows; sites pooled across a condition's runs)\n", minPerSite)
	fmt.Fprintf(w, "  %-28s %-32s %-32s\n", "condition", "error: last-answer", "error: littlesnitch-mac")
	for _, k := range keys {
		merged := map[string]*Counts{}
		for _, r := range groups[k] {
			for site, c := range r.Sites {
				if merged[site] == nil {
					m := newCounts()
					merged[site] = &m
				}
				merged[site].merge(*c)
			}
		}
		if len(merged) == 0 {
			continue
		}
		var list []*Counts
		for _, c := range merged {
			list = append(list, c)
		}
		la := perSite(list, func(c *Counts) (int, int) { return c.ShownError(StratLastAnswer) })
		ls := perSite(list, func(c *Counts) (int, int) { return c.ShownError(StratLittleSnitch) })
		fmt.Fprintf(w, "  %-28s %-32s %-32s\n", trunc(k, 28), la, ls)
	}
}
