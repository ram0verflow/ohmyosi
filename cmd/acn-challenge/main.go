// acn-challenge creates, on the real internet, the connections that make
// DNS-correlated naming go wrong, and writes down what each one really was.
//
// The lab (cmd/acn-lab) builds known-answer traffic synthetically. This does
// the same with real DNS, real CDNs and whatever firewall is running on the
// machine: every connection it makes is logged with its 5-tuple, the process
// that made it, the name it asked for and the scenario. That file is a truth
// file for `ohmyosi -eval capture.pcapng -truth challenge.truth.json`, so
// every naming strategy - and, with tools/realtools, a real firewall's own
// log - is scored against ground truth rather than against another heuristic.
//
// Scenarios (each repeated -n times, jittered):
//
//	baseline      look the name up, connect announcing it              (control)
//	cohost        look up the real name, then a decoy on the same IP; connect for the real one
//	crossprocess  process acn-resolver looks up a decoy; process acn-fetcher connects to that
//	              IP for the real name without any lookup of its own
//	doh           resolve over DNS-over-HTTPS, connect: no system lookup at all
//	stale         look a name up, wait past its TTL, connect to that IP for another name
//	coalesce      look up two names on one IP, then one HTTP/2 connection requests both
//	snihost       TLS announces one name, the HTTP Host header asks for another
//
// Endpoints: names from the fixed Tranco list (or -names), paired by shared
// IPv4 addresses discovered over DoH, so the discovery itself leaves no
// system DNS trace. Only TLS handshakes and HEAD requests, a few hundred in
// total, jittered: polite to the sites involved.
//
// Run under sudo with the capture going (tools/realtools/challenge.sh does
// both) so the system DNS cache can be flushed before each scenario; without
// root the flush is skipped and cached answers show up as bypass, which the
// truth file then labels honestly.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"ohmyosi/internal/eval"
)

var (
	names    = flag.String("names", "", "file of candidate host names, one per line (default: the newest dist/workload/tranco-*.txt)")
	limit    = flag.Int("limit", 300, "candidate names to consider")
	reps     = flag.Int("n", 20, "repetitions per scenario")
	only     = flag.String("only", "", "comma-separated scenarios to run (default all)")
	out      = flag.String("o", "dist/challenge/challenge", "output prefix: writes <o>.truth.json and <o>.log.jsonl")
	dohURL   = flag.String("doh", "https://cloudflare-dns.com/dns-query", "DNS-over-HTTPS JSON endpoint")
	dryRun   = flag.Bool("dry-run", false, "discover endpoints and print the plan; make no scenario connections")
	maxStale = flag.Duration("stale-max", 6*time.Minute, "skip stale reps whose TTL wait would exceed this")
	flush    = flag.Bool("flush", true, "flush the system DNS cache before each rep (needs root; skipped otherwise)")
	role     = flag.String("role", "", "internal: resolver|fetcher child process")
)

var scenarios = []string{"baseline", "cohost", "crossprocess", "doh", "stale", "coalesce", "snihost"}

// entry is one logged connection.
type entry struct {
	Scenario string    `json:"scenario"`
	Rep      int       `json:"rep"`
	App      string    `json:"app"`
	PID      int       `json:"pid"`
	Local    string    `json:"local"`
	Remote   string    `json:"remote"`
	Name     string    `json:"name"`              // what the connection announced (SNI)
	Fetched  []string  `json:"fetched,omitempty"` // HTTP authorities actually requested over it
	Decoy    string    `json:"decoy,omitempty"`   // the name a DNS correlator is set up to show
	Outcome  string    `json:"outcome"`
	At       time.Time `json:"at"`
}

func main() {
	flag.Parse()
	switch *role {
	case "resolver":
		childResolve()
		return
	case "fetcher":
		childFetch()
		return
	}

	cands, err := candidates()
	if err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "discovering shared IPv4 addresses for %d names over DoH...\n", len(cands))
	addrs := discover(cands)
	pairs := sharedPairs(addrs)
	singles := singleNames(addrs)
	fmt.Fprintf(os.Stderr, "%d names resolved, %d co-hosted pairs\n", len(addrs), len(pairs))
	if len(pairs) == 0 {
		fail(fmt.Errorf("no co-hosted name pairs found; try -limit higher"))
	}
	want := map[string]bool{}
	for _, s := range strings.Split(*only, ",") {
		if s = strings.TrimSpace(s); s != "" {
			want[s] = true
		}
	}
	if *dryRun {
		fmt.Println("plan:")
		for _, s := range scenarios {
			if len(want) == 0 || want[s] {
				fmt.Printf("  %-13s x %d\n", s, *reps)
			}
		}
		for i, p := range pairs {
			if i == 10 {
				fmt.Printf("  ... %d more pairs\n", len(pairs)-10)
				break
			}
			fmt.Printf("  pair %s + %s on %s\n", p.real, p.decoy, p.ip)
		}
		return
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fail(err)
	}
	logf, err := os.Create(*out + ".log.jsonl")
	if err != nil {
		fail(err)
	}
	defer logf.Close()
	enc := json.NewEncoder(logf)
	truth := eval.Truth{}
	record := func(e entry) {
		e.At = time.Now()
		enc.Encode(e)
		if e.Local == "" || e.Remote == "" {
			return
		}
		l, err1 := netip.ParseAddrPort(e.Local)
		r, err2 := netip.ParseAddrPort(e.Remote)
		if err1 != nil || err2 != nil {
			return
		}
		note := "challenge " + e.Scenario
		if e.Decoy != "" {
			note += " (decoy " + e.Decoy + ")"
		}
		if len(e.Fetched) > 1 {
			note += " (also fetched " + strings.Join(e.Fetched[1:], ", ") + ")"
		}
		truth[eval.Key("tcp", netip.AddrPortFrom(l.Addr().Unmap(), l.Port()), netip.AddrPortFrom(r.Addr().Unmap(), r.Port()))] =
			eval.TruthEntry{App: e.App, Name: e.Name, Note: note}
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	self := filepath.Base(os.Args[0])
	if len(pairs) < len(scenarios) {
		fmt.Fprintf(os.Stderr, "warning: only %d pairs for %d scenarios; scenarios will share addresses\n", len(pairs), len(scenarios))
	}
	for si, sc := range scenarios {
		if len(want) > 0 && !want[sc] {
			continue
		}
		// Each scenario gets its own addresses: answers left in the capture by
		// one scenario must not become evidence for another's flows.
		own := partition(pairs, si, len(scenarios))
		fmt.Fprintf(os.Stderr, "== %s x %d (%d address pairs)\n", sc, *reps, len(own))
		if sc == "stale" {
			runStale(own, record)
			continue
		}
		for i := 0; i < *reps; i++ {
			flushDNS()
			p := own[(i+rng.Intn(len(own)))%len(own)]
			switch sc {
			case "baseline":
				n := p.real
				if len(singles) > 0 {
					n = singles[i%len(singles)]
				}
				record(connectNamed(sc, i, self, n, ""))
			case "cohost":
				sysLookup(p.real)
				sysLookup(p.decoy) // last answer for the IP is now the decoy
				record(dialTLS(sc, i, self, p.ip, p.real, p.decoy))
			case "crossprocess":
				record(crossProcess(i, p))
			case "doh":
				record(dialTLS(sc, i, self, p.ip, p.real, "")) // IP came from DoH discovery
			case "coalesce":
				sysLookup(p.real)
				sysLookup(p.decoy)
				record(coalesce(i, self, p))
			case "snihost":
				sysLookup(p.real)
				record(sniHost(i, self, p))
			}
			time.Sleep(time.Duration(200+rng.Intn(800)) * time.Millisecond)
		}
	}

	b, _ := json.MarshalIndent(truth, "", "  ")
	if err := os.WriteFile(*out+".truth.json", b, 0o644); err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s.truth.json (%d connections) and %s.log.jsonl\n", *out, len(truth), *out)
}

// ---- endpoints ----

type pair struct {
	ip          netip.Addr
	real, decoy string
	ttl         uint32
}

func candidates() ([]string, error) {
	path := *names
	if path == "" {
		m, _ := filepath.Glob("dist/workload/tranco-*-top*.txt")
		sort.Strings(m)
		if len(m) == 0 {
			return nil, fmt.Errorf("no -names file and no dist/workload/tranco-*.txt; run the workload once or pass -names")
		}
		path = m[len(m)-1]
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(out) < *limit {
		n := strings.TrimSpace(sc.Text())
		if n == "" {
			continue
		}
		out = append(out, n, "www."+n)
	}
	return out, nil
}

type dohAnswer struct {
	IPs []netip.Addr
	TTL uint32
}

var dohClient = &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{
	DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
	},
}}

func dohResolve(name string) (dohAnswer, error) {
	u := *dohURL + "?type=A&name=" + url.QueryEscape(name)
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Accept", "application/dns-json")
	resp, err := dohClient.Do(req)
	if err != nil {
		return dohAnswer{}, err
	}
	defer resp.Body.Close()
	var body struct {
		Answer []struct {
			Type int    `json:"type"`
			TTL  uint32 `json:"TTL"`
			Data string `json:"data"`
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return dohAnswer{}, err
	}
	var a dohAnswer
	for _, r := range body.Answer {
		if r.Type != 1 {
			continue
		}
		if ip, err := netip.ParseAddr(r.Data); err == nil {
			a.IPs = append(a.IPs, ip)
			if a.TTL == 0 || r.TTL < a.TTL {
				a.TTL = r.TTL
			}
		}
	}
	return a, nil
}

func discover(cands []string) map[string]dohAnswer {
	out := map[string]dohAnswer{}
	for _, n := range cands {
		a, err := dohResolve(n)
		if err == nil && len(a.IPs) > 0 {
			out[n] = a
		}
		time.Sleep(50 * time.Millisecond)
	}
	return out
}

// sharedPairs finds names whose IPv4 answers overlap and returns one pair per
// shared address, names in a stable order. Pure, so it is tested directly.
func sharedPairs(addrs map[string]dohAnswer) []pair {
	byIP := map[netip.Addr][]string{}
	ttl := map[string]uint32{}
	for n, a := range addrs {
		ttl[n] = a.TTL
		for _, ip := range a.IPs {
			byIP[ip] = append(byIP[ip], n)
		}
	}
	var out []pair
	used := map[string]bool{}
	var ips []netip.Addr
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	for _, ip := range ips {
		ns := byIP[ip]
		sort.Strings(ns)
		var a, b string
		for _, n := range ns {
			if used[n] {
				continue
			}
			if a == "" {
				a = n
			} else if registrable(n) != registrable(a) {
				b = n
				break
			}
		}
		if a != "" && b != "" {
			used[a], used[b] = true, true
			out = append(out, pair{ip: ip, real: a, decoy: b, ttl: ttl[b]})
		}
	}
	return out
}

// singleNames are names whose addresses no other candidate shares - clean
// baselines.
func singleNames(addrs map[string]dohAnswer) []string {
	count := map[netip.Addr]int{}
	for _, a := range addrs {
		for _, ip := range a.IPs {
			count[ip]++
		}
	}
	var out []string
	for n, a := range addrs {
		alone := true
		for _, ip := range a.IPs {
			if count[ip] > 1 {
				alone = false
			}
		}
		if alone {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// partition gives scenario k of n its own share of the pairs: pairs k, k+n,
// k+2n... Too few pairs to go round, and every scenario gets all of them.
func partition(pairs []pair, k, n int) []pair {
	if len(pairs) < n {
		return pairs
	}
	var out []pair
	for i := k; i < len(pairs); i += n {
		out = append(out, pairs[i])
	}
	return out
}

func registrable(n string) string {
	parts := strings.Split(strings.TrimPrefix(n, "www."), ".")
	if len(parts) < 2 {
		return n
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// ---- connections ----

func sysLookup(name string) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", name)
	if err != nil {
		return nil
	}
	return ips
}

func connectNamed(sc string, rep int, app, name, decoy string) entry {
	ips := sysLookup(name)
	if len(ips) == 0 {
		return entry{Scenario: sc, Rep: rep, App: app, PID: os.Getpid(), Name: name, Outcome: "lookup failed"}
	}
	return dialTLS(sc, rep, app, ips[0], name, decoy)
}

func dialTLS(sc string, rep int, app string, ip netip.Addr, sni, decoy string) entry {
	e := entry{Scenario: sc, Rep: rep, App: app, PID: os.Getpid(), Name: sni, Decoy: decoy}
	d := &net.Dialer{Timeout: 6 * time.Second}
	raw, err := d.Dial("tcp4", netip.AddrPortFrom(ip, 443).String())
	if err != nil {
		e.Outcome = "connect: " + err.Error()
		return e
	}
	defer raw.Close()
	e.Local, e.Remote = raw.LocalAddr().String(), raw.RemoteAddr().String()
	c := tls.Client(raw, &tls.Config{ServerName: sni, NextProtos: []string{"http/1.1"}})
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if err := c.Handshake(); err != nil {
		e.Outcome = "handshake: " + err.Error() // the SNI was still announced
		return e
	}
	e.Outcome = "ok"
	return e
}

func crossProcess(rep int, p pair) entry {
	dir, _ := os.MkdirTemp("", "acn-challenge")
	defer os.RemoveAll(dir)
	self, _ := os.Executable()
	// Distinct executables, so pktap reports distinct process names and the
	// borrowing counts as crossing applications, not siblings of one app.
	res, fet := filepath.Join(dir, "acn-resolver"), filepath.Join(dir, "acn-fetcher")
	if err := copyExe(self, res); err != nil {
		return entry{Scenario: "crossprocess", Rep: rep, Outcome: err.Error()}
	}
	if err := copyExe(self, fet); err != nil {
		return entry{Scenario: "crossprocess", Rep: rep, Outcome: err.Error()}
	}
	if err := exec.Command(res, "-role", "resolver", p.decoy).Run(); err != nil {
		return entry{Scenario: "crossprocess", Rep: rep, Outcome: "resolver: " + err.Error()}
	}
	outb, err := exec.Command(fet, "-role", "fetcher", p.ip.String(), p.real, p.decoy, fmt.Sprint(rep)).Output()
	var e entry
	if err != nil || json.Unmarshal(outb, &e) != nil {
		return entry{Scenario: "crossprocess", Rep: rep, Outcome: fmt.Sprintf("fetcher: %v", err)}
	}
	return e
}

func childResolve() {
	for _, n := range flag.Args() {
		sysLookup(n)
	}
}

func childFetch() {
	a := flag.Args()
	if len(a) < 4 {
		os.Exit(2)
	}
	ip, err := netip.ParseAddr(a[0])
	if err != nil {
		os.Exit(2)
	}
	var rep int
	fmt.Sscan(a[3], &rep)
	e := dialTLS("crossprocess", rep, "acn-fetcher", ip, a[1], a[2])
	json.NewEncoder(os.Stdout).Encode(e)
}

func copyExe(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

func coalesce(rep int, app string, p pair) entry {
	e := entry{Scenario: "coalesce", Rep: rep, App: app, PID: os.Getpid(), Name: p.real, Decoy: p.decoy}
	raw, err := (&net.Dialer{Timeout: 6 * time.Second}).Dial("tcp4", netip.AddrPortFrom(p.ip, 443).String())
	if err != nil {
		e.Outcome = "connect: " + err.Error()
		return e
	}
	defer raw.Close()
	e.Local, e.Remote = raw.LocalAddr().String(), raw.RemoteAddr().String()
	c := tls.Client(raw, &tls.Config{ServerName: p.real, NextProtos: []string{"h2"}})
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.Handshake(); err != nil {
		e.Outcome = "handshake: " + err.Error()
		return e
	}
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		e.Outcome = "no h2"
		return e
	}
	cc, err := (&http2.Transport{}).NewClientConn(c)
	if err != nil {
		e.Outcome = "h2: " + err.Error()
		return e
	}
	for _, host := range []string{p.real, p.decoy} {
		req, _ := http.NewRequest("HEAD", "https://"+host+"/", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMisdirectedRequest {
			e.Fetched = append(e.Fetched, host) // the server accepted it on this connection
		}
	}
	e.Outcome = "ok"
	return e
}

func sniHost(rep int, app string, p pair) entry {
	e := dialTLSFetch(rep, app, p)
	e.Scenario = "snihost"
	return e
}

func dialTLSFetch(rep int, app string, p pair) entry {
	e := entry{Rep: rep, App: app, PID: os.Getpid(), Name: p.real, Decoy: p.decoy}
	raw, err := (&net.Dialer{Timeout: 6 * time.Second}).Dial("tcp4", netip.AddrPortFrom(p.ip, 443).String())
	if err != nil {
		e.Outcome = "connect: " + err.Error()
		return e
	}
	defer raw.Close()
	e.Local, e.Remote = raw.LocalAddr().String(), raw.RemoteAddr().String()
	c := tls.Client(raw, &tls.Config{ServerName: p.real, NextProtos: []string{"http/1.1"}})
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if err := c.Handshake(); err != nil {
		e.Outcome = "handshake: " + err.Error()
		return e
	}
	fmt.Fprintf(c, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", p.decoy)
	io.Copy(io.Discard, io.LimitReader(c, 64<<10))
	e.Fetched = []string{p.decoy}
	e.Outcome = "ok"
	return e
}

func runStale(pairs []pair, record func(entry)) {
	type job struct {
		p   pair
		rep int
	}
	var jobs []job
	for i := 0; i < *reps && i < len(pairs); i++ {
		p := pairs[i]
		wait := time.Duration(p.ttl+5) * time.Second
		if p.ttl == 0 || wait > *maxStale {
			continue
		}
		jobs = append(jobs, job{p, i})
	}
	if len(jobs) == 0 {
		fmt.Fprintln(os.Stderr, "  stale: no pair with a TTL under -stale-max; skipped")
		return
	}
	flushDNS()
	var longest time.Duration
	start := time.Now()
	for _, j := range jobs {
		sysLookup(j.p.decoy) // the answer that will go stale
		if w := time.Duration(j.p.ttl+5) * time.Second; w > longest {
			longest = w
		}
	}
	fmt.Fprintf(os.Stderr, "  stale: %d reps, waiting %s for TTLs to expire\n", len(jobs), longest.Round(time.Second))
	time.Sleep(time.Until(start.Add(longest)))
	self := filepath.Base(os.Args[0])
	for _, j := range jobs {
		// No fresh lookup: the only answer for the address is the expired decoy.
		record(dialTLS("stale", j.rep, self, j.p.ip, j.p.real, j.p.decoy))
	}
}

func flushDNS() {
	if !*flush || os.Geteuid() != 0 {
		return
	}
	exec.Command("dscacheutil", "-flushcache").Run()
	exec.Command("killall", "-HUP", "mDNSResponder").Run()
	time.Sleep(300 * time.Millisecond)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "acn-challenge:", err)
	os.Exit(1)
}
