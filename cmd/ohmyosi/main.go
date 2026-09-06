// ohmyosi - see every connection leaving this machine, and which process opened it.
//
// Requires root: the pktap pseudo-interface is privileged. That is the whole
// price of admission - no kernel extension, no entitlement, no Apple developer
// account. Observation on macOS is open to anyone with sudo; only *blocking*
// needs Apple's permission.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ohmyosi/internal/api"
	"ohmyosi/internal/decode"
	"ohmyosi/internal/enrich"
	"ohmyosi/internal/flow"
	"ohmyosi/internal/pktap"
)

const version = "0.1.0"

func main() {
	iface := flag.String("i", "pktap,all", "capture interface; pktap,all covers every interface including VPNs, or name one like pktap,en0")
	filter := flag.String("filter", "", "BPF filter, e.g. \"not port 22\"")
	addr := flag.String("addr", "127.0.0.1:7777", "listen address for the UI and event stream")
	interval := flag.Duration("interval", time.Second, "how often to emit a tick")
	snaplen := flag.Int("snaplen", 1600, "bytes captured per packet; needs to cover a TLS ClientHello for SNI, drop to 128 for headers only")
	noRDNS := flag.Bool("no-rdns", false, "disable reverse DNS (the only thing here that sends packets)")
	noIcons := flag.Bool("no-icons", false, "skip application icon extraction")
	jsonOut := flag.Bool("json", false, "write NDJSON to stdout instead of serving a UI")
	cacheDir := flag.String("cache", filepath.Join(os.TempDir(), "ohmyosi"), "cache directory for extracted icons")
	readFile := flag.String("read", "", "replay a saved capture (.pcap or .pcapng) instead of capturing live; needs no root")
	rangesFile := flag.String("ranges", "", "published address-allocation table (default <cache>/ranges.json)")
	updateRanges := flag.Bool("update-ranges", false, "fetch published address ranges from Cloudflare, AWS, Google, Fastly and GitHub, then exit")
	rdap := flag.Bool("rdap", false, "look up domain ownership and registration age over RDAP (makes network requests, cached to disk)")
	favicons := flag.Bool("favicons", false, "fetch site favicons (connects to each destination; cached to disk)")
	flag.Parse()

	if *rangesFile == "" {
		*rangesFile = filepath.Join(*cacheDir, "ranges.json")
	}
	if *updateRanges {
		os.Exit(doUpdateRanges(*rangesFile))
	}

	if os.Geteuid() != 0 && *readFile == "" && !*updateRanges {
		fmt.Fprintln(os.Stderr, "ohmyosi: needs root to open pktap. try: sudo ohmyosi")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var (
		src *pktap.Source
		err error
	)
	if *readFile != "" {
		src, err = pktap.OpenFile(*readFile)
	} else {
		src, err = pktap.Open(ctx, *iface, *filter, *snaplen)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ohmyosi: %v\n", err)
		if *readFile == "" {
			fmt.Fprintf(os.Stderr, "hint: list interfaces with `ifconfig -l`, then try -i pktap,all or -i pktap,en0\n")
		}
		os.Exit(1)
	}
	defer src.Close()
	source := *iface
	if *readFile != "" {
		source = *readFile
	}
	logf("capturing on %s", source)

	// Whether the capture is readable cannot be answered at startup. With
	// classic pcap, tcpdump holds its header in a stdio buffer until the first
	// packet forces a flush, so an idle interface produces nothing at all.
	// Waiting for that inline hung the daemon silently, so it happens here,
	// with a running commentary.
	var pktapOK atomic.Bool
	pktapOK.Store(true)
	// Closed when capture ends, for any reason.
	captureDone := make(chan struct{})
	go func() {
		for attempt := 0; ; attempt++ {
			select {
			case <-captureDone:
				return
			default:
			}
			switch err := src.WaitReady(ctx, 5*time.Second); {
			case err == nil:
				select {
				case <-captureDone: // already finished; saying "live" now would be noise
				default:
					logf("capture live (%s)", src.Format())
				}
				return
			case errors.Is(err, pktap.ErrNoPacketsYet):
				if attempt == 0 {
					logf("capture running but nothing readable yet on %s - still waiting", source)
					logf("if that interface is idle, stop and try -i pktap,all (ifconfig -l lists them)")
				}
			case ctx.Err() != nil:
				return
			default:
				logf("capture failed: %v", err)
				cancel()
				return
			}
		}
	}()

	table := flow.NewTable(int32(os.Getpid()))
	if _, portStr, err := net.SplitHostPort(*addr); err == nil {
		if n, err := strconv.Atoi(portStr); err == nil {
			table.SelfPort = uint16(n)
		}
	}
	names := enrich.NewNames(!*noRDNS)
	names.Run(ctx, 4)

	// Published allocation lists. Absent is fine - it just means more addresses
	// stay unidentified - but say so rather than degrading quietly.
	icons, err := enrich.NewFavicons(filepath.Join(*cacheDir, "favicons"), *favicons)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ohmyosi: favicon cache: %v\n", err)
		os.Exit(1)
	}
	icons.Run(ctx)
	if *favicons {
		logf("favicons enabled: ohmyosi will connect to destination sites to fetch them")
	}

	owners := enrich.NewOwners(filepath.Join(*cacheDir, "owners.json"), *rdap)
	if err := owners.Load(); err == nil {
		logf("loaded cached domain ownership")
	}
	owners.Run(ctx)
	if *rdap {
		logf("RDAP enabled: domain ownership lookups will leave this machine")
	}

	ranges := enrich.NewRanges()
	if err := ranges.Load(*rangesFile); err != nil {
		logf("no address-allocation table (%v)", err)
		logf("run `ohmyosi -update-ranges` once to fetch it; without it, hosts outside DNS stay unnamed")
	} else {
		logf("loaded %d published prefixes (updated %s)", ranges.Len(), ranges.Updated().Format("2006-01-02"))
	}
	procs, err := enrich.NewProcs(filepath.Join(*cacheDir, "icons"), !*noIcons)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ohmyosi: icon cache: %v\n", err)
		os.Exit(1)
	}
	procs.Run(ctx, 2)

	var pkts, decoded, undecoded atomic.Uint64
	started := time.Now()
	hostname, _ := os.Hostname()

	// sent tracks which processes each connected client already knows about, so
	// ticks carry only newly-resolved ones. A new client gets the lot in hello.
	var sentMu sync.Mutex
	sent := map[int32]bool{}

	hostInfo := func() *api.Host {
		return &api.Host{
			Hostname: hostname, Iface: *iface, Pktap: pktapOK.Load(),
			Started: float64(started.UnixNano()) / 1e9, Version: version,
		}
	}

	// build assembles an envelope, resolving names for each flow. A flow's own
	// SNI wins over the address cache: it is what this client actually asked
	// for, whereas one address can serve a hundred names.
	build := func(typ string, fs []flow.Flow, gone []string, allProcs bool) api.Envelope {
		env := api.Envelope{Type: typ, T: float64(time.Now().UnixNano()) / 1e9, Gone: gone}
		env.Flows = make([]api.FlowView, 0, len(fs))
		needed := make(map[int32]bool, len(fs))
		for _, f := range fs {
			env.Flows = append(env.Flows, api.View(f, endpoint(f, names, ranges, owners, icons)))
			if f.PID > 0 {
				needed[f.PID] = true
			}
		}
		sentMu.Lock()
		for pid := range needed {
			if !allProcs && sent[pid] {
				continue
			}
			if p := procs.Get(pid); p != nil {
				env.Procs = append(env.Procs, *p)
				sent[pid] = true
			}
		}
		known := len(sent)
		sentMu.Unlock()

		st := &api.Stats{
			Packets: pkts.Load(), Decoded: decoded.Load(), Undecoded: undecoded.Load(),
			Flows: len(fs), ProcsKnown: known,
		}
		// Coverage across every live flow, so the number does not swing with
		// whatever happened to change in this tick.
		st.Prefixes = ranges.Len()
		for _, f := range table.All() {
			if f.Self {
				continue
			}
			st.LiveFlows++
			if f.PID > 0 {
				st.WithProcess++
			}
			e := endpoint(f, names, ranges, owners, icons)
			if e.Host != "" {
				st.WithName++
			}
			if e.Org != "" {
				st.WithOrg++
			}
			if e.Host == "" && e.Org == "" {
				st.Unidentified++
			}
			if e.HostSrc != "sni" && e.HostSrc != "dns" {
				st.DirectIP++
			}
		}
		env.Stats = st
		return env
	}

	hello := func() api.Envelope {
		e := build("hello", table.All(), nil, true)
		e.Host = hostInfo()
		return e
	}

	// Capture loop. Everything expensive - resolvers, icon extraction, JSON -
	// happens elsewhere; a blocking call here drops packets.
	// Replaying a file reaches the end almost immediately, and the last flows
	// would otherwise be lost between the final packet and the next tick.
	dec := decode.New()
	go func() {
		defer close(captureDone)
		var (
			seen      int
			withPID   int
			verdict   sync.Once
		)
		for {
			p, err := src.Read()
			if err != nil {
				if errors.Is(err, io.EOF) {
					logf("end of capture file, %d packets", pkts.Load())
				} else if ctx.Err() == nil {
					logf("capture stopped: %v", err)
				}
				return
			}
			if p == nil {
				continue // PTH_TYPE_DROP and friends
			}
			// Whether process attribution works can only be judged from real
			// packets, and not from one: a couple genuinely have no owning
			// process (kernel-originated ARP, some multicast). So sample the
			// first fifty and then decide once.
			if seen < 50 {
				seen++
				if p.PID > 0 {
					withPID++
				}
			} else {
				verdict.Do(func() {
					if withPID == 0 {
						pktapOK.Store(false)
						logf("warning: no process metadata in this capture - flows will have no process names")
					} else {
						logf("process attribution working (%d of first %d packets attributed)", withPID, seen)
					}
				})
			}
			pkts.Add(1)
			o := dec.Decode(p)
			if o == nil {
				undecoded.Add(1)
				continue
			}
			for _, r := range o.DNS {
				names.Learn(r.IP, r.Name, enrich.SrcDNS)
			}
			if o.SNI != "" {
				names.Learn(o.Dst, o.SNI, enrich.SrcSNI)
			}
			table.Observe(o)
			decoded.Add(1)
		}
	}()

	srv := api.NewServer(hello, procs.IconDir(), icons.Dir())
	if !*jsonOut {
		httpSrv := &http.Server{Addr: *addr, Handler: srv.Handler()}
		go func() {
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logf("http: %v", err)
				cancel()
			}
		}()
		defer func() {
			sctx, c := context.WithTimeout(context.Background(), 2*time.Second)
			defer c()
			httpSrv.Shutdown(sctx)
		}()
		logf("watching %s - open http://%s", *iface, *addr)
	} else {
		enc := json.NewEncoder(os.Stdout)
		enc.Encode(hello())
	}

	enc := json.NewEncoder(os.Stdout)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	emit := func() {
		for _, pid := range table.PIDs() {
			procs.Get(pid)
		}
		for _, ip := range table.RemoteIPs() {
			names.Lookup(ip)
		}
		// Expire on the capture clock, not the wall clock - see flow.Table.Now.
		gone := table.Expire(table.Now())
		changed := table.Snapshot()
		if len(changed) == 0 && len(gone) == 0 {
			return
		}
		env := build("tick", changed, gone, false)
		if *jsonOut {
			enc.Encode(env)
		} else {
			srv.Broadcast(env)
		}
	}

	for {
		select {
		case <-ctx.Done():
			logf("stopped after %s, %d packets", time.Since(started).Round(time.Second), pkts.Load())
			return
		case <-captureDone:
			// Flush whatever the last packets produced before exiting.
			emit()
			logf("stopped after %s, %d packets", time.Since(started).Round(time.Second), pkts.Load())
			return
		case <-ticker.C:
			emit()
		}
	}
}

// endpoint assembles everything known about the far end.
//
// Name and organisation are kept apart on purpose. The SNI says who the client
// asked for; the allocation table says whose hardware answered. For most modern
// traffic those are different companies, and collapsing them into one field
// would report "Cloudflare" for half the internet.
func endpoint(f flow.Flow, names *enrich.Names, ranges *enrich.Ranges, owners *enrich.Owners, icons *enrich.Favicons) api.Endpoint {
	ip := f.Remote.Addr()
	e := api.Endpoint{IP: ip.String(), Port: f.Remote.Port(), AgeDays: -1}
	if f.SNI != "" {
		e.Host, e.HostSrc = f.SNI, string(enrich.SrcSNI)
	} else if h, src := names.Lookup(ip); h != "" {
		e.Host, e.HostSrc = h, string(src)
	}
	if p, ok := ranges.Lookup(ip); ok {
		e.Org, e.OrgDetail, e.OrgSrc = p.Org, p.Detail, p.Src
	}
	// Ownership hangs off the name, not the address. A reverse-DNS name is the
	// hoster's own (ec2-…compute.amazonaws.com), so looking up who registered
	// it would just report Amazon again - only a name the machine actually
	// asked for identifies the far end.
	if e.Host != "" && (e.HostSrc == string(enrich.SrcSNI) || e.HostSrc == string(enrich.SrcDNS)) {
		e.Domain = enrich.Registrable(e.Host)
		if o := owners.Lookup(e.Domain); o != nil {
			e.Owner, e.Registrar, e.AgeDays = o.Registrant, o.Registrar, o.AgeDays()
		}
		e.Favicon = icons.Lookup(e.Domain)
	}
	return e
}

// doUpdateRanges fetches every published list and reports each one separately.
// A source that fails is named, not swallowed: fewer names is a result the
// operator should be told about.
func doUpdateRanges(path string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fmt.Fprintln(os.Stderr, "fetching published address ranges...")
	prefixes, results := enrich.Update(ctx)
	failed := 0
	for _, r := range results {
		switch {
		case r.Err != nil:
			failed++
			fmt.Fprintf(os.Stderr, "  %-14s FAILED  %v\n", r.Source, r.Err)
		default:
			fmt.Fprintf(os.Stderr, "  %-14s %6d prefixes\n", r.Source, r.Count)
		}
	}
	if len(prefixes) == 0 {
		fmt.Fprintln(os.Stderr, "no prefixes fetched; leaving any existing table alone")
		return 1
	}
	r := enrich.NewRanges()
	r.Set(prefixes, time.Now())
	if err := r.Save(path); err != nil {
		fmt.Fprintf(os.Stderr, "writing %s: %v\n", path, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote %d prefixes to %s", r.Len(), path)
	if failed > 0 {
		fmt.Fprintf(os.Stderr, " (%d source(s) failed - coverage will be lower)", failed)
	}
	fmt.Fprintln(os.Stderr)
	return 0
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s ohmyosi: %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
}
