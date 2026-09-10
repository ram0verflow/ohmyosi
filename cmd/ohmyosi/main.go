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
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ohmyosi/internal/api"
	"ohmyosi/internal/decode"
	"ohmyosi/internal/enforce"
	"ohmyosi/internal/enrich"
	"ohmyosi/internal/flow"
	"ohmyosi/internal/history"
	"ohmyosi/internal/pktap"
	"ohmyosi/internal/rules"
	"ohmyosi/internal/score"
	"ohmyosi/internal/spoof"
)

const version = "0.1.0"

// persistentDataDir holds state that should outlive a run - the block/allow
// rules above all. System-wide and root-owned, matching where enforcement acts.
const persistentDataDir = "/Library/Application Support/ohmyosi"

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
	recordFile := flag.String("record", "", "record this session's findings to an NDJSON file for later replay")
	playFile := flag.String("play", "", "replay a recorded session instead of capturing; needs no root")
	playSpeed := flag.Float64("speed", 1, "playback speed multiplier (0 = as fast as possible)")
	diffFiles := flag.String("diff", "", "compare two recordings: -diff baseline.ndjson,today.ndjson - reports which app/destination relationships are new, gone or changed, then exits")
	diffLimit := flag.Int("diff-limit", 25, "how many entries to print per section of a diff")
	readFile := flag.String("read", "", "replay a saved capture (.pcap or .pcapng) instead of capturing live; needs no root")
	rangesFile := flag.String("ranges", "", "published address-allocation table (default <cache>/ranges.json)")
	updateRanges := flag.Bool("update-ranges", false, "fetch published address ranges from Cloudflare, AWS, Google, Fastly and GitHub, then exit")
	rdap := flag.Bool("rdap", false, "look up domain ownership and registration age over RDAP (makes network requests, cached to disk)")
	favicons := flag.Bool("favicons", false, "fetch site favicons (connects to each destination; cached to disk)")
	asn := flag.Bool("asn", true, "resolve IP addresses to ASN/organisation via Team Cymru DNS (cached)")
	noSeed := flag.Bool("no-seed", false, "skip seeding existing sockets from lsof at startup")
	rulesFile := flag.String("rules", "", "block/allow rule file (default <cache>/rules.json)")
	enforceFlag := flag.Bool("enforce", false, "apply block rules via pf and /etc/hosts (needs root; off by default - observe first)")
	importList := flag.String("import-blocklist", "", "import a hosts-format blocklist (file path or http(s) URL) as domain block rules, then exit")
	spoofMAC := flag.String("spoof-mac", "", "assign a random locally-administered MAC to this interface, then exit (root)")
	setHostname := flag.String("set-hostname", "", "set the machine hostname (all three macOS names), then exit (root)")
	flag.Parse()

	if *rulesFile == "" {
		// Rules live in a persistent, system-wide location, not the temp cache:
		// a blocklist you imported should survive a reboot, and enforcement is
		// system-wide anyway. Root can always write here.
		*rulesFile = filepath.Join(persistentDataDir, "rules.json")
	}
	if *importList != "" {
		os.Exit(doImportBlocklist(*importList, *rulesFile))
	}
	if *spoofMAC != "" || *setHostname != "" {
		os.Exit(doSpoof(*spoofMAC, *setHostname))
	}

	if *rangesFile == "" {
		*rangesFile = filepath.Join(*cacheDir, "ranges.json")
	}
	if *updateRanges {
		os.Exit(doUpdateRanges(*rangesFile))
	}

	// Diffing two recordings reads two files and opens no interface, so it runs
	// as whoever recorded them. It sits above the root check for that reason.
	if *diffFiles != "" {
		os.Exit(doDiff(*diffFiles, *diffLimit, *jsonOut))
	}

	// Root is needed to open pktap, and only for that. Reading a capture file
	// or replaying a recording touches no interface, so neither needs it - the
	// flags have always said so, and now the check agrees with them.
	if os.Geteuid() != 0 && *readFile == "" && *playFile == "" && !*updateRanges {
		fmt.Fprintln(os.Stderr, "ohmyosi: needs root to open pktap. try: sudo ohmyosi")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *playFile != "" {
		os.Exit(doPlayback(ctx, *playFile, *addr, *playSpeed, *jsonOut))
	}

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

	beacons := score.NewTracker()

	// First-sighting history: which process/destination pairs this machine has
	// talked to before, so a pair never seen until now can be flagged. Absent is
	// fine - it just means nothing is known yet.
	hist := history.New(filepath.Join(*cacheDir, "history.json"))
	if err := hist.Load(); err != nil {
		logf("first-sighting history unavailable (%v)", err)
	} else if n := hist.Len(); n > 0 {
		logf("loaded %d known process/destination pairs", n)
	}
	hist.Run(ctx, 30*time.Second)
	// alerted dedups: a flow raises at most one alert for its lifetime.
	alerted := map[string]bool{}

	// Block/allow rules, and the optional enforcer that applies them. Rules are
	// always evaluated so the UI can show what each one *would* do; nothing is
	// actually blocked unless -enforce is set. Observe first stays the default.
	ruleset := rules.New(*rulesFile)
	if err := ruleset.Load(); err != nil {
		logf("rules unavailable (%v)", err)
	} else if n := len(ruleset.List()); n > 0 {
		logf("loaded %d block/allow rules", n)
	}
	// Enforcement is runtime-toggleable so the app can turn blocking on and off
	// without a restart. It starts on only if -enforce was passed and we are
	// root; otherwise it is off and the app can enable it later (which also
	// needs root).
	if *enforceFlag && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "ohmyosi: -enforce needs root to edit /etc/hosts and load a pf anchor")
		os.Exit(1)
	}
	enf := newEnforcement(*enforceFlag)
	defer enf.restore()
	if *enforceFlag {
		logf("ENFORCEMENT ON: matching flows blocked via pf, blocked domains via /etc/hosts")
		logf("note: pf enforcement needs the ohmyosi anchor referenced in /etc/pf.conf - see README")
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

	asnDB := enrich.NewASN(*asn)
	asnDB.Run(ctx, 2)
	if *asn {
		logf("ASN lookup enabled via Team Cymru DNS (cached per address)")
	}

	if *readFile == "" && !*noSeed {
		if n, err := enrich.SeedTable(ctx, table); err != nil {
			logf("lsof seed skipped: %v", err)
		} else if n > 0 {
			logf("seeded %d existing connections from lsof", n)
		}
	}

	inv := api.InvestigateCtx{Names: names, Ranges: ranges, Owners: owners, Icons: icons, ASN: asnDB}

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
			e := api.Investigate(f.Remote.Addr(), f.Remote.Port(), f.SNI, inv)
			fc := hist.FirstContact(histKey(f.DisplayComm(), e))
			v := rate(f, e, procs, beacons, fc)
			dec := ruleset.Decide(targetOf(f, e, procs))
			env.Flows = append(env.Flows, api.View(f, e, v, fc, dec, enf.isOn() && dec.Blocked()))
			if pid := f.DisplayPID(); pid > 0 {
				needed[pid] = true
			}
			// Alerts fire on ticks only - a client that just connected gets the
			// current state in hello without a burst of banners for flows that
			// were already loud before it was watching. One alert per flow, when
			// it first crosses into a band worth interrupting for.
			if typ == "tick" && !f.Self && v.Band == "loud" && !alerted[f.ID] {
				alerted[f.ID] = true
				dest := e.Host
				if dest == "" {
					dest = e.Org
				}
				if dest == "" {
					dest = e.IP
				}
				env.Alerts = append(env.Alerts, api.Alert{
					FlowID: f.ID, Comm: f.DisplayComm(), Dest: dest,
					Score: v.Score, Band: v.Band, Reasons: signalReasons(v),
					T: float64(time.Now().UnixNano()) / 1e9,
				})
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
			if f.DisplayPID() > 0 {
				st.WithProcess++
			}
			e := api.Investigate(f.Remote.Addr(), f.Remote.Port(), f.SNI, inv)
			fc := hist.FirstContact(histKey(f.DisplayComm(), e))
			switch rate(f, e, procs, beacons, fc).Band {
			case "notable":
				st.Notable++
			case "unusual":
				st.Unusual++
			case "loud":
				st.Loud++
			}
			if e.Host != "" {
				st.WithName++
			}
			if e.Org != "" {
				st.WithOrg++
			}
			if e.Host == "" && e.Org == "" {
				st.Unidentified++
			}
			if e.HostSrc != "sni" && e.HostSrc != "dns" && e.HostSrc != "http" {
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
			seen    int
			withPID int
			verdict sync.Once
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
			if o.HTTPHost != "" {
				names.Learn(o.Dst, o.HTTPHost, enrich.SrcHTTP)
			}
			table.Observe(o)
			decoded.Add(1)
		}
	}()

	var rec *api.Recorder
	if *recordFile != "" {
		var rerr error
		rec, rerr = api.NewRecorder(*recordFile, version, hostname, *iface)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "ohmyosi: record: %v\n", rerr)
			os.Exit(1)
		}
		defer func() {
			rec.Close()
			logf("recorded %s", rec.Summary())
		}()
		logf("recording to %s", *recordFile)
	}

	srv := api.NewServer(hello, procs.IconDir(), icons.Dir())
	srv.Rules = ruleset
	// Every action the daemon can take is reachable from the app, not just the
	// command line. Each one that changes the system checks for root itself.
	srv.IsRoot = os.Geteuid() == 0
	srv.Enforcing = enf.isOn
	srv.Interfaces = networkInterfaces
	srv.Enforce = func(on bool) error {
		if os.Geteuid() != 0 {
			return errors.New("enforcement needs root")
		}
		enf.set(on)
		return nil
	}
	srv.ImportBlock = func(src string) (int, error) {
		domains, err := fetchBlocklist(ctx, resolveCategory(src))
		if err != nil {
			return 0, err
		}
		if len(domains) == 0 {
			return 0, nil
		}
		if err := ruleset.AddMany(rules.BlocklistRules(domains, sourceLabel(src))); err != nil {
			return 0, err
		}
		logf("imported %d domains from %q", len(domains), sourceLabel(src))
		return len(domains), nil
	}
	srv.SpoofMAC = func(iface string) (string, error) {
		if os.Geteuid() != 0 {
			return "", errors.New("changing the MAC needs root")
		}
		mac := spoof.RandomMAC()
		if err := spoof.SetMAC(ctx, iface, mac); err != nil {
			return "", err
		}
		logf("MAC on %s set to %s", iface, mac)
		return mac, nil
	}
	srv.SetHostname = func(name string) error {
		if os.Geteuid() != 0 {
			return errors.New("changing the hostname needs root")
		}
		if err := spoof.SetHostname(ctx, name); err != nil {
			return err
		}
		logf("hostname set to %q", name)
		return nil
	}
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
			asnDB.Lookup(ip)
		}
		// Expire on the capture clock, not the wall clock - see flow.Table.Now.
		// A flow in state "new" is a connection that was just opened, which is
		// exactly the event a cadence is measured from.
		gone := table.Expire(table.Now())
		changed := table.Snapshot()
		live := make(map[string]bool, len(changed))
		for _, f := range changed {
			k := fmt.Sprintf("%d|%s", f.PID, f.Remote.Addr())
			live[k] = true
			if f.State == flow.StateNew {
				beacons.Observe(k, f.FirstSeen)
			}
		}
		beacons.Forget(live)

		// Apply enforcement against every live flow, not just what changed: a
		// rule can match a long-lived connection that moved no packet this tick,
		// and a rule added a moment ago must bite the flows already open. The
		// controller skips the work when nothing changed, so this is cheap on an
		// idle tick, and does nothing at all while enforcement is off.
		if enf.isOn() {
			var conns []enforce.Conn
			for _, f := range table.All() {
				if f.Self {
					continue
				}
				e := api.Investigate(f.Remote.Addr(), f.Remote.Port(), f.SNI, inv)
				if ruleset.Decide(targetOf(f, e, procs)).Blocked() {
					conns = append(conns, enforce.Conn{
						Proto:   string(f.Proto),
						LocalIP: f.Local.Addr().String(), LocalPort: f.Local.Port(),
						RemoteIP: f.Remote.Addr().String(), RemotePort: f.Remote.Port(),
					})
				}
			}
			enf.sync(ruleset, conns)
		}

		if len(changed) == 0 && len(gone) == 0 {
			return
		}
		env := build("tick", changed, gone, false)
		rec.Write(env)
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

// rate scores one flow. Everything it looks at is already on screen somewhere
// else, which is the point: the score is a summary of visible facts, not a
// separate opinion arrived at privately.
func rate(f flow.Flow, e api.Endpoint, procs *enrich.Procs, beacons *score.Tracker, firstContact bool) score.Result {
	key := fmt.Sprintf("%d|%s", f.PID, f.Remote.Addr())
	reg, n := beacons.Regularity(key)
	path, signing := "", ""
	// The process credited to the UI is the one to judge - for a resolver flow
	// that is the effective app, not mDNSResponder.
	if p := procs.Get(f.DisplayPID()); p != nil {
		path, signing = p.Path, p.Signing
	}
	age := -1
	if e.AgeDays > 0 {
		age = e.AgeDays
	}
	return score.Evaluate(score.Input{
		DirectIP:         e.HostSrc != "sni" && e.HostSrc != "dns",
		HasName:          e.Host != "",
		HasOrg:           e.Org != "",
		RemotePort:       f.Remote.Port(),
		Proto:            string(f.Proto),
		ExecPath:         path,
		Signing:          signing,
		IsSelf:           f.Self,
		RemoteIsLocal:    localDestination(f.Remote.Addr()),
		DomainAgeDays:    age,
		BeaconRegularity: reg,
		BeaconSamples:    n,
		Bytes:            f.BytesUp + f.BytesDown,
		BytesUp:          f.BytesUp,
		BytesDown:        f.BytesDown,
		FirstContact:     firstContact,
	})
}

// localDestination reports whether an address is on the machine's own network
// rather than out on the internet. Private ranges, carrier-grade NAT, unique
// local addresses, link-local, multicast and loopback all count: none of them
// have public DNS or an allocation record, so the anonymity signals mean
// nothing there.
func localDestination(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsUnspecified() {
		return true
	}
	// 100.64.0.0/10, carrier-grade NAT, which is also what Tailscale hands out.
	if a.Is4() {
		b := a.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return true
		}
	}
	return false
}

// targetOf assembles what the rule engine matches against from a flow and its
// resolved endpoint. The app name is the load-bearing field: it is what lets a
// rule say "block Spotify" rather than "block this IP".
func targetOf(f flow.Flow, e api.Endpoint, procs *enrich.Procs) rules.Target {
	app := ""
	if p := procs.Get(f.DisplayPID()); p != nil {
		app = p.App
	}
	return rules.Target{
		App: app, Comm: f.DisplayComm(),
		Domain: e.Domain, Host: e.Host, IP: e.IP, Port: f.Remote.Port(),
	}
}

// histKey identifies a process/destination pair for the first-sighting store.
// It leans on the registrable domain or organisation rather than the raw
// address, so a service that rotates through many IPs still reads as one pair.
func histKey(comm string, e api.Endpoint) string {
	dest := e.Domain
	switch {
	case dest != "":
	case e.Org != "":
		dest = e.Org
	case e.Host != "":
		dest = e.Host
	default:
		dest = e.IP
	}
	return comm + "→" + dest
}

// connsSig is a stable fingerprint of the set of connections to block, so the
// pf anchor is only reloaded when the set actually changes rather than once a
// second. Order-independent: the same set in any order yields the same string.
func connsSig(conns []enforce.Conn) string {
	parts := make([]string, len(conns))
	for i, c := range conns {
		parts[i] = fmt.Sprintf("%s|%s:%d>%s:%d", c.Proto, c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// signalReasons flattens a score result's signals into the reason sentences an
// alert carries. An alert with no argument is one nobody can check.
func signalReasons(r score.Result) []string {
	if len(r.Signals) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.Signals))
	for _, s := range r.Signals {
		out = append(out, s.Reason)
	}
	return out
}

// doSpoof performs the one-off MAC/hostname changes and exits. Both need root,
// same as capture, and both are deliberate actions a person asked for on the
// command line - never a background behaviour.
func doSpoof(iface, hostname string) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "ohmyosi: spoofing needs root (it changes the interface and system names)")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if iface != "" {
		before, _ := spoof.CurrentMAC(ctx, iface)
		mac := spoof.RandomMAC()
		if err := spoof.SetMAC(ctx, iface, mac); err != nil {
			fmt.Fprintf(os.Stderr, "mac: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "%s MAC %s -> %s\n", iface, before, mac)
		fmt.Fprintln(os.Stderr, "note: on Wi-Fi, rejoin the network for the new address to take effect")
	}
	if hostname != "" {
		if err := spoof.SetHostname(ctx, hostname); err != nil {
			fmt.Fprintf(os.Stderr, "hostname: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "hostname set to %q\n", hostname)
	}
	return 0
}

// doImportBlocklist reads a hosts-format blocklist from a file or URL and adds
// its domains as block rules. Separated from the running daemon deliberately:
// importing is a one-off that ends with an exit, like updating the ranges, and a
// URL is the only network this command touches - stated plainly because
// fetching a list tells its host you asked for it.
func doImportBlocklist(src, rulesFile string) int {
	ctx := context.Background()
	resolved := resolveCategory(src)
	fmt.Fprintf(os.Stderr, "importing blocklist from %s ...\n", resolved)
	domains, err := fetchBlocklist(ctx, resolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import failed: %v\n", err)
		return 1
	}
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "no domains found in that list")
		return 1
	}
	set := rules.New(rulesFile)
	if err := set.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "loading existing rules: %v\n", err)
		return 1
	}
	if err := set.AddMany(rules.BlocklistRules(domains, sourceLabel(src))); err != nil {
		fmt.Fprintf(os.Stderr, "saving rules: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "imported %d domains as block rules into %s\n", len(domains), rulesFile)
	fmt.Fprintln(os.Stderr, "run with -enforce to apply them (they go into /etc/hosts)")
	return 0
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

// doPlayback serves a recorded session. Everything the UI needs is already in
// the file - names, scores, reasons and all - so nothing is recomputed and
// nothing can quietly reach a different conclusion than the one recorded.
func doPlayback(ctx context.Context, path, addr string, speed float64, jsonOut bool) int {
	var (
		mu    sync.Mutex
		state = api.Envelope{Type: "hello"}
		flows = map[string]api.FlowView{}
		procs = map[int32]enrich.Proc{}
	)

	hello := func() api.Envelope {
		mu.Lock()
		defer mu.Unlock()
		out := api.Envelope{Type: "hello", T: state.T, Host: state.Host, Stats: state.Stats}
		for _, f := range flows {
			out.Flows = append(out.Flows, f)
		}
		for _, p := range procs {
			out.Procs = append(out.Procs, p)
		}
		return out
	}

	srv := api.NewServer(hello, "", "")
	if !jsonOut {
		httpSrv := &http.Server{Addr: addr, Handler: srv.Handler()}
		go func() {
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logf("http: %v", err)
			}
		}()
		defer httpSrv.Close()
		logf("replaying %s - open http://%s", path, addr)
	}

	enc := json.NewEncoder(os.Stdout)
	err := api.Play(path, speed, func(e api.Envelope) {
		mu.Lock()
		if e.Host != nil {
			state.Host = e.Host
		}
		state.T, state.Stats = e.T, e.Stats
		for _, f := range e.Flows {
			flows[f.ID] = f
		}
		for _, p := range e.Procs {
			procs[p.PID] = p
		}
		for _, id := range e.Gone {
			delete(flows, id)
		}
		mu.Unlock()

		if jsonOut {
			enc.Encode(e)
		} else {
			srv.Broadcast(e)
		}
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ohmyosi: replaying %s: %v\n", path, err)
		return 1
	}
	logf("end of recording - the view is frozen where it ended")
	if jsonOut {
		return 0
	}
	<-ctx.Done()
	return 0
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s ohmyosi: %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
}
