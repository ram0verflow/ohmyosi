package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"ohmyosi/internal/api"
	"ohmyosi/internal/enforce"
	"ohmyosi/internal/rules"
)

// enforcement wraps the pf/hosts backend with a runtime on/off switch, so the
// app can turn blocking on and off without restarting the daemon. All access is
// serialised: the tick loop reads it while the HTTP handler may be flipping it.
type enforcement struct {
	mu      sync.Mutex
	e       *enforce.Enforcer
	on      bool
	lastVer int
	lastSig string
}

func newEnforcement(on bool) *enforcement {
	return &enforcement{
		e:       &enforce.Enforcer{HostsPath: "/etc/hosts", Anchor: "ohmyosi", Apply: on, Logf: logf},
		on:      on,
		lastVer: -1,
	}
}

func (en *enforcement) isOn() bool {
	en.mu.Lock()
	defer en.mu.Unlock()
	return en.on
}

// set turns enforcement on or off, applying or tearing down immediately. Turning
// on forces a resync on the next tick; turning off restores /etc/hosts and
// flushes the pf anchor right away.
func (en *enforcement) set(on bool) {
	en.mu.Lock()
	defer en.mu.Unlock()
	if on == en.on {
		return
	}
	en.on = on
	if on {
		en.e.Apply = true
		en.lastVer = -1
		en.lastSig = "\x00" // any real signature differs, forcing a reload
		logf("enforcement ON")
	} else {
		en.e.Apply = true // Restore is a no-op unless Apply is set
		en.e.Restore()
		en.e.Apply = false
		en.lastVer, en.lastSig = -1, ""
		logf("enforcement OFF - /etc/hosts restored, pf anchor flushed")
	}
}

// sync pushes the current rules to the system. Cheap when nothing changed: both
// halves skip the work unless the rules or the blocked-connection set moved.
func (en *enforcement) sync(ruleset *rules.Set, conns []enforce.Conn) {
	en.mu.Lock()
	defer en.mu.Unlock()
	if !en.on {
		return
	}
	if v := ruleset.Version(); v != en.lastVer {
		en.lastVer = v
		if _, err := en.e.SyncHosts(ruleset.BlockedDomains()); err != nil {
			logf("hosts sync: %v", err)
		}
	}
	if sig := connsSig(conns); sig != en.lastSig {
		en.lastSig = sig
		if _, err := en.e.SyncPF(conns, nil); err != nil {
			logf("pf sync: %v", err)
		}
	}
}

func (en *enforcement) restore() {
	en.mu.Lock()
	defer en.mu.Unlock()
	if en.on {
		en.e.Restore()
	}
}

// blocklistCategories maps a short name the app can send to a maintained list.
// StevenBlack's alternates are the de-facto standard and need no account.
var blocklistCategories = map[string]string{
	"adult":    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
	"ads":      "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	"gambling": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
	"social":   "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts",
}

// resolveCategory turns a category keyword into its URL, or passes a URL/path
// through unchanged.
func resolveCategory(src string) string {
	if url, ok := blocklistCategories[strings.ToLower(strings.TrimSpace(src))]; ok {
		return url
	}
	return src
}

// fetchBlocklist reads a hosts-format list from a URL or file path and returns
// the domains. The URL fetch is the one bit of network this touches, stated
// plainly because asking a list's host for it tells them you did.
func fetchBlocklist(ctx context.Context, src string) ([]string, error) {
	var r io.ReadCloser
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(fctx, http.MethodGet, src, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s: %s", src, resp.Status)
		}
		r = resp.Body
	} else {
		f, err := os.Open(src)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	return rules.ParseHostsBlocklist(r), nil
}

// sourceLabel is the short tag attached to imported rules, so they can be told
// apart from hand-written ones.
func sourceLabel(src string) string {
	if _, ok := blocklistCategories[strings.ToLower(strings.TrimSpace(src))]; ok {
		return strings.ToLower(strings.TrimSpace(src))
	}
	if i := strings.LastIndexByte(src, '/'); i >= 0 {
		return src[i+1:]
	}
	return src
}

// networkInterfaces lists the up, non-loopback interfaces with a hardware
// address - the ones a MAC change makes sense for - for the app's spoof control.
func networkInterfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, in := range ifaces {
		if in.Flags&net.FlagLoopback != 0 || in.Flags&net.FlagUp == 0 {
			continue
		}
		if len(in.HardwareAddr) == 0 || !strings.HasPrefix(in.Name, "en") {
			continue
		}
		out = append(out, in.Name)
	}
	return out
}

// doDiff compares two recordings and prints what changed.
//
// The argument is "baseline,today" rather than two flags because the order is
// the whole meaning of the operation: the first file is what you consider
// normal, and everything is reported relative to it. Making that a single
// ordered value is harder to get backwards than two flags whose names you have
// to remember.
func doDiff(spec string, limit int, jsonOut bool) int {
	parts := strings.Split(spec, ",")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		fmt.Fprintln(os.Stderr, "ohmyosi: -diff takes two recordings: -diff baseline.ndjson,today.ndjson")
		return 2
	}
	a, err := api.Summarize(strings.TrimSpace(parts[0]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ohmyosi: %v\n", err)
		return 1
	}
	b, err := api.Summarize(strings.TrimSpace(parts[1]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ohmyosi: %v\n", err)
		return 1
	}
	d := api.Compare(a, b)
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			fmt.Fprintf(os.Stderr, "ohmyosi: %v\n", err)
			return 1
		}
		return 0
	}
	d.Report(os.Stdout, limit)
	return 0
}
