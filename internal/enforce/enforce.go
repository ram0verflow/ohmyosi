// Package enforce turns rule decisions into the two things root can do on macOS
// without a kernel extension or an Apple entitlement: rewrite /etc/hosts and
// load a pf anchor. sudo is the whole price of admission, same as capture.
//
// Two backends, because they answer different questions:
//
//   - hosts blocks names before a connection is ever attempted, for every app
//     at once. It is how category blocklists (ads, adult, malware domains) are
//     meant to work: cheap, pre-emptive, coarse.
//   - pf blocks the exact 5-tuple of a connection ohmyosi has already attributed
//     to a process. This is the per-application control a packet filter cannot
//     express on its own - ohmyosi supplies the process→connection mapping, pf
//     drops that one connection, and other apps to the same address are
//     untouched. It is reactive: it kills the connection right after the first
//     packet rather than preventing the SYN. An honest difference from a
//     NetworkExtension, and the price of not needing one.
//
// Everything renders to a string first, and the renderers are pure and tested.
// Nothing touches the system unless Apply is set, so a caller can show exactly
// what would change before anything does.
package enforce

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	hostsBegin = "# >>> ohmyosi managed block (do not edit this region) >>>"
	hostsEnd   = "# <<< ohmyosi managed block <<<"

	pfConfPath    = "/etc/pf.conf"
	pfAnchorBegin = "# >>> ohmyosi anchor >>>"
	pfAnchorEnd   = "# <<< ohmyosi anchor <<<"
)

// pfAnchorLine references our anchor so the rules loaded into it are actually
// evaluated. Without a reference in the main ruleset, an anchor is dead weight.
func pfAnchorLine(anchor string) string { return `anchor "` + anchor + `"` }

// Conn is one attributed connection to drop - the per-application case.
type Conn struct {
	Proto      string
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
}

// Dest blocks a destination for every app. Port 0 means any port.
type Dest struct {
	Proto string
	IP    string
	Port  uint16
}

// RenderHosts builds the managed /etc/hosts region for a set of domains. Each
// domain is mapped to 0.0.0.0, along with its www. host, which is where most of
// the traffic to a blocked name actually goes.
func RenderHosts(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(hostsBegin + "\n")
	seen := make(map[string]bool, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		fmt.Fprintf(&b, "0.0.0.0 %s\n0.0.0.0 www.%s\n", d, d)
	}
	b.WriteString(hostsEnd)
	return b.String()
}

// Splice replaces (or removes) ohmyosi's managed region in an existing hosts
// file without disturbing anything a person put there by hand. An empty region
// removes the block entirely.
func Splice(existing, region string) string {
	base := strings.TrimRight(stripRegion(existing), "\n")
	if region == "" {
		return base + "\n"
	}
	return base + "\n\n" + region + "\n"
}

func stripRegion(s string) string {
	i := strings.Index(s, hostsBegin)
	if i < 0 {
		return s
	}
	j := strings.Index(s, hostsEnd)
	if j < 0 { // truncated region: drop everything from the begin marker
		return strings.TrimRight(s[:i], "\n") + "\n"
	}
	return strings.TrimRight(s[:i], "\n") + "\n" + strings.TrimLeft(s[j+len(hostsEnd):], "\n")
}

// RenderPF builds the pf anchor rules: per-destination blocks first, then the
// per-connection (per-app) blocks. `quick` makes the first match win, so these
// take effect without depending on the surrounding ruleset's order.
func RenderPF(conns []Conn, dests []Dest) string {
	var b strings.Builder
	for _, d := range dests {
		proto := orTCP(d.Proto)
		if d.Port != 0 {
			fmt.Fprintf(&b, "block drop quick proto %s from any to %s port %d\n", proto, d.IP, d.Port)
		} else {
			fmt.Fprintf(&b, "block drop quick proto %s from any to %s\n", proto, d.IP)
		}
	}
	for _, c := range conns {
		fmt.Fprintf(&b, "block drop quick proto %s from %s port %d to %s port %d\n",
			orTCP(c.Proto), c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort)
	}
	return b.String()
}

func orTCP(p string) string {
	if p == "udp" {
		return "udp"
	}
	return "tcp"
}

// Enforcer applies decisions to the system, or renders them for preview when
// Apply is false.
type Enforcer struct {
	HostsPath  string // usually /etc/hosts
	PFConfPath string // usually /etc/pf.conf; where the anchor gets referenced
	Anchor     string // pf anchor name, e.g. "ohmyosi"
	Apply      bool   // false = dry run: render only, touch nothing
	// Logf, if set, receives a line whenever a system step fails. Enforcement is
	// best-effort by design (a broken pf.conf must never wedge the daemon), but
	// silent failure is how "I blocked it and nothing happened" happens, so the
	// failures are at least spoken.
	Logf func(string, ...any)

	hookedAnchor bool // we added the anchor reference to pf.conf and must remove it
}

func (e *Enforcer) logf(format string, a ...any) {
	if e.Logf != nil {
		e.Logf(format, a...)
	}
}

func (e *Enforcer) pfConf() string {
	if e.PFConfPath != "" {
		return e.PFConfPath
	}
	return pfConfPath
}

// SpliceAnchor adds our anchor reference to a pf.conf body if it is not already
// there. Returns the new body and whether it changed. It never touches an
// existing reference (one the user added by hand), so removing ours later can't
// disturb theirs.
func SpliceAnchor(existing, anchor string) (string, bool) {
	if strings.Contains(existing, pfAnchorLine(anchor)) {
		return existing, false
	}
	block := pfAnchorBegin + "\n" + pfAnchorLine(anchor) + "\n" + pfAnchorEnd
	return strings.TrimRight(existing, "\n") + "\n" + block + "\n", true
}

// StripAnchor removes only the block we added, leaving the rest of pf.conf as it
// was.
func StripAnchor(existing string) string {
	i := strings.Index(existing, pfAnchorBegin)
	if i < 0 {
		return existing
	}
	j := strings.Index(existing, pfAnchorEnd)
	if j < 0 {
		return strings.TrimRight(existing[:i], "\n") + "\n"
	}
	return strings.TrimRight(existing[:i], "\n") + "\n" + strings.TrimLeft(existing[j+len(pfAnchorEnd):], "\n")
}

// ensureAnchorHooked makes pf.conf reference our anchor and reloads the ruleset,
// so blocking works for connections that bypass /etc/hosts (a browser resolving
// over DoH). Idempotent, and a no-op if the reference already exists.
func (e *Enforcer) ensureAnchorHooked() {
	if e.hookedAnchor {
		return
	}
	b, err := os.ReadFile(e.pfConf())
	if err != nil {
		e.logf("pf.conf read failed: %v", err)
		return
	}
	next, changed := SpliceAnchor(string(b), e.Anchor)
	if !changed {
		e.hookedAnchor = true // already referenced (by us earlier, or the user)
		return
	}
	if err := atomicWrite(e.pfConf(), []byte(next)); err != nil {
		e.logf("pf.conf write failed: %v", err)
		return
	}
	e.hookedAnchor = true
	if out, err := exec.Command("pfctl", "-f", e.pfConf()).CombinedOutput(); err != nil {
		e.logf("pfctl -f pf.conf failed (pf blocking will not work): %v: %s", err, strings.TrimSpace(string(out)))
	}
}

// unhookAnchor removes the reference we added, if any, and reloads.
func (e *Enforcer) unhookAnchor() {
	if !e.hookedAnchor {
		return
	}
	e.hookedAnchor = false
	b, err := os.ReadFile(e.pfConf())
	if err != nil {
		return
	}
	stripped := StripAnchor(string(b))
	if stripped == string(b) {
		return // nothing of ours in there (e.g. the user had their own reference)
	}
	if err := atomicWrite(e.pfConf(), []byte(stripped)); err != nil {
		e.logf("pf.conf restore failed: %v", err)
		return
	}
	_ = exec.Command("pfctl", "-f", e.pfConf()).Run()
}

// SyncHosts writes the managed region for the given domains. Returns the region
// it produced, whether or not it was applied.
func (e *Enforcer) SyncHosts(domains []string) (string, error) {
	region := RenderHosts(domains)
	if !e.Apply {
		return region, nil
	}
	existing, err := os.ReadFile(e.HostsPath)
	if err != nil {
		return region, err
	}
	if err := atomicWrite(e.HostsPath, []byte(Splice(string(existing), region))); err != nil {
		return region, err
	}
	flushDNS() // macOS caches resolutions hard; without this a block takes minutes
	return region, nil
}

// flushDNS clears the system resolver cache so a hosts change is felt now rather
// than whenever the old entry happens to expire. Best-effort: both commands are
// harmless if they fail.
func flushDNS() {
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}

// SyncPF loads the anchor with the given blocks. Returns the rules it produced.
func (e *Enforcer) SyncPF(conns []Conn, dests []Dest) (string, error) {
	rules := RenderPF(conns, dests)
	if !e.Apply {
		return rules, nil
	}
	// -E enables pf and bumps a reference count; harmless if already on.
	_ = exec.Command("pfctl", "-E").Run()
	// Make sure the main ruleset references our anchor, or the rules below load
	// into an anchor nothing consults. Done here so the app can turn enforcement
	// on with no manual /etc/pf.conf editing.
	e.ensureAnchorHooked()
	cmd := exec.Command("pfctl", "-a", e.Anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return rules, fmt.Errorf("pfctl load anchor %q: %v: %s", e.Anchor, err, strings.TrimSpace(string(out)))
	}
	return rules, nil
}

// Restore undoes everything: strips the hosts region and flushes the anchor. It
// is safe to call when nothing was applied, and safe to call twice.
func (e *Enforcer) Restore() {
	if !e.Apply {
		return
	}
	if b, err := os.ReadFile(e.HostsPath); err == nil {
		_ = atomicWrite(e.HostsPath, []byte(Splice(string(b), "")))
		flushDNS() // so unblocking is felt immediately too
	}
	_ = exec.Command("pfctl", "-a", e.Anchor, "-F", "rules").Run()
	e.unhookAnchor() // remove the pf.conf reference we added, leaving pf as we found it
}

// atomicWrite replaces a file in place: write a sibling temp, then rename, so a
// crash mid-write can never leave /etc/hosts half-formed.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ohmyosi-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmpName, 0o644)
	return os.Rename(tmpName, path)
}
