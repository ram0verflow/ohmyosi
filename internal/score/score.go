// Package score rates how much a connection deserves a second look.
//
// This is not malware detection and must never be presented as it. There is no
// threat feed, no signature, no model. It is a sum of a handful of properties
// that are individually unremarkable and collectively unusual, and every point
// it awards carries a sentence saying why.
//
// That constraint is the design. A number on its own ("87") invites belief it
// has not earned and cannot be argued with. A number that unfolds into "the
// machine never announced a name for this address" and "the binary lives in
// /tmp" is something a person can check and disagree with, which is the only
// honest form this can take.
//
// Everything here is computed from what the tool already observes. Nothing is
// fetched, nothing is uploaded, nothing is compared against anyone's list.
package score

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// Signal is one reason, with the weight it contributed.
type Signal struct {
	Points int    `json:"points"`
	Reason string `json:"reason"`
}

// Result is a score and the complete argument for it.
type Result struct {
	Score   int      `json:"score"`
	Band    string   `json:"band"` // quiet | notable | unusual | loud
	Signals []Signal `json:"signals,omitempty"`
}

// Input is everything the scorer looks at. All of it comes from observation.
type Input struct {
	DirectIP   bool // no SNI, and no DNS answer we witnessed for this address
	HasName    bool // a hostname from any source
	HasOrg     bool // an owner from the published allocation table
	RemotePort uint16
	Proto      string
	ExecPath   string // full path of the process binary
	IsSelf     bool

	// RemoteIsLocal marks a destination on the machine's own network: a
	// private range, a unique-local or link-local address, multicast, or
	// loopback. It changes what the anonymity signals mean. Nobody publishes
	// DNS for a router, a printer or an AirPlay speaker, and no allocation list
	// covers 192.168.0.0/16, so a LAN peer trips every "we could not identify
	// this" signal at once and lands in the panel every single time. That is a
	// false alarm dressed as a finding, and a panel full of them is a panel
	// nobody reads.
	RemoteIsLocal bool

	// DomainAgeDays is -1 when unknown (no RDAP, or a redacted registry).
	DomainAgeDays int

	// Beacon regularity in [0,1] and how many connections it was measured over.
	BeaconRegularity float64
	BeaconSamples    int

	Bytes uint64
	// BytesUp and BytesDown split the traffic by direction. A large, heavily
	// one-sided upload to a far end the machine never named is the shape of
	// data leaving that nobody announced.
	BytesUp   uint64
	BytesDown uint64

	// Signing is the code signature verdict on the binary that opened this
	// connection: "apple", "developer-id", "adhoc", "unsigned", or "" when it
	// could not be determined. Ad-hoc and unsigned are the interesting ones -
	// anyone can produce them, so they prove nothing about where the code came
	// from.
	Signing string

	// FirstContact is true when this process has never been seen talking to
	// this destination in the on-disk history. It is deliberately quiet: on a
	// fresh install everything is new, so this only carries weight once there
	// is a history to be new against.
	FirstContact bool
}

// Ports that carry the overwhelming majority of ordinary traffic. Everything
// else is not wrong, just worth one point of attention.
var ordinaryPorts = map[uint16]bool{
	80: true, 443: true, 53: true, 22: true, 123: true,
	993: true, 587: true, 465: true, 143: true, 5223: true,
}

// Directory prefixes where software installed the normal way lives.
var ordinaryPrefixes = []string{
	"/Applications/", "/System/", "/usr/", "/bin/", "/sbin/",
	"/Library/Apple/", "/opt/homebrew/", "/usr/local/",
}

// exfilFloor is the volume below which a one-sided upload is just noise. A
// megabyte going out with nothing coming back is not, on its own, alarming; it
// is the combination with an unnamed destination that the scorer reacts to.
const exfilFloor = 1 << 20 // 1 MiB

// humanBytes renders a byte count for a reason sentence, matching how the UI
// shows the same number elsewhere.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Evaluate returns the score and its reasons.
func Evaluate(in Input) Result {
	var out Result
	if in.IsSelf {
		return Result{Score: 0, Band: "quiet"}
	}
	add := func(points int, format string, args ...any) {
		out.Signals = append(out.Signals, Signal{
			Points: points,
			Reason: fmt.Sprintf(format, args...),
		})
		out.Score += points
	}

	// Provenance-attested software - signed by Apple or a Developer ID cert, and
	// running from a normal install location - going to an unnamed address is
	// ordinary: push, QUIC without a readable SNI, a hardcoded Apple endpoint.
	// So the two signals that fire on *every* encrypted-but-unnamed flow are
	// waived for it. The shape signals below (a steady beacon, a one-sided
	// upload, a days-old domain, an odd port) still apply - those matter even
	// for signed code - but "I couldn't read the name" no longer, on its own,
	// paints half of a normal machine's traffic as notable.
	trusted := ordinaryLocation(in.ExecPath) &&
		(in.Signing == "apple" || in.Signing == "developer-id")

	// The strongest single signal available without any external data: the
	// machine went straight to an address, having never said out loud where it
	// was going. Ordinary software asks DNS or announces a name in the TLS
	// handshake; software that does neither is either hardcoded or careful.
	if in.DirectIP && !trusted && !in.RemoteIsLocal {
		add(25, "no name was announced for this address - no TLS SNI and no DNS answer we saw")
	}
	if !in.HasName && !in.HasOrg && !trusted && !in.RemoteIsLocal {
		add(15, "nothing identifies the far end: no hostname, and no published allocation covers this address")
	}
	// Waived, not hidden. The row still says what happened and why it was not
	// counted, because a signal that silently disappears is worse than one that
	// never fired: you cannot tell the difference between "checked and fine"
	// and "never looked".
	if in.RemoteIsLocal && (in.DirectIP || (!in.HasName && !in.HasOrg)) {
		add(0, "this address is on your own network, where no name is ever published - the two anonymity signals are waived, though everything else below still applies")
	}

	if in.ExecPath != "" && !ordinaryLocation(in.ExecPath) {
		add(20, "the binary runs from %s, outside the usual install locations", in.ExecPath)
	}

	// Odd ports are ordinary on a LAN: AirPlay, Chromecast, printer discovery
	// and every smart-home device picks whatever it likes. Scoring them would
	// make the panel a list of the user's own household.
	if in.RemotePort != 0 && !ordinaryPorts[in.RemotePort] && !in.RemoteIsLocal {
		add(12, "port %d is outside the handful that carry ordinary traffic", in.RemotePort)
	}

	// Regular repeat connections are the classic shape of something checking
	// in. Requires enough samples that the regularity means something.
	if in.BeaconSamples >= 4 && in.BeaconRegularity >= 0.80 {
		pts := 15
		if in.BeaconRegularity >= 0.92 {
			pts = 25
		}
		add(pts, "reconnects on a regular cadence - %d connections, %.0f%% interval regularity",
			in.BeaconSamples, in.BeaconRegularity*100)
	}

	switch {
	case in.DomainAgeDays >= 0 && in.DomainAgeDays < 7:
		// Days old. This is the phishing and throwaway-C2 signature: attacker
		// infrastructure is registered right before it is used, and no amount of
		// hosting reputation makes a name registered this week look established.
		add(28, "the domain was registered only %d days ago", in.DomainAgeDays)
	case in.DomainAgeDays >= 7 && in.DomainAgeDays < 30:
		add(18, "the domain was registered %d days ago", in.DomainAgeDays)
	case in.DomainAgeDays >= 30 && in.DomainAgeDays < 180:
		add(8, "the domain is %d days old", in.DomainAgeDays)
	}

	// The code signature on the binary itself. Not who it is talking to, but
	// what it is: signing is the one property here that speaks to the software's
	// own provenance rather than the connection's.
	switch in.Signing {
	case "unsigned":
		add(18, "the binary carries no code signature at all")
	case "adhoc":
		add(10, "the binary is only ad-hoc signed - anyone can produce that, so it says nothing about where the code came from")
	}

	// Data leaving in volume, heavily one-directional, to a far end with no
	// name. Ordinary uploads - backups, photo sync, a video call - go to a
	// named service; a payload going somewhere the machine never announced is
	// the shape worth a second look. Kept deliberately conservative: a real
	// floor, a steep ratio, and only when the destination is anonymous.
	if in.BytesUp > exfilFloor && in.BytesUp > 8*(in.BytesDown+1) && !in.HasName {
		add(15, "sent %s with almost nothing coming back, to a far end with no name", humanBytes(in.BytesUp))
	}

	// Never seen this process reach this destination before. Presentation, not
	// classification (see docs/IDENTITY.md): the tool says "this is new", the
	// person decides what it means. Small on its own; it earns its weight by
	// stacking with the signals above.
	if in.FirstContact {
		add(8, "this process has not been seen contacting this destination before")
	}

	if out.Score > 100 {
		out.Score = 100
	}
	out.Band = band(out.Score)
	return out
}

func band(score int) string {
	switch {
	case score >= 70:
		return "loud"
	case score >= 45:
		return "unusual"
	case score >= 25:
		return "notable"
	default:
		return "quiet"
	}
}

func ordinaryLocation(path string) bool {
	for _, p := range ordinaryPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// Tracker remembers when connections to a given peer were opened, so repeated
// contact at a steady cadence can be measured.
//
// Kept in memory and bounded: this is a shape detector, not an audit log.
type Tracker struct {
	mu   sync.Mutex
	hist map[string][]time.Time
}

const (
	maxSamples = 24
	minCadence = 3 * time.Second
	maxCadence = 30 * time.Minute
)

func NewTracker() *Tracker {
	return &Tracker{hist: make(map[string][]time.Time, 256)}
}

// Observe records that a new connection to key was opened at t.
func (t *Tracker) Observe(key string, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.hist[key]
	if n := len(h); n > 0 && at.Sub(h[n-1]) < time.Second {
		return // same burst, not a separate check-in
	}
	h = append(h, at)
	if len(h) > maxSamples {
		h = h[len(h)-maxSamples:]
	}
	t.hist[key] = h
}

// Regularity scores how evenly spaced the connections to key are, in [0,1],
// with the number of samples it was measured over.
//
// Evenness is 1 - (standard deviation / mean interval), which is scale-free:
// something checking in every 10 seconds and something checking in every 10
// minutes both read as regular, while ordinary bursty human-driven traffic does
// not. Cadences outside a plausible check-in range are ignored entirely.
func (t *Tracker) Regularity(key string) (float64, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.hist[key]
	if len(h) < 4 {
		return 0, len(h)
	}
	intervals := make([]float64, 0, len(h)-1)
	for i := 1; i < len(h); i++ {
		intervals = append(intervals, h[i].Sub(h[i-1]).Seconds())
	}
	var sum float64
	for _, v := range intervals {
		sum += v
	}
	mean := sum / float64(len(intervals))
	if mean < minCadence.Seconds() || mean > maxCadence.Seconds() {
		return 0, len(h)
	}
	var variance float64
	for _, v := range intervals {
		d := v - mean
		variance += d * d
	}
	sd := math.Sqrt(variance / float64(len(intervals)))
	reg := 1 - sd/mean
	if reg < 0 {
		reg = 0
	}
	return reg, len(h)
}

// Forget drops peers we no longer see, so a long session does not accumulate.
func (t *Tracker) Forget(live map[string]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.hist) < 2*len(live)+64 {
		return
	}
	for k := range t.hist {
		if !live[k] {
			delete(t.hist, k)
		}
	}
}
