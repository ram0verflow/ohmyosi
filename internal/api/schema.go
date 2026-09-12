// Package api defines the wire contract between the daemon and any UI, and
// serves it over SSE.
//
// The schema in this file is the handoff boundary. Anything building against
// ohmyosi - the graph UI, a CLI, a script - depends on these shapes and nothing
// else. Treat additions as free and renames as breaking.
package api

import (
	"ohmyosi/internal/enrich"
	"ohmyosi/internal/flow"
	"ohmyosi/internal/rules"
	"ohmyosi/internal/score"
)

func reasonsOf(r score.Result) []string {
	if len(r.Signals) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.Signals))
	for _, s := range r.Signals {
		out = append(out, s.Reason)
	}
	return out
}

// Envelope is one message. Two types:
//
//	hello - sent once on connect: host info plus the complete current state.
//	tick  - sent every interval: only what changed, plus expired flow IDs.
//
// Deltas rather than full snapshots keep a busy machine under a few KB per
// second instead of re-serializing several hundred flows every tick.
type Envelope struct {
	Type  string        `json:"type"`
	T     float64       `json:"t"` // unix seconds, fractional
	Host  *Host         `json:"host,omitempty"`
	Procs []enrich.Proc `json:"procs,omitempty"` // only newly-resolved processes
	Flows []FlowView    `json:"flows,omitempty"`
	Gone  []string      `json:"gone,omitempty"` // flow IDs that expired
	Stats *Stats        `json:"stats,omitempty"`
	// Alerts are moments worth interrupting for: a flow crossing into a loud
	// band, or a genuinely new process/destination pair. Emitted at most once
	// per flow so a UI can raise a banner without polling for them.
	Alerts []Alert `json:"alerts,omitempty"`
}

// Alert is one thing that just became worth a person's attention. It carries
// enough to show a banner without a lookup, and the same reasons the score
// already exposes, because an alert with no argument is one you cannot trust.
type Alert struct {
	FlowID  string   `json:"flow_id"`
	Comm    string   `json:"comm"`
	Dest    string   `json:"dest"`
	Score   int      `json:"score"`
	Band    string   `json:"band"`
	Reasons []string `json:"reasons,omitempty"`
	T       float64  `json:"t"`
}

type Host struct {
	Hostname string  `json:"hostname"`
	Iface    string  `json:"iface"`
	Pktap    bool    `json:"pktap"` // false means no process attribution available
	Started  float64 `json:"started"`
	Version  string  `json:"version"`
}

// Endpoint is one side of a connection.
type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
	// Host is the best name we have. HostSrc says where it came from:
	// "sni" (read off the TLS handshake, what the client asked for),
	// "http" (this flow's cleartext Host), "dns" (sniffed address lookup),
	// or "rdns" (PTR record, often just the hoster).
	// Empty Host with a routable IP usually means QUIC or ECH - see docs.
	Host    string `json:"host,omitempty"`
	HostSrc string `json:"host_src,omitempty"`
	// NameScope says how narrowly Host applies: "flow" for evidence read from
	// this connection, "address" for DNS/PTR evidence that may describe any
	// tenant on a shared IP, and "none" when no name was observed. NameGap then
	// explains the honest limit without pretending we can distinguish ECH from
	// a missed or truncated handshake.
	NameScope string `json:"name_scope,omitempty"`
	NameGap   string `json:"name_gap,omitempty"`
	// NameCandidates are the unexpired address-level DNS names when more than
	// one is plausible. Host stays empty because choosing one would be a guess.
	NameCandidates []string `json:"name_candidates,omitempty"`

	// Org is who owns the address space - Cloudflare, Amazon, Google - from
	// published allocation lists. It answers a DIFFERENT question from Host:
	// where this is hosted, not who you are talking to. Show it as a quieter
	// second line, never as a substitute for Host.
	Org       string `json:"org,omitempty"`
	OrgDetail string `json:"org_detail,omitempty"` // e.g. "S3 ap-southeast-1"
	OrgSrc    string `json:"org_src,omitempty"`    // which published list said so

	// Domain is the registrable unit behind Host: api2.cursor.sh -> cursor.sh.
	Domain string `json:"domain,omitempty"`
	// Owner is who registered that domain, and AgeDays how long ago. These are
	// the fields that separate a company's backend from a rented box, because
	// Org cannot: renting an EC2 instance makes anyone "Amazon".
	Owner     string `json:"owner,omitempty"`
	Registrar string `json:"registrar,omitempty"`
	AgeDays   int    `json:"age_days,omitempty"` // -1 when unknown
	// Favicon is a file name under /favicons/, present only when favicon
	// fetching is enabled and the site had one.
	Favicon string `json:"favicon,omitempty"`

	// ASN is the autonomous system owning this address (Team Cymru DNS lookup).
	ASN     uint32 `json:"asn,omitempty"`
	ASNOrg  string `json:"asn_org,omitempty"`
	Country string `json:"country,omitempty"`

	// Trail records how each fact was learned, in investigation order.
	Trail []string `json:"trail,omitempty"`
}

// FlowView is one connection as the UI sees it.
type FlowView struct {
	ID    string `json:"id"` // stable across restarts for the same 5-tuple
	Proto string `json:"proto"`
	PID   int32  `json:"pid"`
	Comm  string `json:"comm"` // kernel's name, truncated to 16 chars
	Iface string `json:"iface,omitempty"`

	Local  Endpoint `json:"local"`
	Remote Endpoint `json:"remote"`

	BytesUp   uint64 `json:"bytes_up"`
	BytesDown uint64 `json:"bytes_down"`
	PktsUp    uint64 `json:"pkts_up"`
	PktsDown  uint64 `json:"pkts_down"`

	FirstSeen float64 `json:"first_seen"`
	LastSeen  float64 `json:"last_seen"`
	State     string  `json:"state"` // new | active | closed
	Self      bool    `json:"self"`  // ohmyosi's own traffic; hide by default
	// PreExisting marks a flow that existed before the daemon started (seeded
	// from lsof) or whose TCP handshake we never witnessed.
	PreExisting bool `json:"pre_existing,omitempty"`
	// DirectIP means the machine never told us where it was going: no TLS SNI,
	// and no DNS answer we witnessed pointing at this address. Everything we
	// know about the far end is inference after the fact. Software that dials a
	// hardcoded address looks exactly like this, which is why it is surfaced
	// rather than left as an unexplained blank.
	DirectIP bool `json:"direct_ip,omitempty"`
	// Queries are names resolved over this flow. Present on a resolver's
	// connections, where the destination itself is only an intermediary and
	// these are the endpoints the machine actually wanted.
	Queries []string `json:"queries,omitempty"`
	// JA4 is the TLS client fingerprint of the software that opened this flow,
	// read from the ClientHello. It names the caller rather than the callee and
	// survives ECH, so it is the identity signal that remains when the SNI is
	// encrypted away. Empty for flows with no ClientHello we could read.
	JA4 string `json:"ja4,omitempty"`
	// FirstContact is true the first time this process is seen reaching this
	// destination, judged against an on-disk history. Presentation, not a
	// verdict: it says "this is new", nothing more.
	FirstContact bool `json:"first_contact,omitempty"`

	// Suspicion is 0-100 with a band and the reasons behind it. Never a bare
	// number: a score you cannot argue with is a score you cannot trust.
	Suspicion     int      `json:"suspicion"`
	SuspicionBand string   `json:"suspicion_band,omitempty"`
	Reasons       []string `json:"reasons,omitempty"`

	// Blocked is true when a rule denies this flow. Enforced says whether the
	// block was actually applied (pf/hosts) or is only what the rule *would* do,
	// shown when enforcement is off so a rule can be checked before it bites.
	// Rule is a short description of what matched.
	Blocked  bool   `json:"blocked,omitempty"`
	Enforced bool   `json:"enforced,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

type Stats struct {
	Packets               uint64 `json:"packets"`
	Decoded               uint64 `json:"decoded"`
	Undecoded             uint64 `json:"undecoded"`
	PacketsWithProcess    uint64 `json:"packets_with_process"`
	PacketsWithoutProcess uint64 `json:"packets_without_process"`
	TruncatedPackets      uint64 `json:"truncated_packets"`
	InterfaceDrops        uint64 `json:"interface_drops"`
	OSDrops               uint64 `json:"os_drops"`
	InterfaceDropsKnown   bool   `json:"interface_drops_known"`
	OSDropsKnown          bool   `json:"os_drops_known"`
	Flows                 int    `json:"flows"`
	ProcsKnown            int    `json:"procs_known"`

	// Coverage over every live flow, not just the ones in this message. These
	// are the numbers to watch: the goal is that everything leaving the machine
	// is attributed to a process and resolved to a name someone recognizes.
	LiveFlows   int `json:"live_flows"`
	WithProcess int `json:"with_process"`
	WithName    int `json:"with_name"` // any hostname, regardless of evidence scope
	// FlowNames came from this flow's SNI/HTTP handshake. AddressNames are
	// unambiguous DNS/PTR selections. WithoutName is explicit rather than
	// forcing clients to infer it from subtraction; AmbiguousNames is its subset
	// where DNS candidates existed but selecting one would have been a guess.
	FlowNames      int `json:"flow_names"`
	AddressNames   int `json:"address_names"`
	WithoutName    int `json:"without_name"`
	AmbiguousNames int `json:"ambiguous_names"`
	WithOrg        int `json:"with_org"` // an organisation: where it is hosted
	// Unidentified is the number that matters: flows we can say nothing about
	// beyond an address. Reported rather than hidden.
	Unidentified int `json:"unidentified"`
	// DirectIP counts flows the machine never announced a name for. Worth
	// watching on its own: it is where anything deliberately quiet would sit.
	DirectIP int `json:"direct_ip"`
	Prefixes int `json:"prefixes"` // size of the loaded allocation table
	// Flows currently scoring in each band, so the header can show whether
	// anything wants attention without the user hunting for it.
	Notable int `json:"notable"`
	Unusual int `json:"unusual"`
	Loud    int `json:"loud"`
}

// View renders a flow for the wire. The remote endpoint is assembled by the
// daemon, which owns the enrichment caches. firstContact says whether this
// process/destination pair is new against the on-disk history; dec is the rule
// verdict and enforced whether a block was actually applied.
func View(f flow.Flow, remote Endpoint, verdict score.Result, firstContact bool, dec rules.Decision, enforced bool) FlowView {
	classifyNameEvidence(f, &remote)
	v := FlowView{
		ID: f.ID, Proto: string(f.Proto), PID: f.DisplayPID(), Comm: f.DisplayComm(), Iface: f.Iface,
		Local:       Endpoint{IP: f.Local.Addr().String(), Port: f.Local.Port()},
		Remote:      remote,
		PreExisting: f.PreExisting,
		DirectIP:    IsDirectIP(remote),
		BytesUp:     f.BytesUp, BytesDown: f.BytesDown,
		PktsUp: f.PktsUp, PktsDown: f.PktsDown,
		FirstSeen: float64(f.FirstSeen.UnixNano()) / 1e9,
		LastSeen:  float64(f.LastSeen.UnixNano()) / 1e9,
		State:     string(f.State), Self: f.Self, Queries: f.Queries,
		JA4: f.JA4, FirstContact: firstContact,
		Suspicion: verdict.Score, SuspicionBand: verdict.Band,
		Reasons: reasonsOf(verdict),
	}
	if dec.Blocked() {
		v.Blocked = true
		v.Enforced = enforced
		if dec.Rule != nil {
			v.Rule = string(dec.Rule.Scope) + " " + dec.Rule.Match
		}
	}
	return v
}

// IsDirectIP means the application supplied no flow name and no DNS evidence
// was observed. Ambiguous DNS is deliberately not direct-IP: the machine did
// announce names, but the address-level evidence could not select one safely.
func IsDirectIP(remote Endpoint) bool {
	return remote.HostSrc != "sni" && remote.HostSrc != "dns" && remote.HostSrc != "http" && remote.NameGap != "dns_ambiguous"
}

func classifyNameEvidence(f flow.Flow, remote *Endpoint) {
	if remote.NameGap == "dns_ambiguous" {
		remote.NameScope = "address"
		return
	}
	switch remote.HostSrc {
	case "sni", "http":
		remote.NameScope = "flow"
	case "dns", "rdns":
		remote.NameScope = "address"
	default:
		remote.NameScope = "none"
		switch {
		case f.PreExisting:
			remote.NameGap = "pre_existing"
		case f.Remote.Port() == 443:
			remote.NameGap = "handshake_name_unavailable"
		default:
			remote.NameGap = "no_name_observed"
		}
	}
}
