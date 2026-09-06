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
)

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
	// "dns" (sniffed lookup), "rdns" (PTR record, often just the hoster).
	// Empty Host with a routable IP usually means QUIC or ECH - see docs.
	Host    string `json:"host,omitempty"`
	HostSrc string `json:"host_src,omitempty"`

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
	// PreExisting marks a TCP flow whose handshake we never saw, because it was
	// already open when the daemon started. It is why the name is missing, and
	// saying so beats an unexplained blank.
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
}

type Stats struct {
	Packets    uint64 `json:"packets"`
	Decoded    uint64 `json:"decoded"`
	Undecoded  uint64 `json:"undecoded"`
	Flows      int    `json:"flows"`
	ProcsKnown int    `json:"procs_known"`

	// Coverage over every live flow, not just the ones in this message. These
	// are the numbers to watch: the goal is that everything leaving the machine
	// is attributed to a process and resolved to a name someone recognizes.
	LiveFlows   int `json:"live_flows"`
	WithProcess int `json:"with_process"`
	WithName    int `json:"with_name"` // a hostname: who you asked for
	WithOrg     int `json:"with_org"`  // an organisation: where it is hosted
	// Unidentified is the number that matters: flows we can say nothing about
	// beyond an address. Reported rather than hidden.
	Unidentified int `json:"unidentified"`
	// DirectIP counts flows the machine never announced a name for. Worth
	// watching on its own: it is where anything deliberately quiet would sit.
	DirectIP int `json:"direct_ip"`
	Prefixes int `json:"prefixes"` // size of the loaded allocation table
}

// View renders a flow for the wire. The remote endpoint is assembled by the
// daemon, which owns the enrichment caches.
func View(f flow.Flow, remote Endpoint) FlowView {
	return FlowView{
		ID: f.ID, Proto: string(f.Proto), PID: f.PID, Comm: f.Comm, Iface: f.Iface,
		Local:       Endpoint{IP: f.Local.Addr().String(), Port: f.Local.Port()},
		Remote:      remote,
		PreExisting: f.Proto == "tcp" && !f.SawSYN,
		DirectIP:    remote.HostSrc != "sni" && remote.HostSrc != "dns",
		BytesUp:   f.BytesUp, BytesDown: f.BytesDown,
		PktsUp:    f.PktsUp, PktsDown: f.PktsDown,
		FirstSeen: float64(f.FirstSeen.UnixNano()) / 1e9,
		LastSeen:  float64(f.LastSeen.UnixNano()) / 1e9,
		State: string(f.State), Self: f.Self, Queries: f.Queries,
	}
}
