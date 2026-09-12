# Event schema

The daemon emits one JSON object per message. This is the only contract between
`ohmyosi` and any UI. Adding fields is free; renaming one breaks clients.

## Transport

- `GET /events` — Server-Sent Events. Each message arrives as `data: <json>\n\n`.
  Use `EventSource`; it reconnects on its own, so a daemon restart needs no
  client-side handling.
- `GET /api/snapshot` — the same `hello` envelope, once, as plain JSON. For
  `curl`, scripts, and debugging.
- `GET /icons/<icon_id>.png` — 64px PNG extracted from the application bundle.
- `ohmyosi --json` — NDJSON on stdout instead of an HTTP server. Same envelopes.

The Vite dev server proxies `/events` and `/api` to the daemon on the same
origin. The daemon does not enable cross-origin access. Read-only observation
does not require authentication. Changing rules or system settings requires
`Authorization: Bearer <current daemon control token>`; the daemon writes that
token to a root-only file and reports the path at startup. The native app's
Controls panel accepts it for the current session.

## Envelope

```json
{
  "type": "hello",
  "t": 1757148003.412,
  "host":  { "hostname": "air", "iface": "pktap,en0", "pktap": true,
             "started": 1757147901.0, "version": "0.1.0" },
  "procs": [ ... ],
  "flows": [ ... ],
  "gone":  ["1c69ef95adf652ba"],
  "stats": { "packets": 91422, "decoded": 90310, "undecoded": 1112,
             "packets_with_process": 90102, "packets_without_process": 1320,
             "truncated_packets": 4,
             "interface_drops": 0, "interface_drops_known": false,
             "os_drops": 0, "os_drops_known": false,
             "flows": 37, "procs_known": 22,
             "live_flows": 31, "flow_names": 18,
             "address_names": 7, "without_name": 6 }
}
```

Two types:

- **`hello`** — sent once when a client connects. Carries `host` plus the
  complete current state: every live flow and every known process.
- **`tick`** — sent every interval (default 1s). Carries only **what changed**:
  flows touched since the last tick, processes resolved since the last tick, and
  the IDs of flows that expired. Ticks with nothing to say are not sent at all.

A client keeps its own `Map` of flows and processes and applies each tick. This
keeps a busy machine's update under a few KB per second rather than
re-serializing several hundred flows every time.

## Flow

```json
{
  "id": "1c69ef95adf652ba",
  "proto": "tcp",
  "pid": 4321,
  "comm": "Google Chrome H",
  "iface": "en0",
  "local":  { "ip": "192.168.1.5", "port": 52341 },
  "remote": { "ip": "104.18.32.7", "port": 443,
              "host": "notion.so", "host_src": "sni",
              "name_scope": "flow" },
  "bytes_up": 2104, "bytes_down": 88213,
  "pkts_up": 18,    "pkts_down": 71,
  "first_seen": 1757147990.11, "last_seen": 1757148003.40,
  "state": "active",
  "self": false
}
```

| Field | Notes |
|---|---|
| `id` | Stable for a 5-tuple across daemon restarts. Use it as the node key. |
| `pid` | `0` means the kernel gave us no attribution for this flow. |
| `comm` | Kernel's name, **truncated to 16 characters**. Prefer the matching `proc.name`. |
| `host_src` | `sni` \| `http` \| `dns` \| `rdns` — see below. |
| `name_scope` | `flow` \| `address` \| `none` — how narrowly the name evidence applies. |
| `name_gap` | Present when `name_scope` is `none`; explains why no name is available. |
| `state` | `new` on first sight, `active` after, `closed` once a FIN or RST is seen. |
| `self` | ohmyosi's own reverse-DNS traffic. Hide by default. |

`bytes_up` / `bytes_down` are cumulative for the life of the flow, measured on
the wire (unaffected by `-snaplen` truncation). To draw throughput, diff
consecutive ticks.

### host_src, and why a host can be missing

- **`sni`** — read straight off the TLS ClientHello. The strongest signal: it is
  literally the name this flow asked for. It is never reused by another flow.
- **`http`** — read from this flow's cleartext HTTP Host header. Like SNI, it is
  scoped to the exact connection and never copied into the address cache.
- **`dns`** — sniffed from a DNS response, attributed to the name the
  application queried rather than the CNAME target, so you get `notion.so`
  instead of `cdn.notion.akamai.net`. This is an address-level fallback and can
  be ambiguous when several names share one address.
- **`rdns`** — a PTR record. Often the hosting provider, not the site. Show it
  more faintly.

An empty `host` on a routable address is normal and means one of:

- **QUIC whose Initial packet was absent, truncated, or could not be decoded.**
  Readable QUIC Initials are decoded and their SNI remains flow-specific.
- **Encrypted Client Hello.** As ECH rolls out the SNI stops being readable.
- The connection reused an address whose lookup happened before the daemon
  started, and reverse DNS had nothing.

The UI must handle this gracefully — a bare IP with an ASN-ish label is far
better than a blank node.

`name_gap` avoids collapsing all of those cases into a blank while also
avoiding claims the capture cannot support:

- **`pre_existing`** — the connection predates observation, so its handshake
  cannot be recovered.
- **`handshake_name_unavailable`** — a port-443 flow had no readable name. This
  can mean ECH, a missed or truncated TLS/QUIC handshake, or an unsupported
  handshake; the field intentionally does not choose among them.
- **`no_name_observed`** — no naming evidence was observed for another kind of
  flow.

## Capture quality and coverage

Every `stats` object describes the whole live capture, not just flows changed
in that tick:

- `decoded` and `undecoded` expose how many captured records did or did not
  normalize into an IP flow. `undecoded` includes non-IP and unsupported frames
  as well as malformed input; it is a coverage gap, not automatically an error.
- `packets_with_process` and `packets_without_process` expose pktap attribution
  coverage. A zero PID on an individual flow still means unattributed.
- `truncated_packets` counts records whose captured bytes were shorter than
  their original wire length. This commonly reflects `-snaplen` and can explain
  an unavailable handshake name.
- `interface_drops` and `os_drops` are standard pcapng Interface Statistics
  Block counters. Their matching `*_known` fields are essential: a known zero
  is evidence of no reported loss, while `false` means the stream did not
  publish that counter. Classic pcap has no in-band drop telemetry.
- `flow_names`, `address_names`, and `without_name` split hostname coverage by
  evidentiary strength. `with_name` remains their total for older clients.

Drop counters are optional and are often written only when a pcapng stream
ends. A live `false` is therefore “not available yet,” never “zero drops.”

## Process

```json
{ "pid": 4321, "name": "Google Chrome", "path": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome Helper",
  "bundle_id": "com.google.Chrome.helper", "icon_id": "9f2b1c0ae4d7a331" }
```

Processes arrive **after** the flows that reference them, usually one tick
later, because resolution shells out to `ps`, `plutil` and `sips`. Render the
node immediately using `comm`, and upgrade it when the process arrives. Never
block a flow on its process.

`icon_id` may be absent: command-line daemons have no bundle, and apps that ship
artwork in `Assets.car` rather than a `.icns` are not yet handled.
