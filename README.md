# ohmyosi

See every connection leaving this machine, which process opened it, and where it
actually went.

Packet capture and process attribution normally come from different places:
Wireshark sees packets but not PIDs, Activity Monitor sees processes but not
destinations. macOS has a `pktap` pseudo-interface that stamps the PID and
process name onto every captured packet, and almost nothing uses it. ohmyosi
does, then folds the packets into flows and puts names on both ends.

No kernel extension, no entitlement, no Apple developer account. Observation on
macOS just needs root. (Only *blocking* traffic needs Apple's permission, and
ohmyosi does not block.)

## Build and run

```sh
go mod tidy
go build -o ohmyosi ./cmd/ohmyosi
sudo ./ohmyosi
```

Then open http://127.0.0.1:7777 — a deliberately plain table, there to prove the
pipe works. The graph UI is built separately against `docs/SCHEMA.md`.

Root is required: `pktap` is privileged.

## Flags

```
-i pktap,all      capture interface; or name one, e.g. pktap,en0
-filter ""        BPF filter, e.g. "not port 22"
-addr 127.0.0.1:7777
-interval 1s      how often to emit a tick
-snaplen 1600     bytes per packet; must cover a ClientHello for SNI.
                  drop to 128 for headers only and much less overhead
-no-rdns          disable reverse DNS (the only thing here that sends packets)
-no-icons         skip application icon extraction
-json             NDJSON to stdout instead of an HTTP server
-update-ranges    fetch published address allocations, then exit
-rdap             look up domain ownership and registration age (network, cached)
-favicons         fetch site favicons (connects to each destination, cached)
-ranges FILE      allocation table (default <cache>/ranges.json)
-read FILE        replay a saved .pcap/.pcapng instead of capturing live (no root needed)
```

`pktap,all` is the default because it catches whatever is actually carrying
traffic, VPN interfaces (`utun*`) included. `ifconfig -l` lists them if you want
to pin one; `en0` is Wi-Fi on a MacBook.

On startup you should see `capturing on pktap,all` and then `capture live` once
the first packet arrives. If it says it is still waiting, that interface is idle
- tcpdump only flushes its pcap header when it has a packet to write, so nothing
at all comes through until traffic does.

Scriptable straight away:

```sh
sudo ./ohmyosi -json | jq -r 'select(.flows)|.flows[]|select(.remote.host)|
  "\(.comm)\t\(.remote.host)\t\(.bytes_down)"'
```

## Naming the far end

Run this once, and again whenever you feel like it:

```sh
./ohmyosi -update-ranges
```

It fetches the address blocks that Cloudflare, AWS, Google, Fastly and GitHub
publish about themselves, and writes them to a local file used offline from then
on. No account, no API key, no licence to accept - these lists exist because
other people need to route and firewall around them. It reports each source
separately, so a provider that changes its format is visible immediately rather
than quietly costing you coverage.

That turns `2606:4700:4408::ac40:9bd1` into Cloudflare and
`52.219.4.9` into `Amazon S3 ap-southeast-1`.

**Two fields, two questions.** `host` is who the client asked for, from the TLS
handshake or DNS. `org` is who owns the address space. For most modern traffic
those are different companies: a connection to notion.so lands on Cloudflare
hardware, so `org` alone would report Cloudflare for half the internet. They are
kept separate, and `org` never overwrites `host`.

### Who owns the name

`org` is the landlord, not the tenant. Renting an EC2 instance makes anyone
"Amazon ap-southeast-1", identical to a real company's backend, so address
ownership cannot be identity on its own.

Identity hangs off the domain, and `-rdap` fetches it:

```sh
sudo ./ohmyosi -rdap
```

For every host the machine actually asked for, that gives the registrable
domain (`agentn.global.api5.cursor.sh` → `cursor.sh`, via the Public Suffix
List), who registered it, and **how long ago**. The age is the field that does
the work: a domain first registered nine years ago and one registered last
Tuesday are very different things, and no amount of AWS makes them look alike.
A redacted registrant is a normal answer and is reported as such rather than
blanked.

Ownership is only looked up for names the machine stated - SNI or a DNS answer
we watched. A reverse-DNS name is the hoster's own, so asking who registered
`ec2-…compute.amazonaws.com` would just report Amazon a second time.

RDAP is off by default because it is the one part of ohmyosi that makes network
requests, and looking up a domain tells the registry you are interested in it.
Answers are cached to disk, so it mostly happens once.

### Favicons

`-favicons` fetches each destination's icon. Off by default, and worth saying
why: fetching a site's favicon means connecting to that site, so a monitor that
does it automatically is quietly phoning every host it observes. On a machine
you are auditing that is a real cost. When enabled, the fetches appear in
ohmyosi's own graph flagged as self-traffic, like everything else it does.

### direct-ip

A flow flagged `direct-ip` is one where the machine never announced where it was
going: no TLS SNI, and no DNS answer we witnessed pointing at that address.
Everything shown about the far end is inference after the fact. Software dialling
a hardcoded address looks exactly like this. It is counted in the header and
badged in the table rather than left as an unexplained blank.

### Replaying a capture

Debugging live traffic is miserable because the input never repeats. Capture
once, then replay as often as you like, with no root:

```sh
sudo tcpdump -i pktap,all -w /tmp/sample.pcapng -U -s 1600 -c 500
./ohmyosi -read /tmp/sample.pcapng -json -no-rdns
```

## Capture formats, and where the PID actually lives

Apple's tcpdump picks the output format silently, and the choice changes where
the process metadata is:

**`-i pktap,en0` writes classic pcap** with link type `DLT_PKTAP` (258). Each
packet is prefixed with a `struct pktap_header` carrying the PID, the process
name, the interface and a direction flag. `internal/pktap/pktap.go` parses it.

**`-i pktap,all` writes pcapng**, because several interfaces need several
interface descriptions and classic pcap has room for exactly one. Here there is
**no pktap header at all** - the interface blocks declare their real link types
(Ethernet, null) and the process information moves into pcapng's option
machinery via Apple's own extension:

| Block / option | Meaning |
|---|---|
| block `0x80000001` | Process Information Block: a PID plus a name option |
| EPB option `0x8001` | index into the PIB table, in order of appearance |
| EPB option `0x8003` | *effective* process - who the socket was opened for |
| EPB option `0x0002` | standard `epb_flags`; bits 0-1 are direction |

gopacket's pcapng reader discards packet options (its source says handling them
"would be expensive"), so the PID is in the file and thrown away. That is why
`internal/pktap/pcapng.go` exists.

Option `0x8003` is the interesting one: it is how a DNS lookup performed by
`mDNSResponder` can be traced back to the application that actually wanted it.
It is parsed and carried through as `EPID`/`EComm`, not yet used.

The two formats also differ at startup. pcapng flushes its section header
immediately; classic pcap holds its 24-byte header inside tcpdump's stdio buffer
until the first packet forces a flush, so on a silent interface nothing arrives
until traffic does. That is why startup is asynchronous and the daemon narrates
what it is waiting for instead of sitting there mute.

## QUIC

I had this in the limitations list as "encrypted, in principle recoverable",
which was a polite way of not doing it. QUIC Initial packets are encrypted with
keys derived from the Destination Connection ID using constants printed in
RFC 9001 - the protection exists to stop middleboxes ossifying the wire format,
not to stop anyone reading it. Anyone holding the packet can decrypt it.

Since browsers speak QUIC to most of Google and Cloudflare, every one of those
flows was showing as a bare address. `internal/decode/quic.go` now undoes the
header protection, derives the initial secrets, decrypts, walks the CRYPTO
frames and reads the SNI out of the ClientHello.

It is checked against the known-answer vectors in RFC 9001 Appendix A.2 and
RFC 9369, because key derivation is exactly the kind of code that compiles,
runs, returns nothing and looks indistinguishable from a quiet network. That
test caught a real bug: QUIC v2 renumbered the long-header packet types, so a v2
Initial does not look like a v1 one.

## Resolvers

A DNS resolver is not a destination, it is a hop. `mDNSResponder → 1.1.1.1`
tells you nothing; what matters is the list of names being resolved through it.
Those names are now attached to the flow, so a resolver's connection shows what
the machine is actually asking about.

The same idea applies wherever one connection stands in for many. A browser is
already handled by having one flow per site.

## How it works

```
tcpdump -i pktap,en0 -w - -U
        │  pcap stream on stdout, one pktap header per packet
        ▼
   pktap.Source ──► decode.Decoder ──► flow.Table ──► api (SSE, 1Hz)
        │                  │                │
   PID, comm,       DNS answers,       5-tuple aggregation,
   direction        TLS SNI            byte counters, expiry
                           │
                           └──► enrich: IP→name, PID→app+icon
```

We shell out to `tcpdump` rather than linking libpcap, so the whole thing is
pure Go with one dependency and no cgo. It cross-compiles.

The load-bearing decision is that **packets never reach the UI**. A busy laptop
emits thousands a second, which no graph can render and no human can read.
Packets fold into flows; the UI gets a delta once a second.

## Limits, honestly

- **ECH will make SNI go away.** As Encrypted Client Hello ships, that field
  stops being readable and reverse DNS is all that is left.
- **DNS attribution lands on `mDNSResponder`.** Apps ask the system resolver, so
  the lookup is not attributed to whoever wanted it. The `pth_epid` field in the
  pktap header is the thread to pull on; not done yet.
- **Browsers are one bucket.** All of Chrome's traffic goes through a single
  network helper process, so there is no per-tab attribution. Fixing that needs
  an extension or ingesting `chrome://net-export`.
- **A sudo CLI can be killed** by whatever it is watching. Little Snitch runs as
  a NetworkExtension and cannot. Different threat model; know which one you have.
- **Connections older than the daemon are half-blind.** You see their packets,
  but the SYN and the ClientHello happened before you started, so there is no
  SNI and often no DNS - just an address. Fixable: enumerate existing sockets at
  startup with `lsof -i -n -P` and seed the flow table, so long-lived
  connections are named from the first tick instead of never.
- **Kernel drops are invisible.** tcpdump reports "packets dropped by kernel" on
  exit and we throw it away. Under load that number is the difference between
  "complete picture" and "most of one", so it belongs in the stats block.
- **PID reuse** is not handled. A long-running session can in principle attribute
  a flow to the wrong process after a PID wraps.

## Layout

```
cmd/ohmyosi/       flags and wiring
internal/pktap/    tcpdump subprocess, pktap header parser
internal/decode/   frame → 5-tuple, DNS answers, TLS SNI
internal/flow/     aggregation, orientation, expiry
internal/enrich/   IP→hostname, PID→app+icon
internal/api/      event schema, SSE server, debug page
docs/SCHEMA.md     the wire contract
docs/UI_SPEC.md    spec for the canvas UI
docs/IDENTITY.md   plan for naming the far end (ASN, RDAP, clustering)
```

## Tests

```sh
go test ./...
```

The parsers are the part worth testing: both read hostile bytes off the network,
and both are exercised against truncation and garbage, because `-snaplen` cuts
packets off mid-structure and a panic there takes the daemon down.
