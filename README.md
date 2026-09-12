# ohmyosi

See every connection leaving this machine, which process opened it, and where it
actually went.

Packet capture and process attribution normally come from different places:
Wireshark sees packets but not PIDs, Activity Monitor sees processes but not
destinations. macOS has a `pktap` pseudo-interface that stamps the PID and
process name onto every captured packet, and almost nothing uses it. ohmyosi
does, then folds the packets into flows and puts names on both ends.

No kernel extension, no entitlement, no Apple developer account. Observation on
macOS needs root. Optional blocking is reactive and off by default.

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
-record FILE      write this session's findings to an NDJSON recording
-research-trace FILE  write raw DNS/flow evidence for the independent evaluator
-play FILE        replay a recording (no root needed); -speed sets the rate
-diff A,B         compare two recordings and print what changed, then exit
-diff-limit N     entries printed per section of a diff (default 25)
-rules FILE       block/allow rule file (default <cache>/rules.json)
-enforce          apply block rules via pf and /etc/hosts (root; off by default)
-import-blocklist SRC   import a hosts-format blocklist (file or http(s) URL) as
                        domain block rules, then exit
-spoof-mac IFACE  assign a random locally-administered MAC to IFACE, then exit (root)
-set-hostname N   set the machine's hostname (all three macOS names), then exit (root)
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

Ownership is only looked up for names the machine stated - flow-specific SNI
or HTTP Host, or a DNS answer we watched. A reverse-DNS name is the hoster's
own, so asking who registered `ec2-…compute.amazonaws.com` would just report
Amazon a second time.

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
going: no TLS SNI or HTTP Host on that flow, and no DNS answer we witnessed
pointing at that address. Everything shown about the far end is inference after
the fact. Software dialling a hardcoded address looks exactly like this. It is
counted in the header and badged in the table rather than left as an unexplained
blank.

### What the capture could not prove

The API and both UIs report uncertainty instead of turning it into a confident
label. Every remote endpoint has a `name_scope`: `flow` means the name came
from that connection's SNI or HTTP Host, `address` means DNS/PTR evidence, and
`none` means no name was observed. DNS candidates retain their TTL. If several
unexpired names share one address, ohmyosi leaves `host` empty, reports
`name_gap: dns_ambiguous`, and preserves the candidates instead of choosing a
tenant by recency. Other `name_gap` values say whether the flow predates capture,
a TLS/QUIC name was unavailable, or no naming evidence was seen at all.
`handshake_name_unavailable` deliberately does not guess between ECH,
truncation, and a missed handshake.

Capture health is reported beside naming coverage: decoded versus undecoded
packets, packets with and without process metadata, and packets shortened by
the configured snap length. Standard pcapng interface/OS drop counters are
shown when the capture stream provides them. When it does not, drops are
reported as unavailable—not zero.

### What changed since yesterday

A live graph can only ever show now. The question people actually have about
their own machine is comparative - *what is it doing today that it wasn't doing
yesterday?* - and answering it needs two recordings and something that knows
what a real difference looks like.

```sh
sudo ./ohmyosi -record ~/sessions/mon.ndjson      # yesterday
sudo ./ohmyosi -record ~/sessions/tue.ndjson      # today
./ohmyosi -diff ~/sessions/mon.ndjson,~/sessions/tue.ndjson
```

The unit of comparison is the **relationship** - which application talks to
which destination - not the flow. Flow IDs are five-tuples, so every one of them
is new tomorrow; diffing those reports several hundred "new connections" a day,
which is the same as reporting nothing. Collapsing to app-to-destination pairs
leaves the thing that is genuinely stable day to day.

Destinations are identified at the coarsest honest level, and the report says
which:

| level | meaning |
|---|---|
| `[domain]` | reduced to a registrable domain: `api2.cursor.sh` becomes `cursor.sh` |
| `[host]` | a name, but not one with a registrable domain (`nas.local`) |
| `[network]` | no name at all; grouped by the AS that owns the address space |
| `[address]` | no name and no AS - the bare address is everything we have |

That grading is what keeps the diff usable. CDN addresses rotate constantly, so
grouping unnamed destinations by their owning network is the only way a
day-over-day comparison survives contact with Cloudflare - but it is coarse, and
a `[network]`-level "new" entry is usually the same service on a different
address. The report says so at the bottom rather than letting you assume
otherwise.

Nothing is recomputed. A recording holds the daemon's own conclusions - names,
their sources, scores and the sentences behind them - and the diff compares
those as recorded, so two runs over the same pair of files agree forever. That
is what makes it usable as evidence rather than as a curiosity.

It also reports what *stopped*. A process that was calling home yesterday and is
silent today is a change too, and a one-sided report is a worse tool.

`-json` gives the same thing as a document, for scripting.

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

## Suspicion, honestly

Every flow carries a score, a band (`quiet` / `notable` / `unusual` / `loud`)
and the list of reasons behind it. This is not malware detection and never
claims to be: there is no threat feed, no signature, no model. It is a sum of
properties that are individually unremarkable and collectively worth a look,
and **every point carries a sentence saying why** — "no name was announced for
this address", "the binary carries no code signature at all", "reconnects on a
regular cadence". A number you cannot argue with is a number you cannot trust,
so the reasons travel with it everywhere it is shown. See `internal/score`.

The signals, all computed from what the tool already observes:

- **Direct-IP and unidentified** — the machine went somewhere it never named.
- **Beacon cadence** — repeated connections at a steady interval, the classic
  shape of something checking in, measured scale-free so ten seconds and ten
  minutes both read as regular.
- **Domain age** — a name registered last Tuesday against one registered nine
  years ago (needs `-rdap`).
- **Code signature** — a binary that is unsigned or only ad-hoc signed. Anyone
  can produce those, so they say nothing about where the code came from.
- **Exfil shape** — a large upload, heavily one-directional, to a far end with
  no name. A backup goes to a named service; this does not.
- **First sighting** — a process reaching a destination it has never reached
  before, judged against a small on-disk history (`<cache>/history.json`). On a
  fresh install nothing is new, so this stays quiet until there is a history to
  be new against.

When a flow first crosses into `unusual` or `loud`, the daemon emits an
`alert` on the event stream — once per flow — so a UI can raise a banner
without polling. The native app surfaces all of this: a triage rail ranks the
flows worth attention, loudest first, each unfolding into its reasons.

## Fingerprinting the caller (JA4)

The identity work above is about the far end. JA4 is about the near end: it
fingerprints the **software making the call** from the shape of its ClientHello
— the ordered cipher list, the extensions, the version, ALPN. Two things make
it worth the parsing. It is stable per stack and version, so Chrome looks like
Chrome every time and something homemade stands out against the handful of
fingerprints real browsers produce. And it survives Encrypted Client Hello: as
ECH removes the SNI, JA4 is one of the few signals left that says anything about
who is talking. It is read from the same ClientHello as the SNI, over both TCP
and QUIC, checked against hand-built vectors in `internal/decode/ja4_test.go`.

It is presentation, not classification: ohmyosi ships no fingerprint database
and makes no claim from a JA4 alone. It is one more fact next to the others, so
a person can recognise the odd one out.

## Blocking, honestly

ohmyosi is observation-first: it never blocks unless you pass `-enforce`, and
without it every rule still shows what it *would* do (flows come back flagged
`blocked` but nothing is stopped), so a rule can be checked before it bites.

Rules are `allow` or `block`, scoped by **app**, **domain**, **dest** (ip or
ip:port) or **port**. Allow beats block, so a blanket "this app talks to
nothing" can be carved out with a narrow "...except its update server". Rules
live in `internal/rules`; editing them over `/api/rules` requires the current
daemon's control token. At startup, the daemon prints the path to a root-only
token file. Retrieve its contents with `sudo cat '<path printed at startup>'`
and paste the token into the native app's Controls panel. It remains in the app's
memory for that run. For scripting, supply it as a Bearer header:

```sh
# block an app; block a tracker domain and everything under it
control_token='paste the value from the root-only token file'
curl -XPOST -H "Authorization: Bearer $control_token" 127.0.0.1:7777/api/rules -d '{"scope":"app","match":"Spotify"}'
curl -XPOST -H "Authorization: Bearer $control_token" 127.0.0.1:7777/api/rules -d '{"scope":"domain","match":"doubleclick.net"}'
curl 127.0.0.1:7777/api/rules            # list
curl -XDELETE -H "Authorization: Bearer $control_token" '127.0.0.1:7777/api/rules?id=<id>'
```

Enforcement uses the two things root can do on macOS **without a kernel
extension or an Apple developer account** - the same price of admission as
capture:

- **`/etc/hosts`** for domain blocks: names are refused before a connection is
  ever made, for every app at once. This is how the category blocklists work -
  `-import-blocklist` pulls a hosts-format list (StevenBlack's ads/adult/malware
  lists, say) straight into domain rules.
- **`pf`** for the per-application case. A packet filter knows addresses and
  ports, not that *this* connection belongs to Spotify and *that* one to a shell
  in `/tmp`. ohmyosi knows, from pktap - so it takes an app rule and installs a
  pf rule for the exact 5-tuple that app just opened. Other apps to the same
  address are untouched. **This is the per-app control a NetworkExtension is
  usually needed for, done with `sudo` alone.**

The honest limit: pf blocking is **reactive**. It kills the connection right
after the first packet rather than preventing the SYN, because ohmyosi has to
see the flow to attribute it. A NetworkExtension prompts before the first
packet; this does not. Different guarantee, and the price of needing no
entitlement - know which one you have.

pf enforcement loads an anchor named `ohmyosi`. So the rules in it are actually
evaluated, ohmyosi references the anchor in `/etc/pf.conf` for you when
enforcement turns on - inside its own markers, without disturbing Apple's lines
or any reference you added yourself. Everything it writes is undone on exit or
when you turn enforcement off: the `/etc/hosts` region is stripped, the anchor
is flushed, the DNS cache is refreshed, and the `pf.conf` reference we added is
removed. Nothing manual, and nothing left behind.

Rules persist in `/Library/Application Support/ohmyosi/rules.json`, so a
blocklist you import survives a reboot.

**All of this is in the app after unlocking controls.** The Controls panel (gear icon) turns enforcement
on and off, imports category blocklists (adult, ads, gambling, social), and
changes the MAC and hostname. A new token is generated each daemon run. The
network viewer remains available without unlocking; API mutations are disabled
without the token and cross-origin access is not enabled.

**Testing the detector.** `internal/score/detection_test.go` is a benchmark of
malicious vs ordinary traffic *shapes* (100% recall, 0 false alarms at the time
of writing). `cmd/beacon-sim` is a benign generator - no exploit, no payload,
just the traffic shape - that you point at a host you own to watch the score
react live:

```sh
sudo ./ohmyosi
go build -o /tmp/beacon-sim ./cmd/beacon-sim
/tmp/beacon-sim -target <a-box-you-own>:4444 -every 10s -up 5MB -i-own-this-target
```

**Testing destination identity.** `cmd/identity-eval` is the independent
research harness. It compares DNS-only, flow-first, ambiguity-aware, and
flow-only policies while keeping wrong labels separate from abstentions. Ground
truth must come from a workload manifest or server/application log; fixtures
that claim DNS, SNI, or HTTP as truth are rejected.

```sh
go run ./cmd/identity-eval -input research/fixtures/shared-ip.ndjson
```

The checked-in fixture reproduces shared-address contamination but is only a
harness test, not a paper result. The frozen study design and threats to
validity are in [`docs/RESEARCH_PROTOCOL.md`](docs/RESEARCH_PROTOCOL.md).
`cmd/identity-lab` also creates real controlled loopback traffic and writes its
intended destinations separately. Exact 5-tuples join that truth to raw
ohmyosi observations; product labels are never accepted as truth. See the
protocol for the end-to-end commands.

## Changing what you broadcast

Before joining a network you do not trust, the two identifiers a machine hands
out about itself are worth changing: its MAC address and its hostname. Both are
ordinary root operations, done once and then the daemon exits:

```sh
sudo ./ohmyosi -spoof-mac en0          # random locally-administered MAC
sudo ./ohmyosi -set-hostname "laptop"  # sets HostName, LocalHostName, ComputerName
```

The MAC is locally-administered and unicast (the correct shape for a spoof), and
on Wi-Fi you rejoin the network for it to take effect. This is a deliberate
action, never a background behaviour - nothing changes unless you ask.

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
- **DNS attribution used to land on `mDNSResponder`.** Apps ask the system
  resolver, so a lookup is not attributed to whoever wanted it. pktap's
  *effective* PID (option `0x8003`, the `pth_epid` thread) is now carried
  through and, for known system resolvers, credited in place of the socket
  owner - so a lookup shows the app that wanted it, not the resolver. See
  `internal/flow/attrib.go`.
- **Browsers are one bucket.** All of Chrome's traffic goes through a single
  network helper process, so there is no per-tab attribution. Fixing that needs
  an extension or ingesting `chrome://net-export`.
- **A sudo CLI can be killed** by whatever it is watching. Little Snitch runs as
  a NetworkExtension and cannot. Different threat model; know which one you have.
- **Connections older than the daemon are still half-blind.** We enumerate
  existing sockets at startup with `lsof -i -n -P` and seed the flow table, so
  long-lived connections appear from the first tick. Their opening handshake
  happened before capture, though, so a seeded flow can honestly have no SNI or
  DNS evidence; the UI and research trace keep that distinction explicit.
- **Capture loss is reported when the backend exposes it.** The live stats show
  packet decode misses, snaplen truncation, and pcapng interface/OS drop
  counters with separate `known` flags. Classic pcap and some macOS capture
  paths do not export drop counters, so an unknown counter is not presented as
  zero.
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
