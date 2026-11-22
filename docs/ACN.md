# Read, Don't Infer — the ACN project

**Question.** Host network monitors name connections by correlating an address
with a DNS answer. On a modern Mac, per app, how often is that name wrong — and
how often is it wrong while being presented as fact?

**Instrument.** macOS `pktap` stamps every packet with the process that sent it,
and every DNS answer with the app it was looked up for (the "effective PID").
ohmyosi reads the name each connection announces in its own TLS ClientHello or
QUIC Initial, keeps every DNS answer with its time, TTL and asker, and grades
each flow against several correlation strategies.

```sh
make lab                                   # ground-truth experiment, no root, no network
sudo make workload NETWORK=home REPEAT=1   # main experiment (overnight); repeat on 2 more days
sudo make apps NETWORK=home REPEAT=1       # one launch-and-idle capture per desktop app
make report                                # tables + dist/runs.csv
```

---

## 1. Claims, scoped to survive review

Prior art (details in the research report) narrows what can be claimed:

- **Trevisan et al., TRAC 2016** — in-network, ISP + campus, >14B flows: "inconsistencies
  are observed between SNI and DNS in the 6% of flows". The closest result. One
  aggregate number; no per-app view, no typology.
- **DN-Hunter (Bermudez et al., IMC 2012)** — estimated "possible confusion" <4%; never
  validated against SNI. **FlowDNS (CoNEXT 2022)** — states it has no ground truth.
- **Little Snitch** documents per-process DNS sniffing plus SNI reading and calls
  temporal DNS correlation "unreliable"; **Portmaster** documents cross-process
  misattribution. The error is *known*; it is not *quantified*.

So the claims are:

1. *To our knowledge*, the first **per-app, end-host** measurement of DNS-correlated
   naming error validated against each connection's own handshake name, with a
   typology (agree / alias / same-site / mismatch / bypass) and a cause for every error.
2. The first **rate** of cross-process DNS borrowing — a vendor-acknowledged error mode
   that no in-network vantage point can observe.
3. A **comparison of documented strategies** (below), including which ones present
   wrong names as fact ("misled").
4. An **evaluation** of how often DNS-layer blocking fails silently (evasion) — framed
   as measurement, not a new detection technique.

**Scope.** One machine. Results are per app, per version, per condition, and are
reproducible by anyone with the workload scripts. Population prevalence is not claimed.

## 2. Method

**Strategies** (each modelled on what the tool documents):

| strategy | rule | models |
|---|---|---|
| last-answer | latest DNS answer for the address, any process | OpenSnitch, Little Snitch for Linux |
| per-process | latest answer this app asked for | Little Snitch DNS sniffing, Portmaster |
| header-first | handshake name, else per-process | Little Snitch on macOS |
| address-cache | any name cached for the address | ohmyosi v0.1 |
| read-first | own handshake as read; else per-process, labelled a guess | ohmyosi now |

**Reference validity.** The reference is the handshake name — what a monitor can see —
not "what the app fetched". Three cases are flagged and excluded from comparisons:
Encrypted Client Hello (SNI is a public front such as `cloudflare-ech.com`), an IP
literal in SNI, and h2/h3 connections to an address the same app resolved other names
to (possibly coalesced).

*ECH vs GREASE.* Chrome, Brave and Firefox put an ECH extension (`0xfe0d`) in hellos that
are not using ECH ("GREASE", RFC 9849 §6.2); there the SNI is the real destination.
GREASE is built to be indistinguishable on the wire, so the outer name decides: a flow is
`ech-outer` only when it carries the extension **and** its SNI is in the front list
(`internal/decode/ech.go`, currently `cloudflare-ech.com`; printed in every report).
Any other hello carrying the extension is counted as `ech_offered` and graded normally.
A real-ECH provider missing from the list would be graded as if its front were the
destination — the printed list makes that assumption checkable.

**Causes** (one per wrong/blank flow, fixed priority): bypass (no lookup seen),
coalesced, stale (answer expired by its TTL), cross-process, co-hosted (several names
on the address), other-name (one different name; co-hosting and reuse are
indistinguishable).

**Units.** Flows, bytes and distinct (app, name) pairs, since baselines mix them.
"Disagreement" is defined like Trevisan 2016 (wrong / flows with both names) so the
two numbers can sit side by side.

**Statistics.** Rates with 95% Wilson intervals; pooled per condition by adding counts;
run-to-run min–max shown beside each pooled rate. Ordering slack between a DNS
answer and the flow is a parameter (`-eval-slack`); report 0, 100 and 500 ms.

**Precondition, measured not assumed.** Per-process and cross-process numbers need
pktap's effective PID on DNS answers. Every report prints the share of DNS answers
that carried it; check it for your macOS version.

**Precondition: plaintext system DNS.** macOS 14+ follows Discovery of Designated
Resolvers (RFC 9462): if the configured resolver advertises an encrypted endpoint —
8.8.8.8, 1.1.1.1 and 9.9.9.9 all do — mDNSResponder switches to DoH/DoT by itself and
no DNS answer reaches the capture. Use the router's resolver. Every manifest records
the system resolver, whether it advertises DDR and whether mDNSResponder was seen
holding encrypted-DNS sockets (`tools/resolver.sh`); reports print it and warn about
affected runs.

## 3. Experiment design (one person, one Mac)

| part | what | effort |
|---|---|---|
| **Main: controlled workload** | fixed Tranco top-100 list; Safari, Chrome, Firefox; DoH off/on (Safari off only); cold then warm cache; fresh profiles | ~2.5 h unattended per repeat; 3 repeats on different days |
| **Apps** | launch-and-idle, 90 s each, cold DNS cache, ~10 installed apps | ~20 min per repeat |
| **Networks** | repeat the workload once on campus and once on a phone hotspot | 2 more evenings |
| **Case study** | your normal use, `sudo make field`, 2–3 sessions | labelled as one person |

**Cold and warm.** *Cold*: fresh browser profile, system DNS flushed. *Warm*: after the
cold pass the browser is quit and relaunched with the **same** profile, system DNS not
flushed — system DNS and the browser's disk cache are warm, its connection pool is
fresh, so every connection opens (and announces its name) inside the capture. Safari
always runs in the user's own profile, so for Safari only system DNS differs.

*Evaluating warm.* With system DNS warm, most warm-pass lookups are answered from
mDNSResponder's cache and never cross the wire; the answers are in the cold capture.
A real monitor runs throughout, so `-report` evaluates each warm capture with its cold
capture's DNS answers preloaded, with their own times and TTLs, so answers that expired
in between count as stale (`-eval-prior` does the same for one file). The browser was
relaunched, so its PIDs changed: a preloaded answer is re-keyed to the process of the
same name that starts connections or lookups in the warm capture (the exited one still
appears while its old sockets close, and is ignored); if several do, its asker becomes
unknown (no per-process match, no cross-process claim). Not carried over: handshake sightings
(the address-cache strategy sees only the warm capture's own) and the seconds between
the two captures. A warm run without its cold capture is evaluated alone and flagged.

Every capture gets a manifest (browser/app version, macOS version, system resolver, DoH, cache, network,
repeat, Tranco list ID). Captures hold your own traffic: keep them private; publish
`dist/runs.csv` and the tables.

Expected results tables: per-condition error (last-answer vs per-process), DoH on vs off
per browser, cold vs warm, cause breakdown, per-app table, baselines comparison, effective-PID
coverage, slack sensitivity.

## 4. Lab results (mechanism, not prevalence)

`internal/lab` builds a 142-packet Apple-format pcapng: 27 flows, 13 apps, real DNS
(with TTLs), real TLS ClientHellos (with ALPN / ECH), QUIC Initials sealed per RFC 9001.
One scenario per failure mode, plus S9: a GREASE ECH hello (real SNI + ECH extension)
that must grade `agree`, beside S7's real ECH front. Pinned in `internal/eval/lab_test.go`.

| strategy | correct | wrong | missing | **misled** |
|---|---:|---:|---:|---:|
| last-answer | 52% | 9 | 4 | **9** |
| per-process | 59% | 3 | 8 | **3** |
| header-first (Little Snitch macOS) | 89% | 1 | 2 | **1** (the ECH front) |
| address-cache (ohmyosi v0.1) | 89% | 3 | 0 | **3** |
| read-first (ohmyosi now) | 93% | 2 | 0 | **0** |

Every cause occurs at least once; per-process correlation removes cross-process errors
but leaves bypass and shows nothing where the app never looked the name up. The lab
contains one of each failure by construction: **its proportions mean nothing.**

## 5. Threats to validity

- Single machine, single user; per-app claims only.
- Tranco top-N is popular-site browsing, not typical use (hence the case study).
- Safari runs in the user's own profile (no throwaway profiles), so its cold pass only
  flushes system DNS.
- Coalescing is flagged, not resolved; without decryption the full set of names on a
  connection is unknowable.
- SNI is client-asserted (domain fronting); the reference is "what was announced".
- Slack between capture timestamps is a parameter; sensitivity is reported.

## 6. Pitch

*Every network monitor on your laptop guesses who you're talking to from DNS. We read the
real name off each connection and measured, per app, how often the guess is wrong — and how
often it's wrong while looking like fact.*

Don't say: "first to notice", "impossible to hide from", "detects malware", "better
firewall than Little Snitch".

## 7. Code map

```
internal/naming/    ledger (DNS answers with TTL + asker, handshakes); strategies; grades; causes; tally
internal/eval/      eval.go: one capture, all strategies; report.go: many runs, pooled, CSV, baselines
internal/audit/     block-evasion detection, verified-address pf table, enforcement self-audit
internal/lab/       ground-truth capture builder
internal/decode/    ECH + ALPN detection; ech.go: ECH front list; hello.go: ClientHello reassembly;
                    synth.go builds ClientHellos and QUIC Initials
tools/workload/     run.sh (browsers), apps.sh (desktop apps)
tools/field.sh      free-form capture of normal use
tools/resolver.sh   system-resolver probe written into every manifest
ohmyosi -eval FILE [-truth T] [-eval-slack 0s] [-eval-block a,b] [-eval-json]
ohmyosi -report DIR [-report-csv F] [-eval-slack 500ms]
```

## References

- Bermudez et al. *DNS to the Rescue.* IMC 2012.
- Trevisan, Drago, Mellia, Munafò. *Towards Web Service Classification using Addresses and DNS.* IEEE TRAC 2016.
- Maghsoudlou et al. *FlowDNS.* CoNEXT 2022.
- Allman. *Putting DNS in Context.* IMC 2020. · Yu et al. *The Role of DNS in Residential Internet Use.* DNS-OARC 41, 2023.
- Hoang et al. *Assessing the Privacy Benefits of Domain Name Encryption.* AsiaCCS 2020.
- Trevisan et al. *Does Domain Name Encryption Increase Users' Privacy?* CCR 2020.
- Razaghpanah et al. *Apps, Trackers, Privacy, and Regulators* (Lumen). NDSS 2018.
- Gringoli et al. *GT: picking up the truth from the ground.* CCR 2009.
- Sander et al. *Sharding and HTTP/2 Connection Reuse Revisited.* IMC 2021.
- Little Snitch, Portmaster, OpenSnitch documentation on connection naming.
- RFC 9001, RFC 9369, RFC 9460.
