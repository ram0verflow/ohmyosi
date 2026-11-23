# Handoff dossier — ohmyosi / "Read, Don't Infer"

For the agent picking this up. Read this whole file before touching code or
running anything. Written 2026-11-22, updated 2026-11-23.

**Deadline:** course report (ACN) due **2026-11-28**, 5–6 pages, teacher's
conference template (`.docx`), fixed headings: Abstract (~250 words),
1 Introduction, 2 Literature Survey, 3 Methodology, 4 Experimental Setup,
5 Results and Discussion, 6 Conclusion.

**Owner's instruction for this phase:** focus on the research part and get
the maximum (credible) results. The UI/demo work is deferred.

---

## 1. The project in one paragraph

Host network monitors and firewalls (Little Snitch, Portmaster, OpenSnitch,
LuLu) name each connection by **DNS correlation**: they match the destination
IP to a DNS answer seen earlier. That is a guess, and it fails silently
because of CDN co-hosting, resolver bypass (DoH, caches, hardcoded IPs),
cross-app borrowing of lookups, stale answers and connection reuse.
**ohmyosi** is a macOS monitor (Go daemon, pure Go, shells out to `tcpdump`)
that uses Apple's **pktap** interface. pktap stamps every packet with its
process and every DNS packet with the app it was made for (the **effective
PID**, pcapng option 0x8003). ohmyosi then **reads** the name each
connection announces in its own TLS ClientHello SNI or decrypted QUIC
Initial. The study replays real traffic through five documented naming
strategies and measures, per app, how often each is wrong, wrong **as
fact** ("misled"), and why.

Framing agreed with the owner: **ohmyosi is the monitor (observation, not a
firewall); the comparison study is the evidence that its design matters.**
A monitor doesn't have to decide at dial time, so it can wait for the hello
and read. A firewall can't.

## 2. Where everything is

| What | Where |
|---|---|
| Repo | `github.com/ram0verflow/ohmyosi` (public). Work is on branch **`acn-measurement`** (see commit list in §11). `main` is untouched. |
| Local copy | owner's Mac: `/Users/abhiramam/ohmyosi` |
| Method + claims | `docs/ACN.md` (keep in sync with code) |
| Decision log | `Claude outputs/THINKING.md` (git-ignored, append-only, entries D12–D13, C5–C6 cover this work) |
| Team brief (shareable doc) | https://claude.ai/artifact/YA5dSFG8VMeLLmcjVR6giC |
| Captures | `dist/runs/` (latest smoke test, 3 browsers), `dist/runs-smoke1/`, `dist/runs-dns8888-ddr/` (8.8.8.8 era, no visible DNS). **Git-ignored and private: never commit or upload pcaps.** |
| Per-run table | `dist/runs.csv` (from `make report`) |
| Tranco list | `dist/workload/tranco-V38GN-top*.txt` (fixed list; reuse it for every run) |
| Report template | the teacher's `conference-template-a4.docx` (owner has it; ask for it) |

## 3. What works today (verified 2026-11-22)

- `go vet ./...` clean; `go test -race ./...` passes, all 13 packages.
- `make lab` builds a ground-truth capture (`internal/lab`): 26 flows, 13 apps,
  real DNS with TTLs, TLS ClientHellos with ALPN/ECH, RFC 9001-sealed QUIC
  Initials. Results are pinned in `internal/eval/lab_test.go`; scapy
  independently parses the same bytes. Read-first misled = 0; last-answer misled = 9.
- `sudo make workload NETWORK=<label> REPEAT=<n>`: Safari, Chrome and Firefox over
  the fixed Tranco list; DoH off/on (Safari off only); cold pass, then the browser
  is quit and relaunched with the same profile for the warm pass (fresh
  connection pool, warm caches). Writes `<run>.pcapng` + `<run>.manifest.json`
  (versions, conditions, resolver).
- `sudo make apps`: launch-and-idle capture per installed desktop app.
- `sudo make field`: free-form capture of normal use (case study).
- `make report` (`ohmyosi -report dist/runs -report-csv dist/runs.csv`):
  per-run and pooled-by-condition tables with 95% Wilson intervals, causes,
  reference flags, effective-PID coverage, resolver warning, baseline comparison.
- `ohmyosi -eval FILE [-truth T] [-eval-slack 0s|100ms|500ms] [-eval-block a,b] [-eval-json]`.

Fixes already landed (by Claude in this chat, then Claude Code on the Mac):
- Borrowed names no longer labelled `sni`: source `peer`; QUIC source `quic`.
- Pre-capture flows (`handshake_unseen`) are no longer scored as direct-IP.
- History baseline: first-contact is quiet on an empty history.
- Effective-PID identity: DNS answers and flows keyed the same way. Safari's
  WebKit flows had matched nothing; per-process error had been 98%.
- ClientHello reassembly across TCP segments and QUIC CRYPTO frames. Chrome 157's
  post-quantum key share splits the hello; before this only ~15/118 Chrome flows were read.
- Snaplen 2048. pktap's ~156-byte header counts against `-s`; 1600 truncated
  IPv6 frames. The decoder also tolerates truncated segments.
- GREASE vs real ECH. A flow is `ech-outer` only if its SNI is a known public
  front (`internal/decode/ech.go`, currently `cloudflare-ech.com`). Any other
  hello with 0xfe0d gets `ech_offered` and is graded normally.
- Resolver recorded per run. DDR-upgraded public resolvers (8.8.8.8, 1.1.1.1,
  9.9.9.9) hide all system DNS from the wire, so the report warns.

## 4. Preliminary data (smoke test, 5 sites/pass, 1 repeat, home network, router DNS)

**Not results.** Five sites per pass. Use them to sanity-check, never to quote.

| Browser | DoH | Cache | Readable | Comparable | Wrong (last-answer) | Blind (handshake-only) | Wrong causes |
|---|---|---|---|---|---|---|---|
| Chrome 157 | on | cold | 113 | 2 | 0 | 111 | bypass |
| Chrome 157 | on | warm | 94 | 1 | 0 | 93 | bypass |
| Firefox 159 | off | cold | 189 | 189 | 6 | 0 | all coalesced |
| Firefox 159 | off | warm | 127 | 127 | 22 | 0 | all coalesced |
| Firefox 159 | on | cold | 167 | 0 | 0 | 167 | bypass |
| Firefox 159 | on | warm | 138 | 0 | 0 | 138 | bypass |
| Safari 26.5 | off | cold | 43 | 41 | 3 | 2 | coalesced 3 |
| Safari 26.5 | off | warm | 44 | 42 | 6 | 2 | coalesced 5, cross-process 1 |

Effective-PID coverage on router DNS is high (Safari 153/155, Firefox 134/134).
Firefox also sends GREASE ECH on nearly every hello (180/189).

What this already tells us:
1. **DoH on makes DNS-only naming fully blind.** About 98% of readable
   Chrome/Firefox flows are handshake-only. This is the clearest result in
   the project, and it will hold at scale.
2. **With DoH off, almost every disagreement is a coalescing candidate.**
   The "wrong" names are likely connection reuse, not real naming errors.
   **This is the single most important analysis decision left** (task P0-2).
3. Cross-process borrowing is rare in browser-only runs so far (1 case). It
   may show up more in app runs and normal use, where several apps share
   CDNs. Do not overclaim it.

## 5. Unfinished work, in priority order

**Update 2026-11-23.** The design is now the one the owner chose: the
original goal (per-app disagreement + cross-process + causes), made
defensible and fast with three ingredients:
1. **parallel browser lanes** (many independent instances at once, one capture);
2. a **live challenge suite** of known-answer connections on the real internet;
3. **real firewalls** (Little Snitch, LuLu) running alongside, scored on what
   they actually displayed.

Headless browsers are fine: the measurement is at the network level, and
headless asks the same DNS and TLS questions.

### Done on 2026-11-23 (tested: `go test ./...`, lab pins, a live Chromium run of the driver)

- **Little Snitch model, exactly as documented** (`internal/eval/littlesnitch.go`),
  strategies `littlesnitch-mac` (default "Verify server names asserted by
  process" ON) and `littlesnitch-mac-noverify`. The steps:
  2. the app's single DNS name for the IP, handshake unchecked;
  3. the SNI, accepted by default only if some DNS answer mapped it to that IP;
  4. the common registrable domain of the app's names;
  5. otherwise the bare address.

  Step 1 (the NE name) is not observable, so its error is an upper bound.
  Lab: 17/27 correct, 2 misled (verify on); 23/27, 2 misled (verify off).
  Verified quote (FAQ): "By default, Little Snitch uses the server name that a
  process sends only if it matches a DNS lookup it has seen."
  (https://www.obdev.at/support/littlesnitch)
- **Coalescing three-way split** in the report: disagreement over all comparable
  flows, excluding coalescing candidates, and candidates only (RFC 9113 §9.1.1:
  one HTTP/2 connection may legitimately serve several origins).
- **Every strategy graded against the handshake name** in field data, including
  both Little Snitch models; plus a Little Snitch step breakdown (share named at
  step 2, step-2 disagreement, handshake names refused by verification).
- **Cross-process counted only between different apps** (`naming.AppFamily`).
  Two instances of one browser borrowing from each other are counted as
  `sibling_process`, not as cross-process.
- **Per-site statistics.** Workloads write `<capture>.visits.tsv`, and parallel
  runs record each lane's PIDs. The report shows the median and IQR across sites
  next to the pooled Wilson rates.
- **Parallel lanes** (`tools/workload/parallel/`, Node + puppeteer-core 25.14.0):
  installed Chrome (headless), installed Firefox via WebDriver BiDi, optional one
  Safari lane via safaridriver; deterministic sharding; one capture per DoH
  setting; `sudo make parallel NETWORK=home REPEAT=1 DOH="off on"`. A parallel
  capture is reported as one summary per browser.
- **Challenge suite** (`cmd/acn-challenge`, `tools/realtools/challenge.sh`,
  `make challenge`). Known-answer connections on the real internet, each logged
  with its 5-tuple, scenario and announced name, into a truth file for
  `ohmyosi -eval <cap> -truth <cap>.truth.json`. Scenarios:
  - baseline;
  - cohost (decoy looked up after the real name on a shared IP);
  - crossprocess (separate executables `acn-resolver` / `acn-fetcher`);
  - doh;
  - stale (wait past TTL);
  - coalesce (one HTTP/2 connection, two authorities);
  - snihost (SNI ≠ Host).

  Pairs come from DoH discovery over the Tranco top 1000 (top 200 gave only 11
  pairs). Each scenario gets its own addresses. Caveat: some pairs are one
  company under two domains (facebook.com / fbcdn.net). That's still a different
  name shown, but don't call it "a different organisation" without checking.

### P0, still open (needs the Mac; give to Claude Code there)

1. **Setup.** Run `(cd tools/workload/parallel && npm ci)` once. For a Safari
   lane: `sudo safaridriver --enable` and Safari > Develop > Allow Remote Automation.
2. **Real-tool harness: built 2026-11-23** (`internal/eval/realtools.go`,
   `tools/realtools/export.sh`, `tools/realtools/README.md`). Little Snitch's
   `sudo littlesnitch log-traffic` CSV (documented fields: date, ipAddress,
   remoteHostname, protocol, port, connectingExecutable, …) is exported
   automatically for each capture window when `FIREWALL=littlesnitch`, saved
   as `<capture>.littlesnitch.csv`, joined to flows (address, port, protocol,
   executable, ±2 min), and scored as `real:littlesnitch`, both against truth
   and against the handshake name. Flows the log never mentions are
   "unlogged" and excluded, not counted as blank. **Still to do on the Mac:**
   - the owner installs and approves Little Snitch, turns on "Allow access via
     Terminal" and sets allow-all;
   - verify the CLI path and the date format of `log-traffic`;
   - for LuLu, inspect the raw unified log `export.sh` saves and write the
     converter to the common CSV (`time,executable,ip,port,protocol,name`),
     if LuLu logs host names at all.

     LuLu takes names from the OS (`flow.URL.host` / `remoteHostname`, i.e.
     Little Snitch's unobservable step 1), so LuLu runs measure how often
     macOS supplies a name.
3. **Smoke test** (owner runs sudo):
   - `sudo make parallel NETWORK=test REPEAT=0 DOH="off on" SITES=20` with
     `LANES=chrome:2,firefox:1`;
   - `make challenge NETWORK=test REPS=3`, first with no firewall, then with
     `FIREWALL=littlesnitch`.

   Then `make report` and `./ohmyosi -eval <challenge>.pcapng -truth
   <challenge>.truth.json`. Check that:
   - visits map to sites;
   - lanes map to PIDs;
   - the challenge truth keys match flows (the eval output's "AGAINST GROUND TRUTH"
     flow count should be close to the number of connections logged);
   - crossprocess reps show as cross-process under last-answer.
4. **Freeze the protocol:** `git tag protocol-v1` once the smoke test is right.

### P0, data collection (owner runs these; needs sudo + their Mac)

Before every run: Wi-Fi DNS = router or campus resolver (never 8.8.8.8,
1.1.1.1 or 9.9.9.9: DDR hides DNS). Mac plugged in. Your own Chrome and
Firefox can stay open for parallel runs (lanes use their own instances), but
close heavy apps.

| # | Command | Notes |
|---|---|---|
| 1 | `sudo make parallel NETWORK=home REPEAT=1 DOH="off on"` | ~500 sites per capture, 4 Chrome + 2 Firefox lanes (+ `SAFARI=1`) |
| 2 | `make challenge NETWORK=home REPS=50` | no firewall |
| 3 | `make challenge NETWORK=home REPS=50 FIREWALL=littlesnitch` | Little Snitch on, allow-all |
| 4 | `make challenge NETWORK=home REPS=50 FIREWALL=lulu` | LuLu on (Little Snitch off) |
| 5 | `sudo make parallel NETWORK=home REPEAT=2 DOH="on off"` | order swapped, another day |
| 6 | `sudo make apps NETWORK=home` + `sudo make field` (2-3 sessions) | exploratory case studies for cross-process |
| 7 | (if time) the same parallel run on campus | check resolver first |

Stop collecting by **2026-11-25**. The old sequential `sudo make workload` still
works and now writes visit logs too; use it only as a control.

### P1, analysis (maximum results)

1. `make report`; then rerun at `-eval-slack 0s` and `500ms` and show the headline doesn't move.
   For challenge captures: `./ohmyosi -eval <cap> -truth <cap>.truth.json` per run, per firewall.
   **Hand-check 50 randomly sampled "wrong" names in Wireshark** (hello, DNS
   answers, certificate). Label each as a real error, coalescing, or a same-company
   alias, and report the tool's precision. This is the human validation the
   professor will value most.
2. Headline numbers, each with Wilson CI and N:
   - correlation error and disagreement per strategy, per browser, DoH on/off, cold/warm;
   - the Little Snitch step-2 share and step-2 disagreement (now in `make report`);
   - real Little Snitch / LuLu vs ground truth on the challenge suite (P0-2);
   - handshake-only share under DoH (the "blind" result);
   - cross-process rate (all runs, then apps/field separately);
   - GREASE ECH prevalence per browser (`ech_offered`/readable);
   - effective-PID coverage;
   - coalescing three-way split (in `make report`);
   - per-site median + IQR next to pooled rates (in `make report`).
3. **Figures** (4–5): (a) correlation error by browser × DoH, with CIs;
   (b) cold vs warm; (c) causes stacked per condition; (d) per-app error for the
   app runs; (e) ours vs baselines (6%, <4%, 7.2%, 17%). Put numbers in the
   CSV first, plot from the CSV (matplotlib is fine), and check every number
   against the CSV.
4. **Blocklist evasion experiment** (claim 5; currently no data). Import a
   hosts list, e.g. `./ohmyosi -import-blocklist <StevenBlack hosts URL>`; run
   the daemon with `-enforce` or evaluate with
   `-eval-block` on captures; browse with Firefox/Chrome DoH on vs off; count
   blocked names that still complete handshakes, per app.
5. Real Little Snitch alongside the parallel browsing too, if its export works,
   to test its own claim that "Occasional wrong names are rare, but inherent to the
   technique: several names can point to the same IP address, and Little Snitch
   shows the most recently looked up one." (Linux troubleshooting page, verified 2026-11-23.)

### P2, write the report (by 2026-11-27)

Use the teacher's `.docx` template (edit the template itself; keep its styles).
Section → content mapping:

| Section | Content |
|---|---|
| Abstract | problem, objective, monitor + study, 2–3 headline numbers, outcome |
| 1 Introduction | receptionist problem; monitor ≠ firewall; contributions (§7) |
| 2 Literature Survey | §8 of this file |
| 3 Methodology | 3a monitor: pktap, effective PID, SNI + QUIC decryption, reassembly, provenance. 3b study: strategies, grades, causes, reference flags (ECH/GREASE, coalescing, IP literal), metrics, Wilson CIs, slack |
| 4 Experimental Setup | Mac model, macOS 26.5 (25F71), browser versions from manifests, Tranco list V38GN top-N, conditions, networks, resolver, lab |
| 5 Results and Discussion | lab validation table → field results (figures) → discussion (DoH blindness, coalescing, cross-process, GREASE, DDR finding) → threats to validity |
| 6 Conclusion | claim, limits (one machine, modelled Little Snitch, SNI ≠ truth), future work (ECH, real Little Snitch, Linux eBPF port) |

5–6 pages total. Every number must trace to `dist/runs.csv` or `make report`.
Every quote must be verbatim with its URL (§8 lists the verified ones).

### P3, deferred (only if time remains)

- SwiftUI app: show `naming` fields (Read vs Guess popup, header strip, evasion banners). A ready prompt is in the chat history; the schema is already sent.
- Live demo page and `make demo`.
- Literature residual gaps: Google Scholar "cited by" for the three anchors, IEEE Xplore, ECH-GREASE measurement papers, SecureComm 2021 "Using NetFlow to Measure the Impact of Deploying DNS-based Blacklists".

## 6. How to run things

```sh
make build && go test ./...          # always first
make lab                             # ground truth; must still show read-first misled 0
sudo make workload NETWORK=home REPEAT=1
sudo make apps NETWORK=home REPEAT=1
make report                          # tables + dist/runs.csv
./ohmyosi -report dist/runs -eval-slack 0s
./ohmyosi -eval dist/runs/<file>.pcapng -eval-json > x.json   # one run in full
```

The owner must type `sudo` commands themselves. An agent can't enter the
password; ask them to run them, e.g. with the `!` prefix in Claude Code.

## 7. The claim (scoped; don't inflate it)

> To our knowledge, this is the first end-host, per-application measurement of
> how often the DNS-correlated server names used by host firewalls disagree
> with the name each connection asserts in its own TLS ClientHello or QUIC
> Initial. It is also the first to quantify cross-process DNS borrowing and
> blocklisted names that appear in successful handshakes.

Contributions: (1) a new vantage point: on the laptop, per app; (2) a counted,
vendor-admitted failure: cross-process borrowing; (3) a fair comparison of
documented strategies, including the misled rate; (4) a cause for every
error; (5) an evaluation (not an invention) of silent DNS-block failure;
plus the instrument (ohmyosi) and a ground-truth lab.

**Never claim:** first to notice the problem; a population or internet-wide
rate; that SNI is absolute truth; "impossible to hide from"; malware
detection; a better firewall than Little Snitch; novelty for pktap's
effective PID itself (other tools use it: jw0201/NetworkMonitor, PacketScope,
Tracexy).

## 8. Literature (verified quotes; use verbatim)

| Source | Verbatim | URL |
|---|---|---|
| Trevisan, Drago, Mellia, Munafò, *Towards Web Service Classification using Addresses and DNS*, TRAC @ **IWCMC 2016**, pp. 38–43 | "Inconsistencies are observed between SNI and DNS in the 6% of flows." · "Less than 15% of the traffic is owing to singletons, even if those cases are 65% of the addresses." | https://pages.cs.wisc.edu/~plonka/treetop/ClueTrac2016.pdf |
| Bermudez et al., *DNS to the Rescue* (DN-Hunter), IMC 2012 | "Excluding these cases, the percentage of possible confusion reduces to less than 4%." | https://studylib.net/doc/8237702/dns-to-the-rescue--discerning-content-and-services-in-a-t... |
| Hoang et al., *Assessing the Privacy Benefits of Domain Name Encryption*, AsiaCCS 2020 | "We find that 20% of the domains studied will not gain any privacy benefit since they have a one-to-one mapping between their hostname and IP address." · "On the other hand, 30% will gain a significant privacy benefit with a k value greater than 100, since these domains are co-hosted with more than 100 other domains." | https://arxiv.org/abs/1911.00563 |
| Allman, *Putting DNS in Context*, IMC 2020 | "the 7.2% of connections that do not utilize DNS lookups" | https://mallman.net/pubs/All20b/All20b.pdf |
| Yu et al., DNS-OARC 41 talk, 2023 | "Further, we find that 12% of traffic does not use DNS lookups." | https://indico.dns-oarc.net/event/47/contributions/1006/ |
| Yu, Koch, Mammadov, Cao, Zussman, Katz-Bassett, *Internet Service Usage and Delivery As Seen From a Residential Network*, POMACS 9(2) 2025 | 17% of flows with no observed DNS lookup; 14% of flows start after the DNS record expired (median 207 s). **Verify the exact wording in the PDF before quoting.** | https://wimnet.ee.columbia.edu/wp-content/uploads/2025/04/sigmetrics25_Internet_Service_From_Residential_Network.pdf |
| Tharayil et al., *Understanding Orphan Flows*, TMA 2025 | 1.57% orphan outbound flows (in-network). Verify wording. | https://tma.ifip.org/2025/wp-content/uploads/sites/14/2025/06/tma2025_paper65.pdf |
| Maghsoudlou et al., *FlowDNS*, CoNEXT 2022 | no ground truth; last-name-wins per IP | https://arxiv.org/pdf/2211.05682 |
| Little Snitch 6 docs | "If the process can know only one name for the address, we are done, we have the name." | https://help.obdev.at/littlesnitch6/adv-server-names |
| Little Snitch for Linux docs | "Both techniques are unreliable." | https://help.obdev.at/littlesnitch-linux/advanced-topics |
| Little Snitch for Linux troubleshooting | "Occasional wrong names are rare, but inherent to the technique: several names can point to the same IP address," · "and Little Snitch shows the most recently looked up one." (verified 2026-11-23) | https://help.obdev.at/littlesnitch-linux/troubleshooting |
| Little Snitch (macOS) FAQ | "By default, Little Snitch uses the server name that a process sends only if it matches a DNS lookup it has seen." Setting: Settings > Security > "Verify server names asserted by process" (verified 2026-11-23) | https://www.obdev.at/support/littlesnitch |
| RFC 9113 §9.1.1 | HTTP/2 connection reuse across origins (coalescing): cite for treating coalesced disagreement as ambiguous | https://datatracker.ietf.org/doc/html/rfc9113#section-9.1.1 |
| Portmaster docs | "This approach can sometimes lead the Portmaster to a wrong attribution of a domain to a connection." · "if two processes use two different domains but both of them point to the same IP address" | https://docs.safing.io/portmaster/architecture/os-integration |
| Wireshark 4.6.0 release notes | "Wireshark can dissect process information, packet metadata, flow IDs, drop information, and other information provided by tcpdump on macOS" | https://www.wireshark.org/docs/relnotes/wireshark-4.6.0.html |
| Corrata, *Living with ECH*, May 2025 | "In reality our data shows that only 0.06% of connections actually use it." | https://corrata.com/wp-content/uploads/2025/05/Living-with-ECH-May-25.pdf |
| RFC 9001 | "Initial packets apply the packet protection process, but use a secret derived from the Destination Connection ID field" · "these packets are not considered to have confidentiality or integrity protection" | https://www.rfc-editor.org/rfc/rfc9001.html |

Also cite: Razaghpanah et al. (Lumen), NDSS 2018; Gringoli et al. (GT), CCR 2009;
Sander et al., IMC 2021 (coalescing); Trevisan et al., CCR 2020; Huang & Yang SoK
arXiv 2609.02140 (2026); Haas et al. zeek-osquery arXiv 2002.04547.

Novelty check (2026-11-19): forward citations of DN-Hunter (~150), Trevisan
2016 (30) and FlowDNS (10) on Semantic Scholar, plus an 18-query recent-work
sweep. **No prior per-app, end-host SNI-vs-DNS measurement found.** Google Scholar
and IEEE Xplore were not checked directly.

## 9. Gotchas (learned the hard way)

- **DDR:** with Wi-Fi DNS on 8.8.8.8, macOS silently encrypts system DNS. Zero
  DNS on the wire, effective-PID coverage 0%. This is itself a finding for the
  Results section, but it invalidates per-process numbers. Always router or campus DNS.
- **GREASE ECH:** Chrome and Firefox add a fake ECH extension to most hellos.
  Only known front names count as real ECH (`internal/decode/ech.go`).
- **Safari:** networking happens in `com.apple.WebKi…` (pktap truncates names to
  15 chars). Safari has no throwaway profile, so the sites land in the owner's
  history, and the cold pass only flushes system DNS.
- **Split ClientHellos:** Chrome 157 (post-quantum key share) spans two
  segments; the reassembler (`internal/decode/hello.go`) handles it, with a memory cap.
- **Snaplen must be ≥ 2048** with pktap.
- **Warm passes** reuse nothing now (relaunch); earlier warm data
  (`runs-smoke1`) is not comparable.
- **Captures are private** (the owner's real traffic). `dist/` is git-ignored;
  keep it that way. Publish only aggregate tables.
- Under `sudo`, scripts chown outputs back to the owner. Don't break that.
- The method is frozen once overnight runs start. If you change grading
  afterwards, rerun `make report` on all captures (they're re-evaluable) and
  re-pin the lab.

## 10. File map (research-relevant)

```
internal/naming/     ledger (DNS answers w/ TTL + asker; handshakes), Grade(), causes, Tally
internal/eval/       eval.go (one capture, all strategies) · report.go (pooled, CSV, baselines)
                     littlesnitch.go (documented LS model) · visits.go (visit log, lanes, per-site)
                     resolver.go (DDR/encrypted resolver detection) · prior.go · *_test.go
internal/lab/        ground-truth capture builder; cmd/acn-lab writes lab.pcapng + truth
internal/audit/      evasion detection, verified-address pf table, enforcement self-audit
internal/decode/     sni.go quic.go hello.go (reassembly) ech.go (fronts, GREASE) ja4.go synth.go
internal/pktap/      tcpdump reader (classic + Apple pcapng) · writer.go (lab pcapng)
internal/flow/       flow table; attrib.go (effective-PID attribution)
tools/workload/      run.sh (sequential browsers) · apps.sh · parallel/ (lanes.mjs, run.sh) · ../field.sh
cmd/acn-challenge/   live known-answer connections → truth file; tools/realtools/challenge.sh wraps it
docs/ACN.md          method, claims, design, threats
```

## 11. Commits on `acn-measurement`

See `git log main..acn-measurement`. Grouped by area: decode, core fixes,
measurement packages, CLI wiring, workload tools, docs (this file), and the
owner's in-progress SwiftUI change, committed separately as WIP.
