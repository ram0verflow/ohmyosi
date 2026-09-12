# Destination identity evaluation protocol

This is the research track beside the product. Its question is narrow:

> When several names can share an address, does flow-specific handshake
> evidence reduce wrong destination labels compared with DNS-only attribution,
> and what coverage is lost when the system abstains under ambiguity?

The experiment must be able to disprove the product's advantage. Reading SNI
is not the novelty claim. The claim under test is whether combining evidence at
the correct scope produces fewer wrong labels without hiding its unknowns.

## Unit, truth, and outcomes

The unit is one outbound flow. Each flow has exactly one expected destination
identity supplied independently by a controlled workload manifest, a server
log, or an application log. The evaluator refuses `dns`, `sni`, `http`, or an
unspecified source as ground truth because those are the signals being tested.

Each method produces one of three outcomes:

- **correct** — the emitted label equals independent truth;
- **wrong** — it emits a different label;
- **abstain** — it emits no label.

Wrong and abstain are never merged. Accuracy among answered flows can be made
perfect by refusing to answer anything, while coverage can be made perfect by
guessing. Report both, plus correct flows divided by all flows.

## Methods frozen for the first comparison

- `dns-latest`: the most recently observed, unexpired DNS name for the address.
  This models a single-value IP-to-name cache.
- `dns-unique`: DNS-only, but abstains unless exactly one unexpired name is
  known for the address. This is the non-straw-man ambiguity-aware baseline.
- `flow-first-no-ttl`: flow SNI, then cleartext HTTP Host, then the last DNS
  name stored for the address without TTL expiry. This freezes the original
  single-value product cache as a regression baseline.
- `flow-first`: flow SNI, then HTTP Host, then TTL-respecting `dns-latest`.
- `flow-first-safe`: flow SNI, then HTTP Host, then `dns-unique`. This is the
  candidate policy suggested by the shared-IP failure mode.
- `flow-only`: SNI or HTTP Host and otherwise abstain. This bounds the precision
  available without address-level fallback.

DNS TTL and event order are part of the fixture. Results must not use answers
observed after the flow or after their TTL expired.

## Fixture format and runner

Fixtures are NDJSON event streams. Comments beginning with `#` are allowed.

```json
{"type":"dns","at":1,"ip":"203.0.113.10","name":"alpha.example","ttl":300}
{"type":"flow","at":2,"ip":"203.0.113.10","flow_id":"f1","truth":"alpha.example","truth_source":"workload_manifest","sni":"alpha.example"}
```

Run the checked-in shared-address fixture:

```sh
go run ./cmd/identity-eval -input research/fixtures/shared-ip.ndjson
go run ./cmd/identity-eval -input research/fixtures/shared-ip.ndjson -json
```

The synthetic fixture is a test of the evaluator and a reproduction of the
known contamination mechanism. It is not evidence for a paper headline. Its
expected result is deliberately uncomfortable: TTL-respecting `flow-first`
still emits one wrong DNS fallback, while `flow-first-safe` trades that wrong
answer for an abstention.

## End-to-end controlled run

Build the monitor and local workload:

```sh
go build -o /tmp/ohmyosi ./cmd/ohmyosi
go build -o /tmp/identity-lab ./cmd/identity-lab
```

Start the monitor in one terminal. Reverse DNS, external ASN lookups, icons,
and socket seeding are disabled so the trace contains only the controlled run
and unrelated background capture, which the exact-tuple join filters out:

```sh
sudo /tmp/ohmyosi -i pktap,all -no-rdns -no-icons -asn=false -no-seed \
  -research-trace /tmp/ohmyosi-trace.ndjson
```

In another terminal, run the workload. It binds a controlled DNS server to
loopback port 53 so ohmyosi recognizes the packets as DNS; this command needs
root on systems that reserve that port. It never contacts the internet:

```sh
sudo /tmp/identity-lab -out /tmp/ohmyosi-truth.ndjson
```

Stop the monitor cleanly, then join and evaluate:

```sh
go run ./cmd/identity-eval \
  -trace /tmp/ohmyosi-trace.ndjson \
  -truth /tmp/ohmyosi-truth.ndjson \
  -fixture-out /tmp/ohmyosi-joined.ndjson
```

The trace contains packet-derived DNS, SNI, HTTP Host, and exact flow tuples.
The truth file contains workload intent and exact tuples, but no prediction.
The join requires all five tuple fields to match and reports every unmatched
truth flow as an exclusion. The checked-in tests cover header parsing, strict
schemas, independent truth sources, evidence updates, DNS withdrawal, tuple
matching, and exclusion preservation.

This first live workload covers two TLS names on one address, a TLS flow that
withholds SNI, cleartext HTTP Host, direct UDP, and overlapping DNS answers.
QUIC, ECH, encrypted DNS, pre-capture connections, and snap-length sweeps remain
explicit study conditions; absence of those rows must not be presented as
measured evidence.

## Controlled study

1. Provision multiple controlled names that terminate on the same address, plus
   unique-address controls. Record the intended name in a workload manifest and
   confirm it independently in server/application logs.
2. Exercise clear DNS, encrypted DNS, TCP TLS, QUIC, ECH where available,
   connections opened before capture, and deliberately reduced snap lengths.
3. Repeat cold- and warm-cache runs. Randomize destination order so a
   last-answer cache is not helped by a fixed sequence.
4. Join ground truth to captured flows by exact protocol, local address/port,
   and remote address/port. Never join by the destination label under
   evaluation. Preserve failures to join as excluded rows with reasons.
5. Report per-condition and aggregate correct, wrong, and abstain counts;
   coverage, answered accuracy, and total correct rate; plus capture truncation,
   undecoded records, process-attribution coverage, and available drop counters.
6. Measure CPU, memory, capture volume, and UI update latency separately from
   identity accuracy. Product overhead is a feasibility result, not an identity
   result.

Before collecting the paper dataset, freeze the fixture generator, method
definitions, exclusion rules, application/OS versions, and randomization seed.
Keep exploratory runs separate from the frozen evaluation set.

## Release gate back into the product

A naming-policy change needs a fixture that fails under the old policy, passes
under the candidate policy, and states its coverage cost. The first product
response preserves concurrent DNS candidates per address, respects TTL, and
abstains from DNS fallback when more than one unexpired name is plausible. The
checked-in synthetic fixture gates the mechanism; live results must still
measure whether its coverage loss is disproportionate.
