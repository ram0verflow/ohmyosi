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
- `product-current`: flow SNI, then cleartext HTTP Host, then the last DNS name
  stored for the address without TTL expiry. This models the shipped cache,
  including its current limitation.
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
expected result is deliberately uncomfortable: current `flow-first` still
emits one wrong DNS fallback, while `flow-first-safe` trades that wrong answer
for an abstention.

## Controlled study

1. Provision multiple controlled names that terminate on the same address, plus
   unique-address controls. Record the intended name in a workload manifest and
   confirm it independently in server/application logs.
2. Exercise clear DNS, encrypted DNS, TCP TLS, QUIC, ECH where available,
   connections opened before capture, and deliberately reduced snap lengths.
3. Repeat cold- and warm-cache runs. Randomize destination order so a
   last-answer cache is not helped by a fixed sequence.
4. Join ground truth to captured flows by a run nonce and controlled timing,
   not by the destination label under evaluation. Preserve failures to join as
   excluded rows with reasons.
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
under the candidate policy, and states its coverage cost. The next candidate is
to preserve concurrent DNS candidates per address and abstain from DNS fallback
when more than one unexpired name is plausible. Live results may reject that
change if its coverage loss is disproportionate; the evaluator exists so that
decision is measured rather than assumed.
