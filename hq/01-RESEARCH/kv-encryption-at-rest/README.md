# Should KV records be sealed with xkeys — and where would the key live?

**State:** active
**Started:** 2026-08-02

## Abstract

The operator's direction: the fold's KV entries should be encrypted,
using the NATS-native key machinery. The precise hypothesis to test is
**xkey (X25519 curve key) sealing at the application layer** — nkeys
proper are Ed25519 *signing* keys and cannot encrypt; the `nkeys`
library's curve keys (`Seal`/`Open`) are the encryption primitive the
ecosystem offers. This gates M1: the record envelope (plaintext JSON
vs sealed blob) sits inside the store-shape one-way door, so deciding
after M1 lands means a stated migration. The topic must answer against
the alternatives (nats-server filestore encryption at rest;
field-level sealing of only the sensitive records) and must produce a
key-custody story that makes encryption more than obfuscation — a seed
stored beside the ciphertext defends nothing. It knowingly revisits
part of store design D2's reasoning (records inspectable with stock
NATS tooling); the design doc absorbs whatever verdict the bars
produce.

## The question

Does xkey-sealing of KV records preserve everything the store design
already proved (restart, additive evolution, CAS), against which
threat does it actually defend compared to server-side filestore
encryption, and what key-custody story — birth, location, rotation,
loss — makes it worth the inspectability it costs?

## Pre-registered bars

- **Bar 1 — the envelope preserves the proven store properties.**
  Protocol: re-run the store design's three mechanic rigs with a
  seal/unseal layer in place (xkey `Seal` on write, `Open` on read;
  plaintext inside remains the D2/D6 JSON): restart round-trip
  (ciphertext byte-identical, plaintext decodes), the schema-N ↔ N+1
  additive matrix through the envelope, and the CAS race on sealed
  records. Pass: all three green with numbers matching the unsealed
  baselines (zero lost updates; full matrix) [measured].
- **Bar 2 — custody is real, not decorative.** Protocol: with the rig
  stopped, take the complete store directory (and a full stream dump)
  and attempt recovery of any record plaintext using only those
  artifacts. Pass: no plaintext recoverable from store contents alone;
  the seal seed demonstrably lives outside the store; and the custody
  story is written — where the seed is born, where each deployment
  shape keeps it (single binary, embedded, shared JetStream), how
  re-keying works (a stated re-seal migration), and what seed loss
  means (honestly: total data loss) [measured for the recovery
  attempt; the story itself is design matter].
- **Bar 3 — the alternative is measured, not dismissed.** Protocol:
  the same working set on a nats-server with JetStream filestore
  encryption enabled (`cipher`); restart round-trip green; a disk scan
  for known plaintext markers comes back empty; then state which
  threat each option covers — server-side encryption defends the disk
  but not a NATS-API-level reader; app-layer sealing defends both but
  costs inspectability and custody complexity. Pass: both cells
  demonstrated, the threat table written [measured].
- **Bar 4 — the cost is known.** Protocol: seal/unseal micro-benchmark
  over the M1 record shapes (ops/s, added bytes per record) plus the
  flow rig's end-to-end sign-in with the envelope on. Pass: overhead
  quantified; added p50 per record operation under 1 ms and the
  sign-in flow's added wall time under 10 ms, or the numbers recorded
  as the reason to reverse [measured].

## Reversal condition

The custody story degenerates: if for every supported deployment shape
the seal seed necessarily ends up readable by the same principal that
can already read the ciphertext (observable: the rig's recovery
attempt succeeds once the deployment's own config/env is included in
the artifact set, in all shapes), then app-layer sealing adds a
migration burden and an outage class (seed loss) without covering a
real threat — and the direction reverses to server-side filestore
encryption plus constitution-I data minimization, recorded as such.

## Verdict

<Empty until graduation. Filled by /research-graduate: PASS/FAIL per bar with the
honest numbers, each load-bearing claim tagged [measured] / [mechanism-argument]
/ [judgment].>
