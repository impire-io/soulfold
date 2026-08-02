# Episode 0002 — The store is decided: four bars, four passes (2026-08-02)

M1's gating research asked what bucket layout, record shapes, and
concurrency discipline let the fold keep all its state in JetStream KV
alone — and what signing-key lifecycle lets JWKS roll over with zero
consumer restarts. Desk research first pinned the demand side from the
real libraries (`go doc`, not memory): `zitadel/oidc` v3.48.1's
`op.Storage` dictates exactly five record concerns (auth requests,
token records, signing keys, clients, users), and `nats.go` v1.52.0's
KV offers create-only `Create`, revision-CAS `Update`, and TTLs — but
no cross-key transaction, so the schema must never need one. Four
hypotheses were registered before any rig ran: per-kind buckets, JSON
with a `schema` field evolving additively only, CAS for every
transition, and a `pending → active → retiring → retired` key
lifecycle under two invariants (publish-before-sign,
unpublish-only-after-last-token-expiry).

All four pre-registered bars passed, none amended, against an embedded
nats-server v2.14.4 [measured]:

- **Additive decode:** 25/25 across all four record kinds, both
  directions. The one surprise was a measured trap, not a failure: a
  v1 reader that read-modify-writes a v2 record silently drops the
  v2-only fields — additive *reads* are safe, cross-version *writes*
  are not. That became design rule D3 (one writer version per
  deployment) instead of a schema change.
- **Restart round-trip:** 6/6 records byte-identical after a full
  server stop and a new server on the same store dir; buckets found by
  lookup, no re-seeding.
- **CAS:** 8 writers × 1,000 read-modify-write cycles landed at
  exactly 8,000 — zero lost updates, 36,961 CAS rejections all
  observably retried, ~6,400 accepted contended writes/s. Auth-code
  redemption modeled as a CAS flip won exactly once in 100/100 races
  of 8: double redemption is structurally lost, not policed.
- **JWKS rollover:** one stock go-oidc `RemoteKeySet`, never
  restarted, saw 466 verifications with 0 failures across a full
  rotation. Fresh-keyset controls kept it honest: the retiring key's
  straggler token verified from the published JWKS alone, was rejected
  after retirement, and the final JWKS held exactly the new key.
  go-oidc's refetch-on-unknown-kid absorbed the signing switch
  [measured]; for TTL-cached verifiers, the publish-before-sign lead
  carries the guarantee [mechanism-argument].

Nothing was refuted; the topic's reversal condition (a failure
mechanical to JetStream KV itself) was never approached. One decision
the research surfaced rather than tested: the fold signs RS256, because
the seam's verifier of record (soulidentity's callout, its D23) and
Entra both speak RS256 and indistinguishability decides
[mechanism-argument] — the rigs ran ES256 and the lifecycle never
noticed, so the mechanics are algorithm-independent [measured].

What it opened: the fold's first design doc,
[store-and-key-lifecycle](../02-DESIGN/store-and-key-lifecycle.md)
(D1–D8), whose acceptance criteria are these bars restated as M1 gate
tests. M1's remaining research is the session and UI shape; the build
follows it.

Reversal condition: an observed lost update surviving a correct
revision-CAS retry loop, or a rotation unable to reach zero
verification failures without restarting the verifier, reproduced in a
minimal rig against a supported nats-server — that evidence reopens
the genesis KV-as-the-only-store decision itself, because the
alternative would be a quiet second database.

Trail: [store-and-key-lifecycle](../02-DESIGN/store-and-key-lifecycle.md);
the topic's pre-registration, journey, and verdict in git history at
`hq/01-RESEARCH/kv-schema-and-key-lifecycle/` (opened dc5688f, results
4870256, verdict bf97e25; folder removed by this graduation); rigs in
the session scratchpad (`kvrig/` — shapes, additive matrix, restart,
CAS race, rotation), stack pinned in the verdict.
