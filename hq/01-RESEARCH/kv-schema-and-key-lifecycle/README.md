# What KV schema and signing-key lifecycle let the fold live entirely in JetStream KV — with JWKS rollover that never restarts a consumer?

**State:** active
**Started:** 2026-08-02

## Abstract

M1 puts the fold's whole state — users, clients, signing keys, sessions —
in JetStream KV with no second database, and the roadmap's one-way door
makes the record shapes permanent: once M1 lands they must decode
additively forever. This topic decides the bucket layout, the record
shapes, the optimistic-concurrency discipline, and the signing-key
lifecycle (how keys are born, rotated, and retired) so that JWKS rollover
never requires a consumer restart. A decisive answer graduates to the M1
design doc and unblocks the OP-skeleton build; a bar failing for reasons
mechanical to JetStream KV (not fixable by schema choice) would reopen
the store decision itself.

## The question

What bucket layout, record shapes, and optimistic-concurrency discipline
let the fold keep all M1 state (users, clients, signing keys, sessions)
in JetStream KV alone — and what signing-key lifecycle lets JWKS roll
over with zero consumer restarts and zero token-verification failures?

(The session *and UI* shape — pages, CSRF, WebAuthn origin constraints —
is the separate roadmap topic; here sessions appear only as KV records.)

## Pre-registered bars

- **Bar 1 — the schema carries M1's state across restart.** Protocol: a
  throwaway rig against an embedded nats-server writes a working set of
  all four record kinds (users, clients, signing keys, sessions) under
  the proposed bucket layout, stops the embedded server process, restarts
  it on the same store directory, and reads every record back. Pass:
  every record of every kind round-trips byte-identical with no
  re-seeding [measured].
- **Bar 2 — records decode additively.** Protocol: a Go encode/decode
  matrix test over every proposed record shape: a record written at
  shape version N is read by a reader whose shape has added optional
  fields (N+1), and a record written at N+1 is read by the N reader.
  Pass: the full matrix is green — no error, no field loss for the
  fields each reader knows; any shape that cannot evolve additively is
  redesigned before graduation [measured].
- **Bar 3 — concurrent writers cannot lose updates.** Protocol: for each
  record identified as contended (at minimum: session state transitions
  and signing-key state transitions), a rig races ≥ 8 concurrent writers
  through ≥ 1,000 read-modify-write cycles against an embedded
  nats-server using KV revision compare-and-swap. Pass: zero lost
  updates (the final record reflects every accepted write, and every
  loser observably retried or was rejected — no silent overwrite)
  [measured].
- **Bar 4 — JWKS rollover without a consumer restart.** Protocol: a rig
  runs a stock verifier (go-oidc or a plain JWKS-refetching JWT
  verifier) in a continuous verify loop against the fold's JWKS and
  token signer while the key lifecycle executes a full rotation
  (new key born → published → signing switches → old key retiring →
  retired and removed from JWKS). Pass: zero verification failures for
  the whole run with the verifier process never restarted; tokens signed
  by the old key verify until their expiry; the retired key is absent
  from the published JWKS by the end of the run [measured].

## Reversal condition

A bar fails for a reason mechanical to JetStream KV rather than to a
fixable schema choice — an observed lost update that survives a correct
revision-CAS retry loop, or a rotation sequence that cannot achieve zero
verification failures without restarting the verifier — and the failure
reproduces in a minimal rig. That evidence would reopen the
KV-as-the-only-store decision (genesis) rather than patch this schema,
because the alternative would be a quiet second database.

## Verdict

All four pre-registered bars **PASS**, none amended, on the pinned rig
stack (embedded nats-server v2.14.4, nats.go v1.52.0, zitadel/oidc
v3.48.1, go-oidc v3.20.0, Go 1.26.2, this machine, 2026-08-02):

- **Bar 1 — PASS** [measured]: 6/6 records across the four per-kind
  buckets byte-identical after a full server stop and a new server on
  the same store dir; buckets found by lookup, no re-seeding.
- **Bar 2 — PASS** [measured]: additive matrix 25/25 across all four
  record kinds, both directions. Measured caveat: a v1 reader that
  read-modify-writes a v2 record silently drops v2-only fields → design
  rule "one writer version per deployment", not a schema change.
- **Bar 3 — PASS** [measured]: 8 writers × 1,000 CAS
  (`Update(revision)`) increments landed at exactly 8,000; 36,961 CAS
  rejections, all observably rejected and retried (~6,400 accepted
  contended writes/s). Auth-code redemption as a CAS flip: exactly one
  winner in 100/100 races of 8.
- **Bar 4 — PASS** [measured]: one never-restarted go-oidc
  `RemoteKeySet`: 466 verifications, 0 failures across a full rotation
  (pending → active → retiring → retired). Controls: a fresh keyset
  verified the retiring key's straggler token from published JWKS alone
  and rejected it after retirement; final JWKS held exactly the new
  key. go-oidc's refetch-on-unknown-kid is what absorbed the signing
  switch [measured]; for TTL-cached verifiers the publish-before-sign
  invariant carries the guarantee [mechanism-argument].

The reversal condition was not approached: no bar failed for any
reason, mechanical or otherwise. Outcome: graduate to design.
