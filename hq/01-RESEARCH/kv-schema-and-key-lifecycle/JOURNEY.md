# JOURNEY — kv-schema-and-key-lifecycle (started 2026-08-02)

## 2026-08-02 — Desk research: what the store must hold [measured]

Rig module pinned: `nats-server` v2.14.4, `nats.go` v1.52.0,
`zitadel/oidc` v3.48.1, `go-oidc` v3.20.0, `go-jose` v4.1.4 (all
`@latest` today; read via `go doc`, not from memory).

- `op.Storage` (zitadel/oidc v3) = `AuthStorage` + `OPStorage` +
  `Health`. It dictates the record kinds: **auth requests** (by ID and
  by code, deletable), **access/refresh token records** (by token ID,
  for userinfo/introspection/revocation), **signing keys**
  (`SigningKey` — the one private key to sign with; `KeySet` — the
  public keys to publish), **clients** (by client ID), **users**
  (userinfo/claims by user ID). Nothing else is demanded of storage.
- `jetstream.KeyValue` gives create-only `Create`, revision-CAS
  `Update(key, value, revision)`, `Watch`, and history. Optimistic
  concurrency is native; there is no transaction across keys.
- TTL exists at bucket level (`KeyValueConfig.TTL`) and per key
  (`jetstream.KeyTTL` on `Create`, requires `LimitMarkerTTL` on the
  bucket; immutable after create; `Update` resets a key's TTL).

## 2026-08-02 — Hypotheses (registered before any rig runs)

- **H1 — bucket layout: one bucket per record kind** (`users`,
  `clients`, `keys`, `sessions`), because retention config is
  per-bucket and the kinds want different settings: sessions age out
  (TTL as garbage collection), keys/users/clients do not; history
  depth likewise. Names and prefixes are design-doc matter; the rigs
  test the mechanism.
- **H2 — encoding: JSON with a `schema` version field**, evolution by
  adding optional fields only. Simplest thing that satisfies the
  additive one-way door (constitution III); no codegen.
- **H3 — concurrency: `Create` for birth, `Update(revision)` for every
  state transition, bounded retry on CAS failure.** The genuinely
  contended writes are auth-code redemption (single-use: consuming the
  code is a CAS transition, so double redemption loses) and signing-key
  state transitions. Cross-key atomicity is absent in KV, so the schema
  must never *require* it (each record's state must be independently
  valid).
- **H4 — key lifecycle: `pending → active → retiring → retired`,**
  JWKS publishes pending + active + retiring. Two invariants:
  **I1 publish-before-sign** — a key enters JWKS at least one verifier
  cache-lifetime before it signs; **I2 unpublish-after-expiry** — a key
  leaves JWKS only after its last-signed token has expired. Which key
  signs is a singleton pointer record updated by CAS.
- **Expiry principle:** a record's `expires_at` field is authoritative
  and checked on read; KV TTL is garbage collection only, never the
  security boundary [mechanism-argument: TTL granularity and clock
  behavior must not decide token validity].

Rig order, cheapest discriminator first: Bar 2 (pure Go additive
matrix), Bar 1 (restart round-trip), Bar 3 (CAS race), Bar 4 (rollover
under a live verifier).

## 2026-08-02 — Rig results: all four bars pass [measured]

Rigs live in the session scratchpad (`kvrig/`, module pinned as above);
every number below is from an actual run on this machine, embedded
nats-server v2.14.4 with a file store.

- **Bar 2 (additive decode) — PASS, 25/25.** For all four record kinds,
  v1 bytes read by a v2 reader keep every field; v2 bytes read by a v1
  reader decode without error and keep every v1-known field.
  **Measured trap:** a v1 reader that read-modify-writes a v2 record
  silently drops the v2-only fields (demonstrated on the user record:
  email and credentials vanish). Additive *reads* are safe;
  cross-version *writes* are not → design rule: one writer version per
  deployment; a rolling upgrade may only add readers first, writers
  after.
- **Bar 1 (restart round-trip) — PASS, 6/6.** Working set of all four
  kinds (plus a username index key and the active-key pointer) written
  across the four H1 buckets; server fully shut down; a NEW server
  object started on the same store dir; buckets found by lookup (not
  re-created); every record byte-identical. No re-seeding.
- **Bar 3 (CAS) — PASS, zero lost updates.** 8 writers × 1,000
  read-modify-write increments through `Update(revision)`: final value
  exactly 8,000; 36,961 CAS rejections, every one observably rejected
  and retried; 1.25s wall (~6,400 accepted contended writes/s — orders
  beyond an IdP's write rate). Auth-code redemption modeled as a CAS
  state flip: 100 rounds × 8 racers → exactly 1 winner and 7 losers in
  all 100 rounds. Double redemption is structurally lost by the loser's
  CAS failure.
- **Bar 4 (rollover) — PASS, 0 failures in 466 verifications.** One
  `go-oidc` `RemoteKeySet` verified continuously for 7s, never
  restarted, across a full rotation (B born pending → published 1s
  before signing [I1] → promoted by CAS pointer flip → A retiring →
  A retired only after its last-signed token expired [I2]). Controls:
  a *fresh* keyset verified the A-signed straggler while A was retiring
  (proof the straggler verifies from published JWKS, not verifier
  cache) and *rejected* it after retirement; final JWKS contained
  exactly {B}.
  **Mechanism note:** the zero-failure run leans on go-oidc's
  refetch-on-unknown-kid behavior [measured]. For verifiers that cache
  JWKS on a plain TTL, invariant I1 (publish-lead ≥ verifier cache
  lifetime) is what carries the guarantee [mechanism-argument] — the
  lifecycle must keep both invariants regardless of consumer behavior.

Verdict per hypothesis: H1 (per-kind buckets), H2 (JSON + `schema`
field, additive-only), H3 (Create/Update(revision) + bounded retry;
no cross-key atomicity assumed), H4 (pending → active → retiring →
retired with I1/I2) — all survived their discriminating rigs unchanged.
No bar failed for a reason mechanical to JetStream KV; the reversal
condition was not approached.
