# The store and the key lifecycle

**Graduated from research:** kv-schema-and-key-lifecycle, 2026-08-02 —
[episode 0002](../04-JOURNEY/0002-kv-schema-and-key-lifecycle.md).
**Realized by:** M1 (the OP skeleton) on the
[roadmap](../03-IMPLEMENTATION/ROADMAP.md).

What Soulfold keeps, where, and how it changes: the JetStream KV layout
that is the fold's only store, and the signing-key lifecycle that lets
JWKS roll over while consumers keep verifying, uninterrupted. Every
mechanism below passed a pre-registered bar in the graduating research
[measured]; the acceptance criteria at the end are those bars restated
as M1 gate tests. The storage contract this design serves is
`zitadel/oidc` v3's `op.Storage` (constitution III: the certified
library defines the protocol's demands; the fold supplies storage and
lifecycle).

## Decisions

### D1 — One KV bucket per record kind

Four buckets — `users`, `clients`, `keys`, `sessions` — each carrying a
configurable name prefix, default `soulfold_`.

Reasoning: retention is configured per bucket, and the kinds genuinely
differ — sessions age out and want per-key TTL garbage collection
(`LimitMarkerTTL` set, see D5); users, clients, and keys are durable and
keep a short history for operator forensics. The prefix exists because
the fold may share a JetStream domain with its parent deployment; its
buckets must not squat on generic names. Survived Bar 1: all four
buckets found by lookup after restart, 6/6 records byte-identical
[measured].

### D2 — Records are JSON with a `schema` field; evolution is additive only

Every record is a JSON object whose first concern is `schema` (integer,
starting at 1). Evolution may only add optional fields. Renaming,
removing, or retyping a field is a breaking change and therefore a
stated migration under the roadmap's store-shape one-way door — never a
silent re-read.

Reasoning: JSON keeps records inspectable with stock NATS tooling and
needs no codegen (constitution III); Go's decoder ignores unknown
fields, which is exactly the additive property. Survived Bar 2: the
full v1↔v2 matrix over all four record kinds, 25/25 [measured].

### D3 — One writer version per deployment

A deployment runs a single writer schema-version at a time. A rolling
upgrade ships readers first, writers after; an old-version writer must
never read-modify-write a newer record.

Reasoning: measured, not speculative — a v1 reader that RMWs a v2
record silently drops the v2-only fields (demonstrated on the user
record: email and credentials vanish) [measured]. Additive *reads* are
safe; cross-version *writes* are not. For the M1 single binary this is
free; it becomes an operational rule the moment two fold versions can
touch one store.

### D4 — Birth by `Create`, every transition by `Update(revision)`

New records are written with KV `Create` (create-only; a duplicate is
an error, never an overwrite). Every mutation is a compare-and-swap
`Update` against the revision read, retried with a fresh read on
rejection. The schema never requires atomicity across keys: every
record must be independently valid at every reachable state.

Contended paths, named: auth-code redemption (D6 — a single-use CAS
flip; the loser's rejection *is* the single-use guarantee), signing-key
state transitions and the active-pointer flip (D7), and index-key
maintenance (D6).

Reasoning: KV has no cross-key transaction, so the design must not
want one. Survived Bar 3: 8 writers × 1,000 CAS cycles landed at
exactly 8,000 with 36,961 rejections all observably retried (~6,400
accepted contended writes/s — orders beyond an IdP's write rate);
code redemption won exactly once in 100/100 races of 8 [measured].

### D5 — `expires_at` is authoritative; TTL is garbage collection

Every expiring record carries `expires_at`, checked on every read; a
record past it is treated as absent regardless of its presence in KV.
KV TTLs (bucket-level, or per-key via `KeyTTL` on create in the
`sessions` bucket) only reclaim storage, on a schedule with slack
beyond `expires_at`.

Reasoning: TTL granularity, marker semantics, and server clock behavior
must never decide token or code validity — the security boundary lives
in the record, the janitor lives in the bucket [mechanism-argument].

### D6 — Buckets, keys, and record shapes (schema 1)

| Bucket | Key | Record |
|---|---|---|
| `users` | `<user-id>` | user |
| `users` | `idx.username.<username>` | index → user id |
| `clients` | `<client-id>` | client |
| `keys` | `key.<kid>` | signing key |
| `keys` | `active` | pointer → kid |
| `sessions` | `<request-id>` | session (auth request / token record) |
| `sessions` | `code.<code>` | single-use code index → request id |

Record shapes (fields additive-only per D2; timestamps RFC 3339 UTC):

- **user** — `schema`, `id`, `username`, `display_name?`, `status`
  (`active | disabled`), `created_at`, `updated_at`. M2 adds
  `credentials[]` (credential id, **public key**, sign count — public
  material and digests only, constitution I) and profile fields,
  additively.
- **client** — `schema`, `client_id`, `name`, `redirect_uris[]`,
  `public` (M1 clients are public-with-PKCE), `created_at`. A future
  confidential client stores a secret **digest**, never the secret.
- **signing key** — `schema`, `kid`, `alg`, `state` (D7),
  `private_pkcs8`, `public_jwk`, `created_at`, `not_before`,
  `last_signed_expiry?`. These are the fold's own keys — the one place
  the store holds private material; it is private *to the fold*, not a
  user credential, and makes the store exactly as sensitive as any
  IdP's key store [judgment].
- **index** (`idx.*`, `code.*`, `active`) — `schema`, the target id,
  and for `code.*`: `consumed` (the CAS flip) and `expires_at`.
- **session** — `schema`, `id`, `kind`
  (`auth_request | access_token | refresh_token`), `client_id`,
  `user_id?`, `scopes[]`, `redirect_uri?`, `state?`, `nonce?`,
  `pkce_challenge?`, `pkce_method?`, `auth_time?`, `created_at`,
  `expires_at`.

`op.Storage` mapping, so implementation doesn't guess:
`AuthRequestByID` → `sessions/<request-id>`; `SaveAuthCode` →
`Create sessions/code.<code>`; `AuthRequestByCode` → redeem
`code.<code>` (CAS flip of `consumed`, loser fails — single use), then
load the request; `CreateAccessToken` → `Create sessions/<token-id>`
with `kind: access_token`; `SigningKey` → `keys/active` → `key.<kid>`;
`KeySet` → all `key.*` filtered by state (D7).

### D7 — Key lifecycle: `pending → active → retiring → retired`, two invariants

One signing key is active at a time, selected by the CAS-updated
`active` pointer. JWKS publishes every key in state `pending`,
`active`, or `retiring`; `retired` keys stay in the store (audit,
`retired` is terminal) but leave the published set. Two invariants
carry the no-restart guarantee:

- **I1 — publish before sign:** a key enters JWKS (`pending`) at least
  one verifier cache-lifetime before it may sign.
- **I2 — unpublish after expiry:** a key may move `retiring → retired`
  only after `last_signed_expiry` — the latest `exp` it ever signed —
  has passed.

Rotation is then: create `pending` → (lead time) → flip pointer, old
key → `retiring`, stamp its `last_signed_expiry` → (until that instant
passes) → `retired`. Every transition is a D4 CAS.

Reasoning: I1 covers verifiers that cache JWKS on a TTL
[mechanism-argument]; refetch-on-unknown-kid verifiers like go-oidc
absorb the switch instantly [measured]. Survived Bar 4: one
never-restarted go-oidc verifier, 466 verifications, 0 failures across
a full rotation, with fresh-keyset controls proving the straggler
verified from published JWKS while retiring and was rejected after
retirement [measured].

### D8 — Tokens sign RS256

The fold's signing keys are RSA (2048-bit minimum), `alg: RS256`.

Reasoning: the consumer seam's verifier of record — soulidentity's auth
callout (its D23) — is pinned issuer + JWKS discovery + RS256, and
Entra publishes RS256; indistinguishable-by-design (constitution II)
decides the default [mechanism-argument]. The lifecycle mechanics are
algorithm-independent — the graduating rig ran ES256 for key-generation
speed and nothing in D7 noticed [measured]. Reversal: if the seam's
verifier of record grows ES256 support and a deployment need for it
appears, this becomes a per-deployment algorithm choice; the record
shape already carries `alg` per key.

## Acceptance criteria (the M1 gate inherits these)

1. Restart round-trip: the full working set survives a server restart
   byte-identical, buckets found by lookup, no re-seeding.
2. Additive matrix: the schema-N ↔ schema-N+1 decode matrix over every
   record shape runs green in `make test`.
3. Exactly-once redemption: racing redeemers of one auth code produce
   exactly one winner, every round.
4. Rollover: a stock, never-restarted OIDC verifier sees zero
   verification failures across a full key rotation, old-key tokens
   verify until expiry, and the retired key is absent from published
   JWKS.
