# Implementation Plan: the OP skeleton

**Input**: [spec.md](spec.md); designs D1–D19. The research rig
(`xkeyrig/`, kv-encryption-at-rest graduation) is the proven reference
for the storage mapping, the envelope, and the flow shape — this plan
productizes it under the repo's conventions.

## Structure

```
cmd/soulfold/          serve | seed user | seed client | version
internal/envelope/     the D16 seal layer (xkey Seal/Open, seed file birth per D17)
internal/store/        D1 buckets on nats.go/jetstream KV; D2/D6 shapes (schema 1);
                       D4 Create/CAS helpers; D5 expires_at-authoritative reads,
                       sessions bucket per-key TTL; digested keys (D6-as-amended, D12)
internal/keys/         D7 lifecycle: first-key birth, pending→active→retiring→retired,
                       I1/I2 enforced in code; D8 RS256
internal/provider/     zitadel/oidc op.Storage over the store; op.Client from the
                       client record (JWT access tokens, D15); userinfo
internal/ui/           D9 two pages (login, error), server-rendered, zero JS;
                       D13 one-shot CSRF + Origin wall; D11 browser session + sf_session
internal/serve/        the assembly: embedded-or-external NATS, provider + ui mux,
                       http server; Run(ctx, Options) — internal now, M5 lifts it
internal/natsserver/   embedded JetStream server for standalone serve and tests
```

## Load-bearing choices

- **Modern `nats.go/jetstream` API** (context-aware, per-key `KeyTTL`
  on create) — the rig used the legacy API; the product does not.
- **The envelope is not optional.** No plaintext mode exists in the
  product; tests use real sealers (D16). The seed file: born `0600` at
  first serve into `--state-dir`, never under the store dir (D17).
- **Sessions bucket** carries bucket TTL slack + per-key TTL on
  short-lived records; `expires_at` in the record stays authoritative
  on every read (D5).
- **Browser session (D11)**: minted at authentication, cookie
  `sf_session` (HttpOnly, SameSite=Lax, Secure outside loopback); a
  valid one lets a new auth request complete without re-showing the
  form — that is the record's function; measured both ways.
- **First key is born `active`** (no verifier exists before first
  serve); every later rotation walks D7's full ladder with I1/I2
  enforced by code, not convention.
- **CLI stays flag-light**: `serve --state-dir --listen --issuer
  [--nats-url]`; `seed user --username`, `seed client --client-id
  --redirect-uri --name`. Seeding is the M1 stand-in the roadmap
  names; M3 replaces it with the lifecycle.

## Gate mapping

| Spec | Where proven |
|---|---|
| SC-001 store mechanics + envelope | `internal/store` tests (matrix, CAS, redemption, restart, scan+control) |
| SC-001 e2e sign-in + restart | `internal/serve` e2e test (stock go-oidc RP, embedded server) |
| SC-002 pages/CSRF/mid-flow restart | `internal/serve` e2e + `internal/ui` tests |
| SC-003 rotation | `internal/keys` test under live `go-oidc` RemoteKeySet |
