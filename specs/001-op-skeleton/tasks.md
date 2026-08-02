# Tasks: the OP skeleton

All complete; the gate rides `make test` (see spec.md success criteria).

- [x] T001 — `internal/envelope`: D16 seal layer, D17 seed birth
      (0600, outside the store dir), loose-perm refusal.
- [x] T002 — `internal/natsserver`: embedded loopback JetStream server.
- [x] T003 — `internal/store`: D1 buckets (prefix, lookup-first), D2/D6
      schema-1 shapes, D4 Create/CAS, D5 expires_at-authoritative reads
      + sessions TTL slack, digested code/username keys (D12, D6 as
      amended).
- [x] T004 — `internal/keys`: D7 lifecycle (first key born active;
      pending → active → retiring → retired with I1/I2 in code), D8
      RS256, published-set accessor.
- [x] T005 — `internal/provider`: op.Storage over the store; op.Client
      from the client record (public + PKCE, JWT access tokens per
      D15); userinfo from records.
- [x] T006 — `internal/ui`: login + error pages (D9), D10 two-URL seam,
      D13 Origin wall + one-shot CSRF consumed in the same CAS write
      that marks the request done, D11 browser session + sf_session.
- [x] T007 — `internal/serve`: the assembly (embedded-or-external
      NATS), Options value-only ahead of M5's public seam; seeding
      helpers standing in for the ceremonies.
- [x] T008 — `cmd/soulfold`: serve | seed user | seed client | version.
- [x] T009 — Gate tests: store mechanics + envelope custody
      (`store_test.go`), rotation under a live never-restarted verifier
      (`keys_test.go`), the e2e M1 gate — stock go-oidc RP, restarts,
      forged POSTs, page inventory (`serve_test.go`).
- [x] T010 — `make check` green: fmt, tidy, build, test, lint (0 issues).
