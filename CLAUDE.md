# Soulfold — project instructions

The fold of the Soulstream ecosystem: *who exists, who belongs* — the
ecosystem's default IAM, a self-hosted passkey-first OIDC provider that
stands exactly where Entra/Auth0/any OIDC provider may stand instead.
Founded from soulidentity's journey 0019: the identity plane refuses to
be an identity provider, so the fold is its sibling — reached by
consumers exclusively through standard OIDC (discovery, JWKS, token
endpoint) and indistinguishable from Entra by design. JetStream KV is
the store (no second database); the front door is HTTP(S) because
WebAuthn is origin-bound; the serve assembly becomes public for the
single-binary distribution. Protocol comes from certified libraries
(`zitadel/oidc`, `go-webauthn`), never hand-rolled.
Module `github.com/impire-io/soulfold`, Go 1.26.

**How this project is run lives in `../soul-hq/` — read [`AGENTS.md`](AGENTS.md)
first** (orientation order + the non-negotiables), then hold decisions
against `../soul-hq/00-GENESIS/`. Where things stand: `../soul-hq/04-JOURNEY/README.md`.
The plan: `../soul-hq/03-IMPLEMENTATION/ROADMAP.md`. Design docs arrive in
`../soul-hq/02-DESIGN/soulfold/` by research graduation — none exist yet.

Conventions:

- Quality gate before every commit: `make check` (fmt, tidy, build,
  test, lint) — all green, none skipped. The hq
  structural lint rides the soul-hq gate.
- Sign every commit. Push after landing with CI green.
- No password lane, ever (constitution I). No Soulstream-only claim,
  endpoint, or side-channel (constitution II) — the fold must stay
  indistinguishable from any external OIDC provider.
- The journey duty: every landed milestone, concluded research topic,
  or load-bearing decision gets an episode in `../soul-hq/04-JOURNEY/` in the
  same change (`/journey-log`; research via `/research-graduate`).
