# Feature Specification: the embed seam — the fold in the caller's process

**Feature Branch**: `004-embed-seam`
**Created**: 2026-08-03
**Status**: Implemented (landed 2026-08-03 — journey 0056)
**Input**: Roadmap M5: "The public serve assembly (the ecosystem's
embed pattern, soulidentity D29) so the single-binary distribution
runs the fold in-process, and the distribution story wiring
`--oidc-issuer` at the bundled fold by default. Gate: a
consumer-position module embeds and runs the fold with no `internal/`
import compiling [measured]."

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A distribution embeds the fold (Priority: P1)

A single-binary distribution (soulnode) runs the fold inside its own
process: one `embed.Run(ctx, Options)` call with value-only options —
issuer, listen, state dir, optional external NATS, the deployment's
fixed token audience, DCR on, and the founding stand-ins (seed users
and clients, idempotent) — and the fold serves until the ctx ends.
Custody is unchanged: the seal seed is born into StateDir exactly as
the daemon does it.

**Acceptance scenarios**:

1. **Given** a module whose path sits outside
   `github.com/impire-io/soulfold`, **When** it builds against only
   `embed` and `authtest`, **Then** it compiles (no `internal/` import
   can) and the embedded fold serves discovery, JWKS, DCR, and a full
   passkey sign-in.
2. **Given** `TokenAudience` and a seeded user with roles, **Then**
   issued access tokens carry the fixed audience alongside the client
   id, plus `oid` and `roles` — everything the door AS contract (§3)
   and the callout's D24 rule consume.
3. **Given** ctx cancellation, **Then** Run returns nil after a clean
   shutdown.

### User Story 2 — One assembly, two entrypoints (Priority: P2)

`soulfold serve` runs through the same public seam (the daemon is the
seam's first consumer — the D29 discipline), growing
`--token-audience` and `--enable-dcr` on the way.

## Success Criteria

- **SC-001** [measured]: `e2e/embedgate` (module `soulfold.invalid/…`)
  runs the full story in `make test`; the compiler enforces
  zero-internal.
- **SC-002** [measured]: the M4 admission rig's fold half now runs on
  the public seam — the seam's second consumer, unchanged behavior.
- **SC-003** [measured]: DCR (RFC 7591) registers public PKCE clients;
  discovery advertises `registration_endpoint`; the fixed audience
  joins every token's `aud`.

## Decisions of record

- **DCR and the fixed audience are the AS-contract half of the
  bundled story** (soulstream 018's authorization-server contract):
  hosted MCP clients register dynamically and resources validate one
  audience. Both are opt-in (`EnableDCR`, `TokenAudience`) — a plain
  RP deployment keeps deliberate registration and client-id audiences.
- **`authtest` went public**: consumers proving their bundled sign-in
  (soulnode's fold-plane gate, next) need the virtual authenticator;
  it moved from `internal/passkeys/authtest` to `authtest` unchanged.
- **Seeding rides Options** (idempotent, create-only) as the M1-era
  stand-in until M3's lifecycle — the embedding distribution founds
  its first user and client in the act that starts the fold.

## Out of scope

Soulnode's fold plane itself (its own feature, in the soulnode repo —
wiring `planes.door.auth_issuer` at the bundled fold by default);
M3's lifecycle and bootstrap research.
