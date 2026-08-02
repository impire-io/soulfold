# Feature Specification: the fold in the fleet — the callout admission proof

**Feature Branch**: `003-fold-in-the-fleet`
**Created**: 2026-08-02
**Status**: Implemented (landed 2026-08-02 — journey 0054)
**Input**: Roadmap M4: "a soulfold-issued access token admits a browser
user through soulidentity's auth callout (its D23 seam), the token's
role value naming a declared role — with zero soulfold-aware behavior
on either side"; the same rig passing with the fold swapped for the
stub issuer. Sequenced before M3 by the operator's public-door
priority (2026-08-02, episode 0052).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A browser user enters the fleet (Priority: P1)

A person signs into the fold with their passkey and holds an ordinary
OIDC access token. Presenting it (with the deployment's public
sentinel) to a NATS server running soulidentity's auth callout admits
them: the token's role value resolves against a role the deployment
declared, the minted credential carries that role's scoped
permissions, and the server enforces them. Nobody provisioned the
person anywhere — the only declared facts are the role bindings.

**Acceptance scenarios**:

1. **Given** a fold user whose roles claim names a declared role,
   **When** they connect with sentinel + access token, **Then** they
   are admitted with the role's template enforced (in-scope round trip
   green, out-of-scope publish drawing a server-side permissions
   violation), and the audit attributes lane=oidc, the role, and the
   issuer.
2. **Given** a token whose role names nothing declared, **Then** the
   connection refuses and the refusal is audited.

### User Story 2 — Nothing on either side knows the fold (Priority: P1)

soulidentity is imported at its **published tag** and configured with
exactly what any deployment gives it: an issuer URL and an audience.
The identical gate passes with the fold replaced by an Entra-shaped
stub issuer — indistinguishability demonstrated, not asserted
(constitution II).

## Success Criteria

- **SC-001** [measured]: the admission gate passes with the fold as
  issuer — real passkey sign-in, real access token, real operator-mode
  server, soulidentity through its public embed seam at v0.1.0.
- **SC-002** [measured]: the identical gate passes with the
  Entra-shaped stub arm.
- **SC-003** [measured]: undeclared roles refuse on both arms; the
  audit carries admission and refusal.
- **SC-004** (structural): the rig imports no soulidentity internals
  (consumer position; the fold half runs against the working tree via
  replace, soulidentity by tag).

## Decisions of record

- **The fold's access-token claim vocabulary is Entra's** — `oid`
  (stable subject id), `preferred_username`, `roles` — because the
  seam's verifier of record keys subjects by `oid` with no `sub`
  fallback, and constitution II's test is literally "unable to tell
  the fold from Entra" [mechanism-argument]. Additive; nothing
  Soulstream-shaped appears.
- **`User.Roles` arrived additively** (store D2): role values a user's
  tokens carry. M3's groups will populate it from membership (group
  names surface as roles-claim values); seeding populates it until
  then.

## Out of scope

Group-derived roles (M3); the fold running embedded in soulnode (M5);
multi-issuer dispatch on soulidentity's side (its named-not-built D23
extension).
