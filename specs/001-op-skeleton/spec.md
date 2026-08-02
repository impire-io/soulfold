# Feature Specification: the OP skeleton — discovery, JWKS, and the code flow on the sealed store

**Feature Branch**: `001-op-skeleton`
**Created**: 2026-08-02
**Status**: Implemented (landed 2026-08-02 — journey 0052)
**Input**: Roadmap M1 against designs
[store-and-key-lifecycle](../../../soul-hq/02-DESIGN/soulfold/store-and-key-lifecycle.md)
(D1–D8, D16–D19) and
[session-and-ui](../../../soul-hq/02-DESIGN/soulfold/session-and-ui.md)
(D9–D15): "Discovery, JWKS, and the authorization-code flow with PKCE
served from the certified OP library (`zitadel/oidc`), storage on
JetStream KV (users, clients, signing keys, sessions), a seeded user
and client standing in for the ceremonies."

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A stock relying party signs a person in (Priority: P1)

An operator points any stock OIDC relying party at the fold's issuer
URL. A person opens the RP, is sent to the fold's login page, signs in
as the seeded user, and returns to the RP with tokens that verify
against the fold's published JWKS. Nothing about the fold is visible to
the RP beyond the OIDC spec surfaces (constitution II).

**Why this priority**: this is the fold's entire reason to exist — an
issuer any consumer can stand on without knowing it from Entra.

**Independent test**: `make test` runs a stock `go-oidc` RP (discovery,
authorization-code + PKCE, token exchange, JWKS verification) against
an in-process fold on an embedded nats-server, no mocks on either side.

**Acceptance scenarios**:

1. **Given** a running fold with a seeded user and client, **When** the
   RP completes discovery → authorize → login POST → callback → token
   exchange, **Then** it holds an ID token and a JWT access token that
   both verify against the published JWKS, subject = the seeded user's
   ID, and the page inventory of the whole flow is exactly
   {login, error} (D9).
2. **Given** the login POST carries a wrong or missing CSRF token or a
   foreign Origin header, **Then** the request is rejected with zero
   state change (D13) — observable in the store as "nothing happened".
3. **Given** an authorization code already redeemed once, **When** it
   is presented again, **Then** the exchange fails (the CAS flip is the
   single-use guarantee, D4/D6).

### User Story 2 — The process is disposable, the store is not (Priority: P1)

An operator restarts the fold (crash, upgrade) at an arbitrary moment.
Nobody re-seeds anything; sign-ins that were mid-flight complete;
tokens issued before the restart keep verifying.

**Acceptance scenarios**:

1. **Given** a sign-in interrupted by a full process + server restart
   between the login POST and the token exchange, **Then** the exchange
   completes and the tokens verify — the flow state lives in KV (D11).
2. **Given** a fold restarted on the same store directory, **When** a
   new sign-in runs with discovery cached from before the restart,
   **Then** it completes without re-seeding (D1: buckets found by
   lookup).

### User Story 3 — Keys roll over under running verifiers (Priority: P2)

The operator rotates the signing key. A relying party that fetched JWKS
before the rotation and never restarts keeps verifying every token —
old-key tokens until their expiry, new-key tokens immediately.

**Acceptance scenario**: **Given** a never-restarted stock verifier
observing the fold across create-pending → activate → retire, **Then**
it sees zero verification failures, the retiring key's last token
verifies until its expiry, and the retired key leaves the published
JWKS (D7's I1/I2).

### User Story 4 — The store defends itself at rest (Priority: P2)

Someone obtains the fold's stopped store directory, or API-level read
access to its buckets in a shared JetStream domain. They recover no
record plaintext; the seal seed lives outside the store (D16–D17).

**Acceptance scenario**: the marker scan over the stopped store dir and
a full API-level dump finds no record plaintext, with an unsealed
positive control proving the scan (store design acceptance #5).

## Success Criteria *(the gate, from the design acceptance criteria)*

- **SC-001** (store #1–#3, #5 + roadmap M1 gate): a stock go-oidc RP
  completes sign-in against the running fold with an embedded
  nats-server as the store; issued tokens verify against published
  JWKS; the fold survives restart with its state in KV; the working
  set survives byte-identical; additive matrix green; exactly-once
  redemption; envelope scan clean with positive control. All in
  `make test` [measured].
- **SC-002** (session #1–#3): page inventory exactly {login, error};
  mid-flow restart invisible; forged state-changing POSTs rejected
  with zero state change [measured].
- **SC-003** (store #4): zero verification failures across a full key
  rotation under a never-restarted stock verifier; retired key absent
  from JWKS [measured].

## Out of scope (M1)

Passkeys (M2 — the seeded user has no credential and the login form is
the stub the roadmap names); user/group/client lifecycle and admin
(M3); the soulidentity consumer proof (M4); the public embed seam and
default wiring (M5); refresh tokens, introspection, device flow,
back-channel logout (no milestone names them; additive when demanded).
