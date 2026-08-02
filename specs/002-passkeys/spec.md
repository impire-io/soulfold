# Feature Specification: passkeys — the ceremonies replace the stub

**Feature Branch**: `002-passkeys`
**Created**: 2026-08-02
**Status**: Implemented (landed 2026-08-02 — journey 0053)
**Input**: Roadmap M2: "WebAuthn registration and login ceremonies
(`go-webauthn`) replace the seeded stub; the passkey-only rule
(constitution I) becomes enforced behavior." Designs: session-and-ui
D9 (page-local JS only where a ceremony demands it), D13 (the walls),
D14 (RP ID / origin rules — the naming one-way door); store D2/D6
(additive credential records).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — First touch enrolls, second touch asserts (Priority: P1)

A seeded user with no credential opens the login page; the ceremony
that runs is a passkey **registration** — their first authentication
binds their passkey. Every later sign-in is a passkey **assertion**.
There is no password, no fallback lane, nothing to type but a username.

**Why this priority**: constitution I is the founding refusal — with
M2 it stops being policy and becomes what the code does.

**Interim honesty**: first-touch enrollment (trust on first
authentication) is the M2 stand-in for M3's researched bootstrap
story (invites, custody); the quickstart says so loudly.

**Acceptance scenarios**:

1. **Given** a user with zero credentials, **When** they begin the
   ceremony, **Then** it is a registration; finishing it appends
   exactly one credential record (public material only) and completes
   the auth request.
2. **Given** a user with a credential, **When** they begin, **Then**
   it is a login assertion; finishing advances the stored sign count.
3. **Given** any ceremony record, **Then** it is single-use: replaying
   the finish fails.
4. **Given** the retired pre-M2 username-only POST, **Then** it signs
   nobody in.

### User Story 2 — The name is a wall (Priority: P1)

Ceremony responses from anywhere but the exact configured origin —
scheme flip, port change, subdomain, foreign host — are refused
(D14: `RPOrigins` is an exact allowlist; the server-side half is
load-bearing, not hygiene).

### User Story 3 — Nothing stored can impersonate (Priority: P1)

The store holds credential ids, public keys, flags, and sign counts.
The credential's private scalar appears nowhere; the scan that proves
it also finds the public key (positive control).

## Success Criteria

- **SC-001**: full register-then-login proven at library level in
  `make test` via a virtual authenticator performing real ceremonies
  (ES256, honest rpIdHash/flags/counters/signatures) [measured].
- **SC-002**: the e2e gate runs the whole passkey flow through the
  HTTP surface — a stock go-oidc RP completes sign-in whose only
  authentication is the ceremony; forged begin/finish POSTs (CSRF,
  Origin) change nothing; mid-flow restart invisible [measured].
- **SC-003**: the D14 origin matrix refused server-side, four foreign
  shapes [measured].
- **SC-004**: no credential secret in the store,
  positive-control-verified [measured].
- **SC-005**: the browser runbook against a real authenticator is
  documented (quickstart.md); running it is a human act.

## Out of scope (M2)

Invites, account recovery, credential management UI, multi-credential
listing (M3 — with the bootstrap-story research); discoverable-
credential (usernameless) login — the username field stays until M3's
lifecycle decides otherwise; attestation policy beyond "none".
