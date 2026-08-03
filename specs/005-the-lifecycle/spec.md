# Feature Specification: the lifecycle — invitation is the only door

**Feature Branch**: `005-the-lifecycle`
**Created**: 2026-08-03
**Status**: Implemented (landed 2026-08-03 — journey 0060)
**Input**: Roadmap M3 against design
[lifecycle](../../../soul-hq/02-DESIGN/soulfold/lifecycle.md) (D20–D24,
graduated 2026-08-03 from the bootstrap-story research): users, groups
(whose names surface as roles-claim values), OAuth client
registration, invites, and the admin surface — including the
researched bootstrap story that replaces first-touch enrollment.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — From nothing to a signed-in admin (Priority: P1)

An operator founds a fold and, in four counted acts (serve, seed the
admin, mint the invite, one browser ceremony), ends signed in with a
token whose roles claim carries `admin`. The bootstrap invite is
spent by the act that used it; nothing reusable is left behind.

**Acceptance scenarios**:

1. **Given** a fresh fold, **Then** the four-act walk ends in an
   admin-role token verified against published JWKS; replaying the
   consumed invite refuses at begin with the user record unmoved.
2. **Given** any user with no credentials and no invite, **Then** no
   ceremony begins — the open-enrollment lane does not exist (D20).

### User Story 2 — The admin runs the deployment remotely (Priority: P1)

With their own bearer, the admin creates users, sets group
memberships, mints invites (the one response carrying a bearer,
shown once), and registers/deletes clients — all through the JSON
`/admin` surface, no pages, no server-box access.

**Acceptance scenarios**:

1. **Given** an admin-created user in group `engineering`, enrolled
   through an admin-minted invite, **Then** their token's roles carry
   `engineering`; **When** the admin moves them to `platform`,
   **Then** the NEXT token carries exactly the change (D23).
2. **Given** a non-admin bearer or a bare request, **Then** the admin
   surface refuses (403 / 401) (D24).

### User Story 3 — Recovery is a fresh invite (Priority: P2)

A user who lost their passkey (or wants another device) is re-invited:
the same ceremony adds a credential to their record. One mechanism,
no reset lane, no password fallback — ever.

## Success Criteria

- **SC-001** [measured]: the research bars ride `make test` as
  permanent gate tests — bootstrap counted-and-closed
  (`internal/serve/bootstrap_test.go`), invite exactly-once /
  refusals / digest-only and the store-alone attack
  (`internal/lifecycle/bars_test.go`).
- **SC-002** [measured]: membership → next-token propagation and
  admin-surface authz, driven end to end through HTTP with the
  admin's own bearer.
- **SC-003** [measured]: every pre-M3 gate (M1/M2/M4/M5, both rig
  modules) green on the invite mechanism — enrollment everywhere now
  rides invites, including the embed seam's founding
  (`Options.InviteSink`).

## Decisions of record

- The design's D20–D24 (graduated before this build; the bars were
  measured on this branch's prototype, which is this feature's code).
- `soulfold invite` is the operator act (D22); `embed.Options` grew
  `InviteSink` so embedding parents custody founding invites.
- The pre-M3 `roles` field on user records remains readable forever
  (store D2); the lived field is `groups`, and the claim is the union.

## Out of scope

Per-client allowed-groups, queryable audit store, API keys, invite
revocation (TTL bounds it) — all deferred by the Bar-4 audit; open
registration, LDAP, SMTP, branding, custom claims — refused by it.
