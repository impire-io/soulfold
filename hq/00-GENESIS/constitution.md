# Soulfold Constitution

Decisions are held against this file and [`vision.md`](vision.md) — see the
decision test in [`README.md`](README.md).

## Core Principles

### I. Passkeys, Not Passwords

The fold authenticates users with WebAuthn ceremonies and nothing else.

- No password lane exists, ever — not as a fallback, not for bootstrap,
  not behind a flag. Credential records store public keys; the private
  half lives in the user's authenticator and never touches the fold.
- Nothing the fold stores may be sufficient to impersonate a user.
  OAuth client secrets (a client credential, not a user one) are stored
  as digests only.
- Recovery is re-enrollment through a deliberate, logged act — an
  invite from an admin, a second registered passkey — never a knowledge
  factor and never an unattended email loop.

**Rationale**: The fold exists because deployments deserve a default IdP
whose compromise discloses no user secrets. A password column would make
it just another password store — worse than the providers it replaces,
which at least have dedicated teams.

### II. Indistinguishable by Design

Consumers reach the fold only through the OIDC spec surfaces.

- Everything a consumer needs is served by discovery, JWKS, the
  authorization endpoint, and the token endpoint. No Soulstream-only
  claim, header, endpoint, or side-channel exists; soulidentity's
  callout issuer MUST be unable to tell the fold from Entra
  (soulidentity's D23 seam is the contract, its journey 0019 the
  founding record).
- Identity truth — who exists, who belongs — lives here when the fold
  is the deployment's IAM. Authorization inside NATS never does: group
  names surface as roles-claim values that *name* declared roles on the
  soulidentity side; they carry no permissions, and the NATS server
  remains the verifier of record for everything a minted credential
  claims.
- Signing keys rotate through JWKS the way the spec says; a consumer
  that must restart to follow a rotation is a bug on our side.

**Rationale**: The ecosystem decided its identity plane never becomes an
identity provider; the fold is only tolerable as the default IAM because
it is replaceable by construction. Any privileged path collapses the two
planes into one and re-opens that refusal.

### III. Smallest Viable Implementation

- Every change MUST be the smallest implementation that satisfies its
  need; anything not required by a concrete consumer is cut or deferred.
- Protocol comes from certified, maintained libraries — the OP core and
  the WebAuthn ceremonies are consumed, never hand-rolled. Our code is
  storage, lifecycle, and surface; cryptographic protocol is not ours to
  write.
- Speculative generality is prohibited: no configuration options,
  abstraction layers, or plugin points added "for later". Growth is what
  the OIDC and WebAuthn specs name plus the fold's own lifecycle,
  never new machinery beside them.
- Scope creep is a review blocker, not a style concern.

**Rationale**: An identity provider earns trust by being small enough to
audit — and the fold's competition is not other IdPs but the option of
running none. Every optional feature grows the surface an operator must
believe in.

### IV. Documentation Is a First-Class Citizen

- Every concept is explained plainly — an everyday analogy before
  technical detail (the project's own name is one: the fold is who
  belongs, joining the fold is registration). Plain words beat invented
  terms.
- The design docs record every load-bearing decision with a numbered
  entry and its reasoning, so future changes argue against the real
  reasons.
- Docs ship in the same change as the behavior they describe; stale
  documentation is a bug with the same severity as a failing test.

**Rationale**: A security-adjacent tool that cannot be explained simply
will be misused, and misuse of an identity provider is a security
failure, not a UX failure.

## The Working Agreement (Anti-Drift)

Adopted whole from the ecosystem's working agreement (soulstream journey
0002, soulidentity constitution) at genesis — recorded in journey
[0001](../04-JOURNEY/0001-genesis-the-fold.md). It guards the same
failure mode: a fluent counterpart steering the maintainer on a
load-bearing call he cannot independently check in the moment. Applies
to every load-bearing decision — an authentication-surface change, a
seam change, a scope call, or a public claim.

1. **Teach-back as a gate.** No load-bearing direction decision is
   recorded until the maintainer can restate the argument for it in his
   own words.
2. **Claims carry their evidence class.** **[measured]** (a test, a
   demonstrated protocol behavior), **[mechanism-argument]** (a reasoned
   case from how OIDC, WebAuthn, or NATS works), or **[judgment]**. Only
   measured closes a debate.
3. **Decisions record the reversal condition,** written when the
   decision is made, phrased as an observable reading.
4. **Adversarial pass on direction changes.** For decisions that change
   the authentication surface or the consumer seam, the other side is
   argued at full strength before the decision.

## Technology Constraints

- **Language**: Go, matching the ecosystem.
- **Protocol layers are consumed, not written**: the OP core from
  `zitadel/oidc` (certified OIDC library, caller-supplied storage), the
  ceremonies from `go-webauthn/webauthn` (FIDO2-conformant). Hand-rolled
  protocol or cryptography is a review blocker.
- **Storage**: JetStream KV is the initial backend — the deployment's
  NATS is the only stateful dependency; only public material and digests
  are stored for authentication (Principle I).
- **Front door**: HTTP(S), named honestly — WebAuthn is origin-bound and
  OIDC is discovery plus redirects. There is no NATS-fronted sign-in and
  no bespoke wire protocol; NATS-native means the store and the
  deployment story.
- **Embeddable**: the serve assembly is public (the ecosystem's embed
  pattern, soulidentity D29) — the parent-binary consumer already
  exists in the distribution story.
- **Dependencies**: an identity provider is judged by its audit
  surface — keep the dependency tree small enough to read.

## Development Workflow & Quality Gates

- Research (open questions that precede a design) runs the
  `hq/01-RESEARCH/` lifecycle — see [`how-we-work.md`](how-we-work.md).
  Implementation follows the design docs and the roadmap's milestone
  gates.
- Before merge, everything MUST be green: `make check` (fmt, tidy,
  build, test, lint) — all tests pass (none skipped), the hq structural
  lint (`internal/hqlint`) included.
- Every landed milestone, concluded research topic, or load-bearing
  decision gets a numbered episode in `hq/04-JOURNEY/` in the same
  change (the journey duty).
- Commits are signed. `.claude/settings.local.json` is never committed.

## Governance

- This constitution supersedes all other practices for Soulfold. On
  conflict with README or any other document, the constitution wins.
- **Amendments**: made by editing this file, with a version bump and a
  journey episode recording the why and the reversal condition.
- **Versioning policy** (semantic): MAJOR — removing or redefining a
  principle; MINOR — a new principle or section, or materially expanded
  guidance; PATCH — clarifications.

**Version**: 1.0.0 | **Ratified**: 2026-08-02 | **Last Amended**: 2026-08-02

*Amendment history:*
- *1.0.0 (2026-08-02)* — initial ratification (Principles I–IV + the
  working agreement), adopted at genesis with the hq structure (journey
  [0001](../04-JOURNEY/0001-genesis-the-fold.md)); founded from
  soulidentity's journey 0019, whose seam contract Principle II encodes.
