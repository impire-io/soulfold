# Roadmap — milestones and gates

*The design docs in [`../02-DESIGN/`](../02-DESIGN/README.md) will say what
Soulfold is; this document decides what gets built first and behind which
gate. Every milestone's design arrives by research graduation before its
build starts — a capability that isn't decided yet is a research topic, not
a task.*

## Where we are (2026-08-02)

**Both of M1's named research topics are concluded** — the store
([journey 0002](../04-JOURNEY/0002-kv-schema-and-key-lifecycle.md) →
[store-and-key-lifecycle](../02-DESIGN/store-and-key-lifecycle.md),
D1–D8) and the sign-in surface
([journey 0003](../04-JOURNEY/0003-session-and-ui-shape.md) →
[session-and-ui](../02-DESIGN/session-and-ui.md), D9–D15), every
pre-registered bar passing [measured]. One research topic now stands
before the M1 build: **KV entry protection at rest** (opened at the
operator's direction, xkeys hypothesis) — it gates M1 because the
record envelope sits inside the store-shape one-way door. Genesis:
[journey 0001](../04-JOURNEY/0001-genesis-the-fold.md). No product
code exists yet.

## Milestones

1. **M1 — the OP skeleton.** Discovery, JWKS, and the authorization-code
   flow with PKCE served from the certified OP library
   (`zitadel/oidc`), storage on JetStream KV (users, clients, signing
   keys, sessions), a seeded user and client standing in for the
   ceremonies. **Gate**: a stock OIDC relying party (`go-oidc`)
   completes sign-in against the running fold with an embedded
   nats-server as the store; the issued tokens verify against the
   published JWKS; the fold survives restart with its state in KV
   [measured]. Research before build: the KV schema and the signing-key
   lifecycle — **done** ([design](../02-DESIGN/store-and-key-lifecycle.md),
   [journey 0002](../04-JOURNEY/0002-kv-schema-and-key-lifecycle.md));
   the session and UI shape — **done**
   ([design](../02-DESIGN/session-and-ui.md),
   [journey 0003](../04-JOURNEY/0003-session-and-ui-shape.md));
   KV entry protection at rest — open (the record envelope is inside
   the store-shape one-way door).
2. **M2 — passkeys.** WebAuthn registration and login ceremonies
   (`go-webauthn`) replace the seeded stub; the passkey-only rule
   (constitution I) becomes enforced behavior. **Gate**: full
   register-then-login ceremony proven at the library level in
   `make test`, plus a documented browser runbook against a real
   authenticator; no credential secret in the store — public keys and
   digests only, positive-control-verified [measured].
3. **M3 — the lifecycle.** Users, groups (whose names surface as
   roles-claim values), OAuth client registration, invites, and the
   admin surface — including the bootstrap story (the first admin's
   first passkey), which is a research topic before it is code.
   **Gate**: from-nothing bootstrap to a signed-in admin in a counted,
   documented number of acts; group membership changes surface in the
   next issued token [measured].
4. **M4 — the fold in the fleet.** The consumer-position proof against
   soulidentity: a soulfold-issued access token admits a browser user
   through soulidentity's auth callout (its D23 seam), the token's role
   value naming a declared role — with zero soulfold-aware behavior on
   either side. **Gate**: the admission proven in an e2e rig importing
   both systems from consumer position; the same rig passing with the
   fold swapped for the stub issuer, demonstrating indistinguishability
   [measured].
5. **M5 — the embed seam and the default wiring.** The public serve
   assembly (the ecosystem's embed pattern, soulidentity D29) so the
   single-binary distribution runs the fold in-process, and the
   distribution story wiring `--oidc-issuer` at the bundled fold by
   default. **Gate**: a consumer-position module embeds and runs the
   fold with no `internal/` import compiling [measured].

## Open research questions (before their milestones)

- ~~**The KV schema and key lifecycle** (gates M1)~~ — concluded
  2026-08-02, all bars passed: see
  [store-and-key-lifecycle](../02-DESIGN/store-and-key-lifecycle.md) and
  [journey 0002](../04-JOURNEY/0002-kv-schema-and-key-lifecycle.md).
- ~~**The session and UI shape** (gates M1/M2)~~ — concluded
  2026-08-02, all bars passed: see
  [session-and-ui](../02-DESIGN/session-and-ui.md) and
  [journey 0003](../04-JOURNEY/0003-session-and-ui-shape.md).
- **KV entry protection at rest** (gates M1): whether records are
  sealed app-layer with NATS xkeys (x25519 curve keys — nkeys sign,
  xkeys encrypt), protected by server-side filestore encryption, or
  field-level only — and the key-custody story that makes any of it
  more than obfuscation. Opened at the operator's direction; gates M1
  because the envelope is part of the store shape (one-way door).
- **The bootstrap story** (gates M3): the first admin's first passkey —
  the fold's equivalent of soulidentity's first-key research; invite
  URLs, their custody, and their honest naming.
- **The pocket-id surface audit** (informs M3): which of pocket-id's
  admin capabilities the fold actually needs, held against constitution
  III — the smallest lifecycle surface that serves a real deployment.

## One-way doors

| Door | Constraint |
|---|---|
| **The seam.** | Once soulidentity's distribution defaults to the fold, any Soulstream-only claim, endpoint, or side-channel is a constitution-II amendment, not a feature — it would collapse the ecosystem's two planes into one. |
| **Passkeys only.** | Once users enroll, a password lane cannot be added without redefining Principle I; there is no quiet path to "temporary passwords". |
| **Store shape.** | KV records must decode additively once M1 lands; a breaking record change is a stated migration, never a silent re-read. |
