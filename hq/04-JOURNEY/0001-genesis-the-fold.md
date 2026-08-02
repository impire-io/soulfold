# Episode 0001 — Genesis: the fold is founded from a refusal (2026-08-02)

Soulfold exists because a refusal held. The operator's default-IdP
question — Soulstream deployments without an Entra tenant have no human
sign-in story; should soulidentity, bearing the name, become the
passkey-first OIDC provider they get out of the box? — was answered on
the identity plane's side by holding its vision's "not an identity
provider" article (soulidentity journey 0019): identity truth lives in
the deployment's IAM, and the default IAM becomes this sibling. The
load-bearing boundary is the seam, not the repo [mechanism-argument]:
soulidentity's callout validator (its D23) is one pinned issuer, JWKS
discovery, RS256 — it cannot tell providers apart, and the fold's
founding constraint is to keep it that way (constitution II:
indistinguishable by design). "Default" is distribution wiring —
`--oidc-issuer` pointed at the bundled fold — replaceable by any OIDC
provider by config.

Build-vs-adopt was examined before founding. Pocket-id — the shape this
project deliberately resembles — is Go since its v1 (the "it's Node.js"
premise was refuted in the deciding conversation), but it is an
application with an SQL store, not an embeddable library; nothing about
it mounts into a parent binary the way the ecosystem's embed pattern
does (soulidentity D29), and the survey found no embeddable Go
passkey-IdP library to adopt [judgment]. What exists are the building
blocks the constitution now names: `zitadel/oidc` (a certified OP
library with caller-supplied storage — JetStream KV slots in exactly
there) and `go-webauthn` (the maintained FIDO2 backend). The fold is
therefore a storage-and-lifecycle project, not a protocol one; scope
was named honestly at founding — the protocol layers are a fraction of
pocket-id, the lifecycle and admin surface are most of its value and
will be most of the work [judgment].

The name cleared collision checks in the deciding conversation:
soulpass reads as soulbound-token territory in web3, soulgate is a
company filing to list, soulbook is multiply taken; soulfold was clean —
and the fold is literally the founding question, "who belongs".

What shipped at genesis: the hq process adopted whole from the ecosystem
(constitution 1.0.0 ratified — passkeys-not-passwords,
indistinguishable-by-design, smallest-viable, docs-first-class, plus the
working agreement), the structural lint riding `make test`, the three
lifecycle skills, CI, and a version-only binary skeleton. No product
code: M1's research (the KV schema and key lifecycle) comes first, per
how-we-work's hard boundary.

Reversal condition: any Soulstream-only behavior in the fold — a claim
only soulidentity consumes, an endpoint or side-channel past the spec
surfaces (observable: a soulfold-aware branch in soulidentity's issuer,
or a consumer-specific field in the fold's tokens) — collapses the
ecosystem's two planes and re-opens the sibling decision from this
side. Separately, an embeddable Go passkey-IdP library appearing
upstream re-opens build-vs-adopt until the fold's OP layer is
consumer-proven (mirrors soulidentity journey 0019).

Trail: soulidentity journey 0019 and its D23/D24/D29;
`hq/00-GENESIS/` (vision, constitution 1.0.0, how-we-work),
`hq/03-IMPLEMENTATION/ROADMAP.md`; this repository's initial commit.
