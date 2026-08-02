# 04-JOURNEY — the narrative record

What was built, what was measured, what was believed and then refuted, and
what each episode taught. The design docs in `../02-DESIGN/` say what the
system *is*; these episodes say how we *got here* — including the reversals,
because a refuted assumption is as load-bearing as the shipped code.

> **Keeping this log alive:** whenever work lands, a research investigation
> concludes, or a load-bearing decision is made, add a numbered episode with
> `/journey-log` (research topics get theirs via `/research-graduate`). Follow
> [`TEMPLATE.md`](TEMPLATE.md) — including its required Reversal-condition
> line and evidence-class tags. Honesty rules apply here as everywhere: record
> what actually happened, including failures, reversals, and findings that
> contradicted expectations. This duty is anchored in
> [`../00-GENESIS/how-we-work.md`](../00-GENESIS/how-we-work.md); the
> numbering and index are enforced by `internal/hqlint`.

## Where things stand (2026-08-02)

**The sign-in surface is decided**
([episode 0003](0003-session-and-ui-shape.md)): the second M1-gating
research concluded with all four bars passing [measured] — the whole
flow is two server-rendered pages and zero JavaScript (15/15 rig
checks with a stock RP), a process restart mid-flow is invisible, the
CSRF posture rejects every forged shape with zero state change, and
the WebAuthn origin/RP-ID matrix (10/10) fixed the naming rules:
renaming the public host invalidates enrolled passkeys. Second design
doc: [session-and-ui](../02-DESIGN/session-and-ui.md) (D9–D15). M1's
two named research topics are done; one new topic was opened at the
operator's direction before the build starts — KV entry protection at
rest (xkeys), since the record envelope sits inside the store-shape
one-way door.

**The store is decided** ([episode 0002](0002-kv-schema-and-key-lifecycle.md)):
M1's gating research concluded with all four pre-registered bars passing
[measured] — restart round-trip 6/6 byte-identical, additive decode
25/25 (and the cross-version RMW trap measured into design rule D3),
CAS with zero lost updates and exactly-once code redemption 100/100,
and a full JWKS rotation with 0 failures in 466 verifications under a
never-restarted go-oidc verifier. The fold's first design doc landed:
[store-and-key-lifecycle](../02-DESIGN/store-and-key-lifecycle.md)
(D1–D8, including RS256 for the seam). M1's remaining research is the
session and UI shape; the build follows it.

**Genesis — the fold is founded from a refusal**
([episode 0001](0001-genesis-the-fold.md)): soulidentity's default-IdP
question (its journey 0019) resolved with the identity plane's refusal
holding — the ecosystem's default IAM is this sibling project: a
NATS-native (JetStream KV), embeddable, passkey-first OIDC provider that
consumers reach exclusively through standard OIDC, indistinguishable
from Entra by design. Build-vs-adopt was examined (pocket-id is an
application, not an embeddable library; no embeddable Go passkey-IdP
library exists [judgment]); the constitution (1.0.0) fixes the founding
constraints — passkeys, not passwords; indistinguishable by design —
and the roadmap sequences M1 (the OP skeleton) behind its KV-schema and
key-lifecycle research. No product code exists yet.

## Episode index

| # | Episode |
|---|---|
| 0001 | [Genesis: the fold is founded from a refusal](0001-genesis-the-fold.md) |
| 0002 | [The store is decided: four bars, four passes](0002-kv-schema-and-key-lifecycle.md) |
| 0003 | [Two pages, zero scripts, and a name that becomes a door](0003-session-and-ui-shape.md) |
