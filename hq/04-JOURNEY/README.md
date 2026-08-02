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
