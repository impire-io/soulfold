# 02-DESIGN — the normative design

What Soulfold *is*, functional-level: capabilities, seams, configuration
surfaces, acceptance criteria. Load-bearing decisions carry numbered entries
with their reasoning, so future changes argue against the real reasons.
Behavioral changes made during implementation propagate back here — these
docs describe the system as it is.

## Documents

| Document | Covers | Decisions |
|---|---|---|
| [store-and-key-lifecycle.md](store-and-key-lifecycle.md) | The JetStream KV store: buckets, record shapes, additive evolution, the CAS discipline, and the signing-key lifecycle whose JWKS rollover needs no consumer restart. | D1–D8 |

Decision numbers (D-entries) are global across the design docs: the next
document continues where the last one stopped.

Documents arrive by research graduation (see
[`../01-RESEARCH/README.md`](../01-RESEARCH/README.md)) or design
propagation from landed work. The roadmap names the expected next ones —
the OP core surface, the passkey ceremonies, the lifecycle surface, the
embed seam. The founding constraints they must all satisfy are already
fixed: the constitution's Principles I (passkeys, not passwords) and II
(indistinguishable by design), and the seam contract recorded at genesis
([`../04-JOURNEY/0001-genesis-the-fold.md`](../04-JOURNEY/0001-genesis-the-fold.md)).
