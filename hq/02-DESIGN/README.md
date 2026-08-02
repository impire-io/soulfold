# 02-DESIGN — the normative design

What Soulfold *is*, functional-level: capabilities, seams, configuration
surfaces, acceptance criteria. Load-bearing decisions carry numbered entries
with their reasoning, so future changes argue against the real reasons.
Behavioral changes made during implementation propagate back here — these
docs describe the system as it is.

No design document exists yet: the fold is at genesis, and documents arrive
by research graduation (see [`../01-RESEARCH/README.md`](../01-RESEARCH/README.md))
or design propagation from landed work. The roadmap names the expected ones —
the OP core and its JetStream KV schema, the passkey ceremonies, the
lifecycle surface, the embed seam. The founding constraints they must all
satisfy are already fixed: the constitution's Principles I (passkeys, not
passwords) and II (indistinguishable by design), and the seam contract
recorded at genesis
([`../04-JOURNEY/0001-genesis-the-fold.md`](../04-JOURNEY/0001-genesis-the-fold.md)).
