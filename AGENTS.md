# Agent guide for Soulfold

Durable instructions for any coding agent working in this repository. The full
rules live in `../soul-hq/00-GENESIS/`; this file is the orientation and the
non-negotiables.

## Orientation (read in this order)

1. `../soul-hq/00-GENESIS/` — [`vision.md`](../soul-hq/00-GENESIS/vision.md) (the fold:
   the ecosystem's default IAM — passkey-first OIDC on JetStream KV —
   and what it refuses to become: not a password store, not a
   privileged peer of soulidentity, not a parallel permission system,
   not a protocol fork, not a general-purpose IdP product),
   [`constitution.md`](../soul-hq/00-GENESIS/constitution.md) (the articles no
   change may violate, plus the anti-drift working agreement), and
   [`how-we-work.md`](../soul-hq/00-GENESIS/how-we-work.md) (pipeline, research
   lifecycle, the journey duty). Decisions are held against these.
2. `../soul-hq/04-JOURNEY/README.md` — where things stand + the episode index.
3. `../soul-hq/03-IMPLEMENTATION/ROADMAP.md` — the milestones and their gates.
4. `../soul-hq/02-DESIGN/soulfold/` — the design docs and their numbered decisions
   (none yet; they arrive by research graduation).

## Non-negotiables (constitution articles, in brief)

- **Quality gate before "done"** (all green, none skipped, before every
  commit): `make check` — fmt, tidy, build, test, lint. The hq
  structural lint rides the soul-hq gate (make test there).
- **Passkeys, not passwords** (I): no password lane, ever; credential
  records hold public keys and digests only — nothing the fold stores
  may be sufficient to impersonate a user.
- **Indistinguishable by design** (II): consumers reach the fold only
  through the OIDC spec surfaces (discovery, JWKS, authorize, token).
  No Soulstream-only claim, endpoint, or side-channel; soulidentity's
  callout issuer must be unable to tell the fold from Entra. Group
  names surface as roles-claim values that *name* declared roles —
  they never carry permissions; the NATS server stays the verifier of
  record on the other side of the seam.
- **Smallest viable implementation** (III): protocol comes from the
  named certified libraries (`zitadel/oidc`, `go-webauthn`), never
  hand-rolled; growth is what the specs name plus the fold's own
  lifecycle; scope creep is a review blocker.
- **Documentation is first-class** (IV): plain words, decisions
  numbered with reasoning, docs in the same change as behavior.
- **The working agreement** (anti-drift): load-bearing claims carry an
  evidence class (`[measured]` / `[mechanism-argument]` / `[judgment]`,
  only measured closes a debate); direction decisions record their
  reversal condition when made; sign every commit; never commit
  `.claude/settings.local.json`.

## The flow

- **Research** runs through `/research-start` → investigate →
  `/research-graduate` (`../soul-hq/01-RESEARCH/`). A capability that isn't
  decided yet starts as research, not as code — M1's research topics
  are named on the roadmap.
- **Implementation** follows the roadmap's milestones against the design
  docs; landing means gate green, roadmap updated, journey episode
  written, design propagated — in the same merge.
- **The journey duty (required):** every landed milestone, concluded
  research topic, or load-bearing decision gets a numbered episode in
  `../soul-hq/04-JOURNEY/` — `/journey-log` does this.
