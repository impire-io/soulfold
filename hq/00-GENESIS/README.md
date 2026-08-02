# 00-GENESIS — why Soulfold exists and how it decides

This folder is the fixed point every decision is held against. It changes
rarely, deliberately, and always with a journey episode recording why.

| File | Role |
|---|---|
| [`vision.md`](vision.md) | What Soulfold is, who it's for, where it's pointed, and what it refuses to become |
| [`constitution.md`](constitution.md) | The testable articles: principles no work is allowed to violate, plus the anti-drift working agreement |
| [`how-we-work.md`](how-we-work.md) | The process: pipeline, research lifecycle, quality gates, and the working agreement in daily terms |

The reasons behind the non-obvious calls live with the decisions themselves:
the design docs in [`../02-DESIGN/`](../02-DESIGN/README.md) carry numbered
decisions, each recording its reasoning so a future change argues against the
real reasons, not guesses. The founding decision — why the fold exists as a
sibling of the identity plane rather than inside it — is soulidentity's
journey 0019, mirrored here in journey
[0001](../04-JOURNEY/0001-genesis-the-fold.md).

## The decision test

When a choice comes up — a new direction, a shortcut, a scope change — run it
through, in order:

1. **Vision**: does it serve what [`vision.md`](vision.md) says Soulfold is
   for? If it serves something else (a password lane, a general-purpose IdP
   product, a Soulstream-only protocol convenience), say so out loud.
2. **Constitution**: does it violate an article? Articles don't bend for
   product work. The load-bearing questions are usually the first two: can
   anything the fold stores impersonate a user (I), and could a consumer tell
   the fold apart from any other OIDC provider (II)? If an article genuinely
   must change, that's an amendment with a version bump and a journey
   episode, never a quiet exception.
3. **Working agreement**: if the decision is load-bearing, it does not get
   recorded until it survives teach-back, carries its evidence class, names
   its reversal condition, and (for changes to the authentication surface or
   the consumer seam) has had the other side argued at full strength. See
   [`how-we-work.md`](how-we-work.md).

If the test doesn't produce a clear answer, the decision waits for the human.
