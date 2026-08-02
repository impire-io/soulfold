# How little surface do the flows need — and what do WebAuthn's origin rules fix about deployment naming?

**State:** active
**Started:** 2026-08-02

## Abstract

The fold needs a human-facing surface for sign-in, but constitution III
demands the smallest one that serves the flows: the hypothesis is
server-rendered pages with at most page-local script, browser sessions
as KV records (no second session store), and an explicit CSRF posture —
no SPA, no framework. This topic gates M1 (the OP skeleton needs the
login surface and its session records) and M2 (WebAuthn's origin and
RP-ID rules constrain what the deployment may be named, and renaming
later invalidates enrolled passkeys). A decisive answer fixes the page
inventory, the session record's place in the store design (D6), the
CSRF mechanism, and the deployment-naming rules — and unblocks the M1
build.

## The question

What is the smallest human-facing surface — pages, session records,
CSRF mechanism — that completes the fold's sign-in flows with the
certified libraries, and which origin/RP-ID combinations does WebAuthn
accept, so deployment naming rules can be stated before anyone enrolls
a passkey?

(The KV mechanics themselves are decided —
[store-and-key-lifecycle](../../02-DESIGN/store-and-key-lifecycle.md);
here the session *record shape and lifetime* get fixed, not the store.)

## Pre-registered bars

- **Bar 1 — the page inventory is proven sufficient.** Protocol: a rig
  OP built from `zitadel/oidc` with KV storage serves a counted,
  named set of server-rendered pages (target: login and error only for
  M1); a scripted browser-stand-in (cookie jar + form POSTs, no JS
  engine) drives sign-in and a stock `go-oidc` RP completes the
  authorization-code + PKCE flow. Pass: the RP holds verified ID and
  access tokens, and every page the flow touched is in the declared
  inventory — nothing undeclared rendered [measured].
- **Bar 2 — sessions live in KV and survive restart mid-flow.**
  Protocol: same rig; after the login POST sets the browser session
  (KV record) but before the code/token exchange, the fold's process
  is stopped and restarted on the same store. The browser-stand-in
  then continues without re-authenticating. Pass: the flow completes
  and tokens verify; the session record round-trips per the store
  design's restart bar [measured].
- **Bar 3 — the CSRF posture rejects what it must.** Protocol: against
  the rig's state-changing endpoints (the login POST at minimum), send
  (a) a submission missing the CSRF credential, (b) one with a
  mismatched credential, (c) one with a cross-site `Origin`/forged
  referer, and (d) the legitimate submission. Pass: a–c rejected with
  no state change (no session created, no code issued), d accepted —
  all four demonstrated, and the chosen mechanism (token vs
  origin-check vs both) stated with its reasoning [measured].
- **Bar 4 — the origin/RP-ID matrix pins the naming rules.** Protocol:
  at `go-webauthn` library level (no browser), run register-then-login
  ceremonies across a matrix of origin ↔ RP-ID combinations: exact
  host match, subdomain vs registrable parent, port change, scheme
  change (https vs http), and unrelated host. Pass: every cell's
  accept/reject is demonstrated by the library (not asserted from
  docs), the matrix is recorded, and the deployment-naming rules are
  stated from it — including whether renaming the public host
  invalidates enrolled passkeys (the expected one-way door) [measured].

## Reversal condition

A certified-library flow that cannot be completed by server-rendered
pages plus page-local script — observable as a `zitadel/oidc` or
`go-webauthn` requirement in the rig (an endpoint shape, content type,
or ceremony step) that structurally demands a client-side application
or a non-KV session store. That evidence would reopen the
minimal-surface direction (toward a richer front end or an external
session mechanism) rather than be patched around; absent it, "small"
stays the rule (constitution III).

## Verdict

All four pre-registered bars **PASS**, none amended, on the pinned rig
stack (`zitadel/oidc` v3.48.1, `go-oidc` v3.20.0, `go-webauthn`
v0.17.4, `virtualwebauthn` v1.0.5, embedded nats-server v2.14.4,
2026-08-02):

- **Bar 1 — PASS** [measured]: a stock RP completed
  authorization-code + PKCE and verified the ID token (sub, nonce)
  against published JWKS; the measured page inventory over the whole
  run was `GET /login/` ×1 and `POST /login/` ×3 (error renders) —
  nothing undeclared. Login + error is the entire M1 surface.
- **Bar 2 — PASS** [measured]: a full process restart (HTTP + embedded
  NATS, same store, same issuer) between the login POST and the token
  exchange was invisible: no re-authentication, code issued from the
  KV record, exchange succeeded against endpoints cached pre-restart,
  browser-session record intact.
- **Bar 3 — PASS** [measured]: missing token, mismatched token, and
  valid-token-with-cross-site-Origin all rejected 403 with zero state
  change; legitimate submission accepted. Mechanism: one-shot
  synchronizer token minted into the auth-request KV record + Origin
  equality when present; SameSite cannot cover the pre-auth POST
  [mechanism-argument].
- **Bar 4 — PASS** [measured]: 10/10 register-then-login cells. The
  server enforces origin ∈ RPOrigins and rpIdHash == sha256(RPID),
  nothing else (the suffix rule is the browser's half — measured via
  the unrelated-but-allowlisted cell); parent-domain RP ID is a valid
  layout; a renamed host rejects the enrolled passkey (rpIdHash
  mismatch) — deployment naming is a one-way door closing at first
  enrollment.

The reversal condition was never approached: the whole flow ran with
zero JavaScript. Outcome: graduate to design.
