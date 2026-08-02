# The session and the sign-in surface

**Graduated from research:** session-and-ui-shape, 2026-08-02 —
[episode 0003](../04-JOURNEY/0003-session-and-ui-shape.md).
**Realized by:** M1 (the OP skeleton) and M2 (passkeys) on the
[roadmap](../03-IMPLEMENTATION/ROADMAP.md). The store mechanics these
records ride on are
[store-and-key-lifecycle](store-and-key-lifecycle.md) (D1–D8).

How a human signs in: the smallest surface that completes the flows
with the certified libraries, where the flow's state lives, what
defends the state-changing requests, and what WebAuthn's origin rules
fix about a deployment's name. Every mechanism passed a pre-registered
bar [measured]; the acceptance criteria at the end are those bars
restated, inherited by the M1 and M2 gates.

## Decisions

### D9 — The surface is two server-rendered pages

`login` and `error`, rendered server-side from templates. No SPA, no
framework, no bundler; JavaScript only ever page-local, and only where
a ceremony demands it (M2's WebAuthn calls — `navigator.credentials`
is unreachable without script; M1 ships none at all).

Reasoning: the whole authorization-code + PKCE flow completed against
a scripted client with **no JS engine**, and middleware measured the
page inventory at exactly `GET /login/` ×1 + `POST /login/` ×3 error
renders — nothing else rendered HTML [measured]. Smallest viable
surface (constitution III); anything more is a review blocker until a
ceremony demonstrably needs it.

### D10 — The UI plugs into the OP at exactly two URLs

The protocol library owns every OIDC endpoint. The UI's entire seam:
the client record's `LoginURL(authRequestID)` (where authorize sends
the user agent) and `op.AuthCallbackURL(provider)` (where the login
POST returns them). The UI never touches protocol internals; the
provider never renders a page.

Reasoning: this is the integration surface `zitadel/oidc` actually
exposes, proven end-to-end in the rig [measured]. It keeps the fold a
storage-and-lifecycle project (journey 0001).

### D11 — Flow state is KV records; the cookie only names one

No in-memory session state anywhere. Two records in the `sessions`
bucket carry a sign-in:

- **auth request** (store design D6, plus the fields this research
  fixed): `response_type`, `csrf` (one-shot, D13), `done`, with
  `subject`/`auth_time` written at authentication.
- **browser session** — `bs_<id>`: `schema`, `id`, `subject`,
  `created_at`, `expires_at`. The cookie (`sf_session`, HttpOnly,
  `SameSite=Lax`, `Secure` outside loopback) carries only the record's
  name; everything it means lives in KV.

Reasoning: a full process restart injected between the login POST and
the token exchange was invisible to the browser and to an RP that had
cached discovery *before* the restart [measured]. This is what makes
the fold's single-binary/embedded deployment honest: the process is
disposable, the store is not.

### D12 — Bearer secrets never appear verbatim in the store

An authorization code (and any future bearer secret) is indexed by
digest: the KV key is `code.<hex(sha256(code))[:32]>`; the record holds
only the target request ID, `consumed`, and `expires_at`. The code
itself exists nowhere server-side.

Reasoning: a KV key is readable by anything that can list the bucket;
a bearer credential stored verbatim would be sufficient to complete a
sign-in, violating the spirit of constitution I's "nothing the fold
stores may impersonate" [mechanism-argument]. Digest lookup costs
nothing (single hash, measured in the rig's flow).

### D13 — CSRF: a one-shot synchronizer token, with Origin as the outer wall

Every state-changing browser POST carries a token that was minted into
the KV record it acts on (for login: the auth-request record) when the
form was rendered, compared on submit, and cleared on success. When an
`Origin` header is present it must equal the issuer's origin, checked
before anything is read or written. GET never mutates.

Reasoning: `SameSite` cookies cannot protect the pre-auth login POST —
there is no cookie yet [mechanism-argument]. Measured: missing token,
mismatched token, and valid-token-with-foreign-Origin all rejected
with zero state change; the legitimate submission accepted [measured].
The token needs no extra store — it rides the record the flow already
owns.

### D14 — Deployment naming: the RP ID rules, written before anyone enrolls

- The fold's **RP ID defaults to its exact public host** (the issuer
  URL's host). A registrable parent domain is permitted as an explicit
  deployment choice for multi-subdomain estates — it widens where the
  passkey may be asserted [judgment].
- **`RPOrigins` is an exact allowlist** (scheme + host + port). A port
  change, scheme change, subdomain, or foreign host is a rejected
  ceremony, not a warning [measured]. The server does *not* verify the
  origin↔RP-ID suffix relation — that half belongs to the browser
  [measured] — so this configuration is load-bearing, not hygiene.
- **Renaming the public host invalidates every enrolled passkey**
  (rpIdHash mismatch [measured]; a real browser will not even offer
  the credential [mechanism-argument]). The name is a one-way door
  that closes at the first enrollment, not at install: the fold must
  surface this at configuration time, and M3's admin story must treat
  issuer-host changes as a destructive migration.

### D15 — Access tokens are JWTs signed by the fold's key lifecycle

M1 issues JWT access tokens (`op.AccessTokenTypeJWT` on the client
record's answer), signed RS256 by the D7/D8 lifecycle, so both issued
token kinds verify against the published JWKS.

Reasoning: M4's seam is soulidentity's callout verifying a
soulfold-issued **access token** against JWKS, and Entra's access
tokens are JWTs — indistinguishability decides (constitution II)
[mechanism-argument]. The graduating rig ran opaque Bearer tokens and
everything else held; the switch is a certified-library flag, not new
mechanism [measured basis: the rig; the flag's behavior is the
library's contract]. Reversal: if a deployment needs opaque tokens
(introspection-only estates), this becomes a per-client choice — the
record already answers per client.

## Acceptance criteria (the M1 and M2 gates inherit these)

1. A stock OIDC RP completes sign-in with the measured page inventory
   exactly {login, error} — nothing undeclared renders HTML.
2. A process restart at any point between browser steps is invisible:
   the flow completes without re-authentication and tokens verify.
3. Forged state-changing POSTs (missing token, stale token, foreign
   Origin) are rejected with zero state change; every rejection is
   observable in the store as "nothing happened".
4. WebAuthn ceremonies (M2): only allowlisted exact origins pass;
   register-then-login proven at library level in `make test`; the
   configured RP ID is surfaced as a one-way door in deployment docs.
