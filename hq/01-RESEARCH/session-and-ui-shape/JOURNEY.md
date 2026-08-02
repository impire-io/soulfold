# JOURNEY — session-and-ui-shape (started 2026-08-02)

## 2026-08-02 — Desk research: how the certified libraries hand off [measured]

Read from the pinned sources (`zitadel/oidc` v3.48.1 example server,
`go doc`), not from memory; new rig deps pinned: `go-webauthn` v0.17.4,
`virtualwebauthn` v1.0.5.

- **The OP delegates the human surface entirely.** The provider handles
  only protocol endpoints; the integrator mounts a login UI at any
  path. The authorize endpoint redirects the user agent to the *client
  record's* `LoginURL(authRequestID)`; after authenticating, the login
  POST redirects back to `op.AuthCallbackURL(provider)`, which issues
  the code toward the RP. So the UI's size is entirely the fold's
  choice — the library imposes no page beyond "somewhere to send the
  user" [measured].
- `op.WithAllowInsecure()` permits an http loopback issuer for rigs;
  public clients with `oidc.AuthMethodNone` + PKCE S256 are first-class
  [measured].
- **The example's login has no CSRF defense at all** — no token, no
  Origin check; its POST flips the auth request directly [measured].
  The fold's CSRF posture must be its own (Bar 3 is not redundant).

## 2026-08-02 — Hypotheses (registered before any rig runs)

- **H1 — page inventory for M1: login and error, nothing else.** Every
  other surface is a protocol endpoint (JSON or redirect), owned by the
  library.
- **H2 — no in-memory flow state.** The auth request and the browser
  session are KV records in the `sessions` bucket (store design D6);
  a restart between any two HTTP steps of the flow is invisible to the
  browser.
- **H3 — CSRF: synchronizer token bound to the auth-request record,
  plus Origin verification when the header is present.** SameSite
  cookies cannot protect the pre-auth login POST — there is no cookie
  yet [mechanism-argument]; the token lives in the KV record the form
  already names, so no extra store appears.
- **H4 — WebAuthn's server-side checks are origin ∈ RPOrigins and
  rpIdHash == sha256(RPID);** the registrable-suffix rule is the
  browser's half [mechanism-argument, to be split measured/argued by
  the rig]. Renaming the public host therefore invalidates enrolled
  passkeys — the expected naming one-way door.

Rig order: rig5 (bars 1–3, one flow rig: CSRF probes → legit login →
restart mid-flow → completion, page inventory counted over the whole
run), then rig6 (bar 4, the origin/RP-ID matrix at library level).

## 2026-08-02 — Rig 5: bars 1–3 pass, 15/15 [measured]

A complete mini-OP in the scratchpad: `zitadel/oidc` v3.48.1 with every
piece of state in JetStream KV (auth requests, code index, access
tokens, browser sessions, users, clients, RS256 signing key), the human
surface exactly two server-rendered templates (login, error), driven by
a cookie-jar browser-stand-in with no JS engine and a stock
`go-oidc`/`oauth2` RP.

- **Bar 1 — PASS.** The RP completed authorization-code + PKCE and
  verified the ID token (sub, nonce) against the published JWKS. Page
  inventory over the whole run, measured by middleware on every
  non-redirect `text/html` response: `GET /login/` ×1, `POST /login/`
  ×3 (the CSRF error renders) — nothing undeclared. H1 confirmed:
  login + error is the entire M1 page inventory.
- **Bar 2 — PASS.** Full process restart (HTTP server + embedded NATS,
  same store, same issuer) injected between the login POST and the
  code/token exchange: the browser continued without re-authenticating,
  the code was issued from the KV auth-request record, the exchange
  succeeded against endpoints the RP had cached *before* the restart,
  and the ID token verified because the signing key lives in KV. The
  browser-session record (named by the cookie) was intact afterward.
  H2 confirmed: no in-memory flow state anywhere.
- **Bar 3 — PASS.** Missing token, mismatched token, and valid-token-
  but-cross-site-Origin all rejected 403 with zero state change
  (auth-request record unchanged, no cookie set); the legitimate
  submission accepted. Mechanism chosen: synchronizer token minted into
  the auth-request KV record on form render (one-shot, cleared on use)
  plus Origin-header equality when present — the token is the
  guarantee, the Origin check is the cheap outer wall
  [mechanism-argument]; SameSite cannot protect the pre-auth POST.

Design facts the rig surfaced (for the doc at graduation):

- The auth-request record needs four fields beyond the store design's
  session shape: `csrf` (one-shot), `done`, `subject`, and the code is
  indexed by **digest** (`code.<sha256/16B-hex>`), never verbatim — an
  authorization code is a bearer secret and must not appear as a KV key
  [mechanism-argument].
- The browser session is its own small record (`bs_<id>`: subject,
  created, expires); the cookie carries only the record's name.
- `op.AuthCallbackURL(provider)` and per-client `LoginURL` are the
  entire integration seam between the protocol library and the UI —
  the UI plugs in without touching protocol code [measured].
- Open M1 design point: the rig issued opaque Bearer access tokens;
  the M1 gate reads "issued tokens verify against the published JWKS",
  which the ID token satisfies — whether access tokens become JWTs is
  a design-doc decision, not settled here [judgment].

## 2026-08-02 — Rig 6: bar 4 passes, 10/10 [measured]

`go-webauthn` v0.17.4 server-side, `virtualwebauthn` v1.0.5 as the
browser+authenticator stand-in; every cell a real register-then-login
ceremony pair.

| Cell | Server config | Client origin | Result |
|---|---|---|---|
| L1 | RPID `auth.example.com`, origins `[https://auth.example.com]` | `https://auth.example.com` | ACCEPT |
| L2 | same | `https://auth.example.com:8443` | REJECT |
| L3 | same | `http://auth.example.com` | REJECT |
| L4 | same | `https://sub.auth.example.com` | REJECT |
| L5 | same | `https://evil.example` | REJECT |
| R1 (registration) | same | `https://evil.example` | REJECT |
| P1 | RPID `example.com`, origins `[https://auth.example.com]` | `https://auth.example.com` | ACCEPT |
| P2 | RPID `example.com`, origins `[https://unrelated.example]` | `https://unrelated.example` | ACCEPT |
| N1 | renamed: RPID `login.example.com` | `https://login.example.com`, credential scoped to `auth.example.com` | REJECT |

The naming rules that follow:

1. The server enforces exactly two things: the client origin must be in
   `RPOrigins` (exact scheme+host+port canonical match) and the
   assertion's `rpIdHash` must equal sha256(RPID) [measured].
2. The origin↔RP-ID registrable-suffix relation is **not** checked
   server-side (P2) — it is the browser's half of the contract
   [measured]; correct `RPOrigins` configuration is therefore
   load-bearing, not hygiene.
3. A parent-domain RP ID is a legitimate layout for multi-subdomain
   deployments (P1) — but widens where the passkey may be asserted, so
   the default is the exact public host [judgment].
4. **Renaming the public host invalidates every enrolled passkey**
   (N1: rpIdHash mismatch at library level; a real browser would not
   even offer the credential [mechanism-argument]). Deployment naming
   is a one-way door that closes at first enrollment, not at install.

All four bars passed, none amended; the reversal condition (a flow
structurally demanding a client-side app or non-KV session store) was
never approached — the whole flow ran with zero JavaScript.
