# Episode 0003 — Two pages, zero scripts, and a name that becomes a door (2026-08-02)

The second of M1's gating research topics asked how little human-facing
surface the fold's flows actually need — and what WebAuthn's origin
rules fix about deployment naming before anyone enrolls a passkey.
Desk research read the certified libraries' own sources first: the OP
delegates the human surface entirely through two URLs (the client
record's `LoginURL` out, `op.AuthCallbackURL` back), and the library's
own example login ships with no CSRF defense at all — so the fold's
posture had to be designed, not inherited [measured].

All four pre-registered bars passed, none amended:

- **The surface (15/15 rig checks):** a mini-OP with every piece of
  state in JetStream KV served exactly two server-rendered templates;
  a cookie-jar browser-stand-in with **no JS engine** and a stock
  `go-oidc` RP completed authorization-code + PKCE, the ID token
  verifying (sub, nonce) against published JWKS. Middleware measured
  the page inventory over the whole run: `GET /login/` ×1,
  `POST /login/` ×3 error renders — nothing undeclared [measured].
- **Restart mid-flow:** the whole process (HTTP + embedded NATS) was
  killed and restarted between the login POST and the token exchange;
  the browser continued without re-authenticating and the RP exchanged
  the code against endpoints cached *before* the restart. No in-memory
  flow state exists [measured].
- **CSRF:** missing token, mismatched token, and
  valid-token-with-cross-site-Origin each rejected with zero state
  change; the mechanism is a one-shot synchronizer token minted into
  the auth-request KV record plus Origin equality — SameSite cannot
  cover the pre-auth POST [mechanism-argument, behavior measured].
- **The origin/RP-ID matrix (10/10 ceremony pairs):** the server
  enforces exactly origin ∈ allowlist and rpIdHash == sha256(RP ID);
  the registrable-suffix rule is the browser's half (measured by the
  unrelated-but-allowlisted cell passing), so `RPOrigins` config is
  load-bearing. A parent-domain RP ID is a legitimate wider layout.
  **A renamed host rejects the enrolled passkey** — deployment naming
  is a one-way door that closes at first enrollment, not at install
  [measured].

Nothing was refuted; two findings sharpened the store design rather
than changing it: authorization codes are indexed by digest (a bearer
secret must never be a KV key), and the session record gained its
`csrf`/`done` fields — both propagated into
[store-and-key-lifecycle](../02-DESIGN/store-and-key-lifecycle.md) D6.
One decision was argued rather than measured: M1 issues JWT access
tokens (D15), because M4's seam verifies access tokens against JWKS
and Entra's are JWTs [mechanism-argument].

What it opened: the second design doc,
[session-and-ui](../02-DESIGN/session-and-ui.md) (D9–D15). M1's two
named research topics are now both concluded; the store-envelope
question opened by the operator (KV entry protection at rest, xkeys)
is pre-registered as its own topic before the M1 build starts.

Reversal condition: a certified-library flow structurally demanding a
client-side application or a non-KV session store — observable as an
endpoint shape, content type, or ceremony step in the pinned libraries
that server-rendered pages plus page-local script cannot satisfy —
reopens the minimal-surface direction. The naming rules reverse only
with WebAuthn spec/browser behavior changes (observable: a browser
shipping assertions across renamed RP IDs).

Trail: [session-and-ui](../02-DESIGN/session-and-ui.md);
[store-and-key-lifecycle](../02-DESIGN/store-and-key-lifecycle.md)
(D6 propagation); topic pre-registration, journey, and verdict in git
history at `hq/01-RESEARCH/session-and-ui-shape/` (opened c330ee3,
results d7f27bb, verdict 1eb535d; folder removed by this graduation);
rigs in the session scratchpad (`kvrig/rig5-surface`,
`kvrig/rig6-webauthn`), stack pinned in the verdict.
