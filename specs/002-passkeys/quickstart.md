# Quickstart: the passkey ceremonies — and the real-authenticator runbook

The measured half of the M2 gate rides `make test` (virtual
authenticator, real ceremonies). This runbook is the human half: a
physical authenticator (Touch ID, security key, phone) against a
running fold. Run it once per deployment shape you care about and
record the date.

## The runbook

```sh
# 1. Serve. WebAuthn is origin-bound: for anything beyond localhost
#    you need HTTPS and the FINAL public name — the RP ID becomes a
#    one-way door at the FIRST enrollment (D14). Renaming the host
#    afterward invalidates every enrolled passkey.
make build
./bin/soulfold serve --issuer http://localhost:8378 --listen 127.0.0.1:8378 \
  --state-dir /tmp/fold-runbook
# (localhost is a WebAuthn "secure context" without TLS — good for the
#  runbook, not for a deployment.)

# 2. Seed a user and a client (separate store: stop serve first, or use
#    an external NATS for both commands — see spec 001 quickstart).
./bin/soulfold seed user   --state-dir /tmp/fold-runbook --username you
./bin/soulfold seed client --state-dir /tmp/fold-runbook --client-id demo \
  --redirect-uri http://127.0.0.1:9009/cb

# 3. Point any OIDC RP at http://localhost:8378 (client `demo`,
#    code+PKCE, scope openid) — or hand-build the authorize URL and
#    watch the redirects.
```

Then, in the browser:

1. The RP redirects you to the fold's login page. Enter `you`.
2. **First touch**: the browser prompts to CREATE a passkey (Touch
   ID / key). This is the enrollment — the account's first
   authentication binds the passkey. Verify the prompt names the
   issuer host.
3. Complete the RP flow; verify the RP received tokens.
4. Sign in AGAIN (fresh private window to skip the browser session):
   the prompt is now an ASSERTION (use existing passkey), not a
   creation.
5. Negative check: serve the same store under a different host name
   and confirm the browser refuses to offer the passkey (rpIdHash
   mismatch — the one-way door demonstrated).

Record: date, browser, authenticator, pass/fail per step.

## Status

- 2026-08-02 — virtual-authenticator ceremonies measured in
  `make test` (register-then-login, origin matrix, no-secret scan).
  **Physical-authenticator run: pending — Daan, this is your morning
  runbook.**

## Interim honesty

First-touch enrollment (step 2) is trust-on-first-authentication — the
M2 stand-in until M3's researched bootstrap story (invites, custody,
the first admin's first passkey). Do not put a fold with first-touch
enrollment on a hostile network and call it enrolled-safely.
