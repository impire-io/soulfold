# Implementation Plan: passkeys

**Input**: [spec.md](spec.md); designs D9/D13/D14 (session-and-ui),
D2/D6 (store, additive evolution).

## Structure

```
internal/passkeys/            the ceremony service on go-webauthn:
                              Begin (register when zero credentials,
                              login otherwise), Finish (single-use
                              ceremony record, CAS credential append /
                              sign-count update)
internal/passkeys/authtest/   the virtual authenticator for the gate:
                              real ES256 ceremonies in-process
internal/store/               User grows credentials[] (additive, D2);
                              Ceremony record (wa_*) carries the
                              library SessionData between Begin/Finish
internal/ui/                  the login page's ceremony driver
                              (page-local JS — D9's stated exception),
                              POST /login/begin + /login/finish behind
                              the shared D13 guard; the username-form
                              POST is gone
```

## Load-bearing choices

- **First-touch enrollment** stands in for M3's bootstrap research: a
  user with zero credentials registers on first authentication. Loud
  in the docs; replaced by M3, not silently kept.
- **RP config from the issuer only** (D14): RPID = hostname, origins =
  exactly one. No knobs until a deployment shape demands one — the
  quickstart carries the one-way-door warning.
- **The D13 token spans both ceremony POSTs**: compared on begin
  (which creates only scratch state), compared and *cleared* on finish
  in the same CAS write that marks the auth request done. Origin is
  checked before anything is read on both.
- **The ceremony record is consumed by Delete before validation** —
  whoever deletes first wins; a replay meets "already used" regardless
  of the validation outcome.
- **User verification required** on both ceremonies (passkeys, not
  mere presence).

## Gate mapping

| Spec | Where proven |
|---|---|
| SC-001 register-then-login, single-use, sign count | `internal/passkeys/passkeys_test.go` |
| SC-002 e2e flow, forged POSTs, restart, stub retired | `internal/serve/serve_test.go` |
| SC-003 origin matrix | `internal/passkeys/passkeys_test.go` |
| SC-004 no-secret scan + positive control | `internal/passkeys/passkeys_test.go` |
| SC-005 real-authenticator runbook | `quickstart.md` (human act) |
