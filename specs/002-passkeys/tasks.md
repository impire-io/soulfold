# Tasks: passkeys

All complete; the gate rides `make test`.

- [x] T001 — Store: `User.Credentials` (additive), `Ceremony` record +
      `wa_` keys.
- [x] T002 — `internal/passkeys`: Begin/Finish on go-webauthn; RP
      config from the issuer per D14; first-touch registration;
      single-use ceremonies; CAS persistence.
- [x] T003 — `internal/passkeys/authtest`: the virtual authenticator
      (ES256, CBOR attestation "none", honest signatures/counters).
- [x] T004 — UI: ceremony driver page (page-local JS), begin/finish
      endpoints behind the D13 guard; username-form login removed —
      passkey-only enforced.
- [x] T005 — Serve wiring + e2e updated to the ceremony flow.
- [x] T006 — Gate tests green in `make check` (0 lint issues).
- [x] T007 — Real-authenticator runbook documented (quickstart.md).
