# Soulfold

The fold of the Soulstream ecosystem: *who exists, who belongs* — a
self-hosted, passkey-first OpenID Connect provider that ships as the
ecosystem's default IAM, standing exactly where Entra, Auth0, or any
other OIDC provider may stand instead.

- **Passkeys, not passwords** — WebAuthn is the only user
  authentication lane; nothing the fold stores can impersonate a user.
- **Standard OIDC or nothing** — consumers (soulidentity's auth callout
  first among them) reach the fold only through discovery, JWKS, and
  the token endpoint; it is indistinguishable from any external
  provider by design.
- **NATS-native behind the door** — JetStream KV is the store, so a
  deployment already running NATS runs the fold with no second
  database; the front door is HTTP(S), because WebAuthn and OIDC live
  in the browser.
- **Embeddable** — the serve assembly is public, following the
  ecosystem's embed pattern, for the single-binary distribution.

**Status: genesis.** No product code yet — the roadmap starts at the OP
skeleton behind its research gates.

How this project is run lives in [`../soul-hq/`](../soul-hq/README.md) — read
[`AGENTS.md`](AGENTS.md) first. Where things stand:
[`../soul-hq/04-JOURNEY/README.md`](../soul-hq/04-JOURNEY/README.md). The plan:
[`../soul-hq/03-IMPLEMENTATION/ROADMAP.md`](../soul-hq/03-IMPLEMENTATION/ROADMAP.md).
Why the fold exists as a sibling of
[soulidentity](https://github.com/impire-io/soulidentity) rather than
inside it: [`../soul-hq/04-JOURNEY/0041-soulfold-genesis-the-fold.md`](../soul-hq/04-JOURNEY/0041-soulfold-genesis-the-fold.md).

Module `github.com/impire-io/soulfold`, Go 1.26.
[Fair-code](https://faircode.io) licensed under the
[Sustainable Use License](LICENSE) — free to self-host and modify; offering it
to others as a paid product or service requires an agreement — see
[impire.io/license](https://impire.io/license/). Versions released before this
change remain MIT.
