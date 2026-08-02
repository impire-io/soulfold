# Soulfold Vision

*Founded 2026-08-02 from a refusal that held: soulidentity's default-IdP
question (its journey 0019) tested the identity plane's "we never become
an identity provider" article, and the answer was this sibling project —
the fold is where identity truth lives, and it is deliberately not the
identity plane.*

## What Soulfold is

Soulfold is **the fold of the Soulstream ecosystem**: the deployment's
answer to *who exists and who belongs* — a self-hosted, passkey-first
OpenID Connect provider that ships as the ecosystem's **default IAM**,
standing exactly where Entra, Auth0, or any other OIDC provider may
stand instead. A deployment that already has an IdP never runs Soulfold;
a deployment that has none gets a sign-in story out of the box: a human
opens a browser, touches a passkey, and arrives in the realm as a NATS
principal — admitted by soulidentity's auth callout, which validates the
fold's tokens exactly as it validates anyone else's.

Its front door is HTTP, named honestly: WebAuthn ceremonies are bound to
browser origins and OIDC is discovery plus redirects — there is no
NATS-native passkey ceremony, and we do not invent a bespoke sign-in
wire protocol. What makes Soulfold NATS-native is everything behind the
door: **JetStream KV is the store** — users, credentials, groups,
clients, sessions — so a deployment that already runs NATS runs Soulfold
with no second database, and the assembly is **embeddable in a parent Go
binary** the way the rest of the ecosystem is (soulidentity's embed
seam, its D29).

Authentication is **passkeys, not passwords**. The fold never holds a
secret that can impersonate a user: WebAuthn credential records carry
public keys, the private halves live in the users' authenticators, and
recovery is re-enrollment through a deliberate act — never a knowledge
factor, never an email loop the deployment didn't ask for.

## The founding bet

A working Soulfold is exactly:

1. **An OP core speaking standard OIDC** — discovery, JWKS,
   authorization code with PKCE — built on a certified library, its
   signing keys rotating without consumer restarts.
2. **Passkey ceremonies** — WebAuthn registration and login, and no
   other user authentication lane.
3. **The fold's records on JetStream KV** — users, their credentials
   (public halves only), groups whose names surface as the token's
   roles-claim values, OAuth clients, sessions.
4. **A lifecycle surface** — invite, enroll, group membership, client
   registration; small enough to audit, honest enough to bootstrap
   (the first admin's first passkey is a named story, not an accident).

Nothing else. No password lane, no LDAP bridge, no email dependency in
the core loop, no permission engine. If a future addition doesn't
survive this list staying this short, it isn't the fold's to add.

## Who it is for

Soulstream deployments that have no external IdP — the team on plain
NATS that still needs humans to sign in. The fold is the default, not a
dependency: the distribution points soulidentity's `--oidc-issuer` at it
out of the box, and replacing it with Entra, Auth0, pocket-id, or
anything else that speaks OIDC is a configuration change, never a
migration through us.

## Where it is pointed

The sequencing lives in
[`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md);
design documents arrive by research graduation into
[`../02-DESIGN/`](../02-DESIGN/README.md). The arc: the OP skeleton
proven by a stock OIDC client, then the passkey ceremonies, then the
lifecycle surface, then the consumer-position proof against
soulidentity's callout seam, then the embed seam for the single-binary
distribution.

## What we refuse to become

- **A password store.** Passkeys only. The day a password column seems
  convenient is the day the fold has lost its reason to exist beside
  the providers that already have one.
- **A privileged peer of soulidentity.** The callout issuer must never
  be able to tell the fold from Entra: consumers reach us only through
  the spec surfaces — discovery, JWKS, the token endpoint — and no
  claim, header, or side-channel exists that only a Soulstream
  component understands. The moment we are special-cased, the
  ecosystem has two identity planes.
- **A parallel permission system.** Group names surface as roles-claim
  values that *name* declared roles on the other side; they carry no
  permissions. What a principal may do inside NATS is the NATS
  server's to enforce, on soulidentity's minted scopes — never ours.
- **A protocol fork.** Standard OIDC or nothing. A consumer need the
  spec doesn't cover is a conversation with the consumer, not a
  proprietary claim.
- **A general-purpose IdP product.** The fold serves Soulstream
  deployments; features that only make sense outside that frame
  (multi-tenancy, federation brokering, SAML) go nowhere.

## How ambition stays honest

The discipline is inherited whole from the ecosystem: load-bearing
decisions carry numbered entries with reasoning and reversal
conditions, claims carry evidence classes, and only `[measured]` closes
a debate. The full rules live in [`constitution.md`](constitution.md)
and [`how-we-work.md`](how-we-work.md); the founding decision and its
reversal conditions are recorded in
[`../04-JOURNEY/0001-genesis-the-fold.md`](../04-JOURNEY/0001-genesis-the-fold.md).
