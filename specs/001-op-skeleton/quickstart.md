# Quickstart: running the M1 fold by hand

The measured gate rides `make test`; this is the human-shaped version.

```sh
# 1. Build.
make build

# 2. Found the fold (first start births the seal seed and signing key).
./bin/soulfold serve --issuer http://127.0.0.1:8378 --state-dir ~/.soulfold &

# 3. Seed the M1 stand-ins (M3 replaces seeding with the lifecycle).
./bin/soulfold seed user   --state-dir ~/.soulfold --username alice \
  --nats-url <printed or external>   # embedded store: stop serve first, seed, restart —
                                     # or point both at one external NATS (--nats-url)
./bin/soulfold seed client --state-dir ~/.soulfold --client-id demo \
  --redirect-uri http://127.0.0.1:9009/cb

# 4. Point any OIDC RP at http://127.0.0.1:8378 (client id `demo`,
#    authorization-code + PKCE, scope openid). Sign in as `alice`.
curl -s http://127.0.0.1:8378/.well-known/openid-configuration | head
```

Notes:

- **The issuer host is a one-way door** once M2 passkeys enroll (D14):
  renaming it invalidates every enrolled credential. Choose the public
  name before real users arrive.
- The seal seed lives at `<state-dir>/seal.xkey`, mode 0600, outside
  the JetStream store dir (`<state-dir>/jetstream/`). Back it up
  separately from the store; losing it is total data loss (D17).
- With the embedded server, only one process can hold the store at a
  time — stop `serve` before running `seed`, or run one external
  JetStream server and give every command `--nats-url`.
