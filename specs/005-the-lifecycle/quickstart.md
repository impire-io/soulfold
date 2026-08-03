# Quickstart: the lifecycle by hand

The measured gate rides `make test`; this is the human-shaped walk.

## Bootstrap (the four acts)

```sh
# 1. Found and serve.
./bin/soulfold serve --issuer http://localhost:8378 --state-dir ~/.soulfold

# 2. Seed the first admin (stop serve first, or use --nats-url for both).
./bin/soulfold seed user --state-dir ~/.soulfold --username root --roles admin

# 3. Mint the bootstrap invite — printed ONCE; the store keeps a digest.
./bin/soulfold invite --state-dir ~/.soulfold --username root

# 4. Browser: open  <issuer>/login/?invite=sfi_…  behind any RP's
#    authorize redirect — one passkey ceremony enrolls AND signs in.
```

## Day-to-day (the admin API, with your own bearer)

```sh
TOK=<your access token — sign in via any client; roles must carry "admin">

# A new colleague, in a group whose name their tokens will carry:
curl -sX POST -H "Authorization: Bearer $TOK" http://localhost:8378/admin/users \
  -d '{"username":"erin","display_name":"Erin","groups":["engineering"]}'

# Their invite (the one response that ever shows a bearer — hand it
# out-of-band, it is single-use and expires in 24h):
curl -sX POST -H "Authorization: Bearer $TOK" http://localhost:8378/admin/invites \
  -d '{"username":"erin"}'

# Move them between groups — the change rides their NEXT token:
curl -sX POST -H "Authorization: Bearer $TOK" http://localhost:8378/admin/users/erin/groups \
  -d '{"groups":["platform"]}'

# Clients (deliberate registration; hosted MCP clients use DCR instead):
curl -sX POST -H "Authorization: Bearer $TOK" http://localhost:8378/admin/clients \
  -d '{"client_id":"wiki","name":"Wiki","redirect_uris":["https://wiki.example/cb"]}'
```

Lost passkey / new device: mint a fresh invite for the same username —
the ceremony adds a credential. There is no reset lane.

In the bundled soulnode shape, the founding invite for the owner is
printed by the founding run itself — acts 1–3 collapse into
`soulnode init && soulnode up`.
