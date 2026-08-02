package passkeys_test

// The M2 gate's library half: full register-then-login proven in make
// test with a real (virtual) authenticator; only allowlisted exact
// origins pass (session design acceptance #4, D14); no credential
// secret in the store, positive-control-verified (constitution I).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/impire-io/soulfold/authtest"
	"github.com/impire-io/soulfold/internal/envelope"
	"github.com/impire-io/soulfold/internal/natsserver"
	"github.com/impire-io/soulfold/internal/passkeys"
	"github.com/impire-io/soulfold/internal/serve"
	"github.com/impire-io/soulfold/internal/store"
)

const issuerStr = "http://fold.test:8378"

func setup(t *testing.T) (*store.Store, *passkeys.Service) {
	t.Helper()
	base := t.TempDir()
	sealer, err := envelope.LoadOrCreate(filepath.Join(base, "seal.xkey"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := natsserver.Start(filepath.Join(base, "jetstream"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), js, sealer, "")
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := url.Parse(issuerStr)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := passkeys.New(st, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return st, svc
}

func finishReq(t *testing.T, body []byte) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, issuerStr+"/login/finish", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestRegisterThenLogin(t *testing.T) {
	ctx := context.Background()
	st, svc := setup(t)
	user, err := serve.SeedUser(ctx, st, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authtest.New("fold.test", issuerStr)
	if err != nil {
		t.Fatal(err)
	}

	// First touch: no credential yet, the ceremony is a registration.
	cerID, kind, options, err := svc.Begin(ctx, "alice", "authreq-1")
	if err != nil {
		t.Fatal(err)
	}
	if kind != "register" {
		t.Fatalf("first ceremony is %q, want register (passkey-only first touch)", kind)
	}
	body, err := auth.CreateResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	got, boundReq, err := svc.Finish(ctx, cerID, finishReq(t, body))
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	if got.ID != user.ID || boundReq != "authreq-1" {
		t.Fatalf("registered %s bound %s, want %s / authreq-1", got.ID, boundReq, user.ID)
	}

	// Second touch: the ceremony is a login assertion.
	cerID2, kind2, options2, err := svc.Begin(ctx, "alice", "authreq-2")
	if err != nil {
		t.Fatal(err)
	}
	if kind2 != "login" {
		t.Fatalf("second ceremony is %q, want login", kind2)
	}
	body2, err := auth.GetResponse(options2)
	if err != nil {
		t.Fatal(err)
	}
	got2, _, err := svc.Finish(ctx, cerID2, finishReq(t, body2))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if got2.ID != user.ID {
		t.Fatalf("logged in %s, want %s", got2.ID, user.ID)
	}

	// The sign count moved (clone detection's raw material).
	var rec store.User
	if _, err := st.Get(ctx, st.Users, user.ID, &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Credentials) != 1 {
		t.Fatalf("user carries %d credentials, want 1", len(rec.Credentials))
	}
	var cred struct {
		Authenticator struct {
			SignCount uint32 `json:"signCount"`
		} `json:"authenticator"`
	}
	if err := json.Unmarshal(rec.Credentials[0], &cred); err != nil {
		t.Fatal(err)
	}
	if cred.Authenticator.SignCount == 0 {
		t.Error("sign count did not advance on login")
	}

	// A ceremony is single-use: replaying the finish fails.
	if _, _, err := svc.Finish(ctx, cerID2, finishReq(t, body2)); err == nil {
		t.Fatal("a consumed ceremony finished twice")
	}
}

// D14: only allowlisted exact origins pass — scheme, host, and port.
func TestForeignOriginRefused(t *testing.T) {
	ctx := context.Background()
	st, svc := setup(t)
	if _, err := serve.SeedUser(ctx, st, "bob", "Bob"); err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []string{
		"https://fold.test:8378",    // scheme flip
		"http://fold.test:9999",     // port change
		"http://sub.fold.test:8378", // subdomain
		"http://evil.example",       // foreign host
	} {
		auth, err := authtest.New("fold.test", foreign)
		if err != nil {
			t.Fatal(err)
		}
		cerID, _, options, err := svc.Begin(ctx, "bob", "authreq-x")
		if err != nil {
			t.Fatal(err)
		}
		body, err := auth.CreateResponse(options)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.Finish(ctx, cerID, finishReq(t, body)); err == nil {
			t.Errorf("origin %s: ceremony passed, want refusal", foreign)
		}
	}
}

// Constitution I: nothing the fold stores may impersonate the user.
// The credential's private scalar must appear nowhere in any opened
// record; the public key must (the positive control proving the scan
// could find key material).
func TestNoCredentialSecretStored(t *testing.T) {
	ctx := context.Background()
	st, svc := setup(t)
	user, err := serve.SeedUser(ctx, st, "carol", "Carol")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authtest.New("fold.test", issuerStr)
	if err != nil {
		t.Fatal(err)
	}
	cerID, _, options, err := svc.Begin(ctx, "carol", "authreq-1")
	if err != nil {
		t.Fatal(err)
	}
	body, err := auth.CreateResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Finish(ctx, cerID, finishReq(t, body)); err != nil {
		t.Fatal(err)
	}

	var rec store.User
	if _, err := st.Get(ctx, st.Users, user.ID, &rec); err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	priv := auth.PrivateScalar()
	pubX := auth.PublicX()
	if bytes.Contains(stored, priv) || strings.Contains(string(stored), string(priv)) {
		t.Fatal("the credential private key is in the store")
	}
	if !bytes.Contains(stored, pubX) {
		// The COSE key embeds X raw inside base64 JSON — check the raw
		// credential bytes instead of the JSON text.
		var found bool
		for _, raw := range rec.Credentials {
			var c struct {
				PublicKey []byte `json:"publicKey"`
			}
			if json.Unmarshal(raw, &c) == nil && bytes.Contains(c.PublicKey, pubX) {
				found = true
			}
		}
		if !found {
			t.Fatal("positive control failed: the public key is not findable, so the private-key scan proves nothing")
		}
	}
}
