package keys_test

// The store design's acceptance #4, inherited by the M1 gate: a stock,
// never-restarted OIDC verifier sees zero verification failures across
// a full key rotation; the straggler token verifies until its expiry;
// the retired key leaves the published JWKS.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/impire-io/soulfold/internal/envelope"
	"github.com/impire-io/soulfold/internal/keys"
	"github.com/impire-io/soulfold/internal/natsserver"
	"github.com/impire-io/soulfold/internal/store"
)

func TestRotationUnderLiveVerifier(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	sealer, err := envelope.LoadOrCreate(filepath.Join(base, "seal.xkey"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := natsserver.Start(filepath.Join(base, "jetstream"))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, js, sealer, "")
	if err != nil {
		t.Fatal(err)
	}
	svc := &keys.Service{St: st}
	if err := svc.EnsureFirstKey(ctx); err != nil {
		t.Fatal(err)
	}

	// JWKS endpoint straight off the lifecycle's published set.
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		published, err := svc.Published(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: published}); err != nil {
			t.Error(err)
		}
	}))
	defer jwksSrv.Close()

	// The stock verifier — created once, never restarted.
	keySet := gooidc.NewRemoteKeySet(ctx, jwksSrv.URL)

	const maxTokenLifetime = 3 * time.Second
	sign := func() (string, string) {
		t.Helper()
		kid, key, err := svc.ActiveSigner(ctx)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
			(&jose.SignerOptions{}).WithHeader("kid", kid))
		if err != nil {
			t.Fatal(err)
		}
		claims, _ := json.Marshal(map[string]any{
			"iss": "https://fold.test", "sub": "u_1", "aud": "c_1",
			"exp": time.Now().Add(maxTokenLifetime).Unix(), "iat": time.Now().Unix(),
		})
		obj, err := signer.Sign(claims)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := obj.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw, kid
	}
	verify := func(raw string) error {
		_, err := keySet.VerifySignature(ctx, raw)
		return err
	}

	failures, verifications := 0, 0
	check := func(raw string) {
		t.Helper()
		verifications++
		if err := verify(raw); err != nil {
			failures++
			t.Errorf("verification failed mid-rotation: %v", err)
		}
	}

	// Key A signs; the verifier learns it.
	straggler, kidA := sign()
	for i := 0; i < 20; i++ {
		check(straggler)
	}

	// Rotation: B pending (published, not signing — I1), then active.
	kidB, err := svc.CreatePending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check(straggler)
	if err := svc.Activate(ctx, kidB, maxTokenLifetime); err != nil {
		t.Fatal(err)
	}

	// New tokens come from B; the straggler still verifies (A retiring,
	// still published — I2).
	fromB, signingKid := sign()
	if signingKid != kidB {
		t.Fatalf("active signer is %s, want %s", signingKid, kidB)
	}
	for i := 0; i < 20; i++ {
		check(fromB)
		check(straggler)
	}

	// I2: retirement refuses until the straggler's expiry has passed.
	if retired, err := svc.RetireExpired(ctx); err != nil || len(retired) != 0 {
		t.Fatalf("retired %v before last_signed_expiry (err %v) — I2 broken", retired, err)
	}
	time.Sleep(maxTokenLifetime + 500*time.Millisecond)
	retired, err := svc.RetireExpired(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 || retired[0] != kidA {
		t.Fatalf("retired %v, want exactly [%s]", retired, kidA)
	}

	// The retired key leaves the published set: a fresh keyset (the
	// control) no longer verifies the straggler; B's tokens still do.
	freshSet := gooidc.NewRemoteKeySet(ctx, jwksSrv.URL)
	if _, err := freshSet.VerifySignature(ctx, straggler); err == nil {
		t.Error("retired key still verifiable from published JWKS")
	} else if !strings.Contains(err.Error(), "key") {
		t.Logf("straggler refused as expected: %v", err)
	}
	lastB, _ := sign()
	if _, err := freshSet.VerifySignature(ctx, lastB); err != nil {
		t.Errorf("fresh keyset cannot verify the active key: %v", err)
	}

	if failures != 0 {
		t.Fatalf("%d verification failures in %d verifications", failures, verifications)
	}
	t.Logf("rotation %s→%s: %d verifications, 0 failures; straggler refused only after retirement", kidA, kidB, verifications)
}
