package e2e_test

// The M4 gate (roadmap: the fold in the fleet): a soulfold-issued
// access token admits a browser user through soulidentity's auth
// callout — its D23 seam: issuer URL, JWKS, the D24 roles-claim rule —
// with the token's role value naming a declared role, and zero
// soulfold-aware behavior on either side (soulidentity is imported at
// its published tag; the identity plane is configured with nothing but
// an issuer URL and an audience). The same gate runs with the fold
// swapped for an Entra-shaped stub: indistinguishability demonstrated,
// not asserted.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/impire-io/soulidentity/client"
	"github.com/impire-io/soulidentity/embed"
)

func TestM4FoldTokenAdmitsThroughCallout(t *testing.T) {
	runAdmissionGate(t, func(t *testing.T) issuerArm {
		return newFoldArm(t, "engineering", "marketing")
	})
}

func TestM4StubIssuerIndistinguishable(t *testing.T) {
	runAdmissionGate(t, func(t *testing.T) issuerArm {
		return newStubArm(t)
	})
}

func runAdmissionGate(t *testing.T, newArm func(t *testing.T) issuerArm) {
	t.Helper()
	c := provision(t)
	arm := newArm(t)

	// The identity plane through its public embed seam, the OIDC lane
	// configured with exactly what any deployment gives it: an issuer
	// URL and an audience. Nothing here knows what stands behind them.
	audit := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- embed.Run(ctx, embed.Options{
			Conn:         c.ncService,
			CalloutConn:  c.ncCallout,
			FirstKey:     c.firstSeed,
			SurfaceKey:   c.surfaceSeed,
			CalloutKey:   c.calloutSeed,
			AuthAccount:  c.authPub,
			CalloutTTL:   2 * time.Minute,
			OIDCIssuer:   arm.IssuerURL(),
			OIDCAudience: arm.Audience(),
			Logger:       newAuditLogger(audit),
		})
	}()

	ops := client.New(c.ncOps, c.appPub, "ops")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := ops.Status(); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("identity plane never served: %v (audit: %s)", err, audit.String())
		}
		select {
		case err := <-runErr:
			t.Fatalf("embed.Run returned during startup: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}

	// Provisioning through the public client only: the declared role
	// (ENG's scoped signing key under the name the tokens will speak),
	// the AUTH issuer key, the sentinel. Zero per-person acts.
	if _, err := ops.ImportKey("engineering", client.KindNATSAccountSigningKey, c.engSKSeed, c.engPub, ""); err != nil {
		t.Fatalf("import engineering role: %v", err)
	}
	if _, err := ops.ImportKey("auth/issuer", client.KindNATSAccountSigningKey, c.authSKSeed, c.authPub, ""); err != nil {
		t.Fatalf("import auth key: %v", err)
	}
	sentinel, err := ops.MintSentinel()
	if err != nil {
		t.Fatalf("mint sentinel: %v", err)
	}
	sentinelPath := filepath.Join(t.TempDir(), "sentinel.creds")
	if err := os.WriteFile(sentinelPath, []byte(sentinel.Creds), 0o600); err != nil {
		t.Fatal(err)
	}

	// --- The admission: sentinel + the issuer's access token.
	token := arm.TokenForRole(t, "engineering")
	violations := make(chan error, 8)
	nc, err := nats.Connect(c.url,
		nats.UserCredentials(sentinelPath), nats.Token(token),
		nats.RetryOnFailedConnect(false), nats.MaxReconnects(0),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			violations <- err
		}))
	if err != nil {
		t.Fatalf("admission refused: %v\naudit:\n%s", err, audit.String())
	}
	defer nc.Close()

	// Server-enforced scope: the declared role's template, nothing more.
	sub, err := nc.SubscribeSync("demo.ping")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := nc.Publish("demo.ping", []byte("pong")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := sub.NextMsg(5 * time.Second); err != nil {
		t.Fatalf("in-scope round-trip: %v", err)
	}
	if err := nc.Publish("forbidden.subject", []byte("x")); err != nil {
		t.Fatalf("out-of-scope publish: %v", err)
	}
	_ = nc.Flush()
	select {
	case verr := <-violations:
		if !strings.Contains(strings.ToLower(verr.Error()), "permissions violation") {
			t.Fatalf("expected a permissions violation, got %v", verr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("out-of-scope publish drew no permission violation")
	}

	// Attribution: the lane, the resolved role, and the issuer are in
	// the audit — the subject arrived through OIDC, whoever stood
	// behind the issuer URL.
	for _, want := range []string{"lane=oidc", "role=engineering", "issuer=" + arm.IssuerURL()} {
		if !strings.Contains(audit.String(), want) {
			t.Fatalf("attribution %q missing from audit:\n%s", want, audit.String())
		}
	}

	// --- The refusal: a token whose role names nothing declared.
	undeclared := arm.TokenForRole(t, "marketing")
	if ncBad, err := nats.Connect(c.url,
		nats.UserCredentials(sentinelPath), nats.Token(undeclared),
		nats.RetryOnFailedConnect(false), nats.MaxReconnects(0)); err == nil {
		ncBad.Close()
		t.Fatal("an undeclared role admitted")
	}
	if !strings.Contains(audit.String(), "callout REFUSED") {
		t.Fatalf("the refusal is not in the audit:\n%s", audit.String())
	}
}
