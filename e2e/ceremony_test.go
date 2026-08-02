package e2e_test

// The operator-mode ceremony the admission gate runs on: operator, SYS,
// AUTH (external authorization + callout xkey + issuer user), APP (the
// identity plane's own account, JetStream), and ENG — the tenant
// account whose scoped signing key is the declared role "engineering".
// Adapted from soulidentity's embedgate ceremony (its spec 002), pure
// server.Options, no config file.

import (
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newAuditLogger(w *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type ceremony struct {
	url         string
	appPub      string
	authPub     string
	engPub      string
	firstSeed   string
	surfaceSeed string
	calloutSeed string
	engSKSeed   string
	authSKSeed  string

	ncService *nats.Conn
	ncCallout *nats.Conn
	ncOps     *nats.Conn
}

// provision stands up the realm entirely in code: the declared state is
// the ENG account's scoped signing key (the role) — nothing anywhere
// names a person.
func provision(t *testing.T) *ceremony {
	t.Helper()

	opKP, _ := nkeys.CreateOperator()
	opPub, _ := opKP.PublicKey()
	sysKP, _ := nkeys.CreateAccount()
	sysPub, _ := sysKP.PublicKey()
	authKP, _ := nkeys.CreateAccount()
	authPub, _ := authKP.PublicKey()
	authSK, _ := nkeys.CreateAccount()
	authSKPub, _ := authSK.PublicKey()
	authSKSeed, _ := authSK.Seed()
	issuerUserKP, _ := nkeys.CreateUser()
	issuerUserPub, _ := issuerUserKP.PublicKey()
	issuerUserSeed, _ := issuerUserKP.Seed()
	calloutKP, _ := nkeys.CreateCurveKeys()
	calloutPub, _ := calloutKP.PublicKey()
	calloutSeed, _ := calloutKP.Seed()
	appKP, _ := nkeys.CreateAccount()
	appPub, _ := appKP.PublicKey()
	engKP, _ := nkeys.CreateAccount()
	engPub, _ := engKP.PublicKey()
	engSK, _ := nkeys.CreateAccount()
	engSKPub, _ := engSK.PublicKey()
	engSKSeed, _ := engSK.Seed()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	surfaceKP, _ := nkeys.CreateCurveKeys()
	surfaceSeed, _ := surfaceKP.Seed()

	sysJWT, err := jwt.NewAccountClaims(sysPub).Encode(opKP)
	if err != nil {
		t.Fatalf("sys jwt: %v", err)
	}

	authClaims := jwt.NewAccountClaims(authPub)
	authClaims.Name = "AUTH"
	authClaims.SigningKeys.Add(authSKPub)
	authClaims.EnableExternalAuthorization(issuerUserPub)
	authClaims.Authorization.AllowedAccounts.Add(engPub)
	authClaims.Authorization.XKey = calloutPub
	authJWT, err := authClaims.Encode(opKP)
	if err != nil {
		t.Fatalf("auth jwt: %v", err)
	}

	appClaims := jwt.NewAccountClaims(appPub)
	appClaims.Name = "APP"
	appClaims.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	appJWT, err := appClaims.Encode(opKP)
	if err != nil {
		t.Fatalf("app jwt: %v", err)
	}

	engClaims := jwt.NewAccountClaims(engPub)
	engClaims.Name = "ENG"
	scope := jwt.NewUserScope()
	scope.Key = engSKPub
	scope.Role = "engineering"
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{Allow: []string{"demo.>"}},
			Sub: jwt.Permission{Allow: []string{"demo.>", "_INBOX.>"}},
		},
	}
	engClaims.SigningKeys.AddScopedSigner(scope)
	engJWT, err := engClaims.Encode(opKP)
	if err != nil {
		t.Fatalf("eng jwt: %v", err)
	}

	res := &natsserver.MemAccResolver{}
	for pub, token := range map[string]string{
		sysPub: sysJWT, authPub: authJWT, appPub: appJWT, engPub: engJWT,
	} {
		if err := res.Store(pub, token); err != nil {
			t.Fatalf("resolver store: %v", err)
		}
	}
	srv, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1,
		JetStream: true, StoreDir: t.TempDir(),
		TrustedKeys: []string{opPub}, SystemAccount: sysPub,
		AccountResolver: res, NoLog: true, NoSigs: true,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		t.Fatal("server not ready")
	}
	t.Cleanup(srv.Shutdown)

	userJWTSeed := func(name string, signer nkeys.KeyPair) (string, string) {
		ukp, _ := nkeys.CreateUser()
		upub, _ := ukp.PublicKey()
		useed, _ := ukp.Seed()
		uc := jwt.NewUserClaims(upub)
		uc.Name = name
		token, err := uc.Encode(signer)
		if err != nil {
			t.Fatalf("user %s: %v", name, err)
		}
		return token, string(useed)
	}
	serviceJWT, serviceSeed := userJWTSeed("service", appKP)
	opsJWT, opsSeed := userJWTSeed("ops", appKP)
	issuerClaims := jwt.NewUserClaims(issuerUserPub)
	issuerClaims.Name = "soulidentity-issuer"
	issuerJWT, err := issuerClaims.Encode(authKP)
	if err != nil {
		t.Fatalf("issuer user: %v", err)
	}

	connect := func(what, token, seed string) *nats.Conn {
		nc, err := nats.Connect(srv.ClientURL(), nats.UserJWTAndSeed(token, seed),
			nats.Name(what), nats.RetryOnFailedConnect(false), nats.MaxReconnects(0))
		if err != nil {
			t.Fatalf("%s connect: %v", what, err)
		}
		t.Cleanup(nc.Close)
		return nc
	}

	return &ceremony{
		url: srv.ClientURL(), appPub: appPub, authPub: authPub, engPub: engPub,
		firstSeed: string(firstSeed), surfaceSeed: string(surfaceSeed),
		calloutSeed: string(calloutSeed), engSKSeed: string(engSKSeed),
		authSKSeed: string(authSKSeed),
		ncService:  connect("service", serviceJWT, serviceSeed),
		ncCallout:  connect("issuer", issuerJWT, string(issuerUserSeed)),
		ncOps:      connect("ops", opsJWT, opsSeed),
	}
}
