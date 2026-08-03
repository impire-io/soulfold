package e2e_test

// The two issuer arms. Both present the same face to soulidentity —
// discovery, JWKS, RS256 access tokens carrying oid / roles /
// preferred_username — which is the point: the callout must be unable
// to tell the fold from an Entra-shaped issuer (constitution II).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/impire-io/soulfold/authtest"
	"github.com/impire-io/soulfold/embed"
)

// issuerArm is what the admission gate needs from an issuer: where it
// lives, which audience it stamps, and an access token for a user
// holding one role.
type issuerArm interface {
	IssuerURL() string
	Audience() string
	// TokenForRole returns an access token whose roles claim is exactly
	// [role], for a subject of the arm's choosing.
	TokenForRole(t *testing.T, role string) string
}

// --- Arm 1: the fold ---------------------------------------------------

const foldClientID = "fleet-rp"

type foldArm struct {
	issuer    string
	cfg       oauth2.Config
	users     map[string]*authtest.Authenticator // role -> enrolled passkey
	usernames map[string]string                  // role -> username
	invites   map[string]string                  // username -> unconsumed invite (M3)
}

// newFoldArm runs a real fold through its public embed seam (M5):
// passkey users, one per role the gate needs, each enrolled through the
// full ceremony on first sign-in.
func newFoldArm(t *testing.T, roles ...string) *foldArm {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	issuer := "http://" + addr

	const redirectURI = "http://127.0.0.1:1/cb"
	arm := &foldArm{
		issuer: issuer,
		users:  map[string]*authtest.Authenticator{}, usernames: map[string]string{},
		invites: map[string]string{},
	}
	seedUsers := make([]embed.SeedUser, 0, len(roles))
	for _, role := range roles {
		username := "user-" + role
		seedUsers = append(seedUsers, embed.SeedUser{
			Username: username, DisplayName: username, Roles: []string{role},
		})
		auth, err := authtest.New("127.0.0.1", issuer)
		if err != nil {
			t.Fatal(err)
		}
		arm.users[role] = auth
		arm.usernames[role] = username
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan struct{})
	runErr := make(chan error, 1)
	go func() {
		runErr <- embed.Run(ctx, embed.Options{
			Issuer: issuer, Listen: addr, StateDir: t.TempDir(),
			SeedUsers: seedUsers,
			SeedClients: []embed.SeedClient{
				{ClientID: foldClientID, Name: "fleet", RedirectURIs: []string{redirectURI}},
			},
			InviteSink: func(username, token string) { arm.invites[username] = token },
			Ready:      func(string) { close(ready) },
		})
	}()
	select {
	case <-ready:
	case err := <-runErr:
		t.Fatalf("embed.Run failed during startup: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("the fold never became ready")
	}

	rpProvider, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatal(err)
	}
	arm.cfg = oauth2.Config{
		ClientID: foldClientID, Endpoint: rpProvider.Endpoint(),
		RedirectURL: redirectURI, Scopes: []string{gooidc.ScopeOpenID},
	}
	return arm
}

func (f *foldArm) IssuerURL() string { return f.issuer }
func (f *foldArm) Audience() string  { return foldClientID }

// TokenForRole is a full browser sign-in: authorize → login page →
// passkey ceremony (register on first touch, assert after) → callback →
// code → exchange. The access token is what a real browser user holds.
func (f *foldArm) TokenForRole(t *testing.T, role string) string {
	t.Helper()
	auth, ok := f.users[role]
	if !ok {
		t.Fatalf("no fold user for role %s", role)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	httpc := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == "127.0.0.1:1" {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	pkce := oauth2.GenerateVerifier()
	resp, err := httpc.Get(f.cfg.AuthCodeURL("s", oauth2.S256ChallengeOption(pkce)))
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	authReqID := resp.Request.URL.Query().Get("authRequestID")
	csrf := extractAttr(t, string(page), "csrf")

	q := url.Values{"authRequestID": {authReqID}, "csrf": {csrf}, "username": {f.usernames[role]}}
	if invite, ok := f.invites[f.usernames[role]]; ok {
		q.Set("invite", invite)
		delete(f.invites, f.usernames[role]) // single use — like the browser it models
	}
	beginResp, err := httpc.Post(f.issuer+"/login/begin?"+q.Encode(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var begin struct {
		CeremonyID string          `json:"ceremonyID"`
		Kind       string          `json:"kind"`
		Options    json.RawMessage `json:"options"`
	}
	if err := json.NewDecoder(beginResp.Body).Decode(&begin); err != nil {
		t.Fatalf("begin: %v", err)
	}
	_ = beginResp.Body.Close()
	var waBody []byte
	if begin.Kind == "register" {
		waBody, err = auth.CreateResponse(begin.Options)
	} else {
		waBody, err = auth.GetResponse(begin.Options)
	}
	if err != nil {
		t.Fatal(err)
	}
	q.Set("ceremonyID", begin.CeremonyID)
	finResp, err := httpc.Post(f.issuer+"/login/finish?"+q.Encode(), "application/json", strings.NewReader(string(waBody)))
	if err != nil {
		t.Fatal(err)
	}
	var fin struct {
		Redirect string `json:"redirect"`
	}
	if err := json.NewDecoder(finResp.Body).Decode(&fin); err != nil {
		t.Fatalf("finish: %v", err)
	}
	_ = finResp.Body.Close()
	redirect := fin.Redirect
	if !strings.HasPrefix(redirect, "http") {
		redirect = f.issuer + redirect
	}
	cb, err := httpc.Get(redirect)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, cb.Body)
	_ = cb.Body.Close()
	locURL, err := url.Parse(cb.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := f.cfg.Exchange(context.Background(), locURL.Query().Get("code"), oauth2.VerifierOption(pkce))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return tok.AccessToken
}

func extractAttr(t *testing.T, page, id string) string {
	t.Helper()
	marker := `id="` + id + `" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no %s field in page:\n%s", id, page)
	}
	rest := page[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}

// --- Arm 2: the Entra-shaped stub --------------------------------------

type stubArm struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	audience string
}

// newStubArm serves discovery + JWKS and mints Entra-v2.0-shaped
// tokens — the indistinguishability control.
func newStubArm(t *testing.T) *stubArm {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &stubArm{key: key, audience: "fleet-rp-stub"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": s.srv.URL, "jwks_uri": s.srv.URL + "/keys",
			"authorization_endpoint":                s.srv.URL + "/authorize",
			"token_endpoint":                        s.srv.URL + "/token",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: "stub-1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubArm) IssuerURL() string { return s.srv.URL }
func (s *stubArm) Audience() string  { return s.audience }

func (s *stubArm) TokenForRole(t *testing.T, role string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.key},
		(&jose.SignerOptions{}).WithHeader("kid", "stub-1"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims, err := json.Marshal(map[string]any{
		"iss": s.srv.URL, "aud": s.audience,
		"sub": "stub-subject", "oid": "dddddddd-1111-2222-3333-eeeeeeeeffff",
		"preferred_username": "stub-user@example.test",
		"roles":              []string{role},
		"iat":                now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
