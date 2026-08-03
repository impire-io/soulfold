package serve_test

// Bar 1 of the bootstrap-story research plus the M3 gate: the
// from-nothing ceremony is counted and closed — a fresh fold to a
// signed-in ADMIN in exactly four acts (three operator, one browser),
// the bootstrap invite single-use (replay refused, nothing left
// behind), first-touch enrollment structurally gone — and group
// membership changes surface in the next issued token, driven through
// the admin surface with the admin's own bearer.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/impire-io/soulfold/authtest"
	"github.com/impire-io/soulfold/internal/serve"
)

func TestBar1BootstrapCountedAndClosed(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	addr := reservePort(t)
	issuer := "http://" + addr

	// ---- Act 1 (operator): found and serve the fold.
	fold, err := serve.Open(ctx, serve.Options{Issuer: issuer, Listen: addr, StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	defer fold.Close()
	go func() { _ = fold.Run(ctx) }()

	// ---- Act 2 (operator): create the first admin.
	//      (CLI: soulfold seed user --username root --roles admin)
	if _, err := serve.SeedUser(ctx, fold.Store, "root", "The First Admin", "admin"); err != nil {
		t.Fatal(err)
	}
	// The RP standing in for wherever the admin will sign in.
	const redirectURI = "http://" + rpAddr + "/cb"
	if _, err := serve.SeedClient(ctx, fold.Store, "bootstrap-rp", "rp", []string{redirectURI}); err != nil {
		t.Fatal(err)
	}

	// ---- Act 3 (operator): mint the bootstrap invite.
	//      (CLI: soulfold invite --username root)
	invite, err := fold.Lifecycle.MintInvite(ctx, "root", 0)
	if err != nil {
		t.Fatal(err)
	}

	// ---- Act 4 (browser): open the enroll URL, one passkey ceremony —
	// enrollment and sign-in in the same act.
	rpProvider, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatal(err)
	}
	cfg := oauth2.Config{
		ClientID: "bootstrap-rp", Endpoint: rpProvider.Endpoint(),
		RedirectURL: redirectURI, Scopes: []string{gooidc.ScopeOpenID},
	}
	auth, err := authtest.New("127.0.0.1", issuer)
	if err != nil {
		t.Fatal(err)
	}
	adminToken := flowSignIn(ctx, t, issuer, cfg, auth, "root", invite)

	// The four acts produced a signed-in ADMIN: the token's roles say so.
	ks := gooidc.NewRemoteKeySet(ctx, issuer+"/keys")
	payload, err := ks.VerifySignature(ctx, adminToken)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Roles []string `json:"roles"`
		OID   string   `json:"oid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if !contains(claims.Roles, "admin") {
		t.Fatalf("the bootstrap did not end in an admin: roles=%v", claims.Roles)
	}

	// ---- Closed: the bootstrap invite is spent — replaying the whole
	// enrollment refuses at begin, and the user record is unmoved.
	q := url.Values{"username": {"root"}, "invite": {invite}, "authRequestID": {"x"}, "csrf": {"x"}}
	resp, err := http.Post(issuer+"/login/begin?"+q.Encode(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	drain(resp)
	if resp.StatusCode < 400 {
		t.Fatalf("the consumed bootstrap invite began a ceremony: %d", resp.StatusCode)
	}
	root, err := fold.Lifecycle.UserByName(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if len(root.Credentials) != 1 {
		t.Fatalf("replay changed the record: %d credentials", len(root.Credentials))
	}

	// ---- First-touch is structurally gone: a second user with no
	// invite cannot begin any ceremony.
	if _, err := serve.SeedUser(ctx, fold.Store, "mallory", "No Invite"); err != nil {
		t.Fatal(err)
	}
	q2 := url.Values{"username": {"mallory"}, "authRequestID": {"x"}, "csrf": {"x"}}
	resp2, err := http.Post(issuer+"/login/begin?"+q2.Encode(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	drain(resp2)
	if resp2.StatusCode < 400 {
		t.Fatalf("a credential-less user without an invite began a ceremony: %d", resp2.StatusCode)
	}

	// ---- The M3 gate's second observable, driven through the admin
	// surface with the admin's own bearer: create a user, put them in a
	// group, invite and enroll them — their token carries the group;
	// change the membership — the NEXT token carries the change.
	adminReq := func(method, path string, body any) *http.Response {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Fatal(err)
			}
		}
		req, err := http.NewRequest(method, issuer+path, &buf)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	r1 := adminReq(http.MethodPost, "/admin/users", map[string]any{
		"username": "erin", "display_name": "Erin", "groups": []string{"engineering"},
	})
	drain(r1)
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("admin create user: %d", r1.StatusCode)
	}
	r2 := adminReq(http.MethodPost, "/admin/invites", map[string]any{"username": "erin"})
	var inv struct {
		Invite string `json:"invite"`
	}
	if err := json.NewDecoder(r2.Body).Decode(&inv); err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()

	erinAuth, err := authtest.New("127.0.0.1", issuer)
	if err != nil {
		t.Fatal(err)
	}
	erinTok1 := flowSignIn(ctx, t, issuer, cfg, erinAuth, "erin", inv.Invite)
	if roles := rolesOf(ctx, t, ks, erinTok1); !contains(roles, "engineering") || contains(roles, "platform") {
		t.Fatalf("first token roles %v, want [engineering]", roles)
	}

	r3 := adminReq(http.MethodPost, "/admin/users/erin/groups", map[string]any{
		"groups": []string{"platform"},
	})
	drain(r3)
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("admin set groups: %d", r3.StatusCode)
	}
	erinTok2 := flowSignIn(ctx, t, issuer, cfg, erinAuth, "erin", "")
	if roles := rolesOf(ctx, t, ks, erinTok2); !contains(roles, "platform") || contains(roles, "engineering") {
		t.Fatalf("the membership change did not surface in the next token: %v", roles)
	}

	// ---- The admin surface refuses non-admin bearers and bare requests.
	req, _ := http.NewRequest(http.MethodGet, issuer+"/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+erinTok2)
	r4, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	drain(r4)
	if r4.StatusCode != http.StatusForbidden {
		t.Fatalf("a non-admin token reached the admin surface: %d", r4.StatusCode)
	}
	r5, err := http.Get(issuer + "/admin/users")
	if err != nil {
		t.Fatal(err)
	}
	drain(r5)
	if r5.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a bare request reached the admin surface: %d", r5.StatusCode)
	}
}

// flowSignIn drives the full browser flow (authorize → ceremony →
// callback → exchange) and returns the access token. A non-empty
// invite enrolls; empty asserts.
func flowSignIn(ctx context.Context, t *testing.T, issuer string, cfg oauth2.Config, auth *authtest.Authenticator, username, invite string) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	httpc := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host == rpAddr {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	pkce := oauth2.GenerateVerifier()
	resp, err := httpc.Get(cfg.AuthCodeURL("s", oauth2.S256ChallengeOption(pkce)))
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	id := resp.Request.URL.Query().Get("authRequestID")
	csrf := extractField(t, string(page), "csrf")

	q := url.Values{"authRequestID": {id}, "csrf": {csrf}, "username": {username}, "invite": {invite}}
	beginResp, err := httpc.Post(issuer+"/login/begin?"+q.Encode(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var begin struct {
		CeremonyID string          `json:"ceremonyID"`
		Kind       string          `json:"kind"`
		Options    json.RawMessage `json:"options"`
	}
	if err := json.NewDecoder(beginResp.Body).Decode(&begin); err != nil {
		t.Fatalf("begin (%d): %v", beginResp.StatusCode, err)
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
	finResp, err := httpc.Post(issuer+"/login/finish?"+q.Encode(), "application/json", strings.NewReader(string(waBody)))
	if err != nil {
		t.Fatal(err)
	}
	var fin struct {
		Redirect string `json:"redirect"`
	}
	if err := json.NewDecoder(finResp.Body).Decode(&fin); err != nil {
		t.Fatalf("finish (%d): %v", finResp.StatusCode, err)
	}
	_ = finResp.Body.Close()
	target := fin.Redirect
	if !strings.HasPrefix(target, "http") {
		target = issuer + target
	}
	cb, err := httpc.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	drain(cb)
	loc, err := url.Parse(cb.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := cfg.Exchange(ctx, loc.Query().Get("code"), oauth2.VerifierOption(pkce))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return tok.AccessToken
}

func rolesOf(ctx context.Context, t *testing.T, ks *gooidc.RemoteKeySet, token string) []string {
	t.Helper()
	payload, err := ks.VerifySignature(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.Roles
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
