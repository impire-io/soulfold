// The M5 gate: a consumer-position module embeds and runs the fold
// with no internal/ import compiling [measured] — and the embedded
// fold is the full authorization server the distribution story needs:
// discovery advertising DCR, a dynamically registered client, a
// passkey sign-in, and tokens carrying the deployment's fixed
// audience and the user's roles.
package embedgate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/impire-io/soulfold/authtest"
	"github.com/impire-io/soulfold/embed"
)

func TestEmbedGate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	issuer := "http://" + addr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	runErr := make(chan error, 1)
	invites := make(chan string, 1)
	go func() {
		runErr <- embed.Run(ctx, embed.Options{
			Issuer:        issuer,
			Listen:        addr,
			StateDir:      t.TempDir(),
			TokenAudience: "bundle-audience",
			EnableDCR:     true,
			SeedUsers: []embed.SeedUser{
				{Username: "owner", DisplayName: "The Owner", Roles: []string{"realm"}},
			},
			InviteSink: func(_, token string) { invites <- token },
			Ready:      func(a string) { ready <- a },
		})
	}()
	select {
	case a := <-ready:
		if a != addr {
			t.Fatalf("fold bound %s, want %s", a, addr)
		}
	case err := <-runErr:
		t.Fatalf("embed.Run failed during startup: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("the fold never became ready")
	}

	// Discovery through the stock library; the document advertises DCR.
	rp, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	var extra struct {
		RegistrationEndpoint string `json:"registration_endpoint"`
	}
	if err := rp.Claims(&extra); err != nil || extra.RegistrationEndpoint == "" {
		t.Fatalf("discovery advertises no registration_endpoint (%v)", err)
	}

	// A hosted client registers itself.
	const redirect = "http://127.0.0.1:1/cb"
	regBody, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{redirect}, "client_name": "embedgate",
	})
	regResp, err := http.Post(extra.RegistrationEndpoint, "application/json", strings.NewReader(string(regBody)))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(regResp.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	_ = regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated || reg.ClientID == "" {
		t.Fatalf("DCR: status %d client %q", regResp.StatusCode, reg.ClientID)
	}

	// The registered client enrolls the seeded user with a passkey —
	// against the founding invite the embed seam delivered (D20/D22).
	var ownerInvite string
	select {
	case ownerInvite = <-invites:
	case <-time.After(5 * time.Second):
		t.Fatal("the embed seam delivered no founding invite")
	}
	token := signIn(t, ctx, issuer, rp, reg.ClientID, redirect, "owner", ownerInvite)

	// The access token carries the fixed audience and the roles claim —
	// verified against the fold's own JWKS, all public surfaces.
	ks := gooidc.NewRemoteKeySet(ctx, issuer+"/keys")
	payload, err := ks.VerifySignature(ctx, token)
	if err != nil {
		t.Fatalf("access token vs JWKS: %v", err)
	}
	var claims struct {
		Aud   any      `json:"aud"`
		OID   string   `json:"oid"`
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	audJSON, _ := json.Marshal(claims.Aud)
	if !strings.Contains(string(audJSON), "bundle-audience") {
		t.Fatalf("access token aud %s lacks the fixed audience", audJSON)
	}
	if claims.OID == "" || len(claims.Roles) != 1 || claims.Roles[0] != "realm" {
		t.Fatalf("claims oid=%q roles=%v, want oid set and roles [realm]", claims.OID, claims.Roles)
	}

	// A clean ctx shutdown returns nil.
	cancel()
	select {
	case err := <-runErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v on shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return on ctx end")
	}
}

// signIn walks authorize → passkey ceremony → callback → token with the
// public authtest authenticator — the scripted browser. A non-empty
// invite makes the ceremony an enrollment.
func signIn(t *testing.T, ctx context.Context, issuer string, rp *gooidc.Provider, clientID, redirect, username, invite string) string {
	t.Helper()
	auth, err := authtest.New("127.0.0.1", issuer)
	if err != nil {
		t.Fatal(err)
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
	cfg := oauth2.Config{
		ClientID: clientID, Endpoint: rp.Endpoint(),
		RedirectURL: redirect, Scopes: []string{gooidc.ScopeOpenID},
	}
	pkce := oauth2.GenerateVerifier()
	resp, err := httpc.Get(cfg.AuthCodeURL("s", oauth2.S256ChallengeOption(pkce)))
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	id := resp.Request.URL.Query().Get("authRequestID")
	csrf := extract(t, string(page), "csrf")

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
		t.Fatal(err)
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
		t.Fatal(err)
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
	_, _ = io.Copy(io.Discard, cb.Body)
	_ = cb.Body.Close()
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

func extract(t *testing.T, page, id string) string {
	t.Helper()
	marker := `id="` + id + `" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no %s in page:\n%s", id, page)
	}
	rest := page[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}
