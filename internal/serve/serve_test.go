package serve_test

// The M1+M2 gate (specs 001/002): a stock go-oidc RP completes the
// passkey sign-in against the running fold on an embedded nats-server;
// tokens verify against published JWKS; restarts — mid-flow and full —
// are invisible; forged POSTs change nothing; the page inventory is
// exactly {login, error}; the only way through is a WebAuthn ceremony.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/impire-io/soulfold/authtest"
	"github.com/impire-io/soulfold/internal/serve"
	"github.com/impire-io/soulfold/internal/store"
)

const (
	rpAddr   = "127.0.0.1:1" // never listened on; the scripted browser stops at the door
	clientID = "gate-client"
	username = "gate-user"
)

// browser is the scripted user agent: follows every redirect except the
// RP's own, records which fold URLs rendered HTML (the D9 inventory).
type browser struct {
	c         *http.Client
	mu        sync.Mutex
	htmlPages map[string]int
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	b := &browser{htmlPages: map[string]int{}}
	b.c = &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Host == rpAddr {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return b
}

// record counts rendered pages: HTML bodies on final (non-redirect)
// responses. A 3xx with an incidental HTML body is a redirect, not a
// page — the D9 inventory counts what a person sees.
func (b *browser) record(resp *http.Response) {
	if resp.StatusCode < 300 && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		b.mu.Lock()
		b.htmlPages[resp.Request.URL.Path]++
		b.mu.Unlock()
	}
}

func (b *browser) get(t *testing.T, u string) *http.Response {
	t.Helper()
	resp, err := b.c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	b.record(resp)
	return resp
}

func (b *browser) postForm(t *testing.T, u string, form url.Values, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b.record(resp)
	return resp
}

// postJSON posts a JSON body (the ceremony finish call).
func (b *browser) postJSON(t *testing.T, u string, payload []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b.record(resp)
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// drain discards and closes a response body the test only needed
// headers from.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// reservePort grabs a loopback port for the fold so the issuer can name
// it before the fold listens, and restarts can rebind the same address.
func reservePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func extractField(t *testing.T, page, name string) string {
	t.Helper()
	marker := `id="` + name + `" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no %s field in page:\n%s", name, page)
	}
	rest := page[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}

func TestM1Gate(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	addr := reservePort(t)
	issuer := "http://" + addr
	redirectURI := "http://" + rpAddr + "/cb"

	open := func() *serve.Fold {
		t.Helper()
		f, err := serve.Open(ctx, serve.Options{Issuer: issuer, Listen: addr, StateDir: stateDir})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = f.Run(ctx) }()
		return f
	}
	fold := open()
	if _, err := serve.SeedUser(ctx, fold.Store, username, "The Gate User"); err != nil {
		t.Fatal(err)
	}
	if _, err := serve.SeedClient(ctx, fold.Store, clientID, "gate", []string{redirectURI}); err != nil {
		t.Fatal(err)
	}
	// Enrollment rides an invite since M3 (D20): the first sign-in
	// registers against it, every later one asserts.
	invite1, err := fold.Lifecycle.MintInvite(ctx, username, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The stock RP: discovery, endpoints, verifier — all go-oidc.
	rpProvider, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatal(err)
	}
	cfg := oauth2.Config{
		ClientID: clientID, Endpoint: rpProvider.Endpoint(),
		RedirectURL: redirectURI, Scopes: []string{gooidc.ScopeOpenID},
	}
	verifier := rpProvider.Verifier(&gooidc.Config{ClientID: clientID})

	// One virtual passkey for the seeded user across every flow: the
	// first ceremony enrolls it (passkey-only first touch), later ones
	// assert it.
	authenticator, err := authtest.New("127.0.0.1", issuer)
	if err != nil {
		t.Fatal(err)
	}

	// ceremony drives begin → authenticator → finish and returns the
	// callback redirect the page script would follow.
	ceremony := func(b *browser, id, csrf, invite string) string {
		t.Helper()
		q := url.Values{"authRequestID": {id}, "csrf": {csrf}, "username": {username}, "invite": {invite}}
		beginResp := b.postForm(t, issuer+"/login/begin?"+q.Encode(), nil, nil)
		var begin struct {
			CeremonyID string          `json:"ceremonyID"`
			Kind       string          `json:"kind"`
			Options    json.RawMessage `json:"options"`
		}
		if err := json.Unmarshal([]byte(body(t, beginResp)), &begin); err != nil {
			t.Fatalf("begin: %v", err)
		}
		var waBody []byte
		if begin.Kind == "register" {
			waBody, err = authenticator.CreateResponse(begin.Options)
		} else {
			waBody, err = authenticator.GetResponse(begin.Options)
		}
		if err != nil {
			t.Fatal(err)
		}
		q.Set("ceremonyID", begin.CeremonyID)
		finResp := b.postJSON(t, issuer+"/login/finish?"+q.Encode(), waBody)
		var fin struct {
			Redirect string `json:"redirect"`
		}
		raw := body(t, finResp)
		if finResp.StatusCode != http.StatusOK {
			t.Fatalf("finish: %d %s", finResp.StatusCode, raw)
		}
		if err := json.Unmarshal([]byte(raw), &fin); err != nil {
			t.Fatal(err)
		}
		return fin.Redirect
	}

	// fullSignIn drives authorize → ceremony → callback → RP redirect →
	// token exchange, with a fresh PKCE verifier per flow.
	fullSignIn := func(b *browser, invite string) (*oauth2.Token, string) {
		t.Helper()
		pkce := oauth2.GenerateVerifier()
		resp := b.get(t, cfg.AuthCodeURL("state-1", oauth2.S256ChallengeOption(pkce)))
		var loc string
		if resp.StatusCode == http.StatusFound {
			// Browser session skipped the ceremony entirely (D11).
			loc = resp.Header.Get("Location")
			drain(resp)
		} else {
			page := body(t, resp)
			id := resp.Request.URL.Query().Get("authRequestID")
			csrf := extractField(t, page, "csrf")
			redirect := ceremony(b, id, csrf, invite)
			if !strings.HasPrefix(redirect, "http") {
				redirect = issuer + redirect
			}
			cb := b.get(t, redirect)
			drain(cb)
			loc = cb.Header.Get("Location")
		}
		if loc == "" || !strings.Contains(loc, "code=") {
			t.Fatalf("no code in final redirect %q", loc)
		}
		locURL, err := url.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := cfg.Exchange(ctx, locURL.Query().Get("code"), oauth2.VerifierOption(pkce))
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		return tok, locURL.Query().Get("code")
	}

	verifyTokens := func(tok *oauth2.Token) string {
		t.Helper()
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" {
			t.Fatal("no id_token")
		}
		idt, err := verifier.Verify(ctx, rawID)
		if err != nil {
			t.Fatalf("id_token: %v", err)
		}
		if !strings.HasPrefix(tok.AccessToken, "ey") {
			t.Fatal("access token is not a JWT (D15)")
		}
		ks := gooidc.NewRemoteKeySet(ctx, issuer+"/keys")
		if _, err := ks.VerifySignature(ctx, tok.AccessToken); err != nil {
			t.Fatalf("access token vs JWKS: %v", err)
		}
		return idt.Subject
	}

	// --- SC-001: the happy path -----------------------------------------
	b1 := newBrowser(t)
	tok, _ := fullSignIn(b1, invite1)
	subject := verifyTokens(tok)
	if !strings.HasPrefix(subject, "u-") {
		t.Fatalf("subject %q is not the seeded user", subject)
	}

	// Single-use code: replaying the exchange fails structurally.
	b2 := newBrowser(t)
	tok2, code2 := fullSignIn(b2, "")
	verifyTokens(tok2)
	if _, err := cfg.Exchange(ctx, code2, oauth2.VerifierOption("wrong")); err == nil {
		t.Fatal("second redemption of a code succeeded")
	}

	// --- SC-002: forged ceremony POSTs change nothing -------------------
	b3 := newBrowser(t)
	resp := b3.get(t, cfg.AuthCodeURL("state-2", oauth2.S256ChallengeOption(oauth2.GenerateVerifier())))
	page := body(t, resp)
	id := resp.Request.URL.Query().Get("authRequestID")
	csrf := extractField(t, page, "csrf")

	before := sessionRevision(ctx, t, fold, id)
	for name, attempt := range map[string]struct {
		query   url.Values
		headers map[string]string
	}{
		"missing csrf": {url.Values{"authRequestID": {id}, "username": {username}}, nil},
		"wrong csrf":   {url.Values{"authRequestID": {id}, "csrf": {"forged"}, "username": {username}}, nil},
		"foreign origin": {url.Values{"authRequestID": {id}, "csrf": {csrf}, "username": {username}},
			map[string]string{"Origin": "https://evil.example"}},
	} {
		r := b3.postForm(t, issuer+"/login/begin?"+attempt.query.Encode(), nil, attempt.headers)
		drain(r)
		if r.StatusCode < 400 {
			t.Errorf("%s (begin): status %d, want a refusal", name, r.StatusCode)
		}
		f := b3.postJSON(t, issuer+"/login/finish?"+attempt.query.Encode(), []byte(`{}`))
		drain(f)
		if f.StatusCode < 400 {
			t.Errorf("%s (finish): status %d, want a refusal", name, f.StatusCode)
		}
		if got := sessionRevision(ctx, t, fold, id); got != before {
			t.Errorf("%s: auth request revision moved %d→%d — state changed", name, before, got)
		}
	}
	// The passkey-only rule is enforced behavior: the pre-M2 form POST
	// no longer signs anyone in.
	stub := b3.postForm(t, issuer+"/login/", url.Values{
		"authRequestID": {id}, "csrf": {csrf}, "username": {username},
	}, nil)
	drain(stub)
	if stub.StatusCode < 400 || stub.Header.Get("Location") != "" {
		t.Fatalf("the retired username-only login answered %d %q", stub.StatusCode, stub.Header.Get("Location"))
	}
	// The legitimate ceremony still completes (refusals never consumed
	// the one-shot token).
	if redirect := ceremony(b3, id, csrf, ""); !strings.Contains(redirect, "id=") {
		t.Fatalf("legitimate ceremony after forgeries got %q", redirect)
	}

	// --- SC-001/SC-002: mid-flow restart --------------------------------
	// The restart lands between the ceremony and the token exchange: the
	// code, the ceremony outcome, and the keys all live in KV.
	b4 := newBrowser(t)
	pkce4 := oauth2.GenerateVerifier()
	resp4 := b4.get(t, cfg.AuthCodeURL("state-4", oauth2.S256ChallengeOption(pkce4)))
	page4 := body(t, resp4)
	id4 := resp4.Request.URL.Query().Get("authRequestID")
	redirect4 := ceremony(b4, id4, extractField(t, page4, "csrf"), "")
	if !strings.HasPrefix(redirect4, "http") {
		redirect4 = issuer + redirect4
	}
	cb4 := b4.get(t, redirect4)
	drain(cb4)
	loc4, err := url.Parse(cb4.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	fold.Close()
	fold = open() // same state dir, same address; nobody re-seeds

	tok4, err := cfg.Exchange(ctx, loc4.Query().Get("code"), oauth2.VerifierOption(pkce4))
	if err != nil {
		t.Fatalf("exchange across restart: %v", err)
	}
	verifyTokens(tok4)

	// --- D11: the browser session survives too --------------------------
	// b1 signed in before the restart; its cookie now completes a new
	// sign-in with zero pages rendered.
	pagesBefore := countPages(b1)
	tok5, _ := fullSignIn(b1, "")
	verifyTokens(tok5)
	if countPages(b1) != pagesBefore {
		t.Errorf("browser-session sign-in rendered pages: %v", b1.htmlPages)
	}

	// --- D9: the page inventory across everything above -----------------
	for _, b := range []*browser{b1, b2, b3, b4} {
		b.mu.Lock()
		for path := range b.htmlPages {
			if path != "/login/" {
				t.Errorf("undeclared page rendered HTML: %s", path)
			}
		}
		b.mu.Unlock()
	}
	fold.Close()
}

func countPages(b *browser) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, c := range b.htmlPages {
		n += c
	}
	return n
}

func sessionRevision(ctx context.Context, t *testing.T, f *serve.Fold, id string) uint64 {
	t.Helper()
	var rec store.Session
	rev, err := f.Store.Get(ctx, f.Store.Sessions, id, &rec)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}
