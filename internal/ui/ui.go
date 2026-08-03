// Package ui is the sign-in surface (design D9–D14): exactly two
// server-rendered pages — login and error — with page-local JavaScript
// only where a ceremony demands it (M2's WebAuthn calls; nothing else),
// the one-shot CSRF token and the Origin outer wall on state-changing
// POSTs (D13), flow state in KV records with the cookie naming exactly
// one of them (D11). Since M2 the only way through is a passkey
// ceremony — the passkey-only rule is enforced behavior, not policy
// (constitution I).
package ui

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/impire-io/soulfold/internal/passkeys"
	"github.com/impire-io/soulfold/internal/store"
)

// BrowserSessionLifetime bounds the sf_session record (D11).
const BrowserSessionLifetime = 12 * time.Hour

// CookieName carries the browser-session record's name — nothing else.
const CookieName = "sf_session"

var (
	// The login page: a username field and the ceremony driver. The
	// script is page-local and exists because navigator.credentials is
	// unreachable without it (D9's stated exception).
	loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<meta charset="utf-8"><title>sign in — soulfold</title>
<main><h1>{{if .Invite}}Enroll your passkey{{else}}Sign in{{end}}</h1>
<form id="f">
<input type="hidden" id="authRequestID" value="{{.AuthRequestID}}">
<input type="hidden" id="csrf" value="{{.CSRF}}">
<input type="hidden" id="invite" value="{{.Invite}}">
<label>Username <input id="username" autocomplete="username webauthn" autofocus required></label>
<button type="submit">{{if .Invite}}Enroll and sign in{{else}}Sign in with a passkey{{end}}</button>
</form>
<p id="msg"></p>
<script>
const b64u = {
  dec: s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)),
  enc: b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''),
};
document.getElementById('f').addEventListener('submit', async ev => {
  ev.preventDefault();
  const msg = document.getElementById('msg');
  try {
    const q = new URLSearchParams({
      authRequestID: document.getElementById('authRequestID').value,
      csrf: document.getElementById('csrf').value,
      username: document.getElementById('username').value,
      invite: document.getElementById('invite').value,
    });
    const beginResp = await fetch('/login/begin?' + q, {method: 'POST'});
    if (!beginResp.ok) throw new Error(await beginResp.text());
    const begin = await beginResp.json();
    const pk = begin.options.publicKey;
    pk.challenge = b64u.dec(pk.challenge);
    if (pk.user) pk.user.id = b64u.dec(pk.user.id);
    for (const list of [pk.allowCredentials, pk.excludeCredentials])
      if (list) list.forEach(c => c.id = b64u.dec(c.id));
    let body;
    if (begin.kind === 'register') {
      const cred = await navigator.credentials.create({publicKey: pk});
      body = {id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type, response: {
        attestationObject: b64u.enc(cred.response.attestationObject),
        clientDataJSON: b64u.enc(cred.response.clientDataJSON)}};
    } else {
      const cred = await navigator.credentials.get({publicKey: pk});
      body = {id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type, response: {
        authenticatorData: b64u.enc(cred.response.authenticatorData),
        clientDataJSON: b64u.enc(cred.response.clientDataJSON),
        signature: b64u.enc(cred.response.signature),
        userHandle: cred.response.userHandle ? b64u.enc(cred.response.userHandle) : null}};
    }
    q.set('ceremonyID', begin.ceremonyID);
    const fin = await fetch('/login/finish?' + q, {method: 'POST',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    if (!fin.ok) throw new Error(await fin.text());
    window.location = (await fin.json()).redirect;
  } catch (e) { msg.textContent = 'Sign-in failed: ' + e.message; }
});
</script></main>`))

	errorTmpl = template.Must(template.New("error").Parse(`<!doctype html>
<meta charset="utf-8"><title>error — soulfold</title>
<main><h1>Sign-in failed</h1><p>{{.Message}}</p></main>`))
)

// Handler serves the sign-in surface against the store. Callback is
// op.AuthCallbackURL(provider) — the one URL the UI returns users to
// (D10).
type Handler struct {
	St       *store.Store
	Passkeys *passkeys.Service
	Issuer   *url.URL
	Callback func(ctx context.Context, authRequestID string) string
}

// Register mounts the surface on mux: the two pages plus the two
// ceremony endpoints the login page's script drives.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /login/", h.getLogin)
	mux.HandleFunc("POST /login/begin", h.postBegin)
	mux.HandleFunc("POST /login/finish", h.postFinish)
}

func (h *Handler) renderError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := errorTmpl.Execute(w, struct{ Message string }{msg}); err != nil {
		http.Error(w, msg, status)
	}
}

// getLogin renders the ceremony page — or, when a valid browser
// session already names this person (D11), completes the auth request
// without one.
func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.URL.Query().Get("authRequestID")
	if id == "" {
		h.renderError(w, http.StatusBadRequest, "missing auth request")
		return
	}
	var sess store.Session
	if _, err := h.St.Get(ctx, h.St.Sessions, id, &sess); err != nil {
		h.renderError(w, http.StatusBadRequest, "unknown or expired auth request")
		return
	}
	if subject, ok := h.browserSubject(r); ok {
		if err := h.completeAuthRequest(ctx, id, subject); err != nil {
			h.renderError(w, http.StatusInternalServerError, "could not complete the sign-in")
			return
		}
		http.Redirect(w, r, h.Callback(ctx, id), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginTmpl.Execute(w, struct{ AuthRequestID, CSRF, Invite string }{
		id, sess.CSRF, r.URL.Query().Get("invite"),
	}); err != nil {
		h.renderError(w, http.StatusInternalServerError, "render failed")
	}
}

// guard is the D13 wall shared by both ceremony POSTs: Origin first,
// then the CSRF token compared against the auth-request record. The
// token is *cleared* only when the request completes (postFinish) —
// begin creates scratch state, finish changes the flow's.
func (h *Handler) guard(r *http.Request) (store.Session, uint64, error) {
	if origin := r.Header.Get("Origin"); origin != "" {
		if origin != h.Issuer.Scheme+"://"+h.Issuer.Host {
			return store.Session{}, 0, errors.New("cross-origin request refused")
		}
	}
	id := r.URL.Query().Get("authRequestID")
	csrf := r.URL.Query().Get("csrf")
	if id == "" || csrf == "" {
		return store.Session{}, 0, errors.New("missing auth request or token")
	}
	var sess store.Session
	rev, err := h.St.Get(r.Context(), h.St.Sessions, id, &sess)
	if err != nil {
		return store.Session{}, 0, errors.New("unknown or expired auth request")
	}
	if sess.CSRF == "" || sess.CSRF != csrf {
		return store.Session{}, 0, errors.New("the form token is missing, stale, or already used")
	}
	return sess, rev, nil
}

func (h *Handler) postBegin(w http.ResponseWriter, r *http.Request) {
	sess, _, err := h.guard(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	ceremonyID, kind, options, err := h.Passkeys.Begin(r.Context(),
		r.URL.Query().Get("username"), sess.ID, r.URL.Query().Get("invite"))
	if err != nil {
		http.Error(w, "unknown user or invite", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"ceremonyID": ceremonyID, "kind": kind, "options": json.RawMessage(options),
	}); err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
	}
}

func (h *Handler) postFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, rev, err := h.guard(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	user, boundAuthReq, err := h.Passkeys.Finish(ctx, r.URL.Query().Get("ceremonyID"), r)
	if err != nil {
		http.Error(w, "the ceremony failed", http.StatusUnauthorized)
		return
	}
	if boundAuthReq != sess.ID {
		http.Error(w, "ceremony bound to a different sign-in", http.StatusForbidden)
		return
	}

	// One CAS write completes the flow: consume the one-shot token,
	// mark done, bind the authenticated subject (D13).
	sess.CSRF = ""
	sess.Done = true
	sess.UserID = user.ID
	sess.AuthTime = store.Now()
	if _, err := h.St.Update(ctx, h.St.Sessions, sess.ID, sess, rev); err != nil {
		http.Error(w, "the sign-in was already completed", http.StatusConflict)
		return
	}
	h.setBrowserSession(ctx, w, r, user.ID)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"redirect": h.Callback(ctx, sess.ID),
	}); err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
	}
}

func (h *Handler) completeAuthRequest(ctx context.Context, id, subject string) error {
	for {
		var sess store.Session
		rev, err := h.St.Get(ctx, h.St.Sessions, id, &sess)
		if err != nil {
			return err
		}
		sess.CSRF = ""
		sess.Done = true
		sess.UserID = subject
		sess.AuthTime = store.Now()
		if _, err := h.St.Update(ctx, h.St.Sessions, id, sess, rev); err == nil {
			return nil
		}
	}
}

// browserSubject resolves the sf_session cookie to a live record's
// subject; the cookie itself asserts nothing (D11).
func (h *Handler) browserSubject(r *http.Request) (string, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	var bs store.BrowserSession
	if _, err := h.St.Get(r.Context(), h.St.Sessions, store.BrowserSessionKey(c.Value), &bs); err != nil {
		return "", false
	}
	return bs.Subject, true
}

func (h *Handler) setBrowserSession(ctx context.Context, w http.ResponseWriter, r *http.Request, subject string) {
	id := store.RandID(16)
	now := time.Now().UTC()
	bs := store.BrowserSession{
		Schema: 1, ID: id, Subject: subject,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(BrowserSessionLifetime).Format(time.RFC3339),
	}
	if _, err := h.St.Create(ctx, h.St.Sessions, store.BrowserSessionKey(id), bs); err != nil {
		return // sign-in proceeds; only the convenience session is lost
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || h.Issuer.Scheme == "https",
		MaxAge:   int(BrowserSessionLifetime / time.Second),
	})
}
