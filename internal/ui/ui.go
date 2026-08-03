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

	"github.com/impire-io/soulfold/internal/passkeys"
	"github.com/impire-io/soulfold/internal/store"
	"github.com/impire-io/soulfold/internal/websession"
	"github.com/impire-io/soulfold/internal/webstyle"
)

var (
	// The login page: a username field and the ceremony driver. The
	// script is page-local and exists because navigator.credentials is
	// unreachable without it (D9's stated exception).
	loginTmpl = template.Must(template.New("login").Parse(
		webstyle.Head("sign in — soulfold") + `<body><main><div class="center">
<div class="bar"><a class="brand" href="#"><span class="dot"></span><b>soulfold</b></a></div>
<div class="card">
<h1>{{if .Invite}}Enroll your passkey{{else}}Sign in{{end}}</h1>
<p class="lede">{{if .Invite}}Choose a username and create a passkey — the only credential you'll ever need here.{{else}}Sign in with your passkey.{{end}}</p>
<form id="f">
<input type="hidden" id="authRequestID" value="{{.AuthRequestID}}">
<input type="hidden" id="csrf" value="{{.CSRF}}">
<input type="hidden" id="invite" value="{{.Invite}}">
<label class="field">Username <input id="username" autocomplete="username webauthn" autofocus required></label>
<button class="btn" type="submit">{{if .Invite}}Enroll and sign in{{else}}Sign in with a passkey{{end}}</button>
</form>
<p id="msg" class="msg"></p>
</div>
<p class="foot">soulfold · the door of the soulsystem</p>
</div></main>
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
</script></body></html>`))

	errorTmpl = template.Must(template.New("error").Parse(
		webstyle.Head("error — soulfold") + `<body><main><div class="center">
<div class="bar"><a class="brand" href="#"><span class="dot"></span><b>soulfold</b></a></div>
<div class="card"><h1>Sign-in failed</h1><p class="lede">{{.Message}}</p></div>
</div></main></body></html>`))

	// The standalone enrolment page an invite link points at directly:
	// register a passkey against the invite, no relying party involved.
	enrollTmpl = template.Must(template.New("enroll").Parse(
		webstyle.Head("enroll a passkey — soulfold") + `<body><main><div class="center">
<div class="bar"><a class="brand" href="#"><span class="dot"></span><b>soulfold</b></a></div>
<div class="card">
<h1>Enroll your passkey</h1>
<p class="lede">Choose a username and create a passkey — the only credential you'll ever need here.</p>
<form id="f">
<input type="hidden" id="invite" value="{{.Invite}}">
<label class="field">Username <input id="username" autocomplete="username webauthn" autofocus required></label>
<button class="btn" type="submit">Create passkey</button>
</form>
<p id="msg" class="msg"></p>
</div>
<p class="foot">soulfold · the door of the soulsystem</p>
</div></main>
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
      username: document.getElementById('username').value,
      invite: document.getElementById('invite').value,
    });
    const beginResp = await fetch('/enroll/begin?' + q, {method: 'POST'});
    if (!beginResp.ok) throw new Error(await beginResp.text());
    const begin = await beginResp.json();
    const pk = begin.options.publicKey;
    pk.challenge = b64u.dec(pk.challenge);
    if (pk.user) pk.user.id = b64u.dec(pk.user.id);
    for (const list of [pk.allowCredentials, pk.excludeCredentials])
      if (list) list.forEach(c => c.id = b64u.dec(c.id));
    const cred = await navigator.credentials.create({publicKey: pk});
    const body = {id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type, response: {
      attestationObject: b64u.enc(cred.response.attestationObject),
      clientDataJSON: b64u.enc(cred.response.clientDataJSON)}};
    q.set('ceremonyID', begin.ceremonyID);
    const fin = await fetch('/enroll/finish?' + q, {method: 'POST',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    if (!fin.ok) throw new Error(await fin.text());
    window.location = (await fin.json()).redirect;
  } catch (e) { msg.textContent = 'Enrolment failed: ' + e.message; }
});
</script></body></html>`))

	enrollDoneTmpl = template.Must(template.New("enrolldone").Parse(
		webstyle.Head("enrolled — soulfold") + `<body><main><div class="center">
<div class="bar"><a class="brand" href="#"><span class="dot"></span><b>soulfold</b></a></div>
<div class="card">
<h1>Your passkey is enrolled.</h1>
<p class="lede">You can now sign in with it wherever this identity provider is used.
Administrators can open the <a href="/admin">admin console</a>.</p>
</div>
<p class="foot">soulfold · the door of the soulsystem</p>
</div></main></body></html>`))
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

// Register mounts the surface on mux: the login pages the OIDC flow
// redirects into, and a standalone enrolment page an invite link points
// at directly (no relying party, no auth request — the invite is the
// whole capability).
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /login/", h.getLogin)
	mux.HandleFunc("POST /login/begin", h.postBegin)
	mux.HandleFunc("POST /login/finish", h.postFinish)
	mux.HandleFunc("GET /enroll", h.getEnroll)
	mux.HandleFunc("POST /enroll/begin", h.postEnrollBegin)
	mux.HandleFunc("POST /enroll/finish", h.postEnrollFinish)
}

// getEnroll renders the standalone enrolment page for an invite link
// (`/enroll?invite=sfi_…`). With `?done=1` it renders the confirmation.
func (h *Handler) getEnroll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("done") != "" {
		if err := enrollDoneTmpl.Execute(w, nil); err != nil {
			http.Error(w, "render failed", http.StatusInternalServerError)
		}
		return
	}
	invite := r.URL.Query().Get("invite")
	if invite == "" {
		h.renderError(w, http.StatusBadRequest, "this enrolment link is missing its invite")
		return
	}
	if err := enrollTmpl.Execute(w, struct{ Invite string }{invite}); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

// enrollOrigin is the standalone enrolment's outer wall: the invite is
// the capability, and a cross-origin submission is refused (D13's Origin
// half; there is no session-borne CSRF token yet).
func (h *Handler) enrollOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return origin == "" || origin == h.Issuer.Scheme+"://"+h.Issuer.Host
}

func (h *Handler) postEnrollBegin(w http.ResponseWriter, r *http.Request) {
	if !h.enrollOrigin(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	ceremonyID, kind, options, err := h.Passkeys.Begin(r.Context(),
		r.URL.Query().Get("username"), "", r.URL.Query().Get("invite"))
	if err != nil || kind != "register" {
		http.Error(w, "this invite is not valid for that user", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"ceremonyID": ceremonyID, "options": json.RawMessage(options),
	}); err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
	}
}

func (h *Handler) postEnrollFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !h.enrollOrigin(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	user, _, err := h.Passkeys.Finish(ctx, r.URL.Query().Get("ceremonyID"), r)
	if err != nil {
		http.Error(w, "enrolment failed", http.StatusUnauthorized)
		return
	}
	// A convenience session so an admin lands straight in the console;
	// everyone else gets the confirmation page.
	_, _ = websession.Set(ctx, h.St, w, r, user.ID)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"redirect": "/enroll?done=1"}); err != nil {
		http.Error(w, "encode failed", http.StatusInternalServerError)
	}
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
	bs, ok := websession.Get(r.Context(), h.St, r)
	if !ok {
		return "", false
	}
	return bs.Subject, true
}

func (h *Handler) setBrowserSession(ctx context.Context, w http.ResponseWriter, r *http.Request, subject string) {
	// sign-in proceeds even if the convenience session cannot be stored.
	_, _ = websession.Set(ctx, h.St, w, r, subject)
}
