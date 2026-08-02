// Package ui is the sign-in surface (design D9–D14): exactly two
// server-rendered pages — login and error — zero JavaScript in M1, the
// one-shot CSRF token and the Origin outer wall on every state-changing
// POST (D13), flow state in KV records with the cookie naming exactly
// one of them (D11).
package ui

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/impire-io/soulfold/internal/store"
)

// BrowserSessionLifetime bounds the sf_session record (D11).
const BrowserSessionLifetime = 12 * time.Hour

// CookieName carries the browser-session record's name — nothing else.
const CookieName = "sf_session"

var (
	loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<meta charset="utf-8"><title>sign in — soulfold</title>
<main><h1>Sign in</h1>
<form method="post" action="/login/">
<input type="hidden" name="authRequestID" value="{{.AuthRequestID}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label>Username <input name="username" autocomplete="username" autofocus required></label>
<button type="submit">Sign in</button>
</form></main>`))

	errorTmpl = template.Must(template.New("error").Parse(`<!doctype html>
<meta charset="utf-8"><title>error — soulfold</title>
<main><h1>Sign-in failed</h1><p>{{.Message}}</p></main>`))
)

// Handler serves the two pages against the store. Callback is
// op.AuthCallbackURL(provider) — the one URL the UI returns users to
// (D10).
type Handler struct {
	St       *store.Store
	Issuer   *url.URL
	Callback func(ctx context.Context, authRequestID string) string
}

// Register mounts the two routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /login/", h.getLogin)
	mux.HandleFunc("POST /login/", h.postLogin)
}

func (h *Handler) renderError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := errorTmpl.Execute(w, struct{ Message string }{msg}); err != nil {
		http.Error(w, msg, status)
	}
}

// getLogin renders the form — or, when a valid browser session already
// names this person (D11), completes the auth request without a page.
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
	if err := loginTmpl.Execute(w, struct{ AuthRequestID, CSRF string }{id, sess.CSRF}); err != nil {
		h.renderError(w, http.StatusInternalServerError, "render failed")
	}
}

// postLogin authenticates the M1 seeded-user stub (M2 replaces it with
// the passkey ceremony) behind the D13 walls: Origin first, then the
// one-shot CSRF token, cleared on success in the same CAS write that
// marks the request done.
func (h *Handler) postLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if origin := r.Header.Get("Origin"); origin != "" {
		if origin != h.Issuer.Scheme+"://"+h.Issuer.Host {
			h.renderError(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
	}
	id := r.FormValue("authRequestID")
	csrf := r.FormValue("csrf")
	username := r.FormValue("username")
	if id == "" || csrf == "" {
		h.renderError(w, http.StatusBadRequest, "missing form fields")
		return
	}

	var sess store.Session
	rev, err := h.St.Get(ctx, h.St.Sessions, id, &sess)
	if err != nil {
		h.renderError(w, http.StatusBadRequest, "unknown or expired auth request")
		return
	}
	if sess.CSRF == "" || sess.CSRF != csrf {
		h.renderError(w, http.StatusForbidden, "the form token is missing, stale, or already used")
		return
	}

	user, err := h.lookupActiveUser(ctx, username)
	if err != nil {
		h.renderError(w, http.StatusUnauthorized, "unknown user")
		return
	}

	// One CAS write: consume the token, mark done, bind the subject.
	sess.CSRF = ""
	sess.Done = true
	sess.UserID = user.ID
	sess.AuthTime = store.Now()
	if _, err := h.St.Update(ctx, h.St.Sessions, id, sess, rev); err != nil {
		// Someone else moved the record; the token is spent either way.
		h.renderError(w, http.StatusConflict, "the sign-in was already completed")
		return
	}

	h.setBrowserSession(ctx, w, r, user.ID)
	http.Redirect(w, r, h.Callback(ctx, id), http.StatusFound)
}

func (h *Handler) lookupActiveUser(ctx context.Context, username string) (store.User, error) {
	if username == "" {
		return store.User{}, errors.New("ui: empty username")
	}
	var idx store.Index
	if _, err := h.St.Get(ctx, h.St.Users, store.UsernameIndexKey(username), &idx); err != nil {
		return store.User{}, err
	}
	var user store.User
	if _, err := h.St.Get(ctx, h.St.Users, idx.Target, &user); err != nil {
		return store.User{}, err
	}
	if user.Status != "active" {
		return store.User{}, fmt.Errorf("ui: user %s is %s", user.ID, user.Status)
	}
	return user, nil
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
