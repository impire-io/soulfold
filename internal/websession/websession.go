// Package websession is the browser session both surfaces share (D11):
// the OIDC sign-in flow that mints one as a convenience, and the M3
// admin console that gates on one. The sf_session cookie carries only
// the record's name; the subject and the console's CSRF token live in
// the sealed store.
package websession

import (
	"context"
	"net/http"
	"time"

	"github.com/impire-io/soulfold/internal/store"
)

// CookieName carries the browser-session record's name — nothing else.
const CookieName = "sf_session"

// Lifetime bounds the sf_session record.
const Lifetime = 12 * time.Hour

// Set mints a browser-session record for subject (with a fresh CSRF
// token) and writes the cookie. Returns the record's CSRF token.
func Set(ctx context.Context, st *store.Store, w http.ResponseWriter, r *http.Request, subject string) (string, error) {
	id := store.RandID(16)
	csrf := store.RandID(16)
	now := time.Now().UTC()
	bs := store.BrowserSession{
		Schema: 1, ID: id, Subject: subject, CSRF: csrf,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(Lifetime).Format(time.RFC3339),
	}
	if _, err := st.Create(ctx, st.Sessions, store.BrowserSessionKey(id), bs); err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		MaxAge:   int(Lifetime / time.Second),
	})
	return csrf, nil
}

// Get resolves the sf_session cookie to a live record (expiry
// authoritative, D5). Absent, unknown, or expired all read as (_, false).
func Get(ctx context.Context, st *store.Store, r *http.Request) (store.BrowserSession, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return store.BrowserSession{}, false
	}
	var bs store.BrowserSession
	if _, err := st.Get(ctx, st.Sessions, store.BrowserSessionKey(c.Value), &bs); err != nil {
		return store.BrowserSession{}, false
	}
	return bs, true
}

// Clear deletes the cookie (logout). The record ages out on its own TTL.
func Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}
