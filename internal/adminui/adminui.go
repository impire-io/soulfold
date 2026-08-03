// Package adminui is the human half of the admin surface (D25): a
// server-rendered console under /admin, gated on a passkey browser
// session whose user is in the `admin` group. No SPA, no framework —
// the one script is the WebAuthn login ceremony, exactly the D9
// exception the sign-in page already makes. State-changing POSTs carry
// the session's CSRF token (D13) and redirect back (POST/redirect/GET).
//
// The machine half (internal/adminapi, JSON under /api/admin) stays for
// automation; this is for a person with a browser and a passkey.
package adminui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/impire-io/soulfold/internal/lifecycle"
	"github.com/impire-io/soulfold/internal/passkeys"
	"github.com/impire-io/soulfold/internal/store"
	"github.com/impire-io/soulfold/internal/websession"
)

// AdminGroup gates the console.
const AdminGroup = "admin"

// Console serves the admin UI.
type Console struct {
	Lifecycle *lifecycle.Service
	Passkeys  *passkeys.Service
	St        *store.Store
	Issuer    string
}

// Register mounts the console under /admin.
func Register(mux *http.ServeMux, c *Console) {
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})
	mux.HandleFunc("GET /admin/{$}", c.dashboard)
	mux.HandleFunc("POST /admin/login/begin", c.loginBegin)
	mux.HandleFunc("POST /admin/login/finish", c.loginFinish)
	mux.HandleFunc("POST /admin/logout", c.logout)
	mux.HandleFunc("POST /admin/users", guard(c, c.createUser))
	mux.HandleFunc("POST /admin/users/{username}/groups", guard(c, c.setGroups))
	mux.HandleFunc("POST /admin/users/{username}/status", guard(c, c.setStatus))
	mux.HandleFunc("POST /admin/users/{username}/invite", guard(c, c.mintInvite))
	mux.HandleFunc("POST /admin/clients", guard(c, c.createClient))
	mux.HandleFunc("POST /admin/clients/{id}/delete", guard(c, c.deleteClient))
}

// adminSession returns the signed-in admin's user record, or false.
func (c *Console) adminSession(r *http.Request) (store.BrowserSession, store.User, bool) {
	bs, ok := websession.Get(r.Context(), c.St, r)
	if !ok {
		return bs, store.User{}, false
	}
	var u store.User
	if _, err := c.St.Get(r.Context(), c.St.Users, bs.Subject, &u); err != nil {
		return bs, store.User{}, false
	}
	if u.Status != "active" || !isAdmin(u) {
		return bs, store.User{}, false
	}
	return bs, u, true
}

func isAdmin(u store.User) bool {
	for _, g := range lifecycle.RolesOf(u) {
		if g == AdminGroup {
			return true
		}
	}
	return false
}

// guard wraps a state-changing handler: a valid admin session plus a
// matching CSRF token, else a refusal with zero effect.
func guard(c *Console, next func(http.ResponseWriter, *http.Request, store.BrowserSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bs, _, ok := c.adminSession(r)
		if !ok {
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
			return
		}
		if bs.CSRF == "" || r.FormValue("csrf") != bs.CSRF {
			c.redirect(w, r, "the form token was missing or stale — try again")
			return
		}
		next(w, r, bs)
	}
}

// redirect is the POST/redirect/GET landing, carrying a one-line flash.
func (c *Console) redirect(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/admin/?msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (c *Console) dashboard(w http.ResponseWriter, r *http.Request) {
	_, admin, ok := c.adminSession(r)
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := loginTmpl.Execute(w, nil); err != nil {
			http.Error(w, "render failed", http.StatusInternalServerError)
		}
		return
	}
	ctx := r.Context()
	bs, _ := websession.Get(ctx, c.St, r)
	users, err := c.Lifecycle.Users(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups, _ := c.Lifecycle.Groups(ctx)
	clients, _ := c.Lifecycle.Clients(ctx)

	type userRow struct {
		Username, Display, Status, Groups string
		Credentials                       int
	}
	rows := make([]userRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, userRow{
			Username: u.Username, Display: u.DisplayName, Status: u.Status,
			Groups: strings.Join(lifecycle.RolesOf(u), " "), Credentials: len(u.Credentials),
		})
	}
	groupNames := make([]string, 0, len(groups))
	for _, g := range groups {
		groupNames = append(groupNames, g.Name)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashTmpl.Execute(w, map[string]any{
		"Admin":   admin.Username,
		"CSRF":    bs.CSRF,
		"Msg":     r.URL.Query().Get("msg"),
		"Invite":  r.URL.Query().Get("invite"),
		"Users":   rows,
		"Groups":  strings.Join(groupNames, " "),
		"Clients": clients,
	}); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

// --- login (passkey assertion → admin session) -------------------------

func (c *Console) loginBegin(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// authRequestID and invite empty: a session-only login assertion.
	ceremonyID, kind, options, err := c.Passkeys.Begin(r.Context(), username, "", "")
	if err != nil || kind != "login" {
		http.Error(w, "no passkey to sign in with", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremonyID": ceremonyID, "options": json.RawMessage(options)})
}

func (c *Console) loginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _, err := c.Passkeys.Finish(ctx, r.URL.Query().Get("ceremonyID"), r)
	if err != nil {
		http.Error(w, "the ceremony failed", http.StatusUnauthorized)
		return
	}
	if !isAdmin(user) {
		http.Error(w, "this account is not an administrator", http.StatusForbidden)
		return
	}
	if _, err := websession.Set(ctx, c.St, w, r, user.ID); err != nil {
		http.Error(w, "could not start the session", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"redirect": "/admin/"})
}

func (c *Console) logout(w http.ResponseWriter, r *http.Request) {
	websession.Clear(w)
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// --- actions -----------------------------------------------------------

func (c *Console) createUser(w http.ResponseWriter, r *http.Request, _ store.BrowserSession) {
	username := strings.TrimSpace(r.FormValue("username"))
	if _, err := c.Lifecycle.CreateUser(r.Context(), username, r.FormValue("display_name"), splitGroups(r.FormValue("groups"))...); err != nil {
		c.redirect(w, r, "could not create user: "+err.Error())
		return
	}
	c.redirect(w, r, "created user "+username)
}

func (c *Console) setGroups(w http.ResponseWriter, r *http.Request, _ store.BrowserSession) {
	username := r.PathValue("username")
	if err := c.Lifecycle.SetGroups(r.Context(), username, splitGroups(r.FormValue("groups"))...); err != nil {
		c.redirect(w, r, "could not set groups: "+err.Error())
		return
	}
	c.redirect(w, r, "updated groups for "+username)
}

func (c *Console) setStatus(w http.ResponseWriter, r *http.Request, _ store.BrowserSession) {
	username := r.PathValue("username")
	status := r.FormValue("status")
	if err := c.Lifecycle.SetStatus(r.Context(), username, status); err != nil {
		c.redirect(w, r, "could not change status: "+err.Error())
		return
	}
	c.redirect(w, r, username+" is now "+status)
}

func (c *Console) mintInvite(w http.ResponseWriter, r *http.Request, _ store.BrowserSession) {
	username := r.PathValue("username")
	token, err := c.Lifecycle.MintInvite(r.Context(), username, 0)
	if err != nil {
		c.redirect(w, r, "could not mint invite: "+err.Error())
		return
	}
	// The one response carrying a bearer — shown once, in the flash.
	http.Redirect(w, r, "/admin/?invite="+url.QueryEscape(c.Issuer+"/login/?invite="+token)+
		"&msg="+url.QueryEscape("enrollment invite for "+username+" (single use, shown once)"), http.StatusSeeOther)
}

func (c *Console) createClient(w http.ResponseWriter, r *http.Request, _ store.BrowserSession) {
	id := strings.TrimSpace(r.FormValue("client_id"))
	uris := splitGroups(r.FormValue("redirect_uris"))
	if _, err := c.Lifecycle.RegisterClient(r.Context(), id, r.FormValue("name"), uris); err != nil {
		c.redirect(w, r, "could not register client: "+err.Error())
		return
	}
	c.redirect(w, r, "registered client "+id)
}

func (c *Console) deleteClient(w http.ResponseWriter, r *http.Request, _ store.BrowserSession) {
	id := r.PathValue("id")
	if err := c.Lifecycle.DeleteClient(r.Context(), id); err != nil {
		c.redirect(w, r, "could not delete client: "+err.Error())
		return
	}
	c.redirect(w, r, "deleted client "+id)
}

// --- helpers -----------------------------------------------------------

func splitGroups(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
