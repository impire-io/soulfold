// Package adminapi is the machine half of the admin surface (D24, as
// split by D25): a JSON API under /api/admin for automation. The
// bearer is one of the fold's own access tokens whose roles claim
// names `admin` — the fold trusts exactly what it tells everyone else
// to trust (constitution II), verified against its own keys. The
// human half is internal/adminui (a server-rendered console under
// /admin). The one place a bearer secret ever appears in a response
// is the invite mint, shown once (D21).
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/impire-io/soulfold/internal/keys"
	"github.com/impire-io/soulfold/internal/lifecycle"
)

// AdminRole is the group name whose members hold the admin surface.
const AdminRole = "admin"

// API carries the surface's dependencies.
type API struct {
	Lifecycle *lifecycle.Service
	Keys      *keys.Service
	Issuer    string
}

// Register mounts the machine API under /api/admin.
func Register(mux *http.ServeMux, a *API) {
	guard := a.authenticated
	mux.HandleFunc("GET /api/admin/users", guard(a.listUsers))
	mux.HandleFunc("POST /api/admin/users", guard(a.createUser))
	mux.HandleFunc("POST /api/admin/users/{username}/groups", guard(a.setGroups))
	mux.HandleFunc("POST /api/admin/users/{username}/status", guard(a.setStatus))
	mux.HandleFunc("GET /api/admin/groups", guard(a.listGroups))
	mux.HandleFunc("POST /api/admin/invites", guard(a.mintInvite))
	mux.HandleFunc("GET /api/admin/clients", guard(a.listClients))
	mux.HandleFunc("POST /api/admin/clients", guard(a.createClient))
	mux.HandleFunc("DELETE /api/admin/clients/{id}", guard(a.deleteClient))
}

// authenticated verifies the bearer against the fold's own published
// keys: signature, issuer, expiry, and roles containing admin. No
// other authority exists for this surface.
func (a *API) authenticated(next func(w http.ResponseWriter, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" || raw == r.Header.Get("Authorization") {
			jsonError(w, http.StatusUnauthorized, "a fold-issued bearer with the admin role is required")
			return
		}
		if err := a.verifyAdmin(r.Context(), raw); err != nil {
			jsonError(w, http.StatusForbidden, err.Error())
			return
		}
		next(w, r)
	}
}

func (a *API) verifyAdmin(ctx context.Context, raw string) error {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return errors.New("adminapi: not a fold token")
	}
	published, err := a.Keys.Published(ctx)
	if err != nil {
		return err
	}
	var claims struct {
		jwt.Claims
		Roles []string `json:"roles"`
	}
	verified := false
	for i := range published {
		if err := tok.Claims(published[i].Key, &claims); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return errors.New("adminapi: signature does not verify against the fold's keys")
	}
	if claims.Issuer != a.Issuer {
		return errors.New("adminapi: token from a different issuer")
	}
	if claims.Expiry == nil || claims.Expiry.Time().Before(time.Now()) {
		return errors.New("adminapi: token expired")
	}
	for _, role := range claims.Roles {
		if role == AdminRole {
			return nil
		}
	}
	return errors.New("adminapi: the token carries no admin role")
}

// --- handlers ----------------------------------------------------------

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.Lifecycle.Users(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type userOut struct {
		ID          string   `json:"id"`
		Username    string   `json:"username"`
		DisplayName string   `json:"display_name,omitempty"`
		Status      string   `json:"status"`
		Groups      []string `json:"groups,omitempty"`
		Credentials int      `json:"credentials"`
	}
	out := make([]userOut, 0, len(users))
	for _, u := range users {
		out = append(out, userOut{
			ID: u.ID, Username: u.Username, DisplayName: u.DisplayName,
			Status: u.Status, Groups: lifecycle.RolesOf(u), Credentials: len(u.Credentials),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string   `json:"username"`
		DisplayName string   `json:"display_name"`
		Groups      []string `json:"groups"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		jsonError(w, http.StatusBadRequest, "username is required")
		return
	}
	u, err := a.Lifecycle.CreateUser(r.Context(), req.Username, req.DisplayName, req.Groups...)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": u.ID, "username": u.Username, "groups": u.Groups,
	})
}

func (a *API) setGroups(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Groups []string `json:"groups"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "groups is required")
		return
	}
	if err := a.Lifecycle.SetGroups(r.Context(), r.PathValue("username"), req.Groups...); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": req.Groups})
}

func (a *API) setStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "status is required")
		return
	}
	if err := a.Lifecycle.SetStatus(r.Context(), r.PathValue("username"), req.Status); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": req.Status})
}

func (a *API) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := a.Lifecycle.Groups(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

// mintInvite is the one response carrying a bearer secret — shown
// once; the store keeps the digest (D21).
func (a *API) mintInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username   string `json:"username"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		jsonError(w, http.StatusBadRequest, "username is required")
		return
	}
	token, err := a.Lifecycle.MintInvite(r.Context(), req.Username, time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"invite":     token,
		"enroll_url": a.Issuer + "/login/?invite=" + token,
	})
}

func (a *API) listClients(w http.ResponseWriter, r *http.Request) {
	clients, err := a.Lifecycle.Clients(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (a *API) createClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string   `json:"client_id"`
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "client_id and redirect_uris are required")
		return
	}
	c, err := a.Lifecycle.RegisterClient(r.Context(), req.ClientID, req.Name, req.RedirectURIs)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (a *API) deleteClient(w http.ResponseWriter, r *http.Request) {
	if err := a.Lifecycle.DeleteClient(r.Context(), r.PathValue("id")); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
