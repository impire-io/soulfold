package serve

// Dynamic client registration (RFC 7591), the shape hosted MCP clients
// expect of an authorization server: POST /register with redirect_uris
// creates a public PKCE client. Enabled by Options.EnableDCR; the
// discovery document grows registration_endpoint by wrapping the
// certified library's handler — the library still owns the document,
// this only adds the one field it does not know about.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/impire-io/soulfold/internal/store"
)

const registerPath = "/register"

func registerDCR(mux *http.ServeMux, p *op.Provider, issuer string, st *store.Store) {
	mux.HandleFunc("POST "+registerPath, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RedirectURIs []string `json:"redirect_uris"`
			ClientName   string   `json:"client_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.RedirectURIs) == 0 {
			writeDCRError(w, http.StatusBadRequest, "invalid_client_metadata", "redirect_uris is required")
			return
		}
		for _, u := range req.RedirectURIs {
			parsed, err := url.Parse(u)
			if err != nil || parsed.Scheme == "" {
				writeDCRError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must be absolute URLs")
				return
			}
		}
		clientID := "dcr_" + store.RandID(12)
		if _, err := SeedClient(r.Context(), st, clientID, req.ClientName, req.RedirectURIs); err != nil {
			writeDCRError(w, http.StatusInternalServerError, "server_error", "could not persist the client")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  clientID,
			"redirect_uris":              req.RedirectURIs,
			"token_endpoint_auth_method": "none", // public client; PKCE carries the proof
			"grant_types":                []string{"authorization_code"},
			"response_types":             []string{"code"},
		})
	})

	// The discovery wrapper: serve the library's document with
	// registration_endpoint added.
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			for k, vs := range rec.Header() {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
			return
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			http.Error(w, "discovery document unreadable", http.StatusInternalServerError)
			return
		}
		doc["registration_endpoint"] = issuer + registerPath
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
}

func writeDCRError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": code, "error_description": desc,
	})
}
