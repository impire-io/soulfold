package store

// The record shapes at schema 1 (design D2/D6). Evolution is additive
// only; a breaking change is a stated migration under the store-shape
// one-way door. Timestamps are RFC 3339 UTC strings.

import "encoding/json"

// User is a person the fold can sign in. Credentials arrived with M2,
// additively (D2): each entry is a WebAuthn credential record holding
// public material only — credential id, COSE public key, flags, sign
// count. Nothing in it may be sufficient to impersonate the user
// (constitution I).
type User struct {
	Schema      int    `json:"schema"`
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Status      string `json:"status"` // active | disabled
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	// Credentials is the user's enrolled passkeys, serialized
	// go-webauthn credential records (public material only).
	Credentials []json.RawMessage `json:"credentials,omitempty"`
	// Roles surface as the token's roles-claim values (constitution
	// II: they *name* roles declared on the consumer's side — Entra's
	// app-role shape — and never carry permissions). Since M3, Groups
	// is the lived field (group names ARE the roles-claim values);
	// Roles remains readable for pre-M3 records (D2: additive only,
	// fields never removed) and the claim is the union of both.
	Roles []string `json:"roles,omitempty"`
	// Groups is the user's group memberships (M3). Group names surface
	// as roles-claim values; membership changes surface in the next
	// issued token.
	Groups []string `json:"groups,omitempty"`
}

// Group is a named group (M3): its name is a roles-claim value —
// nothing more. It carries no permissions (constitution II).
type Group struct {
	Schema    int    `json:"schema"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// Invite is a single-use enrollment grant (M3, D20–D21): the KV key is
// the DIGEST of the bearer token (D12 — the token itself exists
// nowhere server-side); the record binds the target user and flips
// consumed by CAS in the same act that binds the credential.
type Invite struct {
	Schema    int    `json:"schema"`
	UserID    string `json:"user_id"`
	Consumed  bool   `json:"consumed,omitempty"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

// Client is a registered OAuth client. M1 clients are public-with-PKCE;
// a future confidential client stores a secret digest, never the secret.
type Client struct {
	Schema       int      `json:"schema"`
	ClientID     string   `json:"client_id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Public       bool     `json:"public"`
	CreatedAt    string   `json:"created_at"`
}

// SigningKey is one of the fold's own token-signing keys (D7 lifecycle,
// D8 RS256) — the one place the store holds private material, private
// to the fold, exactly as sensitive as any IdP's key store.
type SigningKey struct {
	Schema           int    `json:"schema"`
	Kid              string `json:"kid"`
	Alg              string `json:"alg"`
	State            string `json:"state"` // pending | active | retiring | retired
	PrivatePKCS8     string `json:"private_pkcs8"`
	PublicJWK        string `json:"public_jwk"`
	CreatedAt        string `json:"created_at"`
	NotBefore        string `json:"not_before"`
	LastSignedExpiry string `json:"last_signed_expiry,omitempty"`
}

// Index is the shape behind idx.*, code.* and the keys/active pointer:
// a target id plus, for single-use codes, the CAS-flipped consumed flag.
type Index struct {
	Schema    int    `json:"schema"`
	Target    string `json:"target"`
	Consumed  bool   `json:"consumed,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// Session is an auth request or token record in the sessions bucket.
type Session struct {
	Schema        int      `json:"schema"`
	ID            string   `json:"id"`
	Kind          string   `json:"kind"` // auth_request | access_token
	ClientID      string   `json:"client_id"`
	UserID        string   `json:"user_id,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	RedirectURI   string   `json:"redirect_uri,omitempty"`
	State         string   `json:"state,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	PKCEChallenge string   `json:"pkce_challenge,omitempty"`
	PKCEMethod    string   `json:"pkce_method,omitempty"`
	ResponseType  string   `json:"response_type,omitempty"`
	AuthTime      string   `json:"auth_time,omitempty"`
	Done          bool     `json:"done,omitempty"`
	CSRF          string   `json:"csrf,omitempty"` // one-shot (D13)
	CreatedAt     string   `json:"created_at"`
	ExpiresAt     string   `json:"expires_at"`
}

// BrowserSession is the record the sf_session cookie names (D11): the
// cookie carries only the record's name; everything it means lives here.
type BrowserSession struct {
	Schema    int    `json:"schema"`
	ID        string `json:"id"`
	Subject   string `json:"subject"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

// Ceremony is a WebAuthn ceremony in flight (M2): the library's
// SessionData between Begin and Finish, bound to the user and the auth
// request it will complete. Short-lived, sealed like everything else.
// InviteKey (M3, additive) carries the invite a registration runs
// against — the record's digest-derived KV key, never the bearer.
type Ceremony struct {
	Schema        int             `json:"schema"`
	ID            string          `json:"id"`
	Kind          string          `json:"kind"` // register | login
	UserID        string          `json:"user_id"`
	AuthRequestID string          `json:"auth_request_id"`
	SessionData   json.RawMessage `json:"session_data"`
	InviteKey     string          `json:"invite_key,omitempty"`
	CreatedAt     string          `json:"created_at"`
	ExpiresAt     string          `json:"expires_at"`
}
