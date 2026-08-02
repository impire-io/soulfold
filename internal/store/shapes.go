package store

// The record shapes at schema 1 (design D2/D6). Evolution is additive
// only; a breaking change is a stated migration under the store-shape
// one-way door. Timestamps are RFC 3339 UTC strings.

// User is a person the fold can sign in. M2 adds credentials (public
// keys and digests only — constitution I) additively.
type User struct {
	Schema      int    `json:"schema"`
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Status      string `json:"status"` // active | disabled
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
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
