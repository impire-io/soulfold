// Package provider adapts the store to zitadel/oidc v3's op.Storage —
// the certified library owns every OIDC endpoint (constitution III);
// the fold supplies storage and lifecycle. The mapping is design D6's,
// proven in the kv-encryption-at-rest rig and productized here.
package provider

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/impire-io/soulfold/internal/keys"
	"github.com/impire-io/soulfold/internal/store"
)

// Lifetimes (M1 defaults; per-client knobs arrive when a milestone
// demands them).
const (
	AuthRequestLifetime = 10 * time.Minute
	CodeLifetime        = 5 * time.Minute
	AccessTokenLifetime = time.Hour
	IDTokenLifetime     = 10 * time.Minute
)

// storage implements op.Storage over the sealed store.
type storage struct {
	St   *store.Store
	Keys *keys.Service
}

var _ op.Storage = (*storage)(nil)

// New assembles the zitadel provider on the store and key lifecycle.
func New(issuer string, st *store.Store, ks *keys.Service) (*op.Provider, error) {
	s := &storage{St: st, Keys: ks}
	var cryptoKey [32]byte
	if _, err := rand.Read(cryptoKey[:]); err != nil {
		return nil, fmt.Errorf("provider: crypto key: %w", err)
	}
	p, err := op.NewProvider(&op.Config{
		CryptoKey:       cryptoKey,
		CodeMethodS256:  true,
		SupportedClaims: []string{"sub", "aud", "exp", "iat", "iss", "auth_time", "nonce"},
		SupportedScopes: []string{oidc.ScopeOpenID},
	}, s, op.StaticIssuer(issuer), op.WithAllowInsecure())
	if err != nil {
		return nil, fmt.Errorf("provider: %w", err)
	}
	return p, nil
}

func (s *storage) Health(context.Context) error { return nil }

// --- auth requests -----------------------------------------------------

func (s *storage) CreateAuthRequest(ctx context.Context, r *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	now := time.Now().UTC()
	rec := store.Session{
		Schema: 1, ID: store.RandID(16), Kind: "auth_request",
		ClientID: r.ClientID, UserID: userID, Scopes: r.Scopes,
		RedirectURI: r.RedirectURI, State: r.State, Nonce: r.Nonce,
		ResponseType: string(r.ResponseType),
		CSRF:         store.RandID(16), // one-shot, minted with the record (D13)
		CreatedAt:    now.Format(time.RFC3339),
		ExpiresAt:    now.Add(AuthRequestLifetime).Format(time.RFC3339),
	}
	if r.CodeChallenge != "" {
		rec.PKCEChallenge = r.CodeChallenge
		rec.PKCEMethod = string(r.CodeChallengeMethod)
	}
	if _, err := s.St.Create(ctx, s.St.Sessions, rec.ID, rec); err != nil {
		return nil, err
	}
	return &authRequest{s: rec}, nil
}

func (s *storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	var rec store.Session
	if _, err := s.St.Get(ctx, s.St.Sessions, id, &rec); err != nil {
		return nil, fmt.Errorf("provider: auth request %s: %w", id, err)
	}
	return &authRequest{s: rec}, nil
}

// AuthRequestByCode redeems the digested single-use code index; the CAS
// flip is the single-use guarantee — the loser's rejection is the
// security property, not an error to smooth over (D4/D6/D12).
func (s *storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	key := store.CodeKey(code)
	var idx store.Index
	rev, err := s.St.Get(ctx, s.St.Sessions, key, &idx)
	if err != nil {
		return nil, errors.New("invalid authorization code")
	}
	if idx.Consumed {
		return nil, errors.New("authorization code already redeemed")
	}
	idx.Consumed = true
	if _, err := s.St.Update(ctx, s.St.Sessions, key, idx, rev); err != nil {
		return nil, errors.New("authorization code already redeemed")
	}
	return s.AuthRequestByID(ctx, idx.Target)
}

func (s *storage) SaveAuthCode(ctx context.Context, id, code string) error {
	idx := store.Index{
		Schema: 1, Target: id,
		ExpiresAt: time.Now().UTC().Add(CodeLifetime).Format(time.RFC3339),
	}
	_, err := s.St.Create(ctx, s.St.Sessions, store.CodeKey(code), idx)
	return err
}

func (s *storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.St.Delete(ctx, s.St.Sessions, id)
}

// --- tokens ------------------------------------------------------------

func (s *storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(AccessTokenLifetime)
	rec := store.Session{
		Schema: 1, ID: store.RandID(16), Kind: "access_token",
		UserID: req.GetSubject(), Scopes: req.GetScopes(),
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: exp.Format(time.RFC3339),
	}
	if ar, ok := req.(op.AuthRequest); ok {
		rec.ClientID = ar.GetClientID()
	}
	if _, err := s.St.Create(ctx, s.St.Sessions, rec.ID, rec); err != nil {
		return "", time.Time{}, err
	}
	return rec.ID, exp, nil
}

func (s *storage) CreateAccessAndRefreshTokens(_ context.Context, _ op.TokenRequest, _ string) (string, string, time.Time, error) {
	return "", "", time.Time{}, errors.New("provider: refresh tokens are not in M1's scope")
}

func (s *storage) TokenRequestByRefreshToken(_ context.Context, _ string) (op.RefreshTokenRequest, error) {
	return nil, errors.New("provider: refresh tokens are not in M1's scope")
}

func (s *storage) TerminateSession(_ context.Context, _, _ string) error {
	return nil
}

func (s *storage) RevokeToken(_ context.Context, _, _, _ string) *oidc.Error {
	return nil
}

func (s *storage) GetRefreshTokenInfo(_ context.Context, _, _ string) (string, string, error) {
	return "", "", op.ErrInvalidRefreshToken
}

// --- keys (D7/D8 through the lifecycle service) ------------------------

func (s *storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	kid, key, err := s.Keys.ActiveSigner(ctx)
	if err != nil {
		return nil, err
	}
	return &signingKey{kid: kid, key: key}, nil
}

func (s *storage) SignatureAlgorithms(_ context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *storage) KeySet(ctx context.Context) ([]op.Key, error) {
	published, err := s.Keys.Published(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]op.Key, 0, len(published))
	for i := range published {
		out = append(out, &publicKey{jwk: published[i]})
	}
	return out, nil
}

// --- clients and userinfo ----------------------------------------------

func (s *storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	var rec store.Client
	if _, err := s.St.Get(ctx, s.St.Clients, clientID, &rec); err != nil {
		return nil, fmt.Errorf("provider: client %s: %w", clientID, err)
	}
	return &client{c: rec}, nil
}

func (s *storage) AuthorizeClientIDSecret(_ context.Context, _, _ string) error {
	return errors.New("provider: M1 clients are public-with-PKCE; no client secrets exist")
}

func (s *storage) SetUserinfoFromScopes(_ context.Context, ui *oidc.UserInfo, userID, _ string, _ []string) error {
	ui.Subject = userID
	return nil
}

func (s *storage) SetUserinfoFromToken(ctx context.Context, ui *oidc.UserInfo, tokenID, _, _ string) error {
	var rec store.Session
	if _, err := s.St.Get(ctx, s.St.Sessions, tokenID, &rec); err != nil {
		return fmt.Errorf("provider: token %s: %w", tokenID, err)
	}
	ui.Subject = rec.UserID
	return nil
}

func (s *storage) SetIntrospectionFromToken(_ context.Context, _ *oidc.IntrospectionResponse, _, _, _ string) error {
	return errors.New("provider: introspection is not in M1's scope")
}

// GetPrivateClaimsFromScopes feeds the JWT access token's private
// claims. The vocabulary is Entra's — `oid` (the stable subject id),
// `preferred_username`, `roles` — because constitution II's test is a
// verifier that cannot tell the fold from Entra, and the seam's
// verifier of record (soulidentity's callout, its D23/D24) keys the
// subject by oid and resolves roles by name. Role values *name* roles
// declared on the consumer's side; they never carry permissions.
func (s *storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, _ string, _ []string) (map[string]any, error) {
	var user store.User
	if _, err := s.St.Get(ctx, s.St.Users, userID, &user); err != nil {
		return nil, fmt.Errorf("provider: claims for %s: %w", userID, err)
	}
	claims := map[string]any{
		"oid":                user.ID,
		"preferred_username": user.Username,
	}
	if len(user.Roles) > 0 {
		claims["roles"] = user.Roles
	}
	return claims, nil
}

func (s *storage) GetKeyByIDAndClientID(_ context.Context, _, _ string) (*jose.JSONWebKey, error) {
	return nil, errors.New("provider: JWT profile is not in M1's scope")
}

func (s *storage) ValidateJWTProfileScopes(_ context.Context, _ string, _ []string) ([]string, error) {
	return nil, errors.New("provider: JWT profile is not in M1's scope")
}
