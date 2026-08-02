package provider

// The thin interface adapters between store records and the op
// interfaces. No behavior lives here — records answer, the library
// decides.

import (
	"crypto/rsa"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/impire-io/soulfold/internal/store"
)

// authRequest answers op.AuthRequest from the session record. extraAud
// is the deployment's fixed audience (empty: client-id only).
type authRequest struct {
	s        store.Session
	extraAud string
}

func (a *authRequest) GetID() string    { return a.s.ID }
func (a *authRequest) GetACR() string   { return "" }
func (a *authRequest) GetAMR() []string { return nil }
func (a *authRequest) GetAudience() []string {
	if a.extraAud != "" && a.extraAud != a.s.ClientID {
		return []string{a.s.ClientID, a.extraAud}
	}
	return []string{a.s.ClientID}
}
func (a *authRequest) GetAuthTime() time.Time {
	t, err := time.Parse(time.RFC3339, a.s.AuthTime)
	if err != nil {
		return time.Time{}
	}
	return t
}
func (a *authRequest) GetClientID() string { return a.s.ClientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.s.PKCEChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: a.s.PKCEChallenge,
		Method:    oidc.CodeChallengeMethod(a.s.PKCEMethod),
	}
}
func (a *authRequest) GetNonce() string                   { return a.s.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.s.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return oidc.ResponseType(a.s.ResponseType) }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return "" }
func (a *authRequest) GetScopes() []string                { return a.s.Scopes }
func (a *authRequest) GetState() string                   { return a.s.State }
func (a *authRequest) GetSubject() string                 { return a.s.UserID }
func (a *authRequest) Done() bool                         { return a.s.Done }

// client answers op.Client from the client record. M1 clients are
// public-with-PKCE native apps issuing JWT access tokens (D15).
type client struct{ c store.Client }

func (c *client) GetID() string                       { return c.c.ClientID }
func (c *client) RedirectURIs() []string              { return c.c.RedirectURIs }
func (c *client) PostLogoutRedirectURIs() []string    { return nil }
func (c *client) ApplicationType() op.ApplicationType { return op.ApplicationTypeNative }
func (c *client) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodNone }
func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode}
}
func (c *client) LoginURL(id string) string           { return "/login/?authRequestID=" + id }
func (c *client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }

//nolint:revive // the method name is op.Client's contract, not ours to spell.
func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *client) IDTokenLifetime() time.Duration { return IDTokenLifetime }
func (c *client) DevMode() bool                  { return false }
func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *client) IsScopeAllowed(string) bool           { return false }
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *client) ClockSkew() time.Duration             { return 0 }

// signingKey and publicKey answer the op key interfaces from the
// lifecycle service's records.
type signingKey struct {
	kid string
	key *rsa.PrivateKey
}

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (s *signingKey) Key() any                                    { return s.key }
func (s *signingKey) ID() string                                  { return s.kid }

type publicKey struct{ jwk jose.JSONWebKey }

func (p *publicKey) ID() string                         { return p.jwk.KeyID }
func (p *publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (p *publicKey) Use() string                        { return "sig" }
func (p *publicKey) Key() any                           { return p.jwk.Key }
