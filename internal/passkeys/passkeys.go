// Package passkeys is the M2 ceremony service: WebAuthn registration
// and login from the certified library (go-webauthn), the passkey-only
// rule as enforced behavior (constitution I). The RP ID is the
// issuer's host and the origin allowlist is exact (D14) — renaming the
// public host invalidates every enrolled credential, a one-way door
// the deployment docs must surface.
package passkeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/impire-io/soulfold/internal/lifecycle"
	"github.com/impire-io/soulfold/internal/store"
)

// CeremonyLifetime bounds an in-flight ceremony record.
const CeremonyLifetime = 5 * time.Minute

// Service runs the ceremonies against the store; Lifecycle carries the
// invite semantics enrollment rides on (D20).
type Service struct {
	St        *store.Store
	WA        *webauthn.WebAuthn
	Lifecycle *lifecycle.Service
}

// New configures the library from the issuer per D14: RP ID = the
// issuer's hostname, origins = exactly the issuer's origin.
func New(st *store.Store, issuer *url.URL) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          issuer.Hostname(),
		RPDisplayName: "soulfold",
		RPOrigins:     []string{issuer.Scheme + "://" + issuer.Host},
	})
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}
	return &Service{St: st, WA: wa, Lifecycle: &lifecycle.Service{St: st}}, nil
}

// waUser adapts the user record to the library's interface.
type waUser struct{ u store.User }

func (w *waUser) WebAuthnID() []byte          { return []byte(w.u.ID) }
func (w *waUser) WebAuthnName() string        { return w.u.Username }
func (w *waUser) WebAuthnDisplayName() string { return w.u.DisplayName }
func (w *waUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(w.u.Credentials))
	for _, raw := range w.u.Credentials {
		var c webauthn.Credential
		if err := json.Unmarshal(raw, &c); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// Begin starts the ceremony for username bound to authRequestID. Since
// M3 (D20) enrollment rights ride invites: a live invite for this user
// makes the ceremony a registration (the first passkey, or another —
// recovery is a fresh invite); no invite means a login assertion,
// which a user without credentials cannot perform. There is no
// open-enrollment lane — the refusal is structural.
func (s *Service) Begin(ctx context.Context, username, authRequestID, inviteToken string) (ceremonyID string, kind string, optionsJSON []byte, err error) {
	user, err := s.lookupActiveUser(ctx, username)
	if err != nil {
		return "", "", nil, err
	}

	var inviteKey string
	if inviteToken != "" {
		invited, key, err := s.Lifecycle.ValidateInvite(ctx, inviteToken)
		if err != nil {
			return "", "", nil, err
		}
		if invited.ID != user.ID {
			return "", "", nil, errors.New("passkeys: the invite names a different user")
		}
		inviteKey = key
	}
	wu := &waUser{u: user}

	var sessionData *webauthn.SessionData
	var options any
	switch {
	case inviteKey != "":
		creation, sd, err := s.WA.BeginRegistration(wu,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey:      protocol.ResidentKeyRequirementPreferred,
				UserVerification: protocol.VerificationRequired,
			}),
			webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		)
		if err != nil {
			return "", "", nil, fmt.Errorf("passkeys: begin registration: %w", err)
		}
		sessionData, options, kind = sd, creation, "register"
	case len(user.Credentials) > 0:
		assertion, sd, err := s.WA.BeginLogin(wu,
			webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return "", "", nil, fmt.Errorf("passkeys: begin login: %w", err)
		}
		sessionData, options, kind = sd, assertion, "login"
	default:
		return "", "", nil, lifecycle.ErrEnrollmentNeedsInvite
	}

	sdJSON, err := json.Marshal(sessionData)
	if err != nil {
		return "", "", nil, fmt.Errorf("passkeys: session data: %w", err)
	}
	now := time.Now().UTC()
	rec := store.Ceremony{
		Schema: 1, ID: store.RandID(16), Kind: kind,
		UserID: user.ID, AuthRequestID: authRequestID,
		SessionData: sdJSON, InviteKey: inviteKey,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(CeremonyLifetime).Format(time.RFC3339),
	}
	if _, err := s.St.Create(ctx, s.St.Sessions, store.CeremonyKey(rec.ID), rec); err != nil {
		return "", "", nil, err
	}
	optionsJSON, err = json.Marshal(options)
	if err != nil {
		return "", "", nil, fmt.Errorf("passkeys: options: %w", err)
	}
	return rec.ID, kind, optionsJSON, nil
}

// Finish completes the ceremony from the browser's response. On
// success it returns the authenticated user and the auth request the
// ceremony was bound to; the ceremony record is consumed (single use,
// the D4 way: whoever deletes it first wins).
func (s *Service) Finish(ctx context.Context, ceremonyID string, r *http.Request) (store.User, string, error) {
	var cer store.Ceremony
	if _, err := s.St.Get(ctx, s.St.Sessions, store.CeremonyKey(ceremonyID), &cer); err != nil {
		return store.User{}, "", errors.New("passkeys: unknown or expired ceremony")
	}
	if err := s.St.Delete(ctx, s.St.Sessions, store.CeremonyKey(ceremonyID)); err != nil {
		return store.User{}, "", errors.New("passkeys: ceremony already used")
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(cer.SessionData, &sd); err != nil {
		return store.User{}, "", fmt.Errorf("passkeys: session data: %w", err)
	}
	var user store.User
	rev, err := s.St.Get(ctx, s.St.Users, cer.UserID, &user)
	if err != nil {
		return store.User{}, "", err
	}
	wu := &waUser{u: user}

	var credential *webauthn.Credential
	switch cer.Kind {
	case "register":
		// The invite is consumed FIRST (D21): in a race the CAS loser is
		// refused before any credential binds — single use is structural.
		// A ceremony that then fails burns its invite; the recovery is a
		// fresh invite, never a reusable one.
		if cer.InviteKey == "" {
			return store.User{}, "", lifecycle.ErrEnrollmentNeedsInvite
		}
		if err := s.Lifecycle.ConsumeInviteKey(ctx, cer.InviteKey); err != nil {
			return store.User{}, "", err
		}
		credential, err = s.WA.FinishRegistration(wu, sd, r)
	case "login":
		credential, err = s.WA.FinishLogin(wu, sd, r)
	default:
		return store.User{}, "", fmt.Errorf("passkeys: ceremony kind %q", cer.Kind)
	}
	if err != nil {
		return store.User{}, "", fmt.Errorf("passkeys: ceremony failed: %w", err)
	}

	// Persist the outcome on the user record (CAS): a new credential on
	// registration, the updated sign count on login.
	credJSON, err := json.Marshal(credential)
	if err != nil {
		return store.User{}, "", fmt.Errorf("passkeys: credential: %w", err)
	}
	for {
		if cer.Kind == "register" {
			user.Credentials = append(user.Credentials, credJSON)
		} else {
			replaced := false
			for i, raw := range user.Credentials {
				var c webauthn.Credential
				if json.Unmarshal(raw, &c) == nil && string(c.ID) == string(credential.ID) {
					user.Credentials[i] = credJSON
					replaced = true
					break
				}
			}
			if !replaced {
				return store.User{}, "", errors.New("passkeys: asserted credential not on the user record")
			}
		}
		user.UpdatedAt = store.Now()
		if _, err := s.St.Update(ctx, s.St.Users, user.ID, user, rev); err == nil {
			break
		}
		rev, err = s.St.Get(ctx, s.St.Users, user.ID, &user)
		if err != nil {
			return store.User{}, "", err
		}
	}
	return user, cer.AuthRequestID, nil
}

func (s *Service) lookupActiveUser(ctx context.Context, username string) (store.User, error) {
	if username == "" {
		return store.User{}, errors.New("passkeys: empty username")
	}
	var idx store.Index
	if _, err := s.St.Get(ctx, s.St.Users, store.UsernameIndexKey(username), &idx); err != nil {
		return store.User{}, errors.New("passkeys: unknown user")
	}
	var user store.User
	if _, err := s.St.Get(ctx, s.St.Users, idx.Target, &user); err != nil {
		return store.User{}, errors.New("passkeys: unknown user")
	}
	if user.Status != "active" {
		return store.User{}, errors.New("passkeys: user is not active")
	}
	return user, nil
}
