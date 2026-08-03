// Package lifecycle is M3's core: users, groups, and the single-use
// invites that carry enrollment rights (design D20–D24). The founding
// refusal extends from passwords to open enrollment — a passkey may be
// registered only against a live invite, and the invite is a bearer
// secret the store knows only by digest (D12/D21). Possession of the
// deployment's state mints the first invite (the operator act, D22);
// every later one is an admin op.
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/impire-io/soulfold/internal/store"
)

// DefaultInviteLifetime bounds an invite that names no lifetime.
const DefaultInviteLifetime = 24 * time.Hour

// TokenPrefix marks fold invite tokens ("soulfold invite").
const TokenPrefix = "sfi_"

// ErrEnrollmentNeedsInvite is the D20 refusal: no live invite, no
// registration — there is no open-enrollment lane to fall back to.
var ErrEnrollmentNeedsInvite = errors.New("lifecycle: enrollment requires a live invite")

// nameRE bounds usernames and group names: lowercase alphanumerics,
// hyphens, dots — valid KV key material and valid soulstream persona
// vocabulary downstream.
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)

// Service runs the lifecycle against the store.
type Service struct {
	St *store.Store
}

// CreateUser births a user with group memberships (groups are created
// on first mention — a group is a name, nothing more). The user cannot
// sign in until an invite enrolls their first passkey.
func (s *Service) CreateUser(ctx context.Context, username, displayName string, groups ...string) (store.User, error) {
	if !nameRE.MatchString(username) {
		return store.User{}, fmt.Errorf("lifecycle: username %q: lowercase alphanumerics, dots, hyphens only", username)
	}
	for _, g := range groups {
		if err := s.EnsureGroup(ctx, g); err != nil {
			return store.User{}, err
		}
	}
	now := store.Now()
	u := store.User{
		Schema: 1, ID: "u-" + store.RandID(8), Username: username,
		DisplayName: displayName, Status: "active", Groups: groups,
		CreatedAt: now, UpdatedAt: now,
	}
	if _, err := s.St.Create(ctx, s.St.Users, u.ID, u); err != nil {
		return store.User{}, err
	}
	if _, err := s.St.Create(ctx, s.St.Users, store.UsernameIndexKey(username), store.Index{Schema: 1, Target: u.ID}); err != nil {
		return store.User{}, err
	}
	return u, nil
}

// EnsureGroup creates a group if absent (idempotent).
func (s *Service) EnsureGroup(ctx context.Context, name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("lifecycle: group %q: lowercase alphanumerics, dots, hyphens only", name)
	}
	_, err := s.St.Create(ctx, s.St.Users, store.GroupKey(name), store.Group{
		Schema: 1, Name: name, CreatedAt: store.Now(),
	})
	if err != nil && store.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// SetStatus flips a user active/disabled (CAS).
func (s *Service) SetStatus(ctx context.Context, username, status string) error {
	if status != "active" && status != "disabled" {
		return fmt.Errorf("lifecycle: status %q: active or disabled", status)
	}
	return s.updateUser(ctx, username, func(u *store.User) error {
		u.Status = status
		return nil
	})
}

// SetGroups replaces a user's memberships (groups created on first
// mention). Membership changes surface in the next issued token — the
// M3 gate's observable.
func (s *Service) SetGroups(ctx context.Context, username string, groups ...string) error {
	for _, g := range groups {
		if err := s.EnsureGroup(ctx, g); err != nil {
			return err
		}
	}
	return s.updateUser(ctx, username, func(u *store.User) error {
		u.Groups = groups
		return nil
	})
}

func (s *Service) updateUser(ctx context.Context, username string, mutate func(*store.User) error) error {
	for {
		var idx store.Index
		if _, err := s.St.Get(ctx, s.St.Users, store.UsernameIndexKey(username), &idx); err != nil {
			return fmt.Errorf("lifecycle: unknown user %q", username)
		}
		var u store.User
		rev, err := s.St.Get(ctx, s.St.Users, idx.Target, &u)
		if err != nil {
			return err
		}
		if err := mutate(&u); err != nil {
			return err
		}
		u.UpdatedAt = store.Now()
		if _, err := s.St.Update(ctx, s.St.Users, u.ID, u, rev); err == nil {
			return nil
		}
	}
}

// UserByName resolves a username to its record.
func (s *Service) UserByName(ctx context.Context, username string) (store.User, error) {
	var idx store.Index
	if _, err := s.St.Get(ctx, s.St.Users, store.UsernameIndexKey(username), &idx); err != nil {
		return store.User{}, fmt.Errorf("lifecycle: unknown user %q", username)
	}
	var u store.User
	if _, err := s.St.Get(ctx, s.St.Users, idx.Target, &u); err != nil {
		return store.User{}, err
	}
	return u, nil
}

// Users lists every user record.
func (s *Service) Users(ctx context.Context) ([]store.User, error) {
	keys, err := s.St.ListKeys(ctx, s.St.Users)
	if err != nil {
		return nil, err
	}
	var out []store.User
	for _, k := range keys {
		if strings.HasPrefix(k, "idx.") || strings.HasPrefix(k, "group.") || strings.HasPrefix(k, "invite.") {
			continue
		}
		var u store.User
		if _, err := s.St.Get(ctx, s.St.Users, k, &u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// Groups lists every group.
func (s *Service) Groups(ctx context.Context) ([]store.Group, error) {
	keys, err := s.St.ListKeys(ctx, s.St.Users)
	if err != nil {
		return nil, err
	}
	var out []store.Group
	for _, k := range keys {
		if !strings.HasPrefix(k, "group.") {
			continue
		}
		var g store.Group
		if _, err := s.St.Get(ctx, s.St.Users, k, &g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// --- invites (D20–D22) -------------------------------------------------

// MintInvite issues a single-use enrollment grant for an existing
// user. The returned token is shown exactly once — the store keeps
// only its digest (D12/D21).
func (s *Service) MintInvite(ctx context.Context, username string, lifetime time.Duration) (string, error) {
	u, err := s.UserByName(ctx, username)
	if err != nil {
		return "", err
	}
	if u.Status != "active" {
		return "", fmt.Errorf("lifecycle: user %q is %s", username, u.Status)
	}
	if lifetime <= 0 {
		lifetime = DefaultInviteLifetime
	}
	token := TokenPrefix + store.RandID(24)
	now := time.Now().UTC()
	rec := store.Invite{
		Schema: 1, UserID: u.ID,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(lifetime).Format(time.RFC3339),
	}
	if _, err := s.St.Create(ctx, s.St.Users, store.InviteKey(token), rec); err != nil {
		return "", err
	}
	return token, nil
}

// ValidateInvite proves a presented token names a live, unconsumed
// invite and returns its target user and the record's KV key (which a
// ceremony may carry — the key is a digest, never the bearer).
func (s *Service) ValidateInvite(ctx context.Context, token string) (store.User, string, error) {
	if !strings.HasPrefix(token, TokenPrefix) {
		return store.User{}, "", errors.New("lifecycle: not an invite token")
	}
	key := store.InviteKey(token)
	var inv store.Invite
	if _, err := s.St.Get(ctx, s.St.Users, key, &inv); err != nil {
		return store.User{}, "", errors.New("lifecycle: unknown or expired invite")
	}
	if inv.Consumed {
		return store.User{}, "", errors.New("lifecycle: invite already used")
	}
	var u store.User
	if _, err := s.St.Get(ctx, s.St.Users, inv.UserID, &u); err != nil {
		return store.User{}, "", err
	}
	if u.Status != "active" {
		return store.User{}, "", fmt.Errorf("lifecycle: user is %s", u.Status)
	}
	return u, key, nil
}

// ConsumeInviteKey flips the invite at key to consumed — the CAS loser
// is refused, which IS the single-use guarantee (D4). Called in the
// same act that binds the enrolled credential.
func (s *Service) ConsumeInviteKey(ctx context.Context, key string) error {
	var inv store.Invite
	rev, err := s.St.Get(ctx, s.St.Users, key, &inv)
	if err != nil {
		return errors.New("lifecycle: unknown or expired invite")
	}
	if inv.Consumed {
		return errors.New("lifecycle: invite already used")
	}
	inv.Consumed = true
	if _, err := s.St.Update(ctx, s.St.Users, key, inv, rev); err != nil {
		return errors.New("lifecycle: invite already used")
	}
	return nil
}

// HasLiveInvite reports whether an unconsumed, unexpired invite exists
// for the user (embedding parents use it to mint founding invites
// idempotently).
func (s *Service) HasLiveInvite(ctx context.Context, userID string) (bool, error) {
	keys, err := s.St.ListKeys(ctx, s.St.Users)
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if !strings.HasPrefix(k, "invite.") {
			continue
		}
		var inv store.Invite
		if _, err := s.St.Get(ctx, s.St.Users, k, &inv); err != nil {
			continue // expired reads as absent (D5)
		}
		if inv.UserID == userID && !inv.Consumed {
			return true, nil
		}
	}
	return false, nil
}

// --- clients -----------------------------------------------------------

// RegisterClient is the deliberate (non-DCR) client registration.
func (s *Service) RegisterClient(ctx context.Context, clientID, name string, redirectURIs []string) (store.Client, error) {
	if clientID == "" || len(redirectURIs) == 0 {
		return store.Client{}, errors.New("lifecycle: client id and redirect uris required")
	}
	c := store.Client{
		Schema: 1, ClientID: clientID, Name: name,
		RedirectURIs: redirectURIs, Public: true, CreatedAt: store.Now(),
	}
	if _, err := s.St.Create(ctx, s.St.Clients, c.ClientID, c); err != nil {
		return store.Client{}, err
	}
	return c, nil
}

// Clients lists every registered client.
func (s *Service) Clients(ctx context.Context) ([]store.Client, error) {
	keys, err := s.St.ListKeys(ctx, s.St.Clients)
	if err != nil {
		return nil, err
	}
	var out []store.Client
	for _, k := range keys {
		var c store.Client
		if _, err := s.St.Get(ctx, s.St.Clients, k, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// DeleteClient removes a registered client.
func (s *Service) DeleteClient(ctx context.Context, clientID string) error {
	return s.St.Delete(ctx, s.St.Clients, clientID)
}

// RolesOf is the roles-claim derivation (D23): group names, plus the
// legacy pre-M3 Roles field (D2 — additive, never removed).
func RolesOf(u store.User) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range append(append([]string{}, u.Groups...), u.Roles...) {
		if r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
