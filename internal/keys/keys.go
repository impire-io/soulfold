// Package keys is the signing-key lifecycle (design D7–D8): RS256 keys
// walking pending → active → retiring → retired under two invariants —
// I1, publish before sign (a pending key enters JWKS a verifier
// cache-lifetime before it may sign); I2, unpublish only after the
// latest expiry the key ever signed has passed. One key is active at a
// time, selected by the CAS-flipped active pointer.
package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/impire-io/soulfold/internal/store"
)

// States of a signing key (D7). Retired is terminal and stays in the
// store for audit; it leaves the published set.
const (
	StatePending  = "pending"
	StateActive   = "active"
	StateRetiring = "retiring"
	StateRetired  = "retired"
)

// Service owns the lifecycle against the keys bucket.
type Service struct {
	St *store.Store
}

// EnsureFirstKey births the fold's first key directly active with the
// pointer set — before first serve no verifier exists, so I1's lead
// time has nothing to protect. Idempotent.
func (s *Service) EnsureFirstKey(ctx context.Context) error {
	if _, err := s.St.Get(ctx, s.St.Keys, store.ActivePointerKey, nil); err == nil {
		return nil
	}
	rec, err := newKeyRecord(StateActive)
	if err != nil {
		return err
	}
	if _, err := s.St.Create(ctx, s.St.Keys, store.SigningKeyKey(rec.Kid), rec); err != nil {
		return err
	}
	if _, err := s.St.Create(ctx, s.St.Keys, store.ActivePointerKey, store.Index{Schema: 1, Target: rec.Kid}); err != nil {
		// Two first-boots raced; the winner's pointer stands (D4).
		if strings.Contains(err.Error(), "already exists") {
			return nil
		}
		return err
	}
	return nil
}

// CreatePending births the next key into JWKS without signing rights
// (I1's first half). Activation is the caller's separate, later act.
func (s *Service) CreatePending(ctx context.Context) (string, error) {
	rec, err := newKeyRecord(StatePending)
	if err != nil {
		return "", err
	}
	if _, err := s.St.Create(ctx, s.St.Keys, store.SigningKeyKey(rec.Kid), rec); err != nil {
		return "", err
	}
	return rec.Kid, nil
}

// Activate flips the active pointer to kid (which must be pending) and
// moves the previously active key to retiring, stamping
// last_signed_expiry with now + maxTokenLifetime — the latest exp it
// could have signed (I2's clock starts).
func (s *Service) Activate(ctx context.Context, kid string, maxTokenLifetime time.Duration) error {
	var next store.SigningKey
	nextRev, err := s.St.Get(ctx, s.St.Keys, store.SigningKeyKey(kid), &next)
	if err != nil {
		return err
	}
	if next.State != StatePending {
		return fmt.Errorf("keys: activate %s: state is %s, want pending", kid, next.State)
	}
	for {
		var ptr store.Index
		ptrRev, err := s.St.Get(ctx, s.St.Keys, store.ActivePointerKey, &ptr)
		if err != nil {
			return err
		}
		oldKid := ptr.Target
		ptr.Target = kid
		if _, err := s.St.Update(ctx, s.St.Keys, store.ActivePointerKey, ptr, ptrRev); err != nil {
			continue // pointer moved under us; re-read and retry (D4)
		}
		next.State = StateActive
		next.NotBefore = store.Now()
		if _, err := s.St.Update(ctx, s.St.Keys, store.SigningKeyKey(kid), next, nextRev); err != nil {
			return err
		}
		if oldKid != "" && oldKid != kid {
			if err := s.markRetiring(ctx, oldKid, maxTokenLifetime); err != nil {
				return err
			}
		}
		return nil
	}
}

func (s *Service) markRetiring(ctx context.Context, kid string, maxTokenLifetime time.Duration) error {
	for {
		var old store.SigningKey
		rev, err := s.St.Get(ctx, s.St.Keys, store.SigningKeyKey(kid), &old)
		if err != nil {
			return err
		}
		old.State = StateRetiring
		old.LastSignedExpiry = time.Now().UTC().Add(maxTokenLifetime).Format(time.RFC3339)
		if _, err := s.St.Update(ctx, s.St.Keys, store.SigningKeyKey(kid), old, rev); err == nil {
			return nil
		}
	}
}

// RetireExpired moves every retiring key whose last_signed_expiry has
// passed to retired (I2's second half). Returns the kids retired.
func (s *Service) RetireExpired(ctx context.Context) ([]string, error) {
	keys, err := s.St.ListKeys(ctx, s.St.Keys)
	if err != nil {
		return nil, err
	}
	var retired []string
	for _, k := range keys {
		if !strings.HasPrefix(k, "key.") {
			continue
		}
		var rec store.SigningKey
		rev, err := s.St.Get(ctx, s.St.Keys, k, &rec)
		if err != nil {
			return nil, err
		}
		if rec.State != StateRetiring || rec.LastSignedExpiry == "" {
			continue
		}
		exp, err := time.Parse(time.RFC3339, rec.LastSignedExpiry)
		if err != nil {
			return nil, fmt.Errorf("keys: %s: bad last_signed_expiry: %w", k, err)
		}
		if time.Now().Before(exp) {
			continue
		}
		rec.State = StateRetired
		if _, err := s.St.Update(ctx, s.St.Keys, k, rec, rev); err != nil {
			return nil, err
		}
		retired = append(retired, rec.Kid)
	}
	return retired, nil
}

// ActiveSigner returns the active key as a crypto signer for the OP.
func (s *Service) ActiveSigner(ctx context.Context) (kid string, key *rsa.PrivateKey, err error) {
	var ptr store.Index
	if _, err := s.St.Get(ctx, s.St.Keys, store.ActivePointerKey, &ptr); err != nil {
		return "", nil, err
	}
	var rec store.SigningKey
	if _, err := s.St.Get(ctx, s.St.Keys, store.SigningKeyKey(ptr.Target), &rec); err != nil {
		return "", nil, err
	}
	der, err := base64.StdEncoding.DecodeString(rec.PrivatePKCS8)
	if err != nil {
		return "", nil, fmt.Errorf("keys: decode %s: %w", rec.Kid, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", nil, fmt.Errorf("keys: parse %s: %w", rec.Kid, err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", nil, errors.New("keys: active key is not RSA (D8)")
	}
	return rec.Kid, rsaKey, nil
}

// Published returns every key in the published set — pending, active,
// retiring (I1/I2); retired keys stay stored but leave JWKS.
func (s *Service) Published(ctx context.Context) ([]jose.JSONWebKey, error) {
	keys, err := s.St.ListKeys(ctx, s.St.Keys)
	if err != nil {
		return nil, err
	}
	var out []jose.JSONWebKey
	for _, k := range keys {
		if !strings.HasPrefix(k, "key.") {
			continue
		}
		var rec store.SigningKey
		if _, err := s.St.Get(ctx, s.St.Keys, k, &rec); err != nil {
			return nil, err
		}
		if rec.State == StateRetired {
			continue
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal([]byte(rec.PublicJWK), &jwk); err != nil {
			return nil, fmt.Errorf("keys: %s public jwk: %w", rec.Kid, err)
		}
		out = append(out, jwk)
	}
	return out, nil
}

func newKeyRecord(state string) (store.SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return store.SigningKey{}, fmt.Errorf("keys: generate: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return store.SigningKey{}, fmt.Errorf("keys: marshal: %w", err)
	}
	kid := "k" + store.RandID(8)
	pubJWK, err := json.Marshal(jose.JSONWebKey{Key: priv.Public(), KeyID: kid, Algorithm: "RS256", Use: "sig"})
	if err != nil {
		return store.SigningKey{}, fmt.Errorf("keys: public jwk: %w", err)
	}
	now := store.Now()
	return store.SigningKey{
		Schema: 1, Kid: kid, Alg: "RS256", State: state,
		PrivatePKCS8: base64.StdEncoding.EncodeToString(der),
		PublicJWK:    string(pubJWK),
		CreatedAt:    now, NotBefore: now,
	}, nil
}
