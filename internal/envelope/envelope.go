// Package envelope is the store's seal layer (design D16–D17): every
// record value is the raw sealed output of an NATS curve-key (xkey,
// X25519) Seal, self-addressed to the deployment's seal key, opened on
// every read. The plaintext inside remains the design's JSON — the
// envelope changes custody, not shape.
//
// The seal seed is the deployment's to keep: born once, stored 0600,
// always outside the JetStream store directory. Losing it is total,
// honest data loss (D17); the deployment docs say so.
package envelope

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nats-io/nkeys"
)

// Sealer seals and opens record values with the deployment key.
type Sealer struct {
	kp  nkeys.KeyPair
	pub string
}

// LoadOrCreate returns the sealer for the seed at path, creating a
// fresh curve key on first start (D17: birth at first start, 0600).
// A seed readable by group or world is refused outright.
func LoadOrCreate(path string) (*Sealer, error) {
	seed, err := os.ReadFile(path)
	switch {
	case err == nil:
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("envelope: stat seed: %w", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("envelope: seal seed %s is mode %o — refuse to run with a group- or world-readable seed", path, info.Mode().Perm())
		}
		return FromSeed(seed)
	case errors.Is(err, os.ErrNotExist):
		kp, err := nkeys.CreateCurveKeys()
		if err != nil {
			return nil, fmt.Errorf("envelope: create curve key: %w", err)
		}
		seed, err := kp.Seed()
		if err != nil {
			return nil, fmt.Errorf("envelope: read seed: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("envelope: create seed dir: %w", err)
		}
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			return nil, fmt.Errorf("envelope: write seed: %w", err)
		}
		return FromSeed(seed)
	default:
		return nil, fmt.Errorf("envelope: read seed: %w", err)
	}
}

// FromSeed reconstructs the sealer from seed bytes already in hand
// (embedded deployments, tests).
func FromSeed(seed []byte) (*Sealer, error) {
	kp, err := nkeys.FromCurveSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("envelope: not a curve seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("envelope: public key: %w", err)
	}
	return &Sealer{kp: kp, pub: pub}, nil
}

// Seal turns a plaintext record into the stored value.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	sealed, err := s.kp.Seal(plaintext, s.pub)
	if err != nil {
		return nil, fmt.Errorf("envelope: seal: %w", err)
	}
	return sealed, nil
}

// Open turns a stored value back into the plaintext record. A value
// this key did not seal fails here — there is no plaintext fallback.
func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	plain, err := s.kp.Open(sealed, s.pub)
	if err != nil {
		return nil, fmt.Errorf("envelope: open: %w", err)
	}
	return plain, nil
}
