// Package store is the fold's only store (design D1–D6, D16–D19): four
// JetStream KV buckets, JSON records under the deployment's xkey
// envelope, birth by Create, every transition a revision-CAS Update,
// expires_at authoritative on every read.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/impire-io/soulfold/internal/envelope"
)

// DefaultPrefix namespaces the buckets so the fold never squats on
// generic names in a shared JetStream domain (D1).
const DefaultPrefix = "soulfold_"

// SessionTTLSlack is how far the sessions bucket's garbage collection
// trails expires_at (D5: TTL reclaims storage; the record decides
// validity).
const SessionTTLSlack = time.Hour

// Store is the four D1 buckets plus the envelope.
type Store struct {
	Users    jetstream.KeyValue
	Clients  jetstream.KeyValue
	Keys     jetstream.KeyValue
	Sessions jetstream.KeyValue

	sealer *envelope.Sealer
}

// Open creates-or-looks-up the four buckets (found by lookup after
// restart, never re-seeded) and binds the envelope. The sealer is
// mandatory: the fold has no plaintext mode (D16).
func Open(ctx context.Context, js jetstream.JetStream, sealer *envelope.Sealer, prefix string) (*Store, error) {
	if sealer == nil {
		return nil, fmt.Errorf("store: a sealer is required — the fold has no plaintext mode (design D16)")
	}
	if prefix == "" {
		prefix = DefaultPrefix
	}
	st := &Store{sealer: sealer}
	for _, b := range []struct {
		name string
		dst  *jetstream.KeyValue
		cfg  jetstream.KeyValueConfig
	}{
		{"users", &st.Users, jetstream.KeyValueConfig{History: 5}},
		{"clients", &st.Clients, jetstream.KeyValueConfig{History: 5}},
		{"keys", &st.Keys, jetstream.KeyValueConfig{History: 5}},
		{"sessions", &st.Sessions, jetstream.KeyValueConfig{History: 1, LimitMarkerTTL: SessionTTLSlack}},
	} {
		cfg := b.cfg
		cfg.Bucket = prefix + b.name
		kv, err := js.KeyValue(ctx, cfg.Bucket)
		if err != nil {
			kv, err = js.CreateKeyValue(ctx, cfg)
		}
		if err != nil {
			return nil, fmt.Errorf("store: bucket %s: %w", cfg.Bucket, err)
		}
		*b.dst = kv
	}
	return st, nil
}

// --- record I/O under the envelope -------------------------------------

// Create births a record (D4); a duplicate key is an error, never an
// overwrite. Opts allow the sessions bucket's per-key TTL.
func (st *Store) Create(ctx context.Context, kv jetstream.KeyValue, key string, rec any, opts ...jetstream.KVCreateOpt) (uint64, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return 0, fmt.Errorf("store: marshal %s: %w", key, err)
	}
	sealed, err := st.sealer.Seal(data)
	if err != nil {
		return 0, err
	}
	rev, err := kv.Create(ctx, key, sealed, opts...)
	if err != nil {
		return 0, fmt.Errorf("store: create %s: %w", key, err)
	}
	return rev, nil
}

// Get reads and opens a record, returning its revision for CAS. A
// record whose expires_at has passed is treated as absent regardless of
// its presence in KV (D5) — expiry lives in the record, not the bucket.
func (st *Store) Get(ctx context.Context, kv jetstream.KeyValue, key string, out any) (uint64, error) {
	e, err := kv.Get(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("store: get %s: %w", key, err)
	}
	plain, err := st.sealer.Open(e.Value())
	if err != nil {
		return 0, fmt.Errorf("store: open %s: %w", key, err)
	}
	if out != nil {
		if err := json.Unmarshal(plain, out); err != nil {
			return 0, fmt.Errorf("store: decode %s: %w", key, err)
		}
	}
	if exp := expiresAt(plain); exp != "" {
		t, err := time.Parse(time.RFC3339, exp)
		if err == nil && time.Now().After(t) {
			return 0, fmt.Errorf("store: get %s: %w", key, jetstream.ErrKeyNotFound)
		}
	}
	return e.Revision(), nil
}

// Update is one CAS attempt against the revision read (D4). Callers own
// the retry loop; a rejection means someone else moved first.
func (st *Store) Update(ctx context.Context, kv jetstream.KeyValue, key string, rec any, rev uint64) (uint64, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return 0, fmt.Errorf("store: marshal %s: %w", key, err)
	}
	sealed, err := st.sealer.Seal(data)
	if err != nil {
		return 0, err
	}
	newRev, err := kv.Update(ctx, key, sealed, rev)
	if err != nil {
		return 0, fmt.Errorf("store: update %s: %w", key, err)
	}
	return newRev, nil
}

// Delete removes a key outright (auth requests after redemption).
func (st *Store) Delete(ctx context.Context, kv jetstream.KeyValue, key string) error {
	if err := kv.Delete(ctx, key); err != nil {
		return fmt.Errorf("store: delete %s: %w", key, err)
	}
	return nil
}

// ListKeys returns every live key in a bucket.
func (st *Store) ListKeys(ctx context.Context, kv jetstream.KeyValue) ([]string, error) {
	lister, err := kv.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: list keys: %w", err)
	}
	var keys []string
	for k := range lister.Keys() {
		keys = append(keys, k)
	}
	return keys, nil
}

// expiresAt pulls expires_at from raw record JSON without knowing the
// shape (every expiring shape spells it the same way, D5).
func expiresAt(plain []byte) string {
	var probe struct {
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(plain, &probe); err != nil {
		return ""
	}
	return probe.ExpiresAt
}

// --- keys (D6 as amended, D12) -----------------------------------------

// CodeKey digests an authorization code for its index key: bearer
// secrets never appear verbatim in the store (D12).
func CodeKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return "code." + hex.EncodeToString(sum[:])[:32]
}

// UsernameIndexKey digests a username for its index key (D6 as amended
// by the kv-encryption-at-rest graduation: no user-supplied plaintext
// in a KV key).
func UsernameIndexKey(username string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(username)))
	return "idx.username." + hex.EncodeToString(sum[:])[:32]
}

// BrowserSessionKey namespaces browser-session records (D11).
func BrowserSessionKey(id string) string { return "bs_" + id }

// CeremonyKey namespaces in-flight WebAuthn ceremony records (M2).
func CeremonyKey(id string) string { return "wa_" + id }

// SigningKeyKey addresses a signing-key record; ActivePointerKey is the
// CAS-flipped pointer (D7).
func SigningKeyKey(kid string) string { return "key." + kid }

// ActivePointerKey is the keys bucket's active-key pointer.
const ActivePointerKey = "active"

// RandID returns a fresh random identifier (hex, 2n chars).
func RandID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("store: rand: %v", err)) // the OS RNG failing is not a recoverable state
	}
	return hex.EncodeToString(b)
}

// Now returns the store's canonical timestamp form.
func Now() string { return time.Now().UTC().Format(time.RFC3339) }
