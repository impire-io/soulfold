package lifecycle_test

// The bootstrap-story research bars 2 and 3 (soul-hq
// 01-RESEARCH/bootstrap-story): invites are bearer-shaped and
// D12-honest — exactly one enrollment per invite, expired and forged
// refuse with zero state change, the store holds only digests
// (positive-control-verified); and the store alone — seal seed
// conceded — cannot enroll.

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/impire-io/soulfold/internal/envelope"
	"github.com/impire-io/soulfold/internal/lifecycle"
	"github.com/impire-io/soulfold/internal/natsserver"
	"github.com/impire-io/soulfold/internal/store"
)

func setup(t *testing.T) (*store.Store, *lifecycle.Service) {
	t.Helper()
	base := t.TempDir()
	sealer, err := envelope.LoadOrCreate(filepath.Join(base, "seal.xkey"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := natsserver.Start(filepath.Join(base, "jetstream"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), js, sealer, "")
	if err != nil {
		t.Fatal(err)
	}
	return st, &lifecycle.Service{St: st}
}

// Bar 2 — exactly one enrollment per invite: racing consumers of one
// invite produce exactly one winner, every round.
func TestBar2ExactlyOnceConsumption(t *testing.T) {
	const rounds, racers = 25, 8
	ctx := context.Background()
	_, lc := setup(t)
	if _, err := lc.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatal(err)
	}
	for r := 0; r < rounds; r++ {
		token, err := lc.MintInvite(ctx, "alice", 0)
		if err != nil {
			t.Fatal(err)
		}
		_, key, err := lc.ValidateInvite(ctx, token)
		if err != nil {
			t.Fatal(err)
		}
		var winners atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := lc.ConsumeInviteKey(ctx, key); err == nil {
					winners.Add(1)
				}
			}()
		}
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("round %d: %d consumers won, want exactly 1", r, winners.Load())
		}
	}
}

// Bar 2 — expired and forged invites refuse; a consumed invite refuses
// on replay; every refusal leaves the store unmoved.
func TestBar2RefusalsChangeNothing(t *testing.T) {
	ctx := context.Background()
	st, lc := setup(t)
	if _, err := lc.CreateUser(ctx, "bob", "Bob"); err != nil {
		t.Fatal(err)
	}

	// Expired: minted with a 50ms lifetime, presented after.
	expired, err := lc.MintInvite(ctx, "bob", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, _, err := lc.ValidateInvite(ctx, expired); err == nil {
		t.Fatal("an expired invite validated")
	}

	// Forged: correct shape, never minted.
	if _, _, err := lc.ValidateInvite(ctx, lifecycle.TokenPrefix+strings.Repeat("00", 24)); err == nil {
		t.Fatal("a forged invite validated")
	}

	// Consumed: replay refuses.
	live, err := lc.MintInvite(ctx, "bob", 0)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := lc.ValidateInvite(ctx, live)
	if err != nil {
		t.Fatal(err)
	}
	if err := lc.ConsumeInviteKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lc.ValidateInvite(ctx, live); err == nil {
		t.Fatal("a consumed invite validated on replay")
	}

	// Zero state change across all refusals: bob still has no
	// credential and no third live invite appeared.
	u, err := lc.UserByName(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Credentials) != 0 {
		t.Fatalf("refusals changed the user record: %d credentials", len(u.Credentials))
	}
	live2, err := lc.HasLiveInvite(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if live2 {
		t.Fatal("a live invite exists after consumption and expiry — refusals left state behind")
	}
	_ = st
}

// Bar 2 — the store holds only digests: the minted bearer appears in
// no KV key and no opened record; the digest key itself is findable
// (the positive control proving the scan sees invite records).
func TestBar2StoreHoldsOnlyDigests(t *testing.T) {
	ctx := context.Background()
	st, lc := setup(t)
	if _, err := lc.CreateUser(ctx, "carol", "Carol"); err != nil {
		t.Fatal(err)
	}
	token, err := lc.MintInvite(ctx, "carol", 0)
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimPrefix(token, lifecycle.TokenPrefix)

	keys, err := st.ListKeys(ctx, st.Users)
	if err != nil {
		t.Fatal(err)
	}
	digestFound := false
	for _, k := range keys {
		if strings.Contains(k, secret) {
			t.Fatalf("the bearer appears in KV key %q", k)
		}
		if k == store.InviteKey(token) {
			digestFound = true
		}
		var raw map[string]any
		if _, err := st.Get(ctx, st.Users, k, &raw); err != nil {
			continue
		}
		for field, v := range raw {
			if s, ok := v.(string); ok && strings.Contains(s, secret) {
				t.Fatalf("the bearer appears in record %q field %q", k, field)
			}
		}
	}
	if !digestFound {
		t.Fatal("positive control failed: the invite's digest key is not in the store — the scan proves nothing")
	}
}

// Bar 3 — the store alone cannot enroll: an attacker holding the
// complete opened store (the seal seed conceded) finds nothing that
// completes an enrollment — every artifact, presented as an invite,
// refuses, including the digest re-dressed as a token.
func TestBar3StoreAloneCannotEnroll(t *testing.T) {
	ctx := context.Background()
	st, lc := setup(t)
	if _, err := lc.CreateUser(ctx, "dave", "Dave", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := lc.MintInvite(ctx, "dave", 0); err != nil {
		t.Fatal(err)
	}

	// The attacker's haul: every key and every opened record field of
	// the users bucket (the envelope is conceded — this bar is about
	// enrollment trust, not confidentiality).
	keys, err := st.ListKeys(ctx, st.Users)
	if err != nil {
		t.Fatal(err)
	}
	var haul []string
	for _, k := range keys {
		haul = append(haul, k)
		if suffix := strings.TrimPrefix(k, "invite."); suffix != k {
			// The digest re-dressed in the token's clothing.
			haul = append(haul, lifecycle.TokenPrefix+suffix)
		}
		var raw map[string]any
		if _, err := st.Get(ctx, st.Users, k, &raw); err != nil {
			continue
		}
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				haul = append(haul, s, lifecycle.TokenPrefix+s)
			}
		}
	}
	if len(haul) < 10 {
		t.Fatalf("the haul is implausibly small (%d artifacts) — the attack is not real", len(haul))
	}
	admitted := 0
	for _, artifact := range haul {
		if _, _, err := lc.ValidateInvite(ctx, artifact); err == nil {
			admitted++
			t.Errorf("store artifact %q validated as an invite", artifact)
		}
	}
	t.Logf("bar 3: %d store artifacts presented as invites, %d admitted (want 0); the live bearer exists only outside the store [sha256 preimage: mechanism-argument]", len(haul), admitted)
}
