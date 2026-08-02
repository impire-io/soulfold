package store_test

// The store design's acceptance criteria (#1–#3, #5), inherited by the
// M1 gate: restart byte-identity, the additive matrix, exactly-once
// redemption, and the envelope's custody — all against a real embedded
// JetStream server, no mocks.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/impire-io/soulfold/internal/envelope"
	"github.com/impire-io/soulfold/internal/natsserver"
	"github.com/impire-io/soulfold/internal/store"
)

func startStore(t *testing.T, dir string, sealer *envelope.Sealer) (*server.Server, *nats.Conn, *store.Store) {
	t.Helper()
	srv, err := natsserver.Start(dir)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), js, sealer, "")
	if err != nil {
		t.Fatal(err)
	}
	return srv, nc, st
}

func newSealer(t *testing.T) *envelope.Sealer {
	t.Helper()
	s, err := envelope.LoadOrCreate(filepath.Join(t.TempDir(), "seal.xkey"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNilSealerRefused(t *testing.T) {
	srv, err := natsserver.Start(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()
	nc, _ := nats.Connect(srv.ClientURL())
	defer nc.Close()
	js, _ := jetstream.New(nc)
	if _, err := store.Open(context.Background(), js, nil, ""); err == nil {
		t.Fatal("store.Open accepted a nil sealer — the fold has no plaintext mode (D16)")
	}
}

// Acceptance #1: the working set survives a full server restart
// byte-identical, buckets found by lookup, no re-seeding.
func TestRestartRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sealer := newSealer(t)
	srv, nc, st := startStore(t, dir, sealer)

	user := store.User{Schema: 1, ID: "u_1", Username: "alice", Status: "active",
		CreatedAt: "2026-08-02T20:00:00Z", UpdatedAt: "2026-08-02T20:00:00Z"}
	if _, err := st.Create(ctx, st.Users, user.ID, user); err != nil {
		t.Fatal(err)
	}
	raw, err := st.Users.Get(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), raw.Value()...)

	nc.Close()
	srv.Shutdown()
	srv.WaitForShutdown()

	srv2, nc2, st2 := startStore(t, dir, sealer)
	defer func() { nc2.Close(); srv2.Shutdown() }()
	raw2, err := st2.Users.Get(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, raw2.Value()) {
		t.Error("stored ciphertext changed across restart")
	}
	var got store.User
	if _, err := st2.Get(ctx, st2.Users, user.ID, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, user) {
		t.Errorf("record mismatch after restart: got %+v want %+v", got, user)
	}
}

// Acceptance #2: the schema-N ↔ N+1 additive matrix. The v2 shapes are
// test-local on purpose — the product ships schema 1 and this proves
// the evolution rule, not a shipped shape.
func TestAdditiveMatrix(t *testing.T) {
	type userV2 struct {
		store.User
		Email string `json:"email,omitempty"`
	}
	type sessionV2 struct {
		store.Session
		ACR string `json:"acr,omitempty"`
	}
	ctx := context.Background()
	srv, nc, st := startStore(t, t.TempDir(), newSealer(t))
	defer func() { nc.Close(); srv.Shutdown() }()

	u1 := store.User{Schema: 1, ID: "u_m", Username: "bob", Status: "active", CreatedAt: "2026-08-02T20:00:00Z", UpdatedAt: "2026-08-02T20:00:00Z"}
	u2 := userV2{User: u1, Email: "bob@example.test"}
	s1 := store.Session{Schema: 1, ID: "s_m", Kind: "auth_request", ClientID: "c", CreatedAt: "2026-08-02T20:00:00Z", ExpiresAt: "2036-01-01T00:00:00Z"}
	s2 := sessionV2{Session: s1, ACR: "urn:x"}

	cells := 0
	for i, cell := range []struct {
		writer any
		reader any
	}{
		{u1, &store.User{}}, {u1, &userV2{}}, {u2, &store.User{}}, {u2, &userV2{}},
		{s1, &store.Session{}}, {s1, &sessionV2{}}, {s2, &store.Session{}}, {s2, &sessionV2{}},
	} {
		key := "matrix." + string(rune('a'+i))
		if _, err := st.Create(ctx, st.Sessions, key, cell.writer); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Get(ctx, st.Sessions, key, cell.reader); err != nil {
			t.Fatalf("cell %d: %v", i, err)
		}
		cells++
	}
	if cells != 8 {
		t.Fatalf("matrix ran %d cells, want 8", cells)
	}

	// The D3 trap stays demonstrable: a v1 RMW of a v2 record drops the
	// v2-only field — the design rule, unchanged by the envelope.
	if _, err := st.Create(ctx, st.Users, u1.ID, u2); err != nil {
		t.Fatal(err)
	}
	var v1 store.User
	rev, err := st.Get(ctx, st.Users, u1.ID, &v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(ctx, st.Users, u1.ID, v1, rev); err != nil {
		t.Fatal(err)
	}
	var back userV2
	if _, err := st.Get(ctx, st.Users, u1.ID, &back); err != nil {
		t.Fatal(err)
	}
	if back.Email != "" {
		t.Error("expected the v1 RMW to drop the v2 field (design rule D3)")
	}
}

// Acceptance #3: racing redeemers of one code produce exactly one
// winner, every round.
func TestExactlyOnceRedemption(t *testing.T) {
	const rounds, racers = 50, 8
	ctx := context.Background()
	srv, nc, st := startStore(t, t.TempDir(), newSealer(t))
	defer func() { nc.Close(); srv.Shutdown() }()

	for r := 0; r < rounds; r++ {
		key := store.CodeKey(store.RandID(8))
		if _, err := st.Create(ctx, st.Sessions, key, store.Index{Schema: 1, Target: "req"}); err != nil {
			t.Fatal(err)
		}
		var winners atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var idx store.Index
				rev, err := st.Get(ctx, st.Sessions, key, &idx)
				if err != nil || idx.Consumed {
					return
				}
				idx.Consumed = true
				if _, err := st.Update(ctx, st.Sessions, key, idx, rev); err == nil {
					winners.Add(1)
				}
			}()
		}
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("round %d: %d winners, want exactly 1", r, winners.Load())
		}
	}
}

// D5: expires_at is authoritative on read — a record past it is absent
// even while still present in KV.
func TestExpiryAuthoritative(t *testing.T) {
	ctx := context.Background()
	srv, nc, st := startStore(t, t.TempDir(), newSealer(t))
	defer func() { nc.Close(); srv.Shutdown() }()

	past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	sess := store.Session{Schema: 1, ID: "s_exp", Kind: "auth_request", ClientID: "c",
		CreatedAt: past, ExpiresAt: past}
	if _, err := st.Create(ctx, st.Sessions, sess.ID, sess); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, st.Sessions, sess.ID, &store.Session{}); err == nil {
		t.Fatal("expired record was returned — expires_at must be authoritative (D5)")
	}
}

// Acceptance #5 (D16–D17): no record plaintext recoverable from the
// stopped store dir or an API-level dump; positive control proves the
// scan; the username index key carries no plaintext.
func TestEnvelopeCustody(t *testing.T) {
	const marker = "custody-probe-alice"
	ctx := context.Background()
	base := t.TempDir()
	storeDir := filepath.Join(base, "jetstream")
	sealer, err := envelope.LoadOrCreate(filepath.Join(base, "seal.xkey"))
	if err != nil {
		t.Fatal(err)
	}
	srv, nc, st := startStore(t, storeDir, sealer)

	user := store.User{Schema: 1, ID: "u_c", Username: marker, DisplayName: marker,
		Status: "active", CreatedAt: store.Now(), UpdatedAt: store.Now()}
	if _, err := st.Create(ctx, st.Users, user.ID, user); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(ctx, st.Users, store.UsernameIndexKey(user.Username), store.Index{Schema: 1, Target: user.ID}); err != nil {
		t.Fatal(err)
	}
	// Positive control: the same plaintext outside the envelope, via the
	// raw KV surface the store never uses.
	js, _ := jetstream.New(nc)
	ctrl, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "control_plain"})
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(user)
	if _, err := ctrl.Put(ctx, "control", plain); err != nil {
		t.Fatal(err)
	}

	// API-level dump of the fold's buckets: keys and raw values.
	keys, err := st.ListKeys(ctx, st.Users)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if bytes.Contains([]byte(k), []byte(marker)) {
			t.Errorf("marker in KV key %q — the username index must be digested (D6 as amended)", k)
		}
		e, err := st.Users.Get(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(e.Value(), []byte(marker)) {
			t.Errorf("marker in raw value of %q", k)
		}
	}

	nc.Close()
	srv.Shutdown()
	srv.WaitForShutdown()

	needles := [][]byte{[]byte(marker), []byte(base64.StdEncoding.EncodeToString([]byte(marker)))}
	hits := 0
	err = filepath.WalkDir(storeDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range needles {
			if bytes.Contains(data, n) {
				// The control bucket is the one place the marker must be.
				if bytes.Contains([]byte(path), []byte("control_plain")) {
					hits++
					continue
				}
				t.Errorf("marker on disk outside the control bucket: %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if hits == 0 {
		t.Fatal("positive control found nothing — the scan proves nothing")
	}
}
