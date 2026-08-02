package envelope_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/impire-io/soulfold/internal/envelope"
)

func TestSeedBirthAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custody", "seal.xkey")
	s1, err := envelope.LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("seed born with mode %o, want 0600 (D17)", info.Mode().Perm())
	}
	sealed, err := s1.Seal([]byte("the record"))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := envelope.LoadOrCreate(path) // reload, same key
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s2.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "the record" {
		t.Errorf("reloaded sealer opened %q", plain)
	}
}

func TestLooseSeedRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seal.xkey")
	if _, err := envelope.LoadOrCreate(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.LoadOrCreate(path); err == nil {
		t.Fatal("a world-readable seal seed was accepted")
	}
}

func TestForeignCiphertextRefused(t *testing.T) {
	dir := t.TempDir()
	s1, err := envelope.LoadOrCreate(filepath.Join(dir, "a.xkey"))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := envelope.LoadOrCreate(filepath.Join(dir, "b.xkey"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s1.Seal([]byte("not yours"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Open(sealed); err == nil {
		t.Fatal("a foreign key opened the ciphertext")
	}
}
