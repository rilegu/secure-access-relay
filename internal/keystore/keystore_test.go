package keystore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.key")

	material := make([]byte, 64)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}

	prot, err := Save(path, material)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The protection actually obtained must match the platform, so a build that
	// silently lost DPAPI would fail here rather than in production.
	want := ProtectionFilePermissions
	if runtime.GOOS == "windows" {
		want = ProtectionDPAPI
	}
	if prot != want {
		t.Errorf("protection = %q, want %q on %s", prot, want, runtime.GOOS)
	}

	got, prot2, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, material) {
		t.Fatal("loaded key does not match what was saved")
	}
	if prot2 != want {
		t.Errorf("load protection = %q, want %q", prot2, want)
	}
}

// TestSealedBytesAreNotPlaintext checks that DPAPI actually transformed the key.
//
// Without this a broken seal would still round-trip perfectly — Save and Load
// would agree with each other while writing the key in the clear.
func TestSealedBytesAreNotPlaintext(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("no encryption at rest on this platform, by design")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "device.key")

	material := bytes.Repeat([]byte("SECRET-KEY-MATERIAL"), 8)
	if _, err := Save(path, material); err != nil {
		t.Fatalf("Save: %v", err)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, []byte("SECRET-KEY-MATERIAL")) {
		t.Fatal("key material is readable on disk: it was not sealed")
	}
}

func TestLoadMissingReportsNotFound(t *testing.T) {
	_, _, err := Load(filepath.Join(t.TempDir(), "absent.key"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// TestSaveIsAtomic checks that no temporary file survives a successful save.
//
// A leftover .tmp holding key material would be a second copy of the key with
// nobody responsible for it.
func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.key")

	if _, err := Save(path, []byte("material")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temporary file %q left behind after save", e.Name())
		}
	}
}

// TestOverwriteReplacesKey checks that re-enrolling replaces the identity rather
// than appending to it or failing.
func TestOverwriteReplacesKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device.key")

	if _, err := Save(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(path, []byte("second")); err != nil {
		t.Fatal(err)
	}

	got, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("loaded %q, want %q", got, "second")
	}
}
