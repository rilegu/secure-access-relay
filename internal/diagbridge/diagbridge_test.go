package diagbridge

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The property that matters most here is that nothing in this package can stop
// the agent working. Every test below is either "a broken library is refused" or
// "a refusal is reported as itself", because the failure this code must never
// have is one that reaches past diagnostics into access.

// TestRelativeDirectoryIsRefused checks the path-pinning rule.
//
// A relative directory resolves against the working directory, which a service
// does not control and an attacker may. Refusing is the whole point: the library
// must come from one known place, not from wherever the process happens to have
// been started.
func TestRelativeDirectoryIsRefused(t *testing.T) {
	_, err := Open(Config{Dir: "sardiag", AllowUnsigned: true})
	if err == nil {
		t.Fatal("a relative install directory was accepted")
	}
	if !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("error = %v, want it to report the library as unavailable", err)
	}
}

// TestEmptyDirectoryIsRefused checks that an unconfigured agent does not fall
// back to searching.
func TestEmptyDirectoryIsRefused(t *testing.T) {
	if _, err := Open(Config{AllowUnsigned: true}); err == nil {
		t.Fatal("an empty install directory was accepted")
	}
}

// TestMissingLibraryIsUnavailableNotFatal checks the ordinary case.
//
// No library installed is the expected state for most deployments. It must
// report as unavailable — a benign condition a caller can log and move past —
// rather than as an error that reads like something is broken.
func TestMissingLibraryIsUnavailableNotFatal(t *testing.T) {
	dir := t.TempDir()

	_, err := Open(Config{Dir: dir, AllowUnsigned: true})
	if err == nil {
		t.Fatal("opening a directory with no library succeeded")
	}
	if !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
}

// TestDirectoryInPlaceOfLibraryIsRefused checks a case that would otherwise
// reach LoadLibrary with something that is not a file.
func TestDirectoryInPlaceOfLibraryIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, LibraryName), 0o700); err != nil {
		t.Fatalf("create directory: %v", err)
	}

	if _, err := Open(Config{Dir: dir, AllowUnsigned: true}); err == nil {
		t.Fatal("a directory named like the library was accepted")
	}
}

// TestGarbageIsRefused checks that a file which is not a DLL fails cleanly.
//
// "Cleanly" means an error, not a crash: the agent process holds device keys and
// live sessions, and a malformed file on disk must not be able to end it.
func TestGarbageIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, LibraryName),
		[]byte("this is not a portable executable"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := Open(Config{Dir: dir, AllowUnsigned: true}); err == nil {
		t.Fatal("a file that is not a library was accepted")
	}
}

// TestSnapshotDecodeRejectsAnUnknownABI checks the second version gate.
//
// The version is checked once by calling into the library and once against what
// the snapshot itself claims. The second catches a library whose exported
// version and whose output disagree — which is what a partially upgraded install
// or a hand-edited file looks like.
func TestSnapshotDecodeRejectsAnUnknownABI(t *testing.T) {
	_, err := decodeSnapshot([]byte(`{"abi_version":99,"platform":"windows"}`))
	if !errors.Is(err, ErrABIMismatch) {
		t.Fatalf("error = %v, want ErrABIMismatch", err)
	}
}

// TestSnapshotDecodeRejectsGarbage checks that unparseable output is reported
// rather than silently becoming an empty snapshot.
func TestSnapshotDecodeRejectsGarbage(t *testing.T) {
	if _, err := decodeSnapshot([]byte("not json at all")); err == nil {
		t.Fatal("unparseable library output was accepted")
	}
}

// TestSnapshotDecodeIgnoresUnknownFields is the compatibility rule the ABI
// version deliberately does not track.
//
// A library may add a field without bumping the version, because the agent
// parses JSON and ignores what it does not recognise. If that stopped being
// true, every new field would become a breaking change.
func TestSnapshotDecodeIgnoresUnknownFields(t *testing.T) {
	raw := `{"abi_version":1,"platform":"windows","invented_later":{"x":1},
	         "adapters":[{"name":"eth0","status":"up","not_a_field":true}]}`

	snap, err := decodeSnapshot([]byte(raw))
	if err != nil {
		t.Fatalf("a snapshot with unknown fields was rejected: %v", err)
	}
	if len(snap.Adapters) != 1 || snap.Adapters[0].Name != "eth0" {
		t.Fatalf("known fields were lost: %+v", snap.Adapters)
	}
}

// TestConfigPath checks the file is looked for where the docs say.
func TestConfigPath(t *testing.T) {
	got := Config{Dir: filepath.Join("C:", "Program Files", "secure-access-relay")}.Path()
	if !strings.HasSuffix(got, LibraryName) {
		t.Fatalf("Path() = %q, want it to end in %s", got, LibraryName)
	}
}
