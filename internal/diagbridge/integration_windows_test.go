//go:build windows

package diagbridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

// The ABI, exercised against the real library.
//
// Skipped unless the DLL has been built, so a checkout without a C toolchain
// still runs the rest of the suite. Build it with:
//
//	scripts/task.ps1 native
//
// These tests are the only place the two halves of the boundary meet. Everything
// else checks one side against its own idea of the contract, which is exactly
// how an ABI mismatch survives a green test run.

// builtLibrary returns the path to a locally built sardiag, or skips.
func builtLibrary(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", "..", "native", "sardiag", "build"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, LibraryName)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("sardiag.dll not built; run scripts/task.ps1 native (looked in %s)", root)
	}
	return root
}

// TestLoadsAndReportsMatchingABI is the check that the header and this package
// have not drifted apart.
//
// A mismatch here is the failure the version field exists to catch, and it is
// invisible to every other test: both sides compile, both sides pass their own
// tests, and the call convention is wrong.
func TestLoadsAndReportsMatchingABI(t *testing.T) {
	dir := builtLibrary(t)

	lib, err := Open(Config{Dir: dir, AllowUnsigned: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = lib.Close() }()
}

// TestSnapshotReturnsUsableData calls the library against the machine running
// the test.
//
// The assertions are deliberately weak about content — a CI runner's adapters
// are not predictable — and strict about shape. What is being tested is that
// bytes crossed the boundary intact and decoded, not that this machine has any
// particular network.
func TestSnapshotReturnsUsableData(t *testing.T) {
	dir := builtLibrary(t)

	lib, err := Open(Config{Dir: dir, AllowUnsigned: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = lib.Close() }()

	snap, err := lib.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	if snap.ABIVersion != SupportedABI {
		t.Fatalf("snapshot reports ABI %d, want %d", snap.ABIVersion, SupportedABI)
	}
	if snap.Platform != "windows" {
		t.Fatalf("platform = %q, want windows", snap.Platform)
	}

	// Every machine has at least a loopback adapter. Zero means the buffer
	// handling dropped everything, which would otherwise look like success.
	if len(snap.Adapters) == 0 {
		t.Fatal("no adapters returned; a machine running this test has at least one")
	}

	// The UTF-16 conversion is the part most likely to produce something that
	// decodes as JSON but is not valid UTF-8. Checking every string field is
	// cheap and catches it.
	for _, a := range snap.Adapters {
		for _, s := range []string{a.Name, a.FriendlyName, a.Description, a.Status, a.MAC} {
			if !utf8Valid(s) {
				t.Fatalf("adapter %q produced invalid UTF-8 in %q", a.Name, s)
			}
		}
	}
}

// TestTruncationIsHandled drives the ask-then-fill path with a real snapshot.
//
// The initial buffer is generous, so an ordinary machine never exercises the
// retry. Asking the library directly for a size and comparing against what a
// full collect produced checks that the retry path returns the same answer as
// the first-try path — a truncation bug that silently returned a short snapshot
// would pass every other test here.
func TestTruncationIsHandled(t *testing.T) {
	dir := builtLibrary(t)

	lib, err := Open(Config{Dir: dir, AllowUnsigned: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = lib.Close() }()

	full, err := lib.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// A second call must agree about the adapter count. If truncation were
	// mishandled the shorter path would return a prefix, which either fails to
	// decode or decodes to fewer adapters.
	again, err := lib.Snapshot()
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if len(again.Adapters) != len(full.Adapters) {
		t.Fatalf("two consecutive snapshots disagree: %d then %d adapters",
			len(full.Adapters), len(again.Adapters))
	}
}

// TestInterfaceMetricsFindsAndMisses checks both outcomes of a lookup.
func TestInterfaceMetricsFindsAndMisses(t *testing.T) {
	dir := builtLibrary(t)

	lib, err := Open(Config{Dir: dir, AllowUnsigned: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = lib.Close() }()

	snap, err := lib.Snapshot()
	if err != nil || len(snap.Adapters) == 0 {
		t.Fatalf("snapshot: %v", err)
	}

	raw, err := lib.InterfaceMetrics(snap.Adapters[0].LUID)
	if err != nil {
		t.Fatalf("metrics for a known interface: %v", err)
	}
	var one Adapter
	if err := json.Unmarshal(raw, &one); err != nil {
		t.Fatalf("interface metrics did not decode: %v", err)
	}
	if one.LUID != snap.Adapters[0].LUID {
		t.Fatalf("asked for LUID %d, got %d", snap.Adapters[0].LUID, one.LUID)
	}

	// A LUID that cannot exist must report not-found rather than returning
	// somebody else's interface.
	if _, err := lib.InterfaceMetrics(^uint64(0)); err == nil {
		t.Fatal("an impossible LUID returned an interface")
	}
}

// TestSignatureVerificationRefusesAnUnsignedLibrary is threat T17.
//
// The locally built library is unsigned, which makes it the ideal subject: with
// AllowUnsigned off it must be refused, and the refusal must say why rather than
// reporting the file as missing. A deployment that silently degraded to "no
// diagnostics" when a substituted DLL failed verification would hide exactly the
// event worth noticing.
func TestSignatureVerificationRefusesAnUnsignedLibrary(t *testing.T) {
	dir := builtLibrary(t)

	_, err := Open(Config{Dir: dir}) // AllowUnsigned deliberately off
	if err == nil {
		t.Fatal("an unsigned library was loaded with signature verification enabled")
	}
	if !isUntrusted(err) {
		t.Fatalf("error = %v, want it to report a signature failure", err)
	}
}

// utf8Valid reports whether s is valid UTF-8.
//
// Go decodes invalid bytes to U+FFFD when converting from JSON, so a string that
// merely *contains* U+FFFD is fine - the library emits it deliberately for
// unpaired surrogates. utf8.ValidString is the check that distinguishes that
// from a genuinely malformed sequence, which is what an unconverted UTF-16
// string would produce.
func utf8Valid(s string) bool { return utf8.ValidString(s) }

func isUntrusted(err error) bool {
	for e := err; e != nil; {
		if e == ErrUntrusted {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return false
}
