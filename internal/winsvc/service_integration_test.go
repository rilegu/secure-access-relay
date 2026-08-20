//go:build windows && windows_integration

package winsvc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These tests register a real service with the service control manager. They
// need Administrator rights and they change machine state, which is why they sit
// behind a build tag and belong on a disposable VM:
//
//	go test -tags=windows_integration ./internal/winsvc/
//
// The service name is deliberately distinct from the product's, so a failed run
// cannot leave something behind that looks like a real installation.
const testServiceName = "SecureAccessRelayTestService"

func TestServiceLifecycle(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, _ = filepath.Abs(exe)

	// Clean up first, in case a previous run died before its own cleanup.
	_ = Uninstall(testServiceName)

	cfg := Config{
		Name:             testServiceName,
		DisplayName:      "Secure Access Relay test service",
		Description:      "Temporary service created by an integration test.",
		ExePath:          exe,
		Args:             []string{"-test.run=TestNothing"},
		DelayedAutoStart: true,
		RestartOnFailure: true,
	}

	if err := Install(cfg); err != nil {
		if errors.Is(err, ErrAccessDenied) {
			t.Skip("needs Administrator rights")
		}
		t.Fatalf("install: %v", err)
	}
	t.Cleanup(func() { _ = Uninstall(testServiceName) })

	state, err := Status(testServiceName)
	if err != nil {
		t.Fatalf("status after install: %v", err)
	}
	if state != StateStopped {
		t.Fatalf("state after install = %q, want %q", state, StateStopped)
	}

	// Installing twice must be refused rather than silently reconfiguring an
	// existing service, which would let an upgrade change a machine's
	// configuration without saying so.
	if err := Install(cfg); !errors.Is(err, ErrAlreadyInstalled) {
		t.Fatalf("second install returned %v, want ErrAlreadyInstalled", err)
	}

	if err := Uninstall(testServiceName); err != nil {
		t.Fatalf("uninstall: %v", err)
	}

	// Every operation on a missing service must report it as missing rather than
	// as some generic failure.
	if _, err := Status(testServiceName); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("status after uninstall returned %v, want ErrNotInstalled", err)
	}
	if err := Uninstall(testServiceName); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("second uninstall returned %v, want ErrNotInstalled", err)
	}
	if err := Start(testServiceName); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("start after uninstall returned %v, want ErrNotInstalled", err)
	}
	if err := Stop(testServiceName, 5*time.Second); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("stop after uninstall returned %v, want ErrNotInstalled", err)
	}
}

// TestNothing exists so the installed service has something harmless to run.
func TestNothing(t *testing.T) {}
