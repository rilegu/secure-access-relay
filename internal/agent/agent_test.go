package agent

import (
	"errors"
	"testing"

	"github.com/rilegu/secure-access-relay/internal/identity"
)

// TestValidateTarget guards invariant 4: a resource may only ever point at
// loopback.
//
// This is the single check standing between an authorization bug and lateral
// movement across the endpoint's network, so the rejected cases are enumerated
// deliberately rather than left to a general rule. Each one is a way an
// over-broad target has historically been introduced by accident.
func TestValidateTarget(t *testing.T) {
	accepted := []struct {
		name string
		addr string
	}{
		{"IPv4 loopback", "127.0.0.1:8080"},
		{"IPv4 loopback, alternate address in the /8", "127.5.5.5:8080"},
		{"IPv6 loopback", "[::1]:8080"},
		{"high port", "127.0.0.1:65535"},
	}
	for _, tc := range accepted {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := ValidateTarget(tc.addr); err != nil {
				t.Fatalf("ValidateTarget(%q) = %v, want nil", tc.addr, err)
			}
		})
	}

	rejected := []struct {
		name string
		addr string
		why  string
	}{
		{"private LAN address", "192.168.1.10:8080",
			"reaching another host on the subnet is exactly what this system exists not to do"},
		{"other private range", "10.0.0.5:22",
			"same reason; the RFC1918 ranges are not special-cased as safe"},
		{"public address", "93.184.216.34:80",
			"an agent must never become an outbound proxy to the internet"},
		{"all interfaces", "0.0.0.0:8080",
			"binds everything, and is not loopback"},
		{"localhost by name", "localhost:8080",
			"a name requires DNS, and DNS can be influenced; only literals are accepted"},
		{"arbitrary hostname", "internal.example.com:8080",
			"same reason, and this one is plainly remote"},
		{"no port", "127.0.0.1",
			"an implicit port could silently resolve to something unintended"},
		{"empty port", "127.0.0.1:",
			"an empty port is not an explicit one"},
		{"empty string", "",
			"unset configuration must fail, not default to something"},
		{"loopback-looking hostname", "127.0.0.1.evil.example.com:80",
			"a name that begins with digits is still a name"},
		{"IPv6 non-loopback", "[2001:db8::1]:8080",
			"IPv6 gets the same treatment as IPv4"},
	}
	for _, tc := range rejected {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			err := ValidateTarget(tc.addr)
			if err == nil {
				t.Fatalf("ValidateTarget(%q) = nil, want an error: %s", tc.addr, tc.why)
			}
			if !errors.Is(err, ErrTargetNotLoopback) {
				t.Fatalf("ValidateTarget(%q) = %v, want ErrTargetNotLoopback", tc.addr, err)
			}
		})
	}
}

// TestNewRejectsBadTarget checks that a bad target stops the agent being
// created at all.
//
// The failure has to happen at construction. A misconfigured allowlist must
// never produce a running agent that only refuses at stream time, because that
// turns a configuration error into something discovered during an incident.
func TestNewRejectsBadTarget(t *testing.T) {
	_, err := New(Config{
		RelayAddr: "127.0.0.1:1",
		Identity:  &identity.Identity{},
		Target:    "192.168.1.10:8080",
	})
	if !errors.Is(err, ErrTargetNotLoopback) {
		t.Fatalf("New with a LAN target returned %v, want ErrTargetNotLoopback", err)
	}
}

// TestNewRequiresIdentity checks that an agent cannot start without credentials.
//
// An unenrolled agent has no way to prove which device it is and would be refused
// by the relay during the TLS handshake anyway. Failing at construction turns a
// confusing connection error into a clear instruction to enroll.
func TestNewRequiresIdentity(t *testing.T) {
	if _, err := New(Config{RelayAddr: "127.0.0.1:1", Target: "127.0.0.1:8080"}); err == nil {
		t.Fatal("New succeeded without an identity")
	}
}
