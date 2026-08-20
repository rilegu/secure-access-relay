package operator

import (
	"errors"
	"testing"
)

// TestValidateListenAddr checks that a forward can only be published to the
// operator's own machine.
//
// A forward carries someone else's private service. Binding it to a routable
// interface would republish that service onto the operator's network — turning a
// scoped, audited grant into an open port that nobody authorized and no audit
// record covers.
func TestValidateListenAddr(t *testing.T) {
	accepted := []string{
		"127.0.0.1:18080",
		"127.0.0.1:0", // port 0 is fine: the OS picks, and it is still loopback
		"[::1]:18080",
	}
	for _, addr := range accepted {
		t.Run("accept/"+addr, func(t *testing.T) {
			if err := validateListenAddr(addr); err != nil {
				t.Fatalf("validateListenAddr(%q) = %v, want nil", addr, err)
			}
		})
	}

	rejected := []struct {
		addr string
		why  string
	}{
		{"0.0.0.0:18080", "binds every interface, publishing the forward to the network"},
		{":18080", "the empty host also means every interface, and is the easiest version of this mistake to make"},
		{"192.168.1.20:18080", "a specific LAN address is still reachable by other hosts"},
		{"localhost:18080", "a name depends on resolution; only literal loopback is accepted"},
		{"127.0.0.1", "no port"},
		{"", "unset configuration must fail rather than default"},
	}
	for _, tc := range rejected {
		t.Run("reject/"+tc.addr, func(t *testing.T) {
			err := validateListenAddr(tc.addr)
			if err == nil {
				t.Fatalf("validateListenAddr(%q) = nil, want an error: %s", tc.addr, tc.why)
			}
			if !errors.Is(err, ErrListenNotLoopback) {
				t.Fatalf("validateListenAddr(%q) = %v, want ErrListenNotLoopback", tc.addr, err)
			}
		})
	}
}

// TestNewRejectsNonLoopbackListen checks the failure happens at construction
// rather than at first connection.
func TestNewRejectsNonLoopbackListen(t *testing.T) {
	_, err := New(Config{RelayAddr: "127.0.0.1:1", ListenAddr: "0.0.0.0:18080"})
	if !errors.Is(err, ErrListenNotLoopback) {
		t.Fatalf("New with a wildcard listen address returned %v, want ErrListenNotLoopback", err)
	}
}
