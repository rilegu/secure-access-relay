package netwatch

import (
	"context"
	"testing"
	"time"
)

// TestFingerprintIsStable checks that reading the same unchanged machine twice
// produces the same value.
//
// This is the whole basis of the portable watcher. If the fingerprint varied on
// its own — because the operating system reordered interfaces, say — every poll
// would report a change, and a reconnect loop woken constantly is worse than one
// never woken at all.
func TestFingerprintIsStable(t *testing.T) {
	first := addressFingerprint()
	for range 20 {
		if got := addressFingerprint(); got != first {
			t.Fatalf("fingerprint changed without the network changing:\n  %q\n  %q", first, got)
		}
	}
}

// TestFingerprintExcludesLoopback checks that the always-present address is not
// part of the comparison.
//
// Loopback is up on every machine and never says anything about reachability, so
// including it would add noise to every fingerprint while never contributing a
// signal.
func TestFingerprintExcludesLoopback(t *testing.T) {
	fp := addressFingerprint()
	for _, s := range []string{"127.0.0.1", "::1"} {
		if contains(fp, s) {
			t.Errorf("fingerprint %q includes the loopback address %s", fp, s)
		}
	}
}

// TestNotifyCoalesces checks that a burst of changes wakes the consumer once.
//
// During a suspend/resume or an adapter reset the operating system reports
// several events in quick succession. The consumer acts identically on all of
// them — redial — so queueing five wakeups would mean four redundant dials.
func TestNotifyCoalesces(t *testing.T) {
	ch := make(chan struct{}, 1)

	// More sends than the buffer can hold. None may block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			notify(ch)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("notify blocked; a slow consumer must never stall the watcher")
	}

	if len(ch) != 1 {
		t.Fatalf("%d signals queued after a burst, want exactly 1", len(ch))
	}
}

// TestWatchClosesOnCancel checks the channel is closed so a consumer's range or
// select terminates rather than blocking forever.
func TestWatchClosesOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := Watch(ctx)
	cancel()

	select {
	case _, open := <-ch:
		if open {
			// A signal that arrived before cancellation took effect is fine; the
			// next receive must then see the close.
			select {
			case _, open := <-ch:
				if open {
					t.Fatal("the channel delivered a second signal after cancellation")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the channel was not closed after cancellation")
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the channel was not closed after cancellation")
	}
}

// TestWatchIsQuietWhenNothingChanges checks that a stable machine produces no
// signals.
//
// A watcher that fired spuriously would defeat the backoff it is meant to
// complement: every false wake cuts a growing delay short and puts the fleet
// back into the stampede the backoff exists to prevent.
func TestWatchIsQuietWhenNothingChanges(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	ch := Watch(ctx)

	// Well under PollInterval, so the portable watcher has not even sampled
	// twice. Any signal in this window is spurious.
	select {
	case _, open := <-ch:
		if open {
			t.Fatal("the watcher reported a change on a machine whose network did not change")
		}
	case <-time.After(200 * time.Millisecond):
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
