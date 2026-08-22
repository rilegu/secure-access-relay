package backoff

import (
	"testing"
	"time"
)

// TestCeilingGrowsAndClamps checks the shape of the sequence.
func TestCeilingGrowsAndClamps(t *testing.T) {
	s := New(Policy{Initial: time.Second, Max: 8 * time.Second, Factor: 2})

	want := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		8 * time.Second, // clamped
		8 * time.Second,
	}
	for i, w := range want {
		if got := s.Ceiling(); got != w {
			t.Fatalf("attempt %d ceiling = %s, want %s", i, got, w)
		}
		s.Next()
	}
}

// TestCeilingSurvivesALongOutage is the overflow guard.
//
// The exponent grows without bound while a relay is down. Computing the ceiling
// with an integer shift would overflow into a negative delay after about sixty
// attempts, turning the backoff into a busy loop at exactly the moment it is
// most needed.
func TestCeilingSurvivesALongOutage(t *testing.T) {
	s := New(Policy{Initial: time.Second, Max: 30 * time.Second, Factor: 2})

	for range 10_000 {
		d := s.Next()
		if d < 0 {
			t.Fatalf("attempt %d produced a negative delay %s", s.Attempt(), d)
		}
		if d > 30*time.Second {
			t.Fatalf("attempt %d produced %s, above the %s maximum", s.Attempt(), d, 30*time.Second)
		}
	}
	if got := s.Ceiling(); got != 30*time.Second {
		t.Fatalf("ceiling after a long outage = %s, want the maximum", got)
	}
}

// TestDelaysAreWithinTheCeiling checks the invariant every caller relies on.
func TestDelaysAreWithinTheCeiling(t *testing.T) {
	s := New(Policy{Initial: 10 * time.Millisecond, Max: 200 * time.Millisecond, Factor: 2})

	for range 500 {
		ceiling := s.Ceiling()
		d := s.Next()
		if d < 0 || d > ceiling {
			t.Fatalf("delay %s is outside [0, %s]", d, ceiling)
		}
	}
}

// TestJitterDecorrelates is the property the package exists for.
//
// A fleet backing off must not arrive together. Two independent sequences that
// produced identical delays would mean every endpoint redialling in lockstep,
// which is the stampede this replaces. Compared as whole sequences rather than
// single samples, because two draws colliding once is ordinary.
func TestJitterDecorrelates(t *testing.T) {
	const attempts = 20

	sequence := func() [attempts]time.Duration {
		s := New(Policy{Initial: time.Second, Max: time.Minute, Factor: 2})
		var out [attempts]time.Duration
		for i := range out {
			out[i] = s.Next()
		}
		return out
	}

	a, b := sequence(), sequence()
	if a == b {
		t.Fatal("two independent backoff sequences were identical; the fleet would reconnect in lockstep")
	}

	// And the spread must be real, not a token wobble around the ceiling. With
	// full jitter, some delay in a long run should land in the lower half of its
	// interval.
	s := New(Policy{Initial: time.Second, Max: time.Second, Factor: 2})
	low := 0
	for range 200 {
		if s.Next() < 500*time.Millisecond {
			low++
		}
	}
	if low == 0 {
		t.Fatal("no delay fell in the lower half of the interval; the jitter is not full")
	}
}

// TestResetReturnsToTheStart checks that a recovered peer starts over.
func TestResetReturnsToTheStart(t *testing.T) {
	s := New(Policy{Initial: time.Second, Max: time.Minute, Factor: 2})
	for range 5 {
		s.Next()
	}
	if s.Ceiling() == time.Second {
		t.Fatal("the ceiling did not grow")
	}

	s.Reset()
	if got := s.Ceiling(); got != time.Second {
		t.Fatalf("ceiling after Reset = %s, want the initial %s", got, time.Second)
	}
	if s.Attempt() != 0 {
		t.Fatalf("attempt after Reset = %d, want 0", s.Attempt())
	}
}

// TestZeroPolicyIsUsable checks that a caller passing nothing gets sane values
// rather than a zero delay busy loop.
func TestZeroPolicyIsUsable(t *testing.T) {
	s := New(Policy{})
	if got := s.Ceiling(); got != DefaultInitial {
		t.Fatalf("zero policy initial = %s, want %s", got, DefaultInitial)
	}
	for range 50 {
		if d := s.Next(); d > DefaultMax {
			t.Fatalf("zero policy produced %s, above %s", d, DefaultMax)
		}
	}
}

// TestDegenerateFactorIsCorrected checks that a misconfiguration does not
// produce a retry loop with no growth.
//
// Corrected rather than rejected: a bad backoff constant should not stop an
// agent from starting, because the agent not running is worse than the agent
// retrying slightly wrong.
func TestDegenerateFactorIsCorrected(t *testing.T) {
	s := New(Policy{Initial: time.Second, Max: time.Minute, Factor: 0.5})
	first := s.Ceiling()
	s.Next()
	if s.Ceiling() <= first {
		t.Fatal("a factor below 1 was accepted; the delay would never grow")
	}
}

// TestInitialAboveMaxIsClamped checks the other misconfiguration.
func TestInitialAboveMaxIsClamped(t *testing.T) {
	s := New(Policy{Initial: time.Hour, Max: time.Second, Factor: 2})
	if got := s.Ceiling(); got != time.Second {
		t.Fatalf("ceiling = %s, want it clamped to the %s maximum", got, time.Second)
	}
}
