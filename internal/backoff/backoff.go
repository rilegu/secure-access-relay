// Package backoff paces retries so a fleet does not reconnect in lockstep.
//
// # Why this exists
//
// A fixed retry interval is fine for one client and pathological for a fleet.
// When a relay restarts, every endpoint that was connected to it notices within
// a keepalive period and redials — at the same instant, and then again at the
// same instant, forever. The relay comes back up into a synchronised stampede
// that it cannot serve, which drops the connections again, which resynchronises
// everybody. A restart becomes an outage.
//
// Two things fix that, and both are needed:
//
//   - **Growth.** Each failed attempt waits longer, so a persistent outage costs
//     the relay a trickle rather than a flood.
//   - **Jitter.** Growth alone keeps the fleet synchronised: everybody backs off
//     to the same delay and arrives together at the longer interval. Randomising
//     the wait is what actually decorrelates the herd.
//
// # Full jitter
//
// The delay is a uniform random value in [0, cap], where cap grows
// exponentially. This is "full jitter", and it is chosen over the obvious
// alternative of cap ± a small percentage because a narrow band around a shared
// value is still a shared value: a thousand endpoints jittering ±10% around 30
// seconds all arrive inside a six-second window. Full jitter spreads them across
// the whole interval.
//
// The cost is that an individual retry can be very short even late in a long
// outage. That is the right trade for this system: a short wait costs one dial
// against a relay that is either up — in which case the client should reconnect
// promptly — or down, in which case a refused TCP connection is cheap.
package backoff

import (
	"math"
	"math/rand/v2"
	"time"
)

// Defaults for reconnect loops. Exported so a caller can see what it is getting
// rather than passing zeros and hoping.
const (
	// DefaultInitial is the first delay's ceiling. Short, because the common case
	// is a relay that restarted and is already back.
	DefaultInitial = 500 * time.Millisecond

	// DefaultMax bounds the wait. Half a minute is long enough to protect a
	// recovering relay and short enough that nobody watching an endpoint
	// reconnect concludes it has given up.
	DefaultMax = 30 * time.Second

	// DefaultFactor is how fast the ceiling grows. Doubling reaches DefaultMax
	// from DefaultInitial in six attempts.
	DefaultFactor = 2.0
)

// Policy describes how delays grow. The zero value is usable and means the
// defaults above.
type Policy struct {
	Initial time.Duration
	Max     time.Duration
	Factor  float64
}

// withDefaults fills unset fields, so a caller can specify only what it cares
// about and a zero Policy still behaves sensibly.
func (p Policy) withDefaults() Policy {
	if p.Initial <= 0 {
		p.Initial = DefaultInitial
	}
	if p.Max <= 0 {
		p.Max = DefaultMax
	}
	if p.Factor <= 1 {
		// A factor of 1 or less would never grow, which defeats the purpose. It
		// is corrected rather than rejected: a misconfigured backoff should not
		// stop an agent from starting.
		p.Factor = DefaultFactor
	}
	if p.Initial > p.Max {
		p.Initial = p.Max
	}
	return p
}

// State tracks one retry sequence. It is not safe for concurrent use; each
// reconnect loop owns its own.
type State struct {
	policy  Policy
	attempt int
}

// New returns a State that has not yet failed.
func New(p Policy) *State {
	return &State{policy: p.withDefaults()}
}

// Next reports how long to wait before the next attempt, and advances the
// sequence.
func (s *State) Next() time.Duration {
	ceiling := s.ceiling()
	s.attempt++

	// Uniform over the whole interval, not a band around the top of it. See the
	// package doc for why the narrow-band version does not decorrelate anything.
	if ceiling <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(ceiling) + 1))
}

// Ceiling reports the current upper bound without advancing, for logging. An
// operator reading "retry_within=8s" learns more than one reading a single
// sampled delay, because the sample says nothing about the trend.
func (s *State) Ceiling() time.Duration { return s.ceiling() }

func (s *State) ceiling() time.Duration {
	if s.attempt <= 0 {
		return s.policy.Initial
	}

	// Computed in float64 and clamped, because the exponent grows without bound
	// during a long outage and an int64 shift would overflow into a negative
	// delay — which would turn the backoff into a busy loop at exactly the moment
	// it matters most.
	grown := float64(s.policy.Initial) * math.Pow(s.policy.Factor, float64(s.attempt))
	if grown >= float64(s.policy.Max) || math.IsInf(grown, 1) {
		return s.policy.Max
	}
	return time.Duration(grown)
}

// Attempt reports how many failures have been recorded, for logging.
func (s *State) Attempt() int { return s.attempt }

// Reset returns to the initial delay.
//
// Called after a *successful* connection, not after a successful dial. The
// distinction matters: a peer that connects and is immediately refused — a
// revoked certificate, say — would otherwise reset its backoff on every attempt
// and retry forever at the initial interval, which is the stampede this package
// exists to prevent.
func (s *State) Reset() { s.attempt = 0 }
