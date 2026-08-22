// Package authorization holds the relay's revocation check and its register of
// live streams.
//
// The relay makes no authorization decisions. What it does is enforce ones
// already made elsewhere: it asks whether a grant is still good before joining a
// stream, and it drops streams whose grant is revoked while they are running.
// Both are fast paths in front of the agent's authoritative check, never
// substitutes for it (invariant 2).
//
// # Why the interfaces are narrow
//
// Nothing here mentions the control plane's types. The relay resolves a grant
// through an interface it defines, exactly as it does for certificate
// verification, so the two package trees stay separable (ADR-0007) and a relay
// deployed apart from the control plane needs a different implementation rather
// than a different relay.
package authorization

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/rilegu/secure-access-relay/internal/proto"
)

// GrantState is everything the relay needs to know about an issued grant.
//
// Deliberately not the control plane's record. The relay has no business
// knowing a grant's policy, its byte budget, or who else holds one — it needs to
// know whether to proceed, and being handed more than that is how a component
// trusted with the least authority starts making decisions.
type GrantState struct {
	// Known reports whether the control plane has a record of this grant.
	//
	// An unknown grant with a valid signature is a serious signal: it means the
	// signing key produced something this control plane never issued. The relay
	// still refuses on its own, but the distinction belongs in the log.
	Known bool

	// Revoked reports whether the grant was explicitly revoked before expiry.
	Revoked bool

	// SessionID and UserID are carried for the audit record only.
	SessionID string
	UserID    string
}

// GrantChecker resolves a grant identifier to its current state.
type GrantChecker interface {
	CheckGrant(ctx context.Context, grantID string) (GrantState, error)
}

// Closer is the part of a stream this package needs: the ability to abort it
// with a reason.
//
// Reset rather than Close, because a revoked grant is not an orderly end. The
// operator must be interrupted, not allowed to finish sending.
type Closer interface {
	Reset(proto.Reason) error
}

// LiveStreams tracks running streams by the grant that authorized them.
//
// This is what makes revocation reach a session already in progress. Without it
// a revoked grant would stop the next stream and leave the current one running
// until it ended on its own — which is precisely the case revocation exists to
// handle, a credential believed to be compromised right now.
type LiveStreams struct {
	mu sync.Mutex

	// byGrant maps a grant identifier to the streams it authorized. A single
	// grant can authorize many streams at once: a browser opening six parallel
	// connections through one forward is six streams on one grant.
	byGrant map[string]map[uint64]*pair

	nextID atomic.Uint64
}

// pair is the two ends of one joined stream.
type pair struct {
	operator Closer
	agent    Closer
}

// NewLiveStreams returns an empty register.
func NewLiveStreams() *LiveStreams {
	return &LiveStreams{byGrant: make(map[string]map[uint64]*pair)}
}

// Add registers a joined stream and returns the function that deregisters it.
//
// The returned function must be deferred by the caller. A stream left in the
// register after it ended would make a later revocation try to reset a corpse —
// harmless in itself, but it would also make the count reported to an
// administrator wrong, and a revocation that claims to have dropped five
// sessions when it dropped none is worse than no report at all.
func (l *LiveStreams) Add(grantID string, operator, agent Closer) (release func()) {
	if grantID == "" {
		return func() {}
	}
	id := l.nextID.Add(1)

	l.mu.Lock()
	streams, ok := l.byGrant[grantID]
	if !ok {
		streams = make(map[uint64]*pair)
		l.byGrant[grantID] = streams
	}
	streams[id] = &pair{operator: operator, agent: agent}
	l.mu.Unlock()

	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if streams, ok := l.byGrant[grantID]; ok {
			delete(streams, id)
			if len(streams) == 0 {
				// The map entry goes too. A long-running relay that issued many
				// short grants would otherwise accumulate one empty map per grant
				// and never release them.
				delete(l.byGrant, grantID)
			}
		}
	}
}

// Terminate aborts every live stream opened under any of the named grants and
// reports how many it dropped.
//
// Both ends are reset. Dropping only the operator's side would leave the agent
// holding an open connection to the local service, which is the resource the
// revocation was trying to take away.
//
// Streams are collected under the lock and reset outside it: a Reset writes a
// frame, and one unresponsive peer must not stall a revocation affecting
// everybody else.
func (l *LiveStreams) Terminate(grantIDs []string, reason proto.Reason) int {
	var doomed []*pair

	l.mu.Lock()
	for _, id := range grantIDs {
		for _, p := range l.byGrant[id] {
			doomed = append(doomed, p)
		}
		// The entry is removed here rather than left to each stream's release
		// function, so a second revocation of the same grant does not report the
		// same streams again.
		delete(l.byGrant, id)
	}
	l.mu.Unlock()

	for _, p := range doomed {
		_ = p.operator.Reset(reason)
		_ = p.agent.Reset(reason)
	}
	return len(doomed)
}

// CountFor reports how many live streams a grant currently has, for status
// output and tests.
func (l *LiveStreams) CountFor(grantID string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.byGrant[grantID])
}

// Count reports the total number of live streams the relay is carrying.
func (l *LiveStreams) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	n := 0
	for _, streams := range l.byGrant {
		n += len(streams)
	}
	return n
}

// CheckerFunc adapts a plain function to GrantChecker.
//
// It exists so the composition root can wire the control plane's store to the
// relay without either package importing the other. The relay declares what it
// needs; whoever builds both supplies the three lines that connect them.
type CheckerFunc func(ctx context.Context, grantID string) (GrantState, error)

// CheckGrant implements GrantChecker.
func (f CheckerFunc) CheckGrant(ctx context.Context, grantID string) (GrantState, error) {
	return f(ctx, grantID)
}
