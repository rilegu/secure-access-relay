package sessions

import (
	"context"
	"errors"
	"sync"

	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// Errors returned when a stream cannot be served. These are deliberately
// distinct: "nobody is connected" and "the connected agent is already busy" are
// different problems with different fixes, and an operator must be able to tell
// them apart.
var (
	// ErrNoAgent means no endpoint agent is currently connected.
	ErrNoAgent = errors.New("sessions: no agent connected")

	// ErrAgentBusy means every connected agent already has a stream in flight.
	ErrAgentBusy = errors.New("sessions: agent already serving a stream")
)

// frameQueueDepth bounds how many frames may sit between an agent's read loop
// and its consumer.
//
// Bounded on purpose. An unbounded queue would let an agent that sends faster
// than the operator drains grow memory without limit, which is exactly the
// resource-exhaustion shape threat T12 covers. When the queue fills, the read
// loop stops reading and TCP back-pressure does the rest.
const frameQueueDepth = 8

// Agent is one connected endpoint agent.
//
// The relay holds no authority over an agent beyond forwarding frames to it. It
// cannot authorize anything and holds no key material — that separation is
// invariant 2, and it is what makes a compromised relay survivable.
//
// # Frame delivery
//
// Exactly one goroutine reads from the connection: [Agent.ReadLoop]. Everything
// else consumes frames through [Agent.Recv]. A single reader is what keeps frame
// ordering meaningful, and it is also the only way to satisfy the codec's rule
// that a Reader must not be used concurrently.
type Agent struct {
	// ID identifies the endpoint. Until enrollment exists this is derived from
	// the connection and carries no authority whatsoever: it is a label for logs,
	// not an authenticated identity.
	ID string

	Conn *transport.Conn

	frames chan proto.Frame

	mu      sync.Mutex
	readErr error
	// busy guards exclusive use. One stream at a time, for now; the cap is
	// enforced by the registry and lifted when multiplexing lands.
	busy bool
}

// NewAgent wraps a connected agent.
func NewAgent(id string, conn *transport.Conn) *Agent {
	return &Agent{
		ID:     id,
		Conn:   conn,
		frames: make(chan proto.Frame, frameQueueDepth),
	}
}

// ReadLoop reads frames from the connection until it fails or ctx is cancelled.
//
// It must be run exactly once per agent, and the agent is unusable after it
// returns. The returned error explains why the connection ended.
//
// Payloads are copied out of the codec buffer before being queued. This is not
// optional: [proto.Frame] payloads alias a buffer the Reader reuses on the next
// read, so a queued frame would otherwise be silently rewritten underneath its
// consumer.
func (a *Agent) ReadLoop(ctx context.Context) error {
	defer close(a.frames)

	for {
		f, err := a.Conn.R.ReadFrame()
		if err != nil {
			a.setReadErr(err)
			return err
		}

		queued := proto.Frame{
			Type:     f.Type,
			StreamID: f.StreamID,
			Payload:  append([]byte(nil), f.Payload...),
		}

		select {
		case a.frames <- queued:
		case <-ctx.Done():
			a.setReadErr(ctx.Err())
			return ctx.Err()
		}
	}
}

// Recv returns the next frame from the agent.
//
// It returns the read loop's error once the connection has ended, so a consumer
// learns why the agent went away rather than just that it did.
func (a *Agent) Recv(ctx context.Context) (proto.Frame, error) {
	select {
	case f, ok := <-a.frames:
		if !ok {
			return proto.Frame{}, a.ReadErr()
		}
		return f, nil
	case <-ctx.Done():
		return proto.Frame{}, ctx.Err()
	}
}

// Send writes a frame to the agent. Safe for concurrent use.
func (a *Agent) Send(t proto.Type, streamID uint32, payload []byte) error {
	return a.Conn.W.WriteFrame(t, streamID, payload)
}

// Close terminates the agent connection.
func (a *Agent) Close() error { return a.Conn.Close() }

// ReadErr reports why the read loop stopped, or nil if it has not.
func (a *Agent) ReadErr() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.readErr
}

func (a *Agent) setReadErr(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.readErr == nil {
		a.readErr = err
	}
}

// Registry tracks connected agents and hands out exclusive use of them.
//
// All state is guarded by one mutex. The critical sections are map lookups and a
// boolean flip, so finer-grained locking would add risk without buying anything
// measurable.
type Registry struct {
	mu     sync.Mutex
	agents map[string]*Agent
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{agents: make(map[string]*Agent)}
}

// Add registers a connected agent.
//
// If an agent with the same ID is already present it is evicted and returned so
// the caller can close it with a session_replaced reason. Replacing rather than
// rejecting is right for a reconnecting endpoint: after a network blip the old
// connection is a corpse the relay has not noticed yet, and refusing the new one
// would keep the endpoint unreachable until a timeout expires.
func (r *Registry) Add(a *Agent) (replaced *Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	replaced = r.agents[a.ID]
	r.agents[a.ID] = a
	return replaced
}

// Remove deregisters an agent, but only if the registry still holds that exact
// connection.
//
// The identity check matters: a reconnect may already have replaced this entry,
// and a late cleanup from the old connection must not evict its successor.
func (r *Registry) Remove(a *Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cur, ok := r.agents[a.ID]; ok && cur == a {
		delete(r.agents, a.ID)
	}
}

// Acquire takes exclusive use of a connected agent for one stream.
//
// Until resources and policy exist the operator does not name a device, so this
// picks any idle agent. That is a placeholder for a policy decision, not a design
// choice: once grants land, the caller names a device and the agent is looked up
// by ID.
func (r *Registry) Acquire() (*Agent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.agents) == 0 {
		return nil, ErrNoAgent
	}
	for _, a := range r.agents {
		if !a.busy {
			a.busy = true
			return a, nil
		}
	}
	return nil, ErrAgentBusy
}

// Release returns an agent to the idle pool.
func (r *Registry) Release(a *Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a.busy = false
}

// CloseAll terminates every connected agent, telling each one why.
//
// Used when the relay is shutting down. Closing the listeners alone is not
// enough: an already-connected agent would keep holding a session to a relay
// that is no longer serving, and would not start looking for a live one until
// something else forced it to notice.
//
// The agent list is copied under the lock and the connections are closed outside
// it. Holding a mutex across network I/O would let one unresponsive peer stall
// every other caller of the registry.
func (r *Registry) CloseAll(reason proto.Reason) {
	r.mu.Lock()
	agents := make([]*Agent, 0, len(r.agents))
	for _, a := range r.agents {
		agents = append(agents, a)
	}
	r.mu.Unlock()

	for _, a := range agents {
		// Best effort: the peer may already be gone, and there is nothing useful
		// to do about it during shutdown.
		_ = a.Send(proto.TypeError, 0, []byte(reason))
		_ = a.Close()
	}
}

// Count reports how many agents are connected. For status output and tests.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.agents)
}

// ReasonFor maps a registry error onto the reason code sent to the operator.
//
// Both cases are availability conditions, never authorization ones. Reporting
// either as policy_denied would tell an operator they lack permission when the
// resource is merely unreachable.
func ReasonFor(err error) proto.Reason {
	switch {
	case errors.Is(err, ErrNoAgent):
		return proto.ReasonNoAgent
	case errors.Is(err, ErrAgentBusy):
		return proto.ReasonLimitStreamsExceeded
	default:
		return proto.ReasonShutdown
	}
}
