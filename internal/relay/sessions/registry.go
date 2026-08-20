package sessions

import (
	"errors"
	"sync"

	"github.com/rilegu/secure-access-relay/internal/mux"
	"github.com/rilegu/secure-access-relay/internal/proto"
)

// ErrNoAgent means no endpoint agent is connected for the requested device.
//
// It is an availability condition, never an authorization one. Reporting it as a
// denial would tell an operator they lack permission when the endpoint is merely
// offline, sending them to argue about access they already have.
var ErrNoAgent = errors.New("sessions: no agent connected for device")

// Registry tracks connected endpoint agents by device.
//
// Concurrency limits are not enforced here. Each session carries its own stream
// cap, negotiated at the handshake and enforced by the multiplexer, so a second
// place to count would be a second place to get it wrong.
type Registry struct {
	mu     sync.Mutex
	agents map[string]*mux.Session
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{agents: make(map[string]*mux.Session)}
}

// Add registers an agent session for a device.
//
// If that device already has a session it is evicted and returned, so the caller
// can close it with a session_replaced reason. Replacing rather than rejecting is
// right for a reconnecting endpoint: after a network blip the old session is a
// corpse the relay has not noticed yet, and refusing the new one would keep the
// endpoint unreachable until a timeout expires.
func (r *Registry) Add(deviceID string, s *mux.Session) (replaced *mux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()

	replaced = r.agents[deviceID]
	r.agents[deviceID] = s
	return replaced
}

// Remove deregisters an agent, but only if the registry still holds that exact
// session.
//
// The identity check matters: a reconnect may already have replaced this entry,
// and a late cleanup from the old session must not evict its successor.
func (r *Registry) Remove(deviceID string, s *mux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cur, ok := r.agents[deviceID]; ok && cur == s {
		delete(r.agents, deviceID)
	}
}

// Get returns the live session for a device.
//
// A session that has already ended is treated as absent and removed, so a caller
// never receives one it cannot use.
func (r *Registry) Get(deviceID string) (*mux.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.agents[deviceID]
	if !ok {
		return nil, ErrNoAgent
	}
	select {
	case <-s.Done():
		delete(r.agents, deviceID)
		return nil, ErrNoAgent
	default:
	}
	return s, nil
}

// Count reports how many agents are connected. For status output and tests.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.agents)
}

// Devices lists the connected device identifiers.
func (r *Registry) Devices() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.agents))
	for id := range r.agents {
		out = append(out, id)
	}
	return out
}

// CloseAll terminates every connected agent, telling each one why.
//
// Used when the relay shuts down. Closing the listener alone is not enough: an
// already-connected agent would keep holding a session to a relay that is no
// longer serving, and would not look for a live one until something forced it to
// notice.
//
// Sessions are copied under the lock and closed outside it, so one unresponsive
// peer cannot stall every other caller of the registry.
func (r *Registry) CloseAll(reason proto.Reason) {
	r.mu.Lock()
	sessions := make([]*mux.Session, 0, len(r.agents))
	for _, s := range r.agents {
		sessions = append(sessions, s)
	}
	r.agents = map[string]*mux.Session{}
	r.mu.Unlock()

	for _, s := range sessions {
		_ = s.Close(reason)
	}
}
