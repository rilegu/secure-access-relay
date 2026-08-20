// Package relay accepts connections from endpoint agents and from operators and
// joins authorized pairs of them.
//
// The relay is the component most exposed to the network and therefore the one
// trusted with the least authority. It holds no signing key, evaluates no
// policy, and cannot decide that a stream may be opened — it forwards frames
// between two peers and nothing more. A compromised relay must not be able to
// reach an endpoint service, which is why the agent verifies authorization
// itself rather than believing what the relay tells it (invariant 2, threat T2).
//
// # Not secure yet
//
// This build has no transport encryption, no peer authentication, and no
// authorization. Anything that can reach the operator port gets a stream. It is
// a development scaffold for the data path, and must not be exposed to an
// untrusted network.
package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/relay/sessions"
	"github.com/rilegu/secure-access-relay/internal/relay/streams"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// Config configures a relay server.
type Config struct {
	// AgentAddr is where endpoint agents connect.
	AgentAddr string

	// OperatorAddr is where operator clients connect.
	//
	// Two listeners rather than one, because until a handshake exists the relay
	// needs some way to tell an agent from an operator. Port separation is the
	// simplest honest answer, and it is replaced by the HELLO/AUTH exchange once
	// peers can identify themselves cryptographically.
	OperatorAddr string

	Logger *slog.Logger
}

// Server is a running relay.
type Server struct {
	cfg      Config
	log      *slog.Logger
	registry *sessions.Registry

	// nextStreamID assigns stream identifiers. Monotonic and never reused within
	// the process, so a stream ID in a log line refers to exactly one stream.
	nextStreamID atomic.Uint32

	// listeners are tracked so Shutdown can close them and unblock the accept
	// loops, which have no other way to be interrupted.
	mu        sync.Mutex
	listeners []net.Listener
	closed    bool

	// ready is closed once both listeners are bound. Callers that need to know
	// where the server ended up - anything binding port 0 - must wait on this
	// first, because the bound address does not exist until Run has started.
	ready chan struct{}
}

// New creates a relay server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		registry: sessions.NewRegistry(),
		ready:    make(chan struct{}),
	}
}

// Run starts both listeners and blocks until ctx is cancelled or a listener
// fails.
//
// Addrs reports the bound addresses once Run has started listening, which is how
// tests bind to port 0 and still find out where the server ended up.
func (s *Server) Run(ctx context.Context) error {
	agentLn, err := s.listen(s.cfg.AgentAddr)
	if err != nil {
		return fmt.Errorf("agent listener: %w", err)
	}
	operatorLn, err := s.listen(s.cfg.OperatorAddr)
	if err != nil {
		_ = agentLn.Close()
		return fmt.Errorf("operator listener: %w", err)
	}

	// Both listeners are bound; the addresses are now readable.
	close(s.ready)

	s.log.Info("relay listening",
		"agent_addr", agentLn.Addr().String(),
		"operator_addr", operatorLn.Addr().String(),
		"secure", false, // stated explicitly so it cannot be assumed otherwise
	)

	// Cancellation closes the listeners, which is what makes the accept loops
	// return. Accept has no context-aware form.
	go func() {
		<-ctx.Done()
		s.Shutdown()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.acceptAgents(ctx, agentLn) }()
	go func() { defer wg.Done(); s.acceptOperators(ctx, operatorLn) }()
	wg.Wait()

	return ctx.Err()
}

// Ready is closed once both listeners are bound and the addresses are readable.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// AgentCount reports how many endpoint agents are connected.
func (s *Server) AgentCount() int { return s.registry.Count() }

// AgentAddr and OperatorAddr report the bound addresses. Valid only after Ready
// is closed.
func (s *Server) AgentAddr() string    { return s.boundAddr(0) }
func (s *Server) OperatorAddr() string { return s.boundAddr(1) }

func (s *Server) boundAddr(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i >= len(s.listeners) {
		return ""
	}
	return s.listeners[i].Addr().String()
}

func (s *Server) listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()
	return ln, nil
}

// Shutdown stops accepting new connections and closes the ones already
// established.
//
// Connected agents are told the relay is shutting down rather than being left
// attached to it. An agent that keeps a session open to a stopped relay is
// unreachable without being aware of it, and will not look for a live relay
// until something forces the issue.
func (s *Server) Shutdown() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	listeners := append([]net.Listener(nil), s.listeners...)
	s.mu.Unlock()

	for _, ln := range listeners {
		_ = ln.Close()
	}
	s.registry.CloseAll(proto.ReasonShutdown)
}

// acceptAgents handles the endpoint-agent listener.
func (s *Server) acceptAgents(ctx context.Context, ln net.Listener) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.stopping(ctx, err) {
				return
			}
			s.log.Warn("agent accept failed", "error", err)
			continue
		}
		go s.serveAgent(ctx, nc)
	}
}

// serveAgent registers a connected agent and drives its read loop.
//
// The agent identity here is derived from the remote address and carries no
// authority at all; it exists so log lines can be correlated. Real identity
// arrives with enrollment and mutual TLS. Nothing in this build should be read as
// authenticating anything.
func (s *Server) serveAgent(ctx context.Context, nc net.Conn) {
	conn := transport.NewConn(nc)
	agent := sessions.NewAgent(nc.RemoteAddr().String(), conn)

	if replaced := s.registry.Add(agent); replaced != nil {
		// A reconnect from the same endpoint. Tell the old connection why before
		// dropping it, so the far end logs a cause rather than a bare EOF.
		s.log.Info("replacing existing agent session", "agent_id", replaced.ID)
		_ = replaced.Send(proto.TypeError, 0, []byte(proto.ReasonSessionReplaced))
		_ = replaced.Close()
	}
	s.log.Info("agent connected", "agent_id", agent.ID, "agents", s.registry.Count())

	defer func() {
		s.registry.Remove(agent)
		_ = agent.Close()
		s.log.Info("agent disconnected", "agent_id", agent.ID, "agents", s.registry.Count())
	}()

	// One read loop owns the connection for its whole lifetime. Everything that
	// needs frames from this agent takes them from the queue it fills, which is
	// what keeps the connection persistent across successive streams.
	if err := agent.ReadLoop(ctx); err != nil && !s.stopping(ctx, err) {
		s.log.Debug("agent read loop ended", "agent_id", agent.ID, "error", err)
	}
}

// acceptOperators handles the operator listener. One accepted connection is one
// stream request.
func (s *Server) acceptOperators(ctx context.Context, ln net.Listener) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.stopping(ctx, err) {
				return
			}
			s.log.Warn("operator accept failed", "error", err)
			continue
		}
		go s.serveOperator(ctx, nc)
	}
}

// serveOperator pairs one operator connection with an agent and forwards the
// stream.
func (s *Server) serveOperator(ctx context.Context, nc net.Conn) {
	op := transport.NewConn(nc)

	// refuse reports why a stream cannot be served and closes cleanly.
	//
	// The drain is what makes the reason arrive. The operator has usually already
	// sent a request by this point; closing on top of those unread bytes would
	// reset the connection and destroy the ERROR frame written just above, so the
	// operator would see a bare connection failure instead of the actual cause.
	refuse := func(reason proto.Reason) {
		_ = op.W.WriteError(reason)
		_ = op.DrainAndClose(2 * time.Second)
	}
	defer func() { _ = op.Close() }()

	streamID := s.nextStreamID.Add(1)
	log := s.log.With("stream_id", streamID, "operator", nc.RemoteAddr().String())

	agent, err := s.registry.Acquire()
	if err != nil {
		// Deny with a reason the operator can act on, and do it before any bytes
		// move. Note this is an availability failure, not an authorization one:
		// see sessions.ReasonFor.
		reason := sessions.ReasonFor(err)
		log.Info("stream refused", "reason", reason.String())
		refuse(reason)
		return
	}
	defer s.registry.Release(agent)

	log = log.With("agent_id", agent.ID)

	// Ask the agent to open the stream. The payload names the resource; until a
	// resource registry exists the agent uses its single configured target and
	// ignores this value.
	if err := agent.Send(proto.TypeOpenStream, streamID, nil); err != nil {
		log.Warn("open stream failed", "error", err)
		refuse(proto.ReasonNoAgent)
		return
	}

	// Wait for the agent to confirm it reached the target, bounded so that an
	// agent which never answers cannot hold the operator open indefinitely.
	ackCtx, cancelAck := context.WithTimeout(ctx, proto.DialTimeout+time.Second)
	ack, err := awaitStreamAck(ackCtx, agent, streamID)
	cancelAck()
	if err != nil {
		log.Warn("no response to open stream", "error", err)
		// The agent may already have opened its side. Tell it to let go, or it
		// would sit holding a target connection for a stream nobody will drive.
		_ = agent.Send(proto.TypeCloseStream, streamID, []byte(proto.ReasonShutdown))
		refuse(proto.ReasonNoAgent)
		return
	}

	switch ack.Type {
	case proto.TypeStreamOK:
		// The agent connected to its target. Proceed.
	case proto.TypeCloseStream, proto.TypeError:
		// The agent refused. Its reason is forwarded verbatim: the operator needs
		// to know whether the target was unreachable or the request was denied,
		// and only the agent knows which. Collapsing these into one code would
		// leave an operator unable to tell "you may not" from "it is down".
		reason := proto.Reason(ack.Payload)
		log.Info("agent refused stream", "reason", reason.String())
		refuse(reason)
		return
	default:
		log.Warn("unexpected response to open stream", "type", ack.Type.String())
		_ = agent.Send(proto.TypeCloseStream, streamID, []byte(proto.ReasonProtocolMalformedFrame))
		refuse(proto.ReasonProtocolMalformedFrame)
		return
	}

	start := time.Now()
	log.Info("stream opened")

	reason, stats := streams.Forward(ctx, streams.ConnPeer{Conn: op}, agent, streamID)

	// The shape of an audit record: what happened, how much, how long, and why it
	// ended. Payload contents are deliberately absent (invariant 7).
	log.Info("stream closed",
		"reason", reason.String(),
		"bytes_to_agent", stats.ToAgent,
		"bytes_to_operator", stats.ToOperator,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

// stopping reports whether an accept error means the server is shutting down
// rather than something worth logging as a failure.
func (s *Server) stopping(ctx context.Context, err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return ctx.Err() != nil
}

// awaitStreamAck waits for the agent's response to OPEN_STREAM for one specific
// stream.
//
// Frames belonging to other streams are discarded rather than accepted as the
// answer. This is not defensive tidying: an agent's connection is long-lived and
// a stream that has just finished can still have a CLOSE_STREAM in flight. Taking
// the first frame that arrives would read that leftover as this stream's reply,
// report a completed stream as a refusal, and leave the agent holding a target
// connection for a stream the relay has already given up on. The two ends then
// disagree about which stream is live, and every subsequent stream is forwarded
// into a handler that is busy discarding it.
func awaitStreamAck(ctx context.Context, agent *sessions.Agent, streamID uint32) (proto.Frame, error) {
	for {
		f, err := agent.Recv(ctx)
		if err != nil {
			return proto.Frame{}, err
		}
		if f.StreamID == streamID {
			return f, nil
		}
		// Stale frame from an earlier stream. Dropping it here is what keeps the
		// two ends in step.
	}
}
