// Package relay accepts connections from endpoint agents and from operators and
// joins authorized pairs of them.
//
// The relay is the component most exposed to the network and therefore the one
// trusted with the least authority. It holds no signing key, evaluates no policy,
// and cannot decide that a stream may be opened — it joins two streams and
// forwards bytes between them. A compromised relay must not be able to reach an
// endpoint service, which is why the agent verifies authorization itself rather
// than believing what the relay tells it (invariant 2, threat T2).
//
// # Not secure yet
//
// This build has no transport encryption and no authorization. The identities in
// a handshake are claims that nothing verifies: any peer may say it is any
// device. It is a development scaffold and must not be exposed to an untrusted
// network.
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

	"github.com/rilegu/secure-access-relay/internal/bridge"
	"github.com/rilegu/secure-access-relay/internal/mux"
	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/relay/sessions"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// Config configures a relay server.
type Config struct {
	// Addr is the single address both agents and operators connect to.
	//
	// One listener, not two: a peer states its role in HELLO, so the relay no
	// longer needs port separation to tell them apart.
	Addr string

	// MaxStreams caps concurrent streams per session.
	MaxStreams uint32

	// KeepAlive and IdleTimeout govern liveness. A dead peer that never sent a
	// FIN is only detectable by silence, so these are what stop the registry
	// filling with sessions to hosts that are gone.
	KeepAlive   time.Duration
	IdleTimeout time.Duration

	Logger *slog.Logger
}

// Server is a running relay.
type Server struct {
	cfg      Config
	log      *slog.Logger
	registry *sessions.Registry

	nextSession atomic.Uint64

	mu     sync.Mutex
	ln     net.Listener
	closed bool

	ready chan struct{}
}

// New creates a relay server.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = proto.MaxStreamsPerConnection
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = proto.IdleTimeout
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = cfg.IdleTimeout / 3
	}
	return &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		registry: sessions.NewRegistry(),
		ready:    make(chan struct{}),
	}
}

// Run listens and serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Addr, err)
	}

	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	close(s.ready)

	s.log.Info("relay listening",
		"addr", ln.Addr().String(),
		"max_streams", s.cfg.MaxStreams,
		"secure", false, // stated explicitly so it cannot be assumed otherwise
	)

	// Cancellation closes the listener, which is what makes Accept return. There
	// is no context-aware form of Accept.
	go func() {
		<-ctx.Done()
		s.Shutdown()
	}()

	for {
		nc, err := ln.Accept()
		if err != nil {
			if s.stopping(ctx, err) {
				return ctx.Err()
			}
			s.log.Warn("accept failed", "error", err)
			continue
		}
		go s.serve(ctx, nc)
	}
}

// Ready is closed once the listener is bound and Addr is readable.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// Addr reports the bound address. Valid only after Ready is closed.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return s.cfg.Addr
	}
	return s.ln.Addr().String()
}

// AgentCount reports how many endpoint agents are connected.
func (s *Server) AgentCount() int { return s.registry.Count() }

// Shutdown stops accepting and closes established agent sessions.
func (s *Server) Shutdown() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	ln := s.ln
	s.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	s.registry.CloseAll(proto.ReasonShutdown)
}

// serve handshakes one connection and dispatches on the role it claims.
func (s *Server) serve(ctx context.Context, nc net.Conn) {
	conn := transport.NewConn(nc)

	h, err := mux.Accept(ctx, conn, mux.Config{
		MaxFramePayload: proto.MaxFramePayload,
		InitialWindow:   proto.InitialWindow,
		MaxStreams:      s.cfg.MaxStreams,
		KeepAlive:       s.cfg.KeepAlive,
		IdleTimeout:     s.cfg.IdleTimeout,
		Logger:          s.log,
	})
	if err != nil {
		s.log.Debug("handshake failed", "peer", nc.RemoteAddr().String(), "error", err)
		_ = conn.Close()
		return
	}

	switch h.Hello.Role {
	case proto.RoleAgent:
		s.serveAgent(ctx, h)
	case proto.RoleOperator:
		s.serveOperator(ctx, h)
	default:
		// Accept validates the role, so reaching here would mean the validation
		// and this switch have drifted apart.
		_ = h.Refuse(proto.ReasonProtocolMalformedFrame)
	}
}

// serveAgent registers an endpoint agent and holds its session open.
//
// The device identity here is a claim and nothing more. Until enrollment and
// mutual TLS exist, any peer can assert any device ID; it is used for routing and
// log correlation, and must not be read as authentication.
func (s *Server) serveAgent(ctx context.Context, h *mux.Handshake) {
	deviceID := h.Auth.DeviceID
	if deviceID == "" {
		// A device that will not name itself cannot be routed to.
		_ = h.Refuse(proto.ReasonAuthFailed)
		return
	}

	sessionID := s.newSessionID("age")
	sess, err := h.Admit(sessionID)
	if err != nil {
		s.log.Warn("failed to admit agent", "device_id", deviceID, "error", err)
		return
	}

	if replaced := s.registry.Add(deviceID, sess); replaced != nil {
		s.log.Info("replacing existing agent session", "device_id", deviceID)
		_ = replaced.Close(proto.ReasonSessionReplaced)
	}

	log := s.log.With("session_id", sessionID, "device_id", deviceID)
	log.Info("agent connected", "agents", s.registry.Count())

	defer func() {
		s.registry.Remove(deviceID, sess)
		_ = sess.Close(proto.ReasonShutdown)
		log.Info("agent disconnected", "agents", s.registry.Count(), "reason", reasonOf(sess))
	}()

	// The relay opens streams toward an agent and never accepts them from one, so
	// there is nothing to do here but hold the session until it ends.
	select {
	case <-sess.Done():
	case <-ctx.Done():
	}
}

// serveOperator joins an operator's streams to the agent it asked for.
func (s *Server) serveOperator(ctx context.Context, h *mux.Handshake) {
	deviceID := h.Auth.DeviceID
	if deviceID == "" {
		_ = h.Refuse(proto.ReasonAuthFailed)
		return
	}

	// Resolved before admitting, so an operator asking for an endpoint that is
	// not connected is told immediately rather than after a session exists.
	agentSess, err := s.registry.Get(deviceID)
	if err != nil {
		s.log.Info("operator refused",
			"device_id", deviceID, "user_id", h.Auth.UserID, "reason", proto.ReasonNoAgent.String())
		_ = h.Refuse(proto.ReasonNoAgent)
		return
	}

	sessionID := s.newSessionID("opr")
	sess, err := h.Admit(sessionID)
	if err != nil {
		s.log.Warn("failed to admit operator", "device_id", deviceID, "error", err)
		return
	}
	defer func() { _ = sess.Close(proto.ReasonShutdown) }()

	log := s.log.With(
		"session_id", sessionID,
		"device_id", deviceID,
		"user_id", h.Auth.UserID,
		"resource", h.Auth.Resource,
	)
	log.Info("operator connected")
	defer log.Info("operator disconnected")

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		st, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		wg.Add(1)
		go func(st *mux.Stream) {
			defer wg.Done()
			s.joinStream(ctx, log, st, agentSess, h.Auth.Resource)
		}(st)
	}
}

// joinStream opens a matching stream on the agent and bridges the two.
func (s *Server) joinStream(ctx context.Context, log *slog.Logger, op *mux.Stream, agentSess *mux.Session, resource string) {
	log = log.With("operator_stream", op.ID())

	openCtx, cancel := context.WithTimeout(ctx, proto.DialTimeout+time.Second)
	agentStream, err := agentSess.Open(openCtx)
	cancel()
	if err != nil {
		// The endpoint could not take another stream, or its session died. Either
		// way this is availability, not authorization, and the operator is told so
		// rather than being left waiting.
		reason := proto.ReasonNoAgent
		if errors.Is(err, mux.ErrTooManyStreams) || errors.Is(err, mux.ErrStreamRefused) {
			reason = proto.ReasonLimitStreamsExceeded
		}
		log.Info("could not open endpoint stream", "reason", reason.String(), "error", err)
		_ = op.Reset(reason)
		return
	}

	start := time.Now()
	log.Info("stream joined", "agent_stream", agentStream.ID(), "resource", resource)

	stats, joinErr := bridge.Join(op, agentStream)

	// The shape of an audit record: what happened, how much, how long, and why it
	// ended. Payload contents are deliberately absent (invariant 7).
	reason := proto.ReasonOK
	if joinErr != nil {
		reason = proto.ReasonShutdown
	}
	log.Info("stream closed",
		"reason", reason.String(),
		"bytes_to_agent", stats.AToB,
		"bytes_to_operator", stats.BToA,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

func (s *Server) newSessionID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, s.nextSession.Add(1))
}

// stopping reports whether an accept error means shutdown rather than a failure
// worth logging.
func (s *Server) stopping(ctx context.Context, err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return ctx.Err() != nil
}

// reasonOf renders why a session ended, for the closing audit line.
func reasonOf(sess *mux.Session) string {
	if err := sess.Err(); err != nil {
		return err.Error()
	}
	return proto.ReasonOK.String()
}
