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
// # Identity
//
// Every connection is mutual TLS. A peer's identity comes from its certificate,
// never from what it says about itself in the handshake: the certificate is
// signed by the deployment's authority and the claim is not. Where a peer states
// an identity that disagrees with its certificate, the connection is refused
// rather than reconciled.
//
// # Not finished
//
// There is still no authorization. An enrolled operator may reach any enrolled
// device, because policy and grants do not exist yet.
package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rilegu/secure-access-relay/internal/ca"

	"github.com/rilegu/secure-access-relay/internal/bridge"
	"github.com/rilegu/secure-access-relay/internal/mux"
	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/relay/sessions"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// Verifier confirms that a certificate belongs to a live enrolled identity.
//
// The relay holds this as an interface rather than importing the control plane,
// so that the two package trees stay separable (ADR-0007). A valid signature is
// not enough on its own: an identity can be revoked, or its certificate
// superseded by a later enrollment, and only the control plane knows.
type Verifier interface {
	VerifyEnrolled(cert *x509.Certificate) (ca.Identity, error)
}

// Config configures a relay server.
type Config struct {
	// Addr is the single address both agents and operators connect to.
	//
	// One listener, not two: a peer states its role in HELLO, so the relay no
	// longer needs port separation to tell them apart.
	Addr string

	// TLS is required. Without it the relay cannot establish who a peer is, and
	// every identity in the system would be a claim again.
	TLS *tls.Config

	// Verify resolves a peer certificate to an enrolled identity.
	Verify Verifier

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
//
// It returns an error rather than a server when TLS or verification is missing.
// A relay that accepted plaintext connections would silently undo the identity
// work, so it refuses to exist instead.
func New(cfg Config) (*Server, error) {
	if cfg.TLS == nil {
		return nil, errors.New("relay: refusing to start without TLS")
	}
	if cfg.Verify == nil {
		return nil, errors.New("relay: refusing to start without a certificate verifier")
	}
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
	}, nil
}

// Run listens and serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := tls.Listen("tcp", s.cfg.Addr, s.cfg.TLS)
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
		"mutual_tls", true,
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

// serve authenticates one connection, then dispatches on its verified role.
//
// Identity is established from the certificate *before* the protocol handshake is
// read, so nothing a peer says can influence who the relay believes it is.
func (s *Server) serve(ctx context.Context, nc net.Conn) {
	conn := transport.NewConn(nc)

	// The handshake must be completed before the certificate can be inspected:
	// Go defers it to the first read, so an accepted connection has no peer
	// certificate until this returns. Bounded, so a peer that connects and then
	// says nothing cannot occupy a slot.
	hsCtx, cancelHS := context.WithTimeout(ctx, proto.HandshakeTimeout)
	err := transport.CompleteHandshake(hsCtx, nc)
	cancelHS()
	if err != nil {
		s.log.Debug("tls handshake failed", "peer", nc.RemoteAddr().String(), "error", err)
		_ = conn.Close()
		return
	}

	peerCert, err := transport.PeerCertificate(nc)
	if err != nil {
		// Unreachable while the listener requires and verifies client
		// certificates. Failing loudly matters because reaching it would mean the
		// TLS configuration had changed underneath this check.
		s.log.Warn("connection without a peer certificate", "peer", nc.RemoteAddr().String(), "error", err)
		_ = conn.Close()
		return
	}

	// A signature from the authority is necessary but not sufficient: the
	// identity must still be one the control plane recognises, which rules out
	// revoked identities and certificates superseded by a later enrollment.
	id, err := s.cfg.Verify.VerifyEnrolled(peerCert)
	if err != nil {
		s.log.Warn("rejecting unrecognised identity",
			"peer", nc.RemoteAddr().String(),
			"subject", peerCert.Subject.CommonName,
			"error", err)
		_ = conn.Close()
		return
	}

	h, err := mux.Accept(ctx, conn, mux.Config{
		MaxFramePayload: proto.MaxFramePayload,
		InitialWindow:   proto.InitialWindow,
		MaxStreams:      s.cfg.MaxStreams,
		KeepAlive:       s.cfg.KeepAlive,
		IdleTimeout:     s.cfg.IdleTimeout,
		Logger:          s.log,
	})
	if err != nil {
		s.log.Debug("handshake failed", "identity", id.String(), "error", err)
		_ = conn.Close()
		return
	}

	// The role in the handshake must agree with the role in the certificate. A
	// device certificate cannot be used to open an operator session.
	if !roleMatches(id.Role, h.Hello.Role) {
		s.log.Warn("role does not match certificate",
			"identity", id.String(), "claimed_role", h.Hello.Role.String())
		_ = h.Refuse(proto.ReasonAuthFailed)
		return
	}

	switch id.Role {
	case ca.RoleDevice:
		s.serveAgent(ctx, h, id)
	case ca.RoleOperator:
		s.serveOperator(ctx, h, id)
	default:
		_ = h.Refuse(proto.ReasonAuthFailed)
	}
}

// roleMatches reports whether a certificate role and a handshake role agree.
func roleMatches(certRole ca.Role, helloRole proto.Role) bool {
	switch certRole {
	case ca.RoleDevice:
		return helloRole == proto.RoleAgent
	case ca.RoleOperator:
		return helloRole == proto.RoleOperator
	default:
		return false
	}
}

// serveAgent registers an endpoint agent and holds its session open.
//
// The device identity is the one in the certificate. Anything the agent says
// about itself in AUTH is checked against it and must agree; it is not an
// alternative source of truth.
func (s *Server) serveAgent(ctx context.Context, h *mux.Handshake, id ca.Identity) {
	if claimed := h.Auth.DeviceID; claimed != "" && claimed != id.ID {
		// A peer presenting one identity and claiming another. Refused rather
		// than reconciled: there is no benign reason for the two to differ.
		s.log.Warn("agent claimed an identity that is not its own",
			"certificate_identity", id.String(), "claimed", claimed)
		_ = h.Refuse(proto.ReasonAuthFailed)
		return
	}
	deviceID := id.ID

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
func (s *Server) serveOperator(ctx context.Context, h *mux.Handshake, id ca.Identity) {
	// The device is what the operator is *asking for*, which is a legitimate
	// request rather than an identity claim. Who is asking comes from the
	// certificate.
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
			"device_id", deviceID, "user_id", id.ID, "reason", proto.ReasonNoAgent.String())
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
		"user_id", id.ID, // from the certificate, not from what the peer said
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
