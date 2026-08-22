package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/rilegu/secure-access-relay/internal/bridge"
	"github.com/rilegu/secure-access-relay/internal/identity"
	"github.com/rilegu/secure-access-relay/internal/mux"
	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// Config configures the endpoint agent.
type Config struct {
	// RelayAddr is the relay. The agent always dials out to it and never listens,
	// which is what removes the need for an inbound firewall rule at the endpoint
	// (threat T1).
	RelayAddr string

	// Identity is this endpoint's enrolled credentials. Required: without a
	// certificate the agent has no way to prove which device it is, and the relay
	// will not admit it.
	Identity *identity.Identity

	// Resources is the local allowlist: the only services this agent will ever
	// reach, keyed by resource identifier.
	//
	// An operator names a resource; the agent resolves it here. The address never
	// crosses the wire, which is what makes an authorization bug unable to become
	// "reach anything you can name".
	Resources Allowlist

	// MaxStreams caps concurrent streams the relay may open on this agent.
	MaxStreams uint32

	// RetryInterval is how long to wait before redialling the relay.
	RetryInterval time.Duration

	KeepAlive   time.Duration
	IdleTimeout time.Duration

	Logger *slog.Logger
}

// Agent is the endpoint-side component.
//
// It holds one outbound session to the relay, accepts the streams the relay opens
// on it, and connects each to an approved local service. It never listens on a
// network interface and never accepts a target address from anyone: the relay
// asks for a stream, and the agent alone decides what that means.
type Agent struct {
	cfg Config
	log *slog.Logger
}

// New creates an agent.
//
// The target is validated here rather than at first use. A resource pointing
// somewhere it must not is a configuration error, and a configuration error
// should stop the process starting rather than surface later as a surprising
// connection: a misconfigured allowlist must never produce a running agent
// (invariant 4).
func New(cfg Config) (*Agent, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = 2 * time.Second
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
	if cfg.Identity == nil {
		return nil, errors.New("agent: not enrolled; run enroll first")
	}
	if len(cfg.Resources) == 0 {
		return nil, errors.New("agent: no resources declared; an agent with nothing to serve would refuse every stream")
	}
	// Re-validated here even though LoadAllowlist already checked, because an
	// allowlist can also be constructed in code. Invariant 4 has to hold however
	// the configuration arrived.
	for id, r := range cfg.Resources {
		if err := ValidateTarget(r.Target); err != nil {
			return nil, fmt.Errorf("resource %q: %w", id, err)
		}
	}
	if cfg.Identity.GrantKey == nil {
		// Without the verification key the agent could authenticate but not
		// authorize, and would have to take the relay's word for what is allowed.
		// Refusing to start is the only safe response.
		return nil, errors.New("agent: no grant verification key; re-enroll to obtain one")
	}
	return &Agent{cfg: cfg, log: cfg.Logger}, nil
}

// ErrTargetNotLoopback reports a target that is not on the loopback interface.
var ErrTargetNotLoopback = errors.New("agent: target must be loopback")

// ValidateTarget checks that addr is a literal loopback address with an explicit
// port.
//
// This is the enforcement point for invariant 4, and the reasoning behind each
// rule matters:
//
//   - A hostname is rejected outright, so no DNS lookup is ever performed for a
//     target. A resource pinned to 127.0.0.1 cannot be moved by a poisoned DNS
//     answer; a resource named panel.local can (threat T7).
//   - The port must be explicit, so a resource cannot silently inherit a default.
//   - Only loopback is permitted, so an authorization bug cannot become lateral
//     movement across the customer's subnet.
func ValidateTarget(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %q is not host:port", ErrTargetNotLoopback, addr)
	}
	if port == "" {
		return fmt.Errorf("%w: %q has no port", ErrTargetNotLoopback, addr)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Deliberately not resolved. Accepting a name here would hand control of
		// the destination to whoever answers DNS.
		return fmt.Errorf("%w: %q is a name, not a literal IP", ErrTargetNotLoopback, addr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%w: %q", ErrTargetNotLoopback, addr)
	}
	return nil
}

// Run maintains the relay session until ctx is cancelled.
//
// A dropped session is expected, not exceptional: endpoints move between
// networks, relays restart, links fail. Run reconnects rather than exiting,
// because an agent that gives up needs a human to notice, and the point is that
// nobody has to.
func (a *Agent) Run(ctx context.Context) error {
	for {
		if err := a.session(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("relay session ended", "error", err, "retry_in", a.cfg.RetryInterval)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(a.cfg.RetryInterval):
		}
	}
}

// session runs one relay session from dial to disconnect.
func (a *Agent) session(ctx context.Context) error {
	// Mutual TLS, verifying the relay against the authority this agent enrolled
	// with. A relay that cannot present a certificate from that authority is not
	// the relay this agent belongs to, however reachable it may be.
	tlsCfg := transport.ClientTLS(
		a.cfg.Identity.Certificate,
		a.cfg.Identity.CAPool,
		a.serverName(),
	)

	dialCtx, cancel := context.WithTimeout(ctx, proto.DialTimeout)
	conn, err := transport.DialTLS(dialCtx, a.cfg.RelayAddr, tlsCfg)
	cancel()
	if err != nil {
		return fmt.Errorf("connect to relay: %w", err)
	}

	sess, err := mux.Dial(ctx, conn, mux.Config{
		Role:        proto.RoleAgent,
		MaxStreams:  a.cfg.MaxStreams,
		KeepAlive:   a.cfg.KeepAlive,
		IdleTimeout: a.cfg.IdleTimeout,
		Logger:      a.log,
	}, proto.Auth{DeviceID: a.cfg.Identity.ID.ID})
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("relay handshake: %w", err)
	}
	defer func() { _ = sess.Close(proto.ReasonShutdown) }()

	a.log.Info("connected to relay",
		"relay_addr", a.cfg.RelayAddr,
		"session_id", sess.ID,
		"device_id", a.cfg.Identity.ID.ID,
		"resources", a.cfg.Resources.IDs(),
		"mutual_tls", true,
		"key_protection", string(a.cfg.Identity.Protection),
	)

	for {
		st, err := sess.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return sess.Err()
		}
		// One goroutine per stream. Concurrency is bounded by the stream limit
		// negotiated at the handshake, so this cannot grow without limit.
		go a.handleStream(ctx, st)
	}
}

// handleStream authorizes one stream and, only if it passes, connects it.
//
// This is the enforcement point the whole system exists to place here. The relay
// asked for a stream and handed over a grant; nothing the relay said is trusted.
// The agent checks the signature itself, against a key it obtained at
// enrollment, and resolves the resource against its own allowlist. A compromised
// relay can therefore ask, and be refused.
//
// The order is deliberate: signature first, because every other field is
// attacker-controlled until it verifies; then expiry and device; then the
// resource; and only then a socket.
func (a *Agent) handleStream(ctx context.Context, st *mux.Stream) {
	log := a.log.With("stream_id", st.ID())

	payload := st.OpenPayload()
	if len(payload) == 0 {
		// No grant at all. Before this phase the relay could open a stream simply
		// by asking; now that is a refusal.
		log.Warn("refusing stream: no grant presented")
		_ = st.Reset(proto.ReasonPolicyDenied)
		return
	}

	grant, err := proto.DecodeGrant(payload)
	if err != nil {
		log.Warn("refusing stream: grant did not decode", "error", err)
		_ = st.Reset(proto.ReasonForGrant(err))
		return
	}

	// Verify against this agent's own identity. The device identifier is inside
	// the signature, so a grant captured at another endpoint cannot be replayed
	// here (threat T6).
	if err := grant.Verify(a.cfg.Identity.GrantKey, time.Now(), a.cfg.Identity.ID.ID); err != nil {
		reason := proto.ReasonForGrant(err)
		log.Warn("refusing stream: grant rejected",
			"reason", reason.String(), "grant_id", grant.GrantID, "error", err)
		_ = st.Reset(reason)
		return
	}

	log = log.With("grant_id", grant.GrantID, "user_id", grant.UserID, "resource_id", grant.ResourceID)

	resource, err := a.cfg.Resources.Lookup(grant.ResourceID)
	if err != nil {
		// A correctly signed grant for something this agent does not serve. The
		// control plane and the agent disagree about what exists here, and the
		// agent's view is the one that decides.
		reason := proto.ReasonResourceUnknown
		if errors.Is(err, ErrTargetNotLoopback) {
			reason = proto.ReasonResourceTargetNotLoopback
		}
		log.Warn("refusing stream: resource not available", "reason", reason.String(), "error", err)
		_ = st.Reset(reason)
		return
	}

	// The session may not outlive the grant. Whichever is shorter — what remains
	// of the grant, or the resource's own limit — bounds it, so an operator
	// cannot hold a connection open past the authorization that opened it.
	deadline := time.Now().Add(grant.Remaining(time.Now()))
	if d := resource.MaxDuration.Duration(); d > 0 && time.Now().Add(d).Before(deadline) {
		deadline = time.Now().Add(d)
	}
	streamCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// The byte budget follows the same rule as the duration: whichever of the
	// grant and the resource is stricter applies. Zero means unlimited on either
	// side, so the smaller *non-zero* value wins rather than the smaller value.
	budget := smallerLimit(grant.MaxBytes, resource.MaxBytes)

	dialCtx, dialCancel := context.WithTimeout(streamCtx, proto.DialTimeout)
	var d net.Dialer
	target, err := d.DialContext(dialCtx, "tcp", resource.Target)
	dialCancel()
	if err != nil {
		// The target being down is an availability problem, not an authorization
		// one, and gets a distinct code so an operator can tell "you may not" from
		// "it is not answering" without reading logs.
		reason := proto.ReasonTargetConnectionRefused
		if errors.Is(err, context.DeadlineExceeded) {
			reason = proto.ReasonTargetTimeout
		}
		log.Info("target unreachable", "reason", reason.String(), "target", resource.Target, "error", err)
		_ = st.Reset(reason)
		return
	}

	start := time.Now()
	log.Info("stream authorized",
		"target", resource.Target,
		"expires_in_s", int(grant.Remaining(start).Seconds()),
		"max_bytes", budget,
	)

	// Closing the stream when the deadline passes is what actually enforces
	// expiry on a session already running. Without it, a grant would bound when a
	// stream may *start* and nothing would bound how long it lasts.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-streamCtx.Done():
			if ctx.Err() == nil {
				_ = st.Reset(proto.ReasonGrantExpired)
				_ = target.Close()
			}
		case <-done:
		}
	}()

	stats, joinErr := bridge.JoinWithBudget(st, target, budget)

	reason := proto.ReasonOK
	switch {
	case streamCtx.Err() == context.DeadlineExceeded:
		reason = proto.ReasonGrantExpired
	case errors.Is(joinErr, bridge.ErrBudgetExhausted):
		// Not a failure. The cap did what it was configured to do, and the
		// distinct code is what lets an operator tell that from a broken
		// connection without reading logs.
		reason = proto.ReasonLimitBytesExceeded
	case joinErr != nil:
		reason = proto.ReasonShutdown
	}

	log.Info("stream closed",
		"reason", reason.String(),
		"bytes_to_target", stats.AToB,
		"bytes_from_target", stats.BToA,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

// smallerLimit returns the stricter of two byte caps, where zero means no cap.
//
// Written out rather than using min, because zero is not the smallest value here
// but the largest: a resource declaring no limit must not override a grant that
// declares one, and the reverse.
func smallerLimit(a, b uint64) uint64 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}

// serverName is the name the relay's certificate must match.
//
// It falls back to the host part of the relay address when enrollment did not
// record one, so that a certificate issued for an IP still verifies. It never
// falls back to skipping verification.
func (a *Agent) serverName() string {
	if a.cfg.Identity.ServerName != "" {
		return a.cfg.Identity.ServerName
	}
	host, _, err := net.SplitHostPort(a.cfg.RelayAddr)
	if err != nil {
		return a.cfg.RelayAddr
	}
	return host
}
