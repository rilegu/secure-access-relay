package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/rilegu/secure-access-relay/internal/bridge"
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

	// DeviceID identifies this endpoint to the relay.
	//
	// A claim, not a credential. Nothing verifies it until enrollment and mutual
	// TLS exist, and the agent must not present it as though it proves anything.
	DeviceID string

	// Target is the local service this agent is willing to reach.
	//
	// One fixed target for now. It becomes a named resource in a local allowlist
	// once the resource registry exists; the loopback restriction does not change
	// when that happens.
	Target string

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
	if cfg.DeviceID == "" {
		return nil, errors.New("agent: device id is required")
	}
	if err := ValidateTarget(cfg.Target); err != nil {
		return nil, err
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
	dialCtx, cancel := context.WithTimeout(ctx, proto.DialTimeout)
	conn, err := transport.Dial(dialCtx, a.cfg.RelayAddr)
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
	}, proto.Auth{DeviceID: a.cfg.DeviceID})
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("relay handshake: %w", err)
	}
	defer func() { _ = sess.Close(proto.ReasonShutdown) }()

	a.log.Info("connected to relay",
		"relay_addr", a.cfg.RelayAddr,
		"session_id", sess.ID,
		"device_id", a.cfg.DeviceID,
		"target", a.cfg.Target,
		"secure", false, // no TLS or authentication in this build; stated, not implied
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

// handleStream connects one stream to the local target.
func (a *Agent) handleStream(ctx context.Context, st *mux.Stream) {
	log := a.log.With("stream_id", st.ID(), "target", a.cfg.Target)

	// Re-validated on every stream, not only at startup. Configuration can be
	// reloaded, and the loopback rule has to hold at the moment of use rather
	// than only at the moment it was last read.
	if err := ValidateTarget(a.cfg.Target); err != nil {
		log.Error("refusing stream: invalid target", "error", err)
		_ = st.Reset(proto.ReasonResourceTargetNotLoopback)
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, proto.DialTimeout)
	var d net.Dialer
	target, err := d.DialContext(dialCtx, "tcp", a.cfg.Target)
	cancel()
	if err != nil {
		// A target that is not listening is an availability problem, not an
		// authorization one, and gets a distinct code so the operator can tell the
		// difference without reading logs.
		reason := proto.ReasonTargetConnectionRefused
		if errors.Is(err, context.DeadlineExceeded) {
			reason = proto.ReasonTargetTimeout
		}
		log.Info("target unreachable", "reason", reason.String(), "error", err)
		_ = st.Reset(reason)
		return
	}

	start := time.Now()
	log.Info("stream opened")

	stats, joinErr := bridge.Join(st, target)

	reason := proto.ReasonOK
	if joinErr != nil {
		reason = proto.ReasonShutdown
	}
	log.Info("stream closed",
		"reason", reason.String(),
		"bytes_to_target", stats.AToB,
		"bytes_from_target", stats.BToA,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}
