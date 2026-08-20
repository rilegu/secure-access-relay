package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// Config configures the endpoint agent.
type Config struct {
	// RelayAddr is the relay's agent endpoint. The agent always dials out to it
	// and never listens, which is what removes the need for an inbound firewall
	// rule at the endpoint (threat T1).
	RelayAddr string

	// Target is the local service this agent is willing to reach.
	//
	// One fixed target for now. It becomes a named resource in a local allowlist
	// once the resource registry exists; the loopback restriction below does not
	// change when that happens.
	Target string

	// RetryInterval is how long to wait before redialling the relay. A fixed
	// delay for now; exponential backoff with jitter arrives with the resilience
	// work.
	RetryInterval time.Duration

	Logger *slog.Logger
}

// Agent is the endpoint-side component.
//
// It holds one outbound connection to the relay, waits to be asked to open a
// stream, and connects that stream to an approved local service. It never
// listens on a network interface and never accepts a target address from
// anyone: the relay asks for a stream, and the agent decides what that means.
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

// Run maintains the relay connection until ctx is cancelled.
//
// A dropped connection is expected, not exceptional: endpoints move between
// networks, relays restart, and links fail. Run reconnects rather than exiting,
// because an agent that gives up needs a human to notice, and the whole point is
// that nobody has to.
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

// session runs one connection to the relay from dial to disconnect.
func (a *Agent) session(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, proto.DialTimeout)
	conn, err := transport.Dial(dialCtx, a.cfg.RelayAddr)
	cancel()
	if err != nil {
		return fmt.Errorf("connect to relay: %w", err)
	}

	// Cancellation reaches the blocking read below by closing the connection.
	stop := conn.CloseOnContext(ctx)
	defer stop()
	defer func() { _ = conn.Close() }()

	a.log.Info("connected to relay",
		"relay_addr", a.cfg.RelayAddr,
		"target", a.cfg.Target,
		"secure", false, // no TLS or authentication in this build; stated, not implied
	)

	for {
		f, err := conn.R.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("relay closed the connection")
			}
			return err
		}

		switch f.Type {
		case proto.TypeOpenStream:
			// Handled inline rather than in a goroutine: this build serves one
			// stream at a time, and doing it inline makes that limit structural
			// instead of something enforced by a counter that could be wrong.
			a.handleStream(ctx, conn, f.StreamID)

		case proto.TypeError:
			return fmt.Errorf("relay error: %s", proto.Reason(f.Payload))

		case proto.TypeCloseStream:
			// A close for a stream that is already finished. Harmless.

		default:
			// Unknown frames are a protocol error, never something to skip.
			_ = conn.W.WriteError(proto.ReasonProtocolMalformedFrame)
			return fmt.Errorf("unexpected frame %s", f.Type)
		}
	}
}

// handleStream connects one stream to the local target and pumps bytes until it
// ends.
func (a *Agent) handleStream(ctx context.Context, conn *transport.Conn, streamID uint32) {
	log := a.log.With("stream_id", streamID, "target", a.cfg.Target)

	// Re-validated on every stream, not just at startup. Configuration can be
	// reloaded, and the loopback rule has to hold at the moment of use, not only
	// at the moment it was last read.
	if err := ValidateTarget(a.cfg.Target); err != nil {
		log.Error("refusing stream: invalid target", "error", err)
		_ = conn.W.WriteClose(streamID, proto.ReasonResourceTargetNotLoopback)
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, proto.DialTimeout)
	var d net.Dialer
	target, err := d.DialContext(dialCtx, "tcp", a.cfg.Target)
	cancel()
	if err != nil {
		// A target that is not listening is an availability problem, not an
		// authorization one, and is reported with a distinct code so the operator
		// can tell the difference without reading logs.
		reason := proto.ReasonTargetConnectionRefused
		if errors.Is(err, context.DeadlineExceeded) {
			reason = proto.ReasonTargetTimeout
		}
		log.Info("target unreachable", "reason", reason.String(), "error", err)
		_ = conn.W.WriteClose(streamID, reason)
		return
	}
	defer func() { _ = target.Close() }()

	if err := conn.W.WriteFrame(proto.TypeStreamOK, streamID, nil); err != nil {
		log.Warn("failed to confirm stream", "error", err)
		return
	}

	start := time.Now()
	log.Info("stream opened")

	sent, received, reason := a.pumpStream(conn, target, streamID)

	log.Info("stream closed",
		"reason", reason.String(),
		"bytes_from_target", sent,
		"bytes_to_target", received,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

// pumpStream moves bytes between the relay connection and the local target for
// the life of one stream.
//
// Only the target-to-relay direction runs in its own goroutine. The relay-to-
// target direction stays on this goroutine because it must return before the
// caller reads the next control frame: two goroutines reading the same
// connection would violate the codec's single-reader rule and interleave frames
// belonging to different streams.
func (a *Agent) pumpStream(conn *transport.Conn, target net.Conn, streamID uint32) (fromTarget, toTarget int64, reason proto.Reason) {
	done := make(chan struct{})

	// remoteClosed records that the relay ended the stream first.
	//
	// Without it the agent answers a close with a close. The relay tells the agent
	// to finish, the agent closes its target, the target read fails, and the
	// reader goroutine below announces the end of a stream that was already over.
	// Nobody is waiting for that frame, so it sits in the relay's queue for this
	// long-lived connection and is picked up as the *next* stream's reply — which
	// makes a healthy stream look refused and leaves the two ends disagreeing
	// about which stream is live.
	var remoteClosed atomic.Bool

	go func() {
		defer close(done)
		// A fixed read buffer, sized to the frame limit, so a large response
		// cannot inflate memory use: bytes are framed as they are read rather
		// than accumulated.
		buf := make([]byte, proto.MaxFramePayload)
		for {
			n, err := target.Read(buf)
			if n > 0 {
				if werr := conn.W.WriteFrame(proto.TypeStreamData, streamID, buf[:n]); werr != nil {
					return
				}
				fromTarget += int64(n)
			}
			if err != nil {
				// Only announce the close if this side ended it. If the relay
				// closed first, it already knows.
				if !remoteClosed.Load() {
					_ = conn.W.WriteClose(streamID, proto.ReasonOK)
				}
				return
			}
		}
	}()

	reason = proto.ReasonOK
	for {
		f, err := conn.R.ReadFrame()
		if err != nil {
			reason = proto.ReasonFor(err)
			break
		}
		if f.StreamID != streamID {
			// The relay only drives one stream at a time, so a frame for a
			// different stream means the two ends no longer agree about which
			// stream is live. Ending here is deliberate: silently dropping these
			// would leave this handler consuming - and discarding - the frames of
			// whatever stream the relay has actually moved on to, which presents
			// as a hang rather than an error.
			reason = proto.ReasonProtocolMalformedFrame
			break
		}

		if f.Type == proto.TypeStreamData {
			if _, werr := target.Write(f.Payload); werr != nil {
				reason = proto.ReasonTargetConnectionRefused
				break
			}
			toTarget += int64(len(f.Payload))
			continue
		}

		if f.Type == proto.TypeCloseStream {
			if r := proto.Reason(f.Payload); r != "" {
				reason = r
			}
			// Set before closing the target, so the reader goroutine sees it when
			// its read fails as a result of that close.
			remoteClosed.Store(true)
			break
		}

		reason = proto.ReasonProtocolMalformedFrame
		break
	}

	// Closing the target unblocks the reader goroutine, which has no other way to
	// be interrupted, then wait for it so its byte count is final before the
	// audit line is written.
	_ = target.Close()
	<-done

	return fromTarget, toTarget, reason
}
