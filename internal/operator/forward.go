package operator

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

// Config configures a local forward.
type Config struct {
	// RelayAddr is the relay's operator endpoint.
	RelayAddr string

	// ListenAddr is the local address to accept connections on. Validated as
	// loopback: a forward is for the operator's own machine, and binding it to a
	// routable interface would silently republish someone else's private service
	// onto the operator's network.
	ListenAddr string

	// Resource names what to reach on the endpoint. Carried to the agent, which
	// resolves it against its own allowlist. Not an address, and never becomes one
	// on this side.
	Resource string

	Logger *slog.Logger
}

// ErrListenNotLoopback reports a listen address that is not on loopback.
var ErrListenNotLoopback = errors.New("operator: listen address must be loopback")

// Forwarder accepts local connections and carries them through the relay.
type Forwarder struct {
	cfg Config
	log *slog.Logger

	// active counts in-flight connections, for logging and for tests that need to
	// wait until the forwarder is quiet.
	active atomic.Int64

	// ready is closed once the listener is bound, and bound holds the resulting
	// address. Needed because a caller may ask for port 0 and cannot know the
	// real port until the listener exists.
	ready chan struct{}
	bound atomic.Pointer[string]
}

// New creates a forwarder, rejecting a non-loopback listen address.
func New(cfg Config) (*Forwarder, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := validateListenAddr(cfg.ListenAddr); err != nil {
		return nil, err
	}
	return &Forwarder{cfg: cfg, log: cfg.Logger, ready: make(chan struct{})}, nil
}

// validateListenAddr requires a literal loopback host and an explicit port.
//
// The empty host in ":18080" is rejected on purpose: it means "all interfaces",
// which is exactly the mistake this check exists to prevent. Making the operator
// write 127.0.0.1 turns an easy accident into a deliberate act.
func validateListenAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %q is not host:port", ErrListenNotLoopback, addr)
	}
	if port == "" {
		return fmt.Errorf("%w: %q has no port", ErrListenNotLoopback, addr)
	}
	if host == "" {
		return fmt.Errorf("%w: %q binds all interfaces; use 127.0.0.1", ErrListenNotLoopback, addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: %q", ErrListenNotLoopback, addr)
	}
	return nil
}

// Run listens and forwards until ctx is cancelled.
func (f *Forwarder) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", f.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", f.cfg.ListenAddr, err)
	}
	defer func() { _ = ln.Close() }()

	addr := ln.Addr().String()
	f.bound.Store(&addr)
	close(f.ready)

	f.log.Info("forwarding",
		"listen_addr", ln.Addr().String(),
		"relay_addr", f.cfg.RelayAddr,
		"resource", f.cfg.Resource,
		"secure", false, // no TLS or authentication in this build
	)

	// Closing the listener is the only way to interrupt a blocked Accept.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			f.log.Warn("accept failed", "error", err)
			continue
		}
		go f.handle(ctx, local)
	}
}

// Ready is closed once the listener is bound and Addr is readable.
func (f *Forwarder) Ready() <-chan struct{} { return f.ready }

// Addr reports the bound listen address. Valid only after Ready is closed; it
// differs from the configured address when port 0 was requested.
func (f *Forwarder) Addr() string {
	if p := f.bound.Load(); p != nil {
		return *p
	}
	return f.cfg.ListenAddr
}

// Active reports how many connections are currently being forwarded.
func (f *Forwarder) Active() int64 { return f.active.Load() }

// handle carries one local connection through the relay.
//
// Each local connection gets its own relay connection. That is a simplification
// of the single-stream phase, not the end state: multiplexing lets many local
// connections share one relay connection, which is what makes a long-lived
// session efficient.
func (f *Forwarder) handle(ctx context.Context, local net.Conn) {
	f.active.Add(1)
	defer f.active.Add(-1)
	defer func() { _ = local.Close() }()

	log := f.log.With("local", local.RemoteAddr().String())

	dialCtx, cancel := context.WithTimeout(ctx, proto.DialTimeout)
	relay, err := transport.Dial(dialCtx, f.cfg.RelayAddr)
	cancel()
	if err != nil {
		log.Error("cannot reach relay", "error", err)
		return
	}
	defer func() { _ = relay.Close() }()

	stop := relay.CloseOnContext(ctx)
	defer stop()

	// The relay assigns the stream ID. Whatever it puts in the frames it sends
	// back is authoritative here; this side never invents one.
	const streamID = 0

	start := time.Now()
	sent, received, reason := f.pump(relay, local, streamID)

	log.Info("forward closed",
		"reason", reason.String(),
		"bytes_sent", sent,
		"bytes_received", received,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

// pump moves bytes between the local connection and the relay.
//
// As on the agent side, only one direction gets its own goroutine, because the
// frame Reader must have a single owner.
func (f *Forwarder) pump(relay *transport.Conn, local net.Conn, streamID uint32) (sent, received int64, reason proto.Reason) {
	done := make(chan struct{})

	go func() {
		defer close(done)
		buf := make([]byte, proto.MaxFramePayload)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				if werr := relay.W.WriteFrame(proto.TypeStreamData, streamID, buf[:n]); werr != nil {
					return
				}
				sent += int64(n)
			}
			if err != nil {
				// The local client finished. Signal the far end rather than
				// leaving it waiting for bytes that will never come.
				_ = relay.W.WriteClose(streamID, proto.ReasonOK)
				return
			}
		}
	}()

	reason = proto.ReasonOK

	// Labelled so that a write failure inside the switch leaves the read loop.
	// A bare break would only leave the switch and silently keep reading, which
	// would spin against a local connection that is already gone.
readLoop:
	for {
		frame, err := relay.R.ReadFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				reason = proto.ReasonFor(err)
			}
			break readLoop
		}

		switch frame.Type {
		case proto.TypeStreamData:
			if _, werr := local.Write(frame.Payload); werr != nil {
				break readLoop
			}
			received += int64(len(frame.Payload))

		case proto.TypeCloseStream:
			if r := proto.Reason(frame.Payload); r != "" {
				reason = r
			}
			_ = local.Close()
			<-done
			return sent, received, reason

		case proto.TypeError:
			// A connection-level refusal from the relay: no agent, agent busy, or
			// the agent could not reach the target. Surfaced verbatim so the
			// operator sees the real cause.
			if r := proto.Reason(frame.Payload); r != "" {
				reason = r
			}
			_ = local.Close()
			<-done
			return sent, received, reason

		default:
			reason = proto.ReasonProtocolMalformedFrame
			_ = local.Close()
			<-done
			return sent, received, reason
		}
	}

	_ = local.Close()
	<-done
	return sent, received, reason
}
