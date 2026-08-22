package operator

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
	"github.com/rilegu/secure-access-relay/internal/identity"
	"github.com/rilegu/secure-access-relay/internal/mux"
	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// Config configures a local forward.
type Config struct {
	// RelayAddr is the relay.
	RelayAddr string

	// ListenAddr is the local address to accept connections on. Validated as
	// loopback: a forward is for the operator's own machine, and binding it to a
	// routable interface would silently republish someone else's private service
	// onto the operator's network.
	ListenAddr string

	// Identity is this operator's enrolled credentials. Required: the relay
	// establishes who is connecting from the certificate, not from a flag.
	Identity *identity.Identity

	// Resource names what to reach on the endpoint. Carried to the agent, which
	// resolves it against its own allowlist. Not an address, and never becomes one
	// on this side.
	Resource string

	// DeviceID identifies the endpoint the operator wants to reach. This is a
	// request, not an identity claim: who is asking comes from the certificate.
	DeviceID string

	// ControlAddr is the control plane, where grants are requested.
	ControlAddr string

	// GrantTTL is how long a grant is asked for. The control plane caps it by
	// policy and by the system maximum, so this is a request rather than a
	// setting.
	GrantTTL time.Duration

	// Session supplies the bearer token presented with each grant request.
	//
	// A function rather than a string because a forward can outlive a session: a
	// support session lasts a shift, grants are refreshed every few minutes, and
	// a token captured once at startup would stop working part way through
	// without the forwarder being able to do anything about it. Called on each
	// grant request, so the provider can renew.
	//
	// Optional. Without it grants are requested on the certificate alone, which a
	// control plane may or may not accept.
	Session func(ctx context.Context) (string, error)

	KeepAlive   time.Duration
	IdleTimeout time.Duration

	Logger *slog.Logger
}

// ErrListenNotLoopback reports a listen address that is not on loopback.
var ErrListenNotLoopback = errors.New("operator: listen address must be loopback")

// Forwarder accepts local connections and carries them through the relay.
//
// All local connections share **one** relay session, each becoming a stream on
// it. That is the point of multiplexing: a session is established once, and
// opening a forward for a browser that makes six parallel requests costs six
// streams rather than six connections and six handshakes.
type Forwarder struct {
	cfg Config
	log *slog.Logger

	// active counts in-flight connections, for logging and for tests that need to
	// wait until the forwarder is quiet.
	active atomic.Int64

	ready chan struct{}
	bound atomic.Pointer[string]

	// sessMu guards lazy session establishment. The session is created on first
	// use and replaced if it dies, so a relay restart does not require restarting
	// the forward.
	sessMu sync.Mutex
	sess   *mux.Session

	// grants holds the current authorization, refreshed as it ages.
	grants grantCache
}

// New creates a forwarder, rejecting a non-loopback listen address.
func New(cfg Config) (*Forwarder, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = proto.IdleTimeout
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = cfg.IdleTimeout / 3
	}
	if cfg.Identity == nil {
		return nil, errors.New("operator: not enrolled; run enroll first")
	}
	if cfg.DeviceID == "" {
		return nil, errors.New("operator: device id is required")
	}
	if cfg.Resource == "" {
		return nil, errors.New("operator: resource is required")
	}
	if cfg.GrantTTL <= 0 {
		cfg.GrantTTL = proto.MaxGrantTTL
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
		"listen_addr", addr,
		"relay_addr", f.cfg.RelayAddr,
		"user_id", f.cfg.Identity.ID.ID,
		"device_id", f.cfg.DeviceID,
		"resource", f.cfg.Resource,
		"mutual_tls", true,
	)

	// Closing the listener is the only way to interrupt a blocked Accept.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	defer f.closeSession()

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

// session returns a live relay session, establishing one if needed.
//
// Dialling is deferred to the first local connection rather than done at startup,
// so a forward can be opened before the endpoint is online and will work once it
// arrives. A dead session is replaced on the next attempt, which is what lets a
// forward survive a relay restart without being restarted itself.
func (f *Forwarder) session(ctx context.Context) (*mux.Session, error) {
	f.sessMu.Lock()
	defer f.sessMu.Unlock()

	if f.sess != nil {
		select {
		case <-f.sess.Done():
			f.sess = nil // died; fall through and redial
		default:
			return f.sess, nil
		}
	}

	tlsCfg := transport.ClientTLS(
		f.cfg.Identity.Certificate,
		f.cfg.Identity.CAPool,
		f.serverName(),
	)

	dialCtx, cancel := context.WithTimeout(ctx, proto.DialTimeout)
	conn, err := transport.DialTLS(dialCtx, f.cfg.RelayAddr, tlsCfg)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("connect to relay: %w", err)
	}

	sess, err := mux.Dial(ctx, conn, mux.Config{
		Role:        proto.RoleOperator,
		KeepAlive:   f.cfg.KeepAlive,
		IdleTimeout: f.cfg.IdleTimeout,
		Logger:      f.log,
	}, proto.Auth{
		DeviceID: f.cfg.DeviceID,
		UserID:   f.cfg.Identity.ID.ID,
		Resource: f.cfg.Resource,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("relay handshake: %w", err)
	}

	f.log.Info("relay session established", "session_id", sess.ID)
	f.sess = sess
	return sess, nil
}

func (f *Forwarder) closeSession() {
	f.sessMu.Lock()
	defer f.sessMu.Unlock()
	if f.sess != nil {
		_ = f.sess.Close(proto.ReasonShutdown)
		f.sess = nil
	}
}

// handle carries one local connection through the relay as a single stream.
func (f *Forwarder) handle(ctx context.Context, local net.Conn) {
	f.active.Add(1)
	defer f.active.Add(-1)

	log := f.log.With("local", local.RemoteAddr().String())

	sess, err := f.session(ctx)
	if err != nil {
		log.Error("cannot reach relay", "error", err)
		_ = local.Close()
		return
	}

	// A grant is obtained before the stream, so an unauthorized request fails
	// here with the control plane's reason rather than as an opaque stream reset.
	grantBytes, err := f.grant(ctx)
	if err != nil {
		log.Error("no grant", "error", err)
		_ = local.Close()
		return
	}

	openCtx, cancel := context.WithTimeout(ctx, proto.DialTimeout)
	st, err := sess.Open(openCtx, grantBytes)
	cancel()
	if err != nil {
		// The relay refused the stream. Its reason is in the error, and the local
		// connection is closed so the client sees a prompt failure rather than a
		// stall.
		log.Error("relay refused stream", "error", err)
		_ = local.Close()
		return
	}

	start := time.Now()
	stats, joinErr := bridge.Join(local, st)

	reason := proto.ReasonOK
	if joinErr != nil {
		reason = proto.ReasonShutdown
	}
	log.Info("forward closed",
		"stream_id", st.ID(),
		"reason", reason.String(),
		"bytes_sent", stats.AToB,
		"bytes_received", stats.BToA,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

// serverName is the name the relay's certificate must match. It never falls back
// to skipping verification.
func (f *Forwarder) serverName() string {
	if f.cfg.Identity.ServerName != "" {
		return f.cfg.Identity.ServerName
	}
	host, _, err := net.SplitHostPort(f.cfg.RelayAddr)
	if err != nil {
		return f.cfg.RelayAddr
	}
	return host
}
