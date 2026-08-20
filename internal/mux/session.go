package mux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// Config configures a session.
type Config struct {
	// Role is announced in HELLO so the responder knows what kind of peer this
	// is. It is a routing hint, not a credential.
	Role proto.Role

	// Limits the responder announces. Ignored by the initiator, which uses
	// whatever the responder sends back.
	MaxFramePayload uint32
	InitialWindow   uint32
	MaxStreams      uint32

	// KeepAlive is how often to send a PING on an otherwise idle connection.
	// Zero disables keepalives.
	KeepAlive time.Duration

	// IdleTimeout is how long a connection may go without receiving anything
	// before it is torn down. Zero disables the check.
	IdleTimeout time.Duration

	Logger *slog.Logger
}

func (c *Config) withDefaults() {
	if c.MaxFramePayload == 0 {
		c.MaxFramePayload = proto.MaxFramePayload
	}
	if c.InitialWindow == 0 {
		c.InitialWindow = proto.InitialWindow
	}
	if c.MaxStreams == 0 {
		c.MaxStreams = proto.MaxStreamsPerConnection
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// Session multiplexes many streams over one framed connection.
//
// Exactly one goroutine reads the connection and dispatches frames to streams.
// That single reader is required rather than preferred: [proto.Reader] reuses one
// buffer and is not safe for concurrent use, and a second reader would also
// scramble frame ordering.
//
// Writes are safe from any goroutine — [proto.Writer] serialises whole frames —
// so many streams can write concurrently without interleaving.
type Session struct {
	// ID names this session in logs on both ends.
	ID string

	// Peer is what the far end claimed in AUTH. Nothing here is proved; until
	// mutual TLS exists these are labels, not credentials.
	Peer proto.Auth

	conn *transport.Conn
	log  *slog.Logger

	maxFrame        uint32
	window          uint32
	maxStreams      uint32
	creditThreshold uint32

	// isClient decides stream-ID parity. The dialer numbers streams odd, the
	// accepter even, so both ends can open streams concurrently without ever
	// choosing the same identifier.
	isClient bool

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	// pending maps a stream this side opened to the channel awaiting its ack.
	pending map[uint32]chan proto.Reason

	acceptCh chan *Stream

	closeOnce sync.Once
	done      chan struct{}
	errMu     sync.Mutex
	err       error

	lastRecv atomic.Int64
}

func newSession(conn *transport.Conn, cfg Config, isClient bool, ack proto.HelloAck) *Session {
	s := &Session{
		conn:            conn,
		log:             cfg.Logger,
		maxFrame:        ack.MaxFramePayload,
		window:          ack.InitialWindow,
		maxStreams:      ack.MaxStreams,
		creditThreshold: ack.InitialWindow / 2,
		isClient:        isClient,
		streams:         make(map[uint32]*Stream),
		pending:         make(map[uint32]chan proto.Reason),
		acceptCh:        make(chan *Stream, ack.MaxStreams),
		done:            make(chan struct{}),
	}
	if s.creditThreshold == 0 {
		s.creditThreshold = 1
	}
	if isClient {
		s.nextID = 1
	} else {
		s.nextID = 2
	}
	s.lastRecv.Store(time.Now().UnixNano())
	return s
}

// Dial performs the initiator side of the handshake and returns a live session.
//
// The exchange is HELLO, HELLO_ACK, AUTH, AUTH_OK, in that order and exactly
// once. Version negotiation happens here or not at all: there is no way to
// change it later, which is deliberate — a protocol that can be renegotiated
// mid-connection is a protocol that can be downgraded mid-connection.
func Dial(ctx context.Context, conn *transport.Conn, cfg Config, auth proto.Auth) (*Session, error) {
	cfg.withDefaults()

	// The handshake is bounded. A peer that opens a connection and then says
	// nothing must not be able to hold resources indefinitely.
	stop := deadlineGuard(ctx, conn, proto.HandshakeTimeout)
	defer stop()

	hello := proto.Hello{MinVersion: proto.Version, MaxVersion: proto.Version, Role: cfg.Role}
	if err := conn.W.WriteFrame(proto.TypeHello, 0, hello.Encode()); err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}

	f, err := conn.R.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("read hello_ack: %w", err)
	}
	if f.Type == proto.TypeError {
		return nil, fmt.Errorf("peer refused connection: %s", proto.Reason(f.Payload))
	}
	if f.Type != proto.TypeHelloAck {
		return nil, fmt.Errorf("%w: expected hello_ack, got %s", proto.ErrMalformedFrame, f.Type)
	}
	ack, err := proto.DecodeHelloAck(f.Payload)
	if err != nil {
		return nil, err
	}
	if ack.Version != proto.Version {
		return nil, fmt.Errorf("%w: peer chose version %d, this build speaks %d",
			proto.ErrUnsupportedVersion, ack.Version, proto.Version)
	}

	if err := conn.W.WriteFrame(proto.TypeAuth, 0, auth.Encode()); err != nil {
		return nil, fmt.Errorf("send auth: %w", err)
	}

	f, err = conn.R.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("read auth_ok: %w", err)
	}
	if f.Type == proto.TypeError {
		return nil, fmt.Errorf("authentication refused: %s", proto.Reason(f.Payload))
	}
	if f.Type != proto.TypeAuthOK {
		return nil, fmt.Errorf("%w: expected auth_ok, got %s", proto.ErrMalformedFrame, f.Type)
	}
	ok, err := proto.DecodeAuthOK(f.Payload)
	if err != nil {
		return nil, err
	}

	s := newSession(conn, cfg, true, ack)
	s.ID = ok.SessionID
	s.Peer = auth
	s.start(cfg)
	return s, nil
}

// Handshake is a half-completed responder handshake.
//
// It exists so the caller can decide whether to admit a peer *after* seeing what
// it claims but *before* a session exists. Admission is an application decision —
// is this device known, is this operator allowed — and the multiplexer has no
// business making it.
type Handshake struct {
	Conn  *transport.Conn
	Hello proto.Hello
	Auth  proto.Auth

	cfg  Config
	ack  proto.HelloAck
	stop func()
}

// Accept performs the responder side of the handshake up to the point of
// admission, returning what the peer claimed.
//
// The caller must then call [Handshake.Admit] or [Handshake.Refuse].
func Accept(ctx context.Context, conn *transport.Conn, cfg Config) (*Handshake, error) {
	cfg.withDefaults()

	stop := deadlineGuard(ctx, conn, proto.HandshakeTimeout)

	fail := func(err error, reason proto.Reason) (*Handshake, error) {
		_ = conn.W.WriteError(reason)
		stop()
		return nil, err
	}

	f, err := conn.R.ReadFrame()
	if err != nil {
		stop()
		return nil, fmt.Errorf("read hello: %w", err)
	}
	if f.Type != proto.TypeHello {
		return fail(fmt.Errorf("%w: expected hello, got %s", proto.ErrMalformedFrame, f.Type),
			proto.ReasonProtocolMalformedFrame)
	}
	hello, err := proto.DecodeHello(f.Payload)
	if err != nil {
		return fail(err, proto.ReasonProtocolMalformedFrame)
	}

	// Pick the highest version both ends can speak. With a single version
	// defined this is a range check, but the shape is what matters: an empty
	// intersection is refused rather than guessed at.
	if proto.Version < hello.MinVersion || proto.Version > hello.MaxVersion {
		return fail(fmt.Errorf("%w: peer speaks %d..%d, this build speaks %d",
			proto.ErrUnsupportedVersion, hello.MinVersion, hello.MaxVersion, proto.Version),
			proto.ReasonProtocolVersionUnsupported)
	}

	ack := proto.HelloAck{
		Version:         proto.Version,
		MaxFramePayload: cfg.MaxFramePayload,
		InitialWindow:   cfg.InitialWindow,
		MaxStreams:      cfg.MaxStreams,
	}
	if err := conn.W.WriteFrame(proto.TypeHelloAck, 0, ack.Encode()); err != nil {
		stop()
		return nil, fmt.Errorf("send hello_ack: %w", err)
	}

	f, err = conn.R.ReadFrame()
	if err != nil {
		stop()
		return nil, fmt.Errorf("read auth: %w", err)
	}
	if f.Type != proto.TypeAuth {
		return fail(fmt.Errorf("%w: expected auth, got %s", proto.ErrMalformedFrame, f.Type),
			proto.ReasonProtocolMalformedFrame)
	}
	auth, err := proto.DecodeAuth(f.Payload)
	if err != nil {
		return fail(err, proto.ReasonProtocolMalformedFrame)
	}

	return &Handshake{Conn: conn, Hello: hello, Auth: auth, cfg: cfg, ack: ack, stop: stop}, nil
}

// Admit accepts the peer and starts the session.
func (h *Handshake) Admit(sessionID string) (*Session, error) {
	if err := h.Conn.W.WriteFrame(proto.TypeAuthOK, 0, proto.AuthOK{SessionID: sessionID}.Encode()); err != nil {
		h.stop()
		return nil, fmt.Errorf("send auth_ok: %w", err)
	}
	h.stop()

	s := newSession(h.Conn, h.cfg, false, h.ack)
	s.ID = sessionID
	s.Peer = h.Auth
	s.start(h.cfg)
	return s, nil
}

// Refuse rejects the peer with a reason and closes the connection.
//
// The reason is written before the close, and the connection is drained first so
// that closing on unread input cannot reset it and discard the explanation.
func (h *Handshake) Refuse(reason proto.Reason) error {
	err := h.Conn.W.WriteError(reason)
	h.stop()
	_ = h.Conn.DrainAndClose(2 * time.Second)
	return err
}

// start launches the read loop and, if configured, the keepalive loop.
func (s *Session) start(cfg Config) {
	go s.readLoop()
	if cfg.KeepAlive > 0 || cfg.IdleTimeout > 0 {
		go s.keepAliveLoop(cfg.KeepAlive, cfg.IdleTimeout)
	}
}

// Open starts a new stream and waits for the peer to acknowledge it.
//
// The payload travels with the OPEN_STREAM frame and is available to the
// accepting side as [Stream.OpenPayload]. On the relay-to-agent path it carries
// the signed grant, so the agent has everything it needs to decide before it
// dials anything.
//
// The wait is what surfaces a refusal: a peer at its stream limit, or one that
// refuses the grant, answers with a CLOSE_STREAM carrying a reason rather than
// silently ignoring the request.
func (s *Session) Open(ctx context.Context, payload []byte) (*Stream, error) {
	s.mu.Lock()
	if s.isClosed() {
		s.mu.Unlock()
		return nil, s.Err()
	}
	if uint32(len(s.streams)) >= s.maxStreams {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %d streams open", ErrTooManyStreams, s.maxStreams)
	}
	id := s.nextID
	s.nextID += 2 // parity is fixed for the life of the session
	st := newStream(id, s, s.window)
	s.streams[id] = st
	ackCh := make(chan proto.Reason, 1)
	s.pending[id] = ackCh
	s.mu.Unlock()

	if err := s.conn.W.WriteFrame(proto.TypeOpenStream, id, payload); err != nil {
		s.retire(id)
		return nil, fmt.Errorf("send open_stream: %w", err)
	}

	select {
	case reason := <-ackCh:
		if reason != proto.ReasonOK {
			s.retire(id)
			return nil, fmt.Errorf("%w: peer refused stream: %s", ErrStreamRefused, reason)
		}
		return st, nil
	case <-ctx.Done():
		s.retire(id)
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.Err()
	}
}

// AcceptStream returns the next stream opened by the peer.
func (s *Session) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.Err()
	}
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err reports why the session ended, or nil while it is live.
func (s *Session) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.err == nil {
		select {
		case <-s.done:
			return ErrSessionClosed
		default:
			return nil
		}
	}
	return s.err
}

// StreamCount reports how many streams are currently open.
func (s *Session) StreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

// Close ends the session, telling the peer why and killing every stream on it.
func (s *Session) Close(reason proto.Reason) error {
	s.closeOnce.Do(func() {
		s.setErr(fmt.Errorf("%w: %s", ErrSessionClosed, reason))
		_ = s.conn.W.WriteError(reason)

		s.mu.Lock()
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.streams = map[uint32]*Stream{}
		pending := s.pending
		s.pending = map[uint32]chan proto.Reason{}
		s.mu.Unlock()

		// Unblock everything waiting on this session before closing the socket,
		// so callers get a reason rather than an opaque read error.
		for _, st := range streams {
			st.kill(reason)
		}
		for _, ch := range pending {
			select {
			case ch <- reason:
			default:
			}
		}

		close(s.done)
		_ = s.conn.Close()
	})
	return nil
}

func (s *Session) isClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *Session) setErr(err error) {
	s.errMu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.errMu.Unlock()
}

// readLoop is the single reader of the connection.
func (s *Session) readLoop() {
	for {
		f, err := s.conn.R.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.setErr(ErrSessionClosed)
			} else {
				s.setErr(err)
			}
			s.shutdown(proto.ReasonFor(err))
			return
		}

		s.lastRecv.Store(time.Now().UnixNano())

		if uint32(len(f.Payload)) > s.maxFrame {
			// The negotiated limit can be lower than the codec's ceiling, so it
			// is enforced here as well as there.
			s.setErr(fmt.Errorf("%w: frame of %d exceeds negotiated %d",
				proto.ErrFrameTooLarge, len(f.Payload), s.maxFrame))
			s.shutdown(proto.ReasonLimitFrameTooLarge)
			return
		}

		if err := s.dispatch(f); err != nil {
			s.setErr(err)
			// A dispatch failure carries its own reason when it has a more
			// precise one than "malformed".
			reason := proto.ReasonProtocolMalformedFrame
			var fe *fatalError
			if errors.As(err, &fe) {
				reason = fe.reason
			}
			s.shutdown(reason)
			return
		}
	}
}

// dispatch routes one frame. A returned error is fatal to the session.
func (s *Session) dispatch(f proto.Frame) error {
	switch f.Type {
	case proto.TypeOpenStream:
		return s.handleOpen(f.StreamID, f.Payload)

	case proto.TypeStreamOK:
		s.completeOpen(f.StreamID, proto.ReasonOK)
		return nil

	case proto.TypeStreamData:
		st := s.lookup(f.StreamID)
		if st == nil {
			// Data for a stream that is gone. Dropped: a stream can be retired
			// locally while frames for it are still in flight, and that race is
			// normal rather than an error.
			return nil
		}
		// The payload aliases the codec's buffer and is overwritten on the next
		// read, so deliver copies it into the stream.
		if err := st.deliver(f.Payload); err != nil {
			return &fatalError{err: err, reason: proto.ReasonFlowControlViolation}
		}
		return nil

	case proto.TypeStreamWindow:
		credit, err := proto.DecodeWindow(f.Payload)
		if err != nil {
			return err
		}
		if st := s.lookup(f.StreamID); st != nil {
			st.grantCredit(credit)
		}
		return nil

	case proto.TypeCloseStream:
		reason := proto.Reason(f.Payload)
		if reason == "" {
			reason = proto.ReasonOK
		}
		// A close may be answering an open this side is still waiting on, which
		// is how a refusal is reported.
		s.completeOpen(f.StreamID, reason)
		if st := s.lookup(f.StreamID); st != nil {
			st.remoteClose(reason)
			s.retireIfDone(st)
		}
		return nil

	case proto.TypePing:
		// Echo the token so the sender can match the reply to its probe.
		return s.conn.W.WriteFrame(proto.TypePong, 0, f.Payload)

	case proto.TypePong:
		return nil // liveness already recorded by lastRecv

	case proto.TypeError:
		reason := proto.Reason(f.Payload)
		s.setErr(fmt.Errorf("%w: peer sent error: %s", ErrSessionClosed, reason))
		s.shutdown(reason)
		return nil

	case proto.TypeHello, proto.TypeHelloAck, proto.TypeAuth, proto.TypeAuthOK:
		// The handshake happens once. Repeating it mid-session is the shape of a
		// downgrade attempt, so it is refused rather than ignored.
		return fmt.Errorf("%w: %s after handshake", proto.ErrMalformedFrame, f.Type)

	default:
		return fmt.Errorf("%w: unexpected %s", proto.ErrMalformedFrame, f.Type)
	}
}

// handleOpen registers a stream the peer opened, or refuses it.
func (s *Session) handleOpen(id uint32, payload []byte) error {
	s.mu.Lock()
	if _, exists := s.streams[id]; exists {
		s.mu.Unlock()
		return fmt.Errorf("%w: peer reopened live stream %d", proto.ErrMalformedFrame, id)
	}
	// Parity check: the peer must number streams from its own half of the space.
	// A peer using our parity could otherwise collide with a stream we are about
	// to open.
	if (id%2 == 1) == s.isClient {
		s.mu.Unlock()
		return fmt.Errorf("%w: peer opened stream %d with the wrong parity", proto.ErrMalformedFrame, id)
	}
	if uint32(len(s.streams)) >= s.maxStreams {
		s.mu.Unlock()
		// Refused, not fatal: the peer asked for one stream too many, which is a
		// limit being enforced rather than a broken peer.
		return s.conn.W.WriteClose(id, proto.ReasonLimitStreamsExceeded)
	}
	st := newStream(id, s, s.window)
	// Copied out of the codec buffer, which is reused on the next read.
	if len(payload) > 0 {
		st.openPayload = append([]byte(nil), payload...)
	}
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.conn.W.WriteFrame(proto.TypeStreamOK, id, nil); err != nil {
		return err
	}

	// The queue is sized to the stream limit, so this cannot block.
	select {
	case s.acceptCh <- st:
	default:
		s.retire(id)
		return s.conn.W.WriteClose(id, proto.ReasonLimitStreamsExceeded)
	}
	return nil
}

func (s *Session) completeOpen(id uint32, reason proto.Reason) {
	s.mu.Lock()
	ch, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if ok {
		select {
		case ch <- reason:
		default:
		}
	}
}

func (s *Session) lookup(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) retire(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	delete(s.pending, id)
	s.mu.Unlock()
}

func (s *Session) retireIfDone(st *Stream) {
	if st.finished() {
		s.retire(st.id)
	}
}

// shutdown ends the session without writing an error frame, used when the
// connection has already failed.
func (s *Session) shutdown(reason proto.Reason) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		streams := make([]*Stream, 0, len(s.streams))
		for _, st := range s.streams {
			streams = append(streams, st)
		}
		s.streams = map[uint32]*Stream{}
		pending := s.pending
		s.pending = map[uint32]chan proto.Reason{}
		s.mu.Unlock()

		for _, st := range streams {
			st.kill(reason)
		}
		for _, ch := range pending {
			select {
			case ch <- reason:
			default:
			}
		}

		close(s.done)
		_ = s.conn.Close()
	})
}

// keepAliveLoop probes an idle connection and enforces the idle timeout.
//
// Without this, a connection whose peer has vanished without a FIN — a yanked
// cable, a NAT table entry expiring, a crashed host — stays "established" here
// indefinitely, and the endpoint appears reachable when it is not.
func (s *Session) keepAliveLoop(interval, idle time.Duration) {
	if interval <= 0 {
		interval = idle / 3
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if idle > 0 {
				since := time.Since(time.Unix(0, s.lastRecv.Load()))
				if since > idle {
					s.setErr(fmt.Errorf("%w: nothing received for %s", ErrSessionClosed, since.Round(time.Second)))
					_ = s.Close(proto.ReasonIdleTimeout)
					return
				}
			}
			if err := s.conn.W.WriteFrame(proto.TypePing, 0, nil); err != nil {
				s.setErr(err)
				s.shutdown(proto.ReasonShutdown)
				return
			}
		}
	}
}

// Frame-sending helpers used by Stream.

func (s *Session) sendData(id uint32, b []byte) error {
	if s.isClosed() {
		return s.Err()
	}
	return s.conn.W.WriteFrame(proto.TypeStreamData, id, b)
}

func (s *Session) sendClose(id uint32, r proto.Reason) error {
	if s.isClosed() {
		return nil
	}
	return s.conn.W.WriteClose(id, r)
}

func (s *Session) sendWindowUpdate(id uint32, credit uint32) error {
	if s.isClosed() {
		return s.Err()
	}
	return s.conn.W.WriteFrame(proto.TypeStreamWindow, id, proto.EncodeWindow(credit))
}

// deadlineGuard bounds a handshake, and also makes it cancellable: a blocking
// read cannot be interrupted in Go, so cancellation works by closing the
// connection underneath it.
func deadlineGuard(ctx context.Context, conn *transport.Conn, d time.Duration) (stop func()) {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	stopWatch := conn.CloseOnContext(ctx)
	return func() {
		stopWatch()
		_ = conn.ClearReadDeadline()
	}
}

// Errors reported when a stream cannot be opened.
var (
	// ErrTooManyStreams means this side is already at its stream limit.
	ErrTooManyStreams = errors.New("mux: too many streams")

	// ErrStreamRefused means the peer declined to open the stream.
	ErrStreamRefused = errors.New("mux: stream refused")
)

// fatalError is a dispatch failure that knows which reason code the peer should
// be told. Without it every dispatch failure would be reported as a malformed
// frame, which would misdescribe a well-formed frame that merely broke a rule.
type fatalError struct {
	err    error
	reason proto.Reason
}

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }
