package mux

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/rilegu/secure-access-relay/internal/proto"
)

// Errors a stream can report.
var (
	// ErrStreamClosed means the stream is finished and cannot carry more data.
	ErrStreamClosed = errors.New("mux: stream closed")

	// ErrSessionClosed means the underlying connection went away, taking every
	// stream on it.
	ErrSessionClosed = errors.New("mux: session closed")
)

// Stream is one logical connection multiplexed over a session.
//
// It satisfies io.ReadWriteCloser, which is the point: once a stream exists,
// forwarding is an io.Copy and callers never touch frames. All the framing,
// windowing, and teardown lives here.
//
// # Close semantics
//
// Close is a half-close, modelled on TCP's FIN. It says "I will send nothing
// further"; the peer's Read then returns io.EOF, and the peer may keep sending
// to us. A stream is fully finished when both directions have closed. Use
// [Stream.Reset] to abort both directions at once with a reason.
//
// This distinction matters for request/response protocols: a client that
// finishes its request and half-closes must still be able to read the response.
// Collapsing both directions into one close would break that.
type Stream struct {
	id      uint32
	session *Session

	mu sync.Mutex
	// readable signals new data, a remote close, or a reset.
	readable *sync.Cond
	// writable signals returned send credit, or a reset.
	writable *sync.Cond

	// buf holds bytes received but not yet read. Its growth is bounded by the
	// receive window: the peer may not send more than we have granted, so this
	// cannot exceed the window regardless of how slowly the reader consumes.
	buf []byte

	// recvWindow is how many more bytes the peer may send before it must wait
	// for credit. sendWindow is how many more we may send.
	recvWindow uint32
	sendWindow uint32

	// pendingCredit accumulates bytes consumed by the reader that have not yet
	// been returned to the peer as credit. Batching avoids a window frame per
	// read, which would double the frame count on a busy stream.
	pendingCredit uint32

	localClosed  bool
	remoteClosed bool
	resetReason  proto.Reason
	reset        bool
}

func newStream(id uint32, s *Session, window uint32) *Stream {
	st := &Stream{
		id:         id,
		session:    s,
		recvWindow: window,
		sendWindow: window,
	}
	st.readable = sync.NewCond(&st.mu)
	st.writable = sync.NewCond(&st.mu)
	return st
}

// ID returns the stream identifier, for logs and audit.
func (s *Stream) ID() uint32 { return s.id }

// Read implements io.Reader.
//
// It returns io.EOF once the peer has closed its side and all buffered data has
// been consumed — never before, so a graceful close cannot truncate data already
// in flight.
//
// As bytes are consumed, credit is returned to the peer. That return is what
// keeps the sender moving; without it the peer stalls once it has sent a full
// window.
func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	for len(s.buf) == 0 {
		switch {
		case s.reset:
			reason := s.resetReason
			s.mu.Unlock()
			return 0, fmt.Errorf("%w: %s", ErrStreamClosed, reason)
		case s.remoteClosed:
			// Peer finished and the buffer is drained: an orderly end.
			s.mu.Unlock()
			return 0, io.EOF
		}
		s.readable.Wait()
	}

	n := copy(p, s.buf)
	s.buf = s.buf[n:]

	// Reclaim the window the delivered bytes occupied, and batch the credit
	// until it is worth a frame.
	s.recvWindow += uint32(n)
	s.pendingCredit += uint32(n)
	credit := uint32(0)
	if s.pendingCredit >= s.session.creditThreshold {
		credit, s.pendingCredit = s.pendingCredit, 0
	}
	s.mu.Unlock()

	if credit > 0 {
		// Sent outside the lock: a blocked write on the connection must not
		// stall a reader that already has its data.
		if err := s.session.sendWindowUpdate(s.id, credit); err != nil {
			return n, nil // the session is dying; the caller learns on the next Read
		}
	}
	return n, nil
}

// Write implements io.Writer.
//
// It blocks while the send window is exhausted and resumes when the peer returns
// credit. That blocking *is* the backpressure: a slow reader on the far end
// eventually stops the writer here rather than causing unbounded buffering in
// between.
//
// Payloads larger than one frame are split. Write returns only when everything
// has been handed to the connection or an error occurred.
func (s *Stream) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		s.mu.Lock()
		for {
			if s.reset {
				reason := s.resetReason
				s.mu.Unlock()
				return written, fmt.Errorf("%w: %s", ErrStreamClosed, reason)
			}
			if s.localClosed {
				s.mu.Unlock()
				return written, ErrStreamClosed
			}
			if s.sendWindow > 0 {
				break
			}
			s.writable.Wait()
		}

		// Bounded by three things at once: what is left to write, the frame
		// limit, and the credit the peer has granted.
		n := len(p) - written
		if uint32(n) > s.sendWindow {
			n = int(s.sendWindow)
		}
		if uint32(n) > s.session.maxFrame {
			n = int(s.session.maxFrame)
		}
		s.sendWindow -= uint32(n)
		s.mu.Unlock()

		if err := s.session.sendData(s.id, p[written:written+n]); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

// Close half-closes the stream: no more data will be sent, but data may still be
// received. It is safe to call more than once.
func (s *Stream) Close() error { return s.closeWith(proto.ReasonOK) }

// CloseWrite half-closes the send direction. It is identical to Close and exists
// so that a stream and a TCP connection satisfy the same interface, letting
// generic forwarding code signal "no more data from me" without knowing which it
// holds.
func (s *Stream) CloseWrite() error { return s.closeWith(proto.ReasonOK) }

// CloseWithReason half-closes the stream and tells the peer why.
//
// Every teardown carries a reason, including successful ones, so an audit record
// can state why a session ended rather than inferring it from the absence of an
// error.
func (s *Stream) CloseWithReason(r proto.Reason) error { return s.closeWith(r) }

func (s *Stream) closeWith(r proto.Reason) error {
	s.mu.Lock()
	if s.localClosed || s.reset {
		s.mu.Unlock()
		return nil
	}
	s.localClosed = true
	s.mu.Unlock()

	// Wake any writer blocked on credit so it observes the close.
	s.writable.Broadcast()

	err := s.session.sendClose(s.id, r)
	s.session.retireIfDone(s)
	return err
}

// Reset aborts the stream in both directions.
//
// Unlike Close, this discards anything still buffered and unblocks a peer
// immediately. It is for failures — the local target died, a limit was
// exceeded — not for an orderly end.
func (s *Stream) Reset(r proto.Reason) error {
	s.mu.Lock()
	if s.reset {
		s.mu.Unlock()
		return nil
	}
	s.reset = true
	s.resetReason = r
	s.localClosed = true
	s.remoteClosed = true
	s.buf = nil
	s.mu.Unlock()

	s.readable.Broadcast()
	s.writable.Broadcast()

	err := s.session.sendClose(s.id, r)
	s.session.retire(s.id)
	return err
}

// deliver hands received bytes to the stream.
//
// Returning an error means the peer exceeded the window it was granted. That is
// a protocol violation, not backpressure: the sender was told exactly how much
// it could send. The session treats it as fatal, because a peer that ignores
// flow control can otherwise force unbounded buffering here.
func (s *Stream) deliver(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.reset || s.remoteClosed {
		// Late data on a finished stream. Dropped rather than buffered; the peer
		// has already been told the stream is over.
		return nil
	}
	if uint32(len(b)) > s.recvWindow {
		return fmt.Errorf("stream %d: peer sent %d bytes with %d window remaining", s.id, len(b), s.recvWindow)
	}
	s.recvWindow -= uint32(len(b))
	s.buf = append(s.buf, b...)
	s.readable.Signal()
	return nil
}

// grantCredit adds send credit returned by the peer.
func (s *Stream) grantCredit(n uint32) {
	s.mu.Lock()
	// Saturate rather than wrap. A peer that over-grants is buggy or hostile,
	// and an integer overflow here would hand it an unbounded send window.
	if s.sendWindow > ^uint32(0)-n {
		s.sendWindow = ^uint32(0)
	} else {
		s.sendWindow += n
	}
	s.mu.Unlock()
	s.writable.Broadcast()
}

// remoteClose records that the peer has finished sending.
func (s *Stream) remoteClose(r proto.Reason) {
	s.mu.Lock()
	if s.remoteClosed || s.reset {
		s.mu.Unlock()
		return
	}
	s.remoteClosed = true
	// A non-ok reason is an abort: the peer is not merely finished, something
	// went wrong, and anything still buffered is no longer meaningful.
	if r != proto.ReasonOK && r != "" {
		s.reset = true
		s.resetReason = r
		s.buf = nil
	}
	s.mu.Unlock()

	s.readable.Broadcast()
	s.writable.Broadcast()
}

// kill tears the stream down because the whole session ended.
func (s *Stream) kill(r proto.Reason) {
	s.mu.Lock()
	if s.reset {
		s.mu.Unlock()
		return
	}
	s.reset = true
	s.resetReason = r
	s.localClosed = true
	s.remoteClosed = true
	s.mu.Unlock()

	s.readable.Broadcast()
	s.writable.Broadcast()
}

// finished reports whether both directions are done.
func (s *Stream) finished() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reset || (s.localClosed && s.remoteClosed)
}
