package proto

import (
	"bufio"
	"fmt"
	"io"
	"sync"
)

// Reader decodes frames from a stream.
//
// It owns a single payload buffer sized to the configured maximum and reuses it
// for every frame, so steady-state reading does not allocate. The consequence is
// the aliasing rule documented on [Frame]: the payload of a returned frame is
// valid only until the next ReadFrame call on this Reader.
//
// A Reader is not safe for concurrent use. Each connection has exactly one read
// loop, which is also what keeps frame ordering meaningful.
type Reader struct {
	br     *bufio.Reader
	header [HeaderSize]byte
	buf    []byte
	max    uint32
}

// NewReader returns a Reader that will refuse any frame declaring a payload
// larger than max.
//
// The payload buffer is allocated once, up front, at max bytes. That is a
// deliberate trade: it costs a fixed amount of memory per connection in exchange
// for never sizing an allocation from a number a peer chose.
func NewReader(r io.Reader, max uint32) *Reader {
	return &Reader{
		// The bufio layer matters for correctness as well as speed: it lets the
		// header read be a single ReadFull against buffered bytes rather than a
		// syscall per field.
		br:  bufio.NewReaderSize(r, int(max)/8),
		buf: make([]byte, max),
		max: max,
	}
}

// ReadFrame reads exactly one frame.
//
// The returned frame's Payload aliases the Reader's internal buffer and is only
// valid until the next call. Copy it if it must outlive that.
//
// On a decode error the connection must be closed. There is no resynchronisation
// path in a length-prefixed protocol: once the stream position is in doubt, every
// subsequent read is attacker-influenced. Use [ReasonFor] to turn the error into
// the reason code the peer is told before closing.
func (r *Reader) ReadFrame() (Frame, error) {
	// Header first. io.EOF here is the normal way a connection ends and is passed
	// through unwrapped so callers can test for it with errors.Is.
	if _, err := io.ReadFull(r.br, r.header[:]); err != nil {
		return Frame{}, err
	}

	// Validation happens entirely inside decodeHeader, before we touch the
	// payload. See the note there on ordering.
	t, streamID, length, err := decodeHeader(r.header[:], r.max)
	if err != nil {
		return Frame{}, err
	}

	if length == 0 {
		return Frame{Type: t, StreamID: streamID}, nil
	}

	// length is already known to be <= r.max, so this slice is always in bounds.
	payload := r.buf[:length]
	if _, err := io.ReadFull(r.br, payload); err != nil {
		// A truncated payload is malformed, not a clean end of stream: the peer
		// promised bytes it did not send. Report it as such rather than letting a
		// bare io.EOF look like an orderly close.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return Frame{}, fmt.Errorf("%w: truncated payload, wanted %d bytes", ErrMalformedFrame, length)
		}
		return Frame{}, err
	}

	return Frame{Type: t, StreamID: streamID, Payload: payload}, nil
}

// Writer encodes frames onto a stream.
//
// Unlike Reader, a Writer is safe for concurrent use. That is required rather
// than convenient: on any given connection a data-forwarding goroutine and a
// control path (close, error, keepalive) may both need to write, and two
// interleaved frame writes would corrupt the stream. The mutex makes each frame
// atomic with respect to other writers.
type Writer struct {
	mu     sync.Mutex
	w      io.Writer
	header [HeaderSize]byte
	max    uint32
}

// NewWriter returns a Writer that refuses to emit a frame larger than max.
func NewWriter(w io.Writer, max uint32) *Writer {
	return &Writer{w: w, max: max}
}

// WriteFrame writes one frame. It is atomic with respect to other WriteFrame
// calls on the same Writer.
//
// Oversized payloads are rejected here as well as on read. Enforcing a limit only
// on receive would let a local bug produce frames no conforming peer can accept,
// which surfaces as a confusing remote failure instead of a clear local one.
func (w *Writer) WriteFrame(t Type, streamID uint32, payload []byte) error {
	if uint32(len(payload)) > w.max {
		return fmt.Errorf("%w: payload %d, max %d", ErrFrameTooLarge, len(payload), w.max)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	encodeHeader(w.header[:], t, streamID, uint32(len(payload)))

	// Header and payload are written separately rather than copied into one
	// buffer. For the sizes involved a second write costs less than the copy, and
	// the mutex already guarantees no other frame interleaves between them.
	if _, err := w.w.Write(w.header[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.w.Write(payload); err != nil {
			return fmt.Errorf("write frame payload: %w", err)
		}
	}
	return nil
}

// WriteClose sends a CLOSE_STREAM carrying a reason code.
//
// Every stream teardown carries a reason, including successful ones, so that the
// audit trail can state why a session ended rather than inferring it from the
// absence of an error.
func (w *Writer) WriteClose(streamID uint32, reason Reason) error {
	return w.WriteFrame(TypeCloseStream, streamID, []byte(reason))
}

// WriteError sends a connection-level ERROR carrying a reason code.
//
// The reason code is the entire payload. No diagnostic detail is attached: an
// error frame goes to a peer that may be hostile, and error text is a classic way
// to leak internal state.
func (w *Writer) WriteError(reason Reason) error {
	return w.WriteFrame(TypeError, 0, []byte(reason))
}
