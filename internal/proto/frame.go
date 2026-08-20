package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Version is the wire protocol version carried in every frame header. A peer that
// receives a version it does not implement must fail the connection rather than
// guess: silently accepting an unknown version is how a downgrade gets smuggled in.
const Version uint8 = 1

// HeaderSize is the fixed size of a frame header in bytes.
//
//	+--------+--------+----------------+------------------+
//	| ver    | type   | stream_id      | length           |
//	| u8     | u8     | u32            | u32              |
//	+--------+--------+----------------+------------------+
//	| payload (length bytes)                              |
//	+-----------------------------------------------------+
//
// All multi-byte integers are big-endian. The layout is fixed: it freezes at the
// first tagged release, and changes after that require bumping Version.
const HeaderSize = 10

// Byte offsets within the header. Named rather than inlined so the encoder and
// decoder cannot drift apart.
const (
	offVersion  = 0
	offType     = 1
	offStreamID = 2
	offLength   = 6
)

// Type identifies what a frame carries.
type Type uint8

// Frame types. Values are fixed by docs/protocol.md and never reused.
//
// Phase note: only OpenStream, StreamOK, StreamData, CloseStream and Error are
// exchanged today. The rest are declared so that the type space is reserved and
// the decoder can recognise a well-formed frame it is simply not ready to handle,
// which is a clearer failure than "unknown type".
const (
	TypeHello        Type = 0x01 // capability and version announcement
	TypeHelloAck     Type = 0x02 // negotiated version and effective limits
	TypeAuth         Type = 0x03 // credential presentation
	TypeAuthOK       Type = 0x04 // credential accepted, session established
	TypeOpenStream   Type = 0x10 // relay asks the agent to open a stream
	TypeStreamOK     Type = 0x11 // agent confirms the target is connected
	TypeStreamData   Type = 0x12 // opaque payload bytes
	TypeStreamWindow Type = 0x13 // flow-control credit
	TypeCloseStream  Type = 0x14 // orderly close, carries a reason code
	TypePing         Type = 0x20 // keepalive probe
	TypePong         Type = 0x21 // keepalive response
	TypeError        Type = 0x7F // connection-level failure, carries a reason code
)

// String renders a frame type for logs. Unknown values are printed numerically
// rather than mapped to a placeholder name, so an unexpected byte on the wire is
// visible for what it is.
func (t Type) String() string {
	switch t {
	case TypeHello:
		return "HELLO"
	case TypeHelloAck:
		return "HELLO_ACK"
	case TypeAuth:
		return "AUTH"
	case TypeAuthOK:
		return "AUTH_OK"
	case TypeOpenStream:
		return "OPEN_STREAM"
	case TypeStreamOK:
		return "STREAM_OK"
	case TypeStreamData:
		return "STREAM_DATA"
	case TypeStreamWindow:
		return "STREAM_WINDOW"
	case TypeCloseStream:
		return "CLOSE_STREAM"
	case TypePing:
		return "PING"
	case TypePong:
		return "PONG"
	case TypeError:
		return "ERROR"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(t))
	}
}

// known reports whether t is a frame type this protocol version defines. Used to
// reject unrecognised types explicitly instead of ignoring them: an unknown frame
// is a protocol error, never something to skip past.
func (t Type) known() bool {
	switch t {
	case TypeHello, TypeHelloAck, TypeAuth, TypeAuthOK,
		TypeOpenStream, TypeStreamOK, TypeStreamData, TypeStreamWindow,
		TypeCloseStream, TypePing, TypePong, TypeError:
		return true
	default:
		return false
	}
}

// Frame is one decoded protocol frame.
//
// Payload aliasing: a Frame returned by [Reader.ReadFrame] points into a buffer
// owned by that Reader, and stays valid only until the next read on it. Callers
// that need the bytes afterwards must copy them. This avoids allocating on every
// frame on the hot path; the cost is that the ownership rule has to be respected.
type Frame struct {
	Type     Type
	StreamID uint32
	Payload  []byte
}

// Errors returned by the codec. They are sentinels so callers can match with
// errors.Is and map them onto the reason code the peer should be told.
var (
	// ErrFrameTooLarge means a peer declared a payload larger than the negotiated
	// maximum. It is reported before any allocation happens.
	ErrFrameTooLarge = errors.New("proto: frame payload exceeds maximum")

	// ErrMalformedFrame covers a structurally invalid frame: an unknown type, or
	// a payload on a frame type that must not carry one.
	ErrMalformedFrame = errors.New("proto: malformed frame")

	// ErrUnsupportedVersion means the header carried a version this build does
	// not implement.
	ErrUnsupportedVersion = errors.New("proto: unsupported protocol version")
)

// ReasonFor maps an error from the codec onto the reason code to report.
//
// Only this package's own sentinel errors are classified as protocol failures.
// Anything else — a reset connection, a timeout, a closed socket — is a
// transport failure and is reported as a shutdown.
//
// The default matters. Reporting a network reset as protocol_malformed_frame
// accuses the peer of sending bad data when it sent nothing wrong at all, and
// sends whoever reads the audit trail looking for a protocol bug that does not
// exist. An unclassified error is not evidence of malformed input.
func ReasonFor(err error) Reason {
	switch {
	case err == nil:
		return ReasonOK
	case errors.Is(err, ErrFrameTooLarge):
		return ReasonLimitFrameTooLarge
	case errors.Is(err, ErrUnsupportedVersion):
		return ReasonProtocolVersionUnsupported
	case errors.Is(err, ErrMalformedFrame):
		return ReasonProtocolMalformedFrame
	default:
		return ReasonShutdown
	}
}

// encodeHeader writes a frame header into dst, which must be at least HeaderSize
// bytes. Split out from the writer so the tests can exercise the exact byte
// layout without going through an io.Writer.
func encodeHeader(dst []byte, t Type, streamID uint32, length uint32) {
	_ = dst[HeaderSize-1] // bounds check once, hint to the compiler
	dst[offVersion] = Version
	dst[offType] = uint8(t)
	binary.BigEndian.PutUint32(dst[offStreamID:], streamID)
	binary.BigEndian.PutUint32(dst[offLength:], length)
}

// decodeHeader parses a frame header from src, which must be at least HeaderSize
// bytes.
//
// It validates the version, the frame type, and the declared length against max
// *before* the caller reads or allocates the payload. That ordering is the whole
// point of this function: it is what stops a peer from turning a 4-byte length
// field into an arbitrary allocation (threat T13).
func decodeHeader(src []byte, max uint32) (t Type, streamID uint32, length uint32, err error) {
	_ = src[HeaderSize-1] // bounds check once, hint to the compiler

	if v := src[offVersion]; v != Version {
		return 0, 0, 0, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, v, Version)
	}

	t = Type(src[offType])
	if !t.known() {
		return 0, 0, 0, fmt.Errorf("%w: unknown type 0x%02x", ErrMalformedFrame, uint8(t))
	}

	streamID = binary.BigEndian.Uint32(src[offStreamID:])
	length = binary.BigEndian.Uint32(src[offLength:])

	if length > max {
		// Reported before allocating. Do not be tempted to allocate first and
		// check after: that inverts the protection this check exists to give.
		return 0, 0, 0, fmt.Errorf("%w: declared %d, max %d", ErrFrameTooLarge, length, max)
	}

	return t, streamID, length, nil
}
