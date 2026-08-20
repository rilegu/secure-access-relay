package proto

import (
	"encoding/binary"
	"fmt"
)

// Role says what a peer is. It is announced in HELLO, before anything else, so
// the relay can tell an endpoint agent from an operator on a single listener.
//
// This is not authentication. A peer claims a role; nothing yet proves it. Until
// mutual TLS is in place, the role is a routing hint and must not be treated as
// a security decision.
type Role uint8

const (
	// RoleAgent is an endpoint agent offering access to its local services.
	RoleAgent Role = 1
	// RoleOperator is a client asking to reach a resource on some agent.
	RoleOperator Role = 2
)

func (r Role) String() string {
	switch r {
	case RoleAgent:
		return "agent"
	case RoleOperator:
		return "operator"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint8(r))
	}
}

func (r Role) known() bool { return r == RoleAgent || r == RoleOperator }

// MaxIdentityLen bounds any single identity string on the wire.
//
// Identities are attacker-supplied until authentication exists, and even
// afterwards they land in logs and audit records. An unbounded string is a way to
// fill a disk, so the limit is enforced at decode.
const MaxIdentityLen = 128

// Hello is the first frame a peer sends. It announces the protocol versions the
// peer can speak and what kind of peer it is.
//
// Version negotiation is a range rather than a single value so that a build
// supporting several versions can interoperate with both older and newer peers.
// It happens exactly once, before anything else is exchanged.
type Hello struct {
	// MinVersion and MaxVersion bound what the sender can speak, inclusive.
	MinVersion uint8
	MaxVersion uint8
	Role       Role
}

// helloSize is the fixed encoded size: min, max, role, and one reserved byte.
//
// The reserved byte exists so a future flag can be added without changing the
// payload length, which would otherwise look like a malformed frame to an older
// peer.
const helloSize = 4

// Encode serialises a Hello.
func (h Hello) Encode() []byte {
	b := make([]byte, helloSize)
	b[0] = h.MinVersion
	b[1] = h.MaxVersion
	b[2] = uint8(h.Role)
	b[3] = 0 // reserved, must be zero
	return b
}

// DecodeHello parses a HELLO payload.
//
// It rejects an unknown role and an inverted version range. Both are malformed
// rather than merely surprising: a peer that cannot state a coherent version
// range has nothing useful to negotiate.
func DecodeHello(b []byte) (Hello, error) {
	if len(b) != helloSize {
		return Hello{}, fmt.Errorf("%w: hello payload is %d bytes, want %d", ErrMalformedFrame, len(b), helloSize)
	}
	h := Hello{MinVersion: b[0], MaxVersion: b[1], Role: Role(b[2])}
	if h.MinVersion > h.MaxVersion {
		return Hello{}, fmt.Errorf("%w: hello version range %d..%d is inverted", ErrMalformedFrame, h.MinVersion, h.MaxVersion)
	}
	if !h.Role.known() {
		return Hello{}, fmt.Errorf("%w: unknown role %d", ErrMalformedFrame, b[2])
	}
	return h, nil
}

// HelloAck answers a Hello with the chosen version and the limits that will
// apply for the life of the connection.
//
// Limits are announced by the responder and are not renegotiable. A peer that
// dislikes them may disconnect; it may not argue. Fixing them once removes a
// whole class of mid-connection state changes that would otherwise need to be
// reasoned about.
type HelloAck struct {
	Version         uint8
	MaxFramePayload uint32
	InitialWindow   uint32
	MaxStreams      uint32
}

const helloAckSize = 1 + 4 + 4 + 4

// Encode serialises a HelloAck.
func (a HelloAck) Encode() []byte {
	b := make([]byte, helloAckSize)
	b[0] = a.Version
	binary.BigEndian.PutUint32(b[1:], a.MaxFramePayload)
	binary.BigEndian.PutUint32(b[5:], a.InitialWindow)
	binary.BigEndian.PutUint32(b[9:], a.MaxStreams)
	return b
}

// DecodeHelloAck parses a HELLO_ACK payload.
//
// The announced limits are sanity-checked here rather than trusted. A peer that
// announces a zero window would deadlock every stream, and one that announces a
// frame size larger than this build supports would induce oversized allocations
// on the first data frame. Both are refused at the handshake, where the failure
// is cheap and obvious.
func DecodeHelloAck(b []byte) (HelloAck, error) {
	if len(b) != helloAckSize {
		return HelloAck{}, fmt.Errorf("%w: hello_ack payload is %d bytes, want %d", ErrMalformedFrame, len(b), helloAckSize)
	}
	a := HelloAck{
		Version:         b[0],
		MaxFramePayload: binary.BigEndian.Uint32(b[1:]),
		InitialWindow:   binary.BigEndian.Uint32(b[5:]),
		MaxStreams:      binary.BigEndian.Uint32(b[9:]),
	}
	if a.MaxFramePayload == 0 || a.MaxFramePayload > MaxFramePayload {
		return HelloAck{}, fmt.Errorf("%w: announced frame size %d, this build supports 1..%d",
			ErrMalformedFrame, a.MaxFramePayload, MaxFramePayload)
	}
	if a.InitialWindow == 0 {
		return HelloAck{}, fmt.Errorf("%w: announced a zero initial window, which cannot carry data", ErrMalformedFrame)
	}
	if a.MaxStreams == 0 {
		return HelloAck{}, fmt.Errorf("%w: announced a zero stream limit", ErrMalformedFrame)
	}
	return a, nil
}

// Auth presents a peer's claimed identity.
//
// Nothing here is proved. Until mutual TLS and enrollment exist, these are
// development identities: labels that make sessions attributable in logs and
// let the relay route an operator to the right agent. They confer no authority,
// and the relay must not treat them as though they do.
type Auth struct {
	// DeviceID identifies the endpoint. Sent by an agent to register itself, and
	// by an operator to say which endpoint it wants to reach.
	DeviceID string

	// UserID identifies the operator. Empty for an agent.
	UserID string

	// Resource names what the operator wants on that device. Empty for an agent.
	//
	// It is a name, never an address. The agent resolves it against its own
	// configuration; nothing on this side turns it into a destination.
	Resource string
}

// Encode serialises an Auth as three length-prefixed strings.
//
// All three fields are always present, even when empty, so the encoding does not
// depend on the sender's role. A decoder that had to know the role to parse the
// payload would have to trust the role before validating the frame.
func (a Auth) Encode() []byte {
	b := make([]byte, 0, 6+len(a.DeviceID)+len(a.UserID)+len(a.Resource))
	b = appendString(b, a.DeviceID)
	b = appendString(b, a.UserID)
	b = appendString(b, a.Resource)
	return b
}

// DecodeAuth parses an AUTH payload.
func DecodeAuth(b []byte) (Auth, error) {
	var a Auth
	var err error
	if a.DeviceID, b, err = takeString(b); err != nil {
		return Auth{}, fmt.Errorf("auth device_id: %w", err)
	}
	if a.UserID, b, err = takeString(b); err != nil {
		return Auth{}, fmt.Errorf("auth user_id: %w", err)
	}
	if a.Resource, b, err = takeString(b); err != nil {
		return Auth{}, fmt.Errorf("auth resource: %w", err)
	}
	if len(b) != 0 {
		// Trailing bytes mean the sender and this decoder disagree about the
		// payload. Ignoring them would let a peer smuggle data past a reviewer.
		return Auth{}, fmt.Errorf("%w: %d trailing bytes after auth", ErrMalformedFrame, len(b))
	}
	return a, nil
}

// AuthOK confirms a session and names it, so both ends log the same identifier.
type AuthOK struct {
	SessionID string
}

// Encode serialises an AuthOK.
func (a AuthOK) Encode() []byte { return appendString(nil, a.SessionID) }

// DecodeAuthOK parses an AUTH_OK payload.
func DecodeAuthOK(b []byte) (AuthOK, error) {
	id, rest, err := takeString(b)
	if err != nil {
		return AuthOK{}, fmt.Errorf("auth_ok session_id: %w", err)
	}
	if len(rest) != 0 {
		return AuthOK{}, fmt.Errorf("%w: %d trailing bytes after auth_ok", ErrMalformedFrame, len(rest))
	}
	return AuthOK{SessionID: id}, nil
}

// EncodeWindow serialises a flow-control credit.
func EncodeWindow(credit uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, credit)
	return b
}

// DecodeWindow parses a STREAM_WINDOW payload.
//
// Zero credit is refused. It conveys nothing, and accepting it would mean a peer
// could spend a connection's budget sending updates that never unblock anything.
func DecodeWindow(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, fmt.Errorf("%w: window payload is %d bytes, want 4", ErrMalformedFrame, len(b))
	}
	credit := binary.BigEndian.Uint32(b)
	if credit == 0 {
		return 0, fmt.Errorf("%w: zero window credit", ErrMalformedFrame)
	}
	return credit, nil
}

// appendString writes a uint16 length prefix followed by the bytes.
func appendString(dst []byte, s string) []byte {
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(s)))
	dst = append(dst, n[:]...)
	return append(dst, s...)
}

// takeString reads one length-prefixed string, returning it and the remainder.
//
// The length is validated against both MaxIdentityLen and the bytes actually
// available before any slicing, so a declared length cannot read past the buffer
// or allocate beyond the cap.
func takeString(b []byte) (string, []byte, error) {
	if len(b) < 2 {
		return "", nil, fmt.Errorf("%w: truncated length prefix", ErrMalformedFrame)
	}
	n := int(binary.BigEndian.Uint16(b))
	if n > MaxIdentityLen {
		return "", nil, fmt.Errorf("%w: string length %d exceeds %d", ErrMalformedFrame, n, MaxIdentityLen)
	}
	if len(b) < 2+n {
		return "", nil, fmt.Errorf("%w: declared %d bytes, have %d", ErrMalformedFrame, n, len(b)-2)
	}
	return string(b[2 : 2+n]), b[2+n:], nil
}
