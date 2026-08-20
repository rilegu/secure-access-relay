package proto

import "time"

// Protocol limits. Every one of these is enforced, tested, and has a distinct
// reason code on violation, so that a peer can tell precisely which bound it hit.
//
// These values are duplicated in docs/protocol.md. Changing one means changing
// both, and changing a wire-visible limit means bumping [Version].
//
// Threat-model note: T12 (resource exhaustion) and T13 (malformed input causing
// crash or overread) are both defended here rather than at a higher layer,
// because by the time a frame reaches the relay or agent logic it is too late to
// refuse to allocate for it.
const (
	// MaxFramePayload bounds a single frame's payload. The decoder checks the
	// declared length against this value *before* allocating or reading, so a
	// peer cannot induce a large allocation just by claiming a large frame.
	MaxFramePayload = 64 * 1024

	// MaxStreamsPerConnection caps concurrent streams on one connection. Phase 1
	// runs single-stream, so the relay currently enforces a cap of 1; this is the
	// value the full protocol uses once multiplexing lands.
	MaxStreamsPerConnection = 16

	// InitialWindow is the starting credit for per-stream flow control. Unused in
	// the single-stream phase, declared here so the constant has one home.
	InitialWindow = 256 * 1024
)

// Timeouts. Every network operation is bounded; nothing in this system is allowed
// to block forever, because an unbounded read is a denial-of-service primitive
// against the process holding it.
const (
	// HandshakeTimeout bounds how long a newly accepted connection may take to
	// identify itself before the listener gives up on it.
	HandshakeTimeout = 10 * time.Second

	// IdleTimeout is how long a connection may go without traffic before it is
	// considered dead. Chosen as two missed keepalive intervals.
	IdleTimeout = 60 * time.Second

	// DialTimeout bounds the agent's dial to a local target. Loopback either
	// answers quickly or is not listening, so this is deliberately short: a long
	// timeout here only delays an error the operator needs to see.
	DialTimeout = 5 * time.Second
)
