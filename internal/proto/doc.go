// Package proto defines the data-plane wire format: frame layout, frame types,
// hard limits, and reason codes. It is the single source of truth for anything
// that goes over a relay connection.
//
// The format is specified in docs/protocol.md. Code and document must agree; if
// one changes, so does the other.
//
// # Why a hand-written codec
//
// The framing, its limits, and its handling of malformed input are the parts of
// this system most exposed to hostile data, so they are written explicitly rather
// than delegated to a general-purpose multiplexer. Every allocation is bounded by
// a check visible in this package. See docs/decisions/0004.
//
// # What this package must never do
//
//   - It must never make an authorization decision. It parses and serializes; it
//     does not decide who may do what.
//   - It must never allocate based on an attacker-supplied length before that
//     length has been validated against a limit.
//   - It must never log payload bytes.
package proto
