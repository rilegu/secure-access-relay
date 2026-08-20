// Package mux multiplexes many logical streams over one framed connection.
//
// A session owns a connection; streams are opened on it by either end and behave
// as io.ReadWriteCloser. Once a stream exists, forwarding is an io.Copy and the
// caller never sees a frame.
//
// # Why this is written here
//
// Established multiplexers exist. This one is written out because the framing,
// its limits, and its behaviour on hostile input are the substance of this
// project rather than an implementation detail of it — see
// docs/decisions/0004-custom-data-plane-framing.md. Every bound is visible in
// this package.
//
// # Flow control
//
// Each stream has a receive window granted to the peer and a send window granted
// by it. A writer blocks when its send window is exhausted and resumes when the
// reader on the far end consumes data and returns credit. That is what stops a
// fast producer from forcing unbounded buffering in a slow consumer, and it is
// enforced: a peer that sends beyond its window kills the session rather than
// growing a buffer here.
//
// # What this package must never do
//
//   - It must never make an authorization decision. Admission is the caller's
//     job, which is why the responder handshake pauses at [Handshake] instead of
//     completing on its own.
//   - It must never log payload bytes.
package mux
