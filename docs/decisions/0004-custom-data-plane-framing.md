# ADR-0004: Hand-rolled binary framing for the data plane

**Status:** accepted

## Context

The data plane multiplexes several TCP streams over one TLS connection, with flow
control and hard limits. Mature options exist: gRPC bidirectional streaming, HTTP/2,
yamux, smux, QUIC.

## Decision

A custom length-prefixed binary frame protocol in `internal/proto`, specified in
[protocol.md](../protocol.md). The control plane, by contrast, uses plain JSON over
HTTPS.

## Rejected: gRPC / HTTP/2 / yamux

They would work, and in a commercial product one of them would probably be the right
call. Two reasons not to here.

First, the framing, credit-based backpressure, limit enforcement, and malformed-input
handling *are* the substance of this project. Delegating them to a library would move
the security-relevant behavior out of the code that is supposed to be reviewable.

Second, a hand-written frame layer with explicit limits is auditable in a way that a
general-purpose multiplexer is not. Every allocation is bounded by a check that is
visible in the source, and the fuzz target covers the whole decode path.

## Rejected: same protocol for both planes

The control plane benefits from being curl-able and self-describing — it makes the demo
and the documentation dramatically better. The data plane benefits from being compact
and strictly bounded. These are different goals, so they get different encodings.

## Consequences

- Protocol maturity is on us: version negotiation, limits, and error handling must be
  right, and are covered by fuzz and malformed-input tests.
- Frame header layout freezes at the first tagged release; changes then require a
  version bump.
- Unknown frame types are a protocol error, never silently skipped, so a downgrade
  cannot be smuggled in as an unrecognized message.
- QUIC remains a plausible future transport underneath the same framing.
