# ADR-0009: Streams half-close; broken connections abort

**Status:** accepted

## Context

A multiplexed stream carries a forwarded TCP connection, and TCP connections end in two
distinct ways. One side may finish sending and still expect to receive — an HTTP client
that has sent its whole request and is waiting for the response. Or the connection may
simply break, with neither side able to continue.

The stream protocol needs to express both, and a multiplexer has a choice: model one
close, or model two.

## Decision

`CLOSE_STREAM` is a **half-close**, modelled on TCP's FIN. It ends only the sender's
direction. The receiver observes end-of-stream and may keep sending. A stream is finished
when both directions have closed.

A `CLOSE_STREAM` carrying a non-`ok` reason is an **abort**: both directions end at once
and buffered data is discarded.

Forwarding code follows the same split. A direction that ends at a clean end-of-stream
half-closes the far side. A direction that ends any other way — a read failure, a write
failure — aborts both sides.

## Rejected: one close that ends both directions

Simpler to implement and to reason about, and wrong for the traffic this system carries.

A forwarded HTTP request finishes its body and closes its send direction while the
response is still being produced. With a single symmetric close, the stream would end
there and every response to a completed request would be discarded. The same applies to
any request/response protocol, which is most of what a support engineer reaches for.

## Rejected: half-close everywhere, with no abort

This was implemented first, and it deadlocked.

When a forwarded connection breaks — an operator's client abandons a large response
mid-transfer — the broken side stops reading. A half-close tells the peer "I will send no
more", but says nothing about receiving, so the peer keeps writing. It exhausts its
flow-control window, blocks waiting for credit that will never be granted because nobody
is reading, and stays blocked indefinitely. It also holds its own upstream connection
open, so the failure propagates outward: in testing, an abandoned response left the
endpoint's local service unable to shut down.

The failure mode is worse than a plain error because it presents as a hang. Nothing logs,
nothing times out, and the affected component looks healthy.

Half-close is correct for a *graceful* end and actively harmful for a *broken* one. Both
cases have to be distinguishable, which means the forwarding layer cannot use `io.Copy` —
it folds read and write failures into one error and cannot tell either from a clean end.
`internal/bridge` copies by hand and reports the three outcomes separately.

## Consequences

- Every teardown carries a reason code, including successful ones, so an audit record can
  state why a stream ended instead of inferring it from the absence of an error.
- A stream needs both `Close` (half) and `Reset` (abort), and forwarding code has to pick
  correctly. Picking wrong in the safe direction — aborting where a half-close would do —
  truncates a response. Picking wrong the other way hangs.
- Flow control makes the abort path mandatory rather than merely tidy. Without windows a
  blocked writer would eventually fail on a full socket buffer; with them it waits
  forever, because waiting for credit is the designed behaviour.
- Regression coverage lives in `internal/mux` for half-close carrying a response, and in
  `internal/e2e` for a client abandoning a response mid-stream.
