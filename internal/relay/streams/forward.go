package streams

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// Peer is one end of a forwarded stream.
//
// The two ends are not symmetric in how they are driven — an operator connection
// is read directly from a socket, while an agent connection is read by a shared
// loop and delivered over a queue — so forwarding is written against this
// interface rather than against a concrete connection type.
type Peer interface {
	// Recv returns the next frame, or an error if the peer has gone away.
	Recv(ctx context.Context) (proto.Frame, error)

	// Send writes a frame. Implementations must be safe for concurrent use.
	Send(t proto.Type, streamID uint32, payload []byte) error

	// Close terminates the peer.
	Close() error
}

// Stats records what a stream carried, for audit.
//
// Byte counts are accumulated as the stream runs rather than estimated
// afterwards, because they are part of the audit record.
type Stats struct {
	// ToAgent counts payload bytes travelling operator to agent.
	ToAgent int64
	// ToOperator counts payload bytes travelling agent to operator.
	ToOperator int64
}

// ConnPeer adapts a framed connection to [Peer].
//
// Recv ignores its context: a blocking socket read cannot be interrupted by
// cancellation in Go, so callers unblock it by closing the connection instead.
type ConnPeer struct{ Conn *transport.Conn }

func (p ConnPeer) Recv(context.Context) (proto.Frame, error) { return p.Conn.R.ReadFrame() }

func (p ConnPeer) Send(t proto.Type, streamID uint32, payload []byte) error {
	return p.Conn.W.WriteFrame(t, streamID, payload)
}

func (p ConnPeer) Close() error { return p.Conn.Close() }

// Forward pumps frames in both directions between an operator and an agent until
// either side ends the stream.
//
// It returns why the stream ended and how much it carried. The reason is always
// meaningful: an orderly close reports what the closing side said, and a failure
// reports what went wrong, so an audit record never has to infer why a session
// stopped.
//
// # What is deliberately not done here
//
// The relay never interprets payload bytes. It forwards STREAM_DATA opaquely and
// understands only the frames needed to know when a stream is over. It cannot
// decide whether the traffic is allowed: that decision was already made, and
// re-deciding it here would place authorization in the component least trusted
// to hold it (invariant 2).
//
// # Teardown
//
// The operator connection is closed when forwarding ends, because closing the
// socket is the only way to unblock a goroutine parked in a socket read. The
// agent connection is left open: it is long-lived and carries later streams, so
// this sends it a CLOSE_STREAM instead and lets it release its own target.
func Forward(ctx context.Context, op, ag Peer, streamID uint32) (proto.Reason, Stats) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu          sync.Mutex // guards stats and the first-reason fields
		stats       Stats
		firstReason proto.Reason
		reasonSet   bool
		wg          sync.WaitGroup
	)

	// record keeps the first reason observed. Whichever direction finishes first
	// explains the close; a later error during teardown is a consequence, not the
	// cause, and would mislead anyone reading the audit trail.
	record := func(r proto.Reason) {
		mu.Lock()
		defer mu.Unlock()
		if !reasonSet {
			firstReason, reasonSet = r, true
		}
	}

	wg.Add(2)

	// Operator to agent.
	go func() {
		defer wg.Done()
		// filterByStreamID is false: the operator connection carries exactly one
		// stream, so any ID it sends refers to that stream. The ID is rewritten
		// on the way out, so what the operator chose never reaches the agent.
		n, reason := pump(ctx, op, ag, streamID, false)
		mu.Lock()
		stats.ToAgent += n
		mu.Unlock()
		record(reason)

		// Tell the agent the stream is over so it can drop its target
		// connection, then unblock the other direction.
		_ = ag.Send(proto.TypeCloseStream, streamID, []byte(reason))
		cancel()
		_ = op.Close()
	}()

	// Agent to operator.
	go func() {
		defer wg.Done()
		// filterByStreamID is true: the agent connection is long-lived and shared
		// across successive streams, so frames must be selected by ID or a late
		// frame from a finished stream could be delivered to this operator.
		n, reason := pump(ctx, ag, op, streamID, true)
		mu.Lock()
		stats.ToOperator += n
		mu.Unlock()
		record(reason)

		cancel()
		_ = op.Close()
	}()

	wg.Wait()

	if !reasonSet {
		return proto.ReasonOK, stats
	}
	return firstReason, stats
}

// pump copies frames from src to dst until the stream ends, returning how many
// payload bytes were forwarded and why it stopped.
//
// The stream ID is rewritten on the way out rather than trusted from the sender,
// so a peer cannot address a stream it was not given by putting a different
// number in the header.
func pump(ctx context.Context, src, dst Peer, streamID uint32, filterByStreamID bool) (int64, proto.Reason) {
	var total int64

	for {
		f, err := src.Recv(ctx)
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				// The ordinary way a TCP session ends: the far end finished.
				return total, proto.ReasonOK
			case errors.Is(err, net.ErrClosed), errors.Is(err, context.Canceled):
				// The other direction already tore the stream down. Not a failure
				// in its own right; the reason it recorded is the real one.
				return total, proto.ReasonOK
			default:
				return total, proto.ReasonFor(err)
			}
		}

		// On a shared connection, drop frames belonging to another stream. Without
		// this a late frame from a finished stream could bleed across a boundary
		// and be delivered to the wrong operator.
		if filterByStreamID && f.StreamID != streamID {
			continue
		}

		switch f.Type {
		case proto.TypeStreamData:
			if err := dst.Send(proto.TypeStreamData, streamID, f.Payload); err != nil {
				return total, proto.ReasonShutdown
			}
			total += int64(len(f.Payload))

		case proto.TypeCloseStream:
			// The payload is the peer's reason code, returned so it lands in the
			// audit record.
			reason := proto.Reason(f.Payload)
			if reason == "" {
				reason = proto.ReasonOK
			}
			return total, reason

		case proto.TypeError:
			return total, proto.Reason(f.Payload)

		default:
			// Well-formed but meaningless on an established stream. Refusing is
			// deliberate: silently ignoring unexpected frames is how a peer
			// smuggles in behaviour a reviewer never considered.
			return total, proto.ReasonProtocolMalformedFrame
		}
	}
}
