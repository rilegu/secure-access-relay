package relay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/relay/sessions"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// TestAwaitStreamAckSkipsStaleFrames is a regression test for a
// desynchronisation that manual testing found and the end-to-end tests missed.
//
// The agent connection is long-lived and carries one stream after another. A
// frame from a stream that has just finished can still be in flight when the
// next stream opens. Taking the first frame that arrives as the answer meant:
//
//  1. a leftover CLOSE_STREAM was read as the new stream's reply,
//  2. a perfectly healthy stream was reported to the operator as refused,
//  3. the agent was left holding a target connection for a stream the relay had
//     already abandoned, and
//  4. every later stream was forwarded into a handler busy discarding it, which
//     presented as a hang rather than an error.
//
// The fix is to select the reply by stream ID. This test pins that down at the
// level where the bug lived, because reproducing the timing end to end is not
// reliable.
func TestAwaitStreamAckSkipsStaleFrames(t *testing.T) {
	agentSide, relaySide := net.Pipe()
	t.Cleanup(func() { _ = agentSide.Close(); _ = relaySide.Close() })

	agent := sessions.NewAgent("test-agent", transport.NewConn(relaySide))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	go func() { _ = agent.ReadLoop(ctx) }()

	// What the agent end sends: leftovers from stream 1, then the real reply for
	// stream 2.
	go func() {
		w := proto.NewWriter(agentSide, proto.MaxFramePayload)
		_ = w.WriteFrame(proto.TypeCloseStream, 1, []byte(proto.ReasonOK))
		_ = w.WriteFrame(proto.TypeStreamData, 1, []byte("late payload"))
		_ = w.WriteFrame(proto.TypeStreamOK, 2, nil)
	}()

	ack, err := awaitStreamAck(ctx, agent, 2)
	if err != nil {
		t.Fatalf("awaitStreamAck: %v", err)
	}
	if ack.Type != proto.TypeStreamOK {
		t.Fatalf("ack type = %v, want STREAM_OK: a stale frame was accepted as the reply", ack.Type)
	}
	if ack.StreamID != 2 {
		t.Fatalf("ack stream id = %d, want 2", ack.StreamID)
	}
}

// TestAwaitStreamAckTimesOut checks that a silent agent cannot hold an operator
// open indefinitely. Failing closed on a timeout is what keeps an unresponsive
// endpoint from looking like a slow one.
func TestAwaitStreamAckTimesOut(t *testing.T) {
	agentSide, relaySide := net.Pipe()
	t.Cleanup(func() { _ = agentSide.Close(); _ = relaySide.Close() })

	agent := sessions.NewAgent("silent-agent", transport.NewConn(relaySide))

	loopCtx, cancelLoop := context.WithCancel(context.Background())
	t.Cleanup(cancelLoop)
	go func() { _ = agent.ReadLoop(loopCtx) }()

	// The agent sends only frames for a different stream, so the reply we want
	// never arrives.
	go func() {
		w := proto.NewWriter(agentSide, proto.MaxFramePayload)
		for {
			if err := w.WriteFrame(proto.TypeCloseStream, 99, []byte(proto.ReasonOK)); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if _, err := awaitStreamAck(ctx, agent, 7); err == nil {
		t.Fatal("awaitStreamAck returned success while the agent never answered")
	}
}
