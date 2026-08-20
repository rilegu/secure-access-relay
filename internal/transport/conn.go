package transport

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rilegu/secure-access-relay/internal/proto"
)

// Conn is a framed connection: a network connection plus the codec state bound
// to it.
//
// Every component speaks frames rather than raw bytes once a connection is
// established, so this type is the single place that pairs a net.Conn with its
// Reader and Writer. When TLS arrives, it wraps the connection here and nothing
// above this layer changes.
//
// Concurrency: W is safe for concurrent use, R is not. That asymmetry is
// intentional and matches how connections are actually driven — one read loop,
// many potential writers (data, close, keepalive).
type Conn struct {
	nc net.Conn
	R  *proto.Reader
	W  *proto.Writer
}

// NewConn wraps an established network connection in the frame codec.
func NewConn(nc net.Conn) *Conn {
	return &Conn{
		nc: nc,
		R:  proto.NewReader(nc, proto.MaxFramePayload),
		W:  proto.NewWriter(nc, proto.MaxFramePayload),
	}
}

// Dial opens a framed connection to addr.
//
// The dial is bounded by ctx. Nothing in this system dials without a deadline:
// an unbounded connect attempt turns an unreachable peer into a goroutine that
// never returns.
func Dial(ctx context.Context, addr string) (*Conn, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return NewConn(nc), nil
}

// Close closes the underlying connection. It is safe to call more than once;
// subsequent calls return the error from the first close, which callers
// generally ignore during teardown.
func (c *Conn) Close() error { return c.nc.Close() }

// RemoteAddr reports the peer address, for logging and audit.
func (c *Conn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

// SetReadDeadline bounds how long the next read may block.
//
// Used to enforce idle timeouts. A connection that has stopped producing frames
// must eventually be torn down rather than held open indefinitely, or a peer can
// exhaust connection slots simply by connecting and going quiet.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.nc.SetReadDeadline(t) }

// ClearReadDeadline removes any read deadline.
func (c *Conn) ClearReadDeadline() error { return c.nc.SetReadDeadline(time.Time{}) }

// DrainAndClose reads and discards any pending input, then closes.
//
// Closing a TCP socket that still has unread data in its receive buffer sends a
// reset, and a reset tells the peer's stack to discard whatever it has already
// buffered — including a frame written moments earlier. That is how a refusal
// reason gets lost and the peer sees a bare connection error instead of being
// told why it was refused.
//
// Draining first lets the write land. The deadline bounds it, because a peer
// that keeps sending must not be able to hold the connection open by refusing
// to stop talking.
func (c *Conn) DrainAndClose(within time.Duration) error {
	_ = c.nc.SetReadDeadline(time.Now().Add(within))

	buf := make([]byte, 4096)
	for {
		if _, err := c.nc.Read(buf); err != nil {
			break
		}
	}
	return c.nc.Close()
}

// CloseOnContext closes the connection when ctx is done.
//
// This is how cancellation reaches a goroutine blocked in a read: Go's net
// package has no way to interrupt a blocking read directly, so cancellation
// works by closing the connection out from under it, which makes the read return
// immediately. The returned function stops the watcher and must be called, or
// the goroutine leaks for as long as ctx lives.
func (c *Conn) CloseOnContext(ctx context.Context) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.nc.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}
