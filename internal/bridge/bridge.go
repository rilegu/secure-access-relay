// Package bridge joins two connections and copies bytes between them.
//
// It is used wherever this system forwards traffic: operator to relay, relay to
// agent, agent to the local target. Keeping it in one place means the teardown
// rules are written once and behave the same everywhere.
package bridge

import (
	"io"
	"sync"

	"github.com/rilegu/secure-access-relay/internal/proto"
)

// bufferSize is the per-direction copy buffer. Sized to the frame limit so a
// copy maps onto whole frames rather than repeatedly splitting them.
const bufferSize = proto.MaxFramePayload

// Stats records what a bridged pair carried, for audit.
type Stats struct {
	// AToB counts bytes copied from the first connection to the second.
	AToB int64
	// BToA counts bytes copied the other way.
	BToA int64
}

// closeWriter is implemented by connections that can end their send direction
// without tearing down the receive direction — TCP connections and multiplexed
// streams both do.
type closeWriter interface {
	CloseWrite() error
}

// resetter is implemented by connections that can abort both directions at once
// and say why. A multiplexed stream can; a plain TCP connection cannot, and is
// simply closed instead.
type resetter interface {
	Reset(proto.Reason) error
}

// Join copies bytes in both directions until both are finished, then releases
// both sides. It returns the byte counts and the first error observed.
//
// # Half-close versus abort
//
// The two cases are genuinely different and conflating them causes hangs.
//
// A direction that ends at a clean EOF means "the sender is finished". Only that
// direction is closed, so the far end can still reply — which is what a
// request/response protocol depends on. Tearing down both directions at the
// first EOF would discard the response to every completed request.
//
// A direction that ends in any other way means the connection is broken. Then
// *both* sides must be aborted, because half-closing would leave the peer
// writing into a window that will never reopen: it blocks forever, holding its
// own upstream connection open with it. That is a hang rather than an error, and
// it is much harder to diagnose.
func Join(a, b io.ReadWriteCloser) (Stats, error) {
	var (
		stats Stats
		mu    sync.Mutex
		first error
		wg    sync.WaitGroup
	)

	record := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if first == nil {
			first = err
		}
		mu.Unlock()
	}

	// abort tears down both sides. Doing both is what unblocks whichever
	// goroutine is parked on the other one.
	abort := func(reason proto.Reason) {
		reset(a, reason)
		reset(b, reason)
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		n, rerr, werr := copyOneWay(b, a)
		mu.Lock()
		stats.AToB = n
		mu.Unlock()

		switch {
		case werr != nil:
			record(werr)
			abort(proto.ReasonShutdown)
		case rerr != nil:
			record(rerr)
			abort(proto.ReasonShutdown)
		default:
			halfClose(b) // clean EOF on a: signal only that direction
		}
	}()

	go func() {
		defer wg.Done()
		n, rerr, werr := copyOneWay(a, b)
		mu.Lock()
		stats.BToA = n
		mu.Unlock()

		switch {
		case werr != nil:
			record(werr)
			abort(proto.ReasonShutdown)
		case rerr != nil:
			record(rerr)
			abort(proto.ReasonShutdown)
		default:
			halfClose(a)
		}
	}()

	wg.Wait()

	_ = a.Close()
	_ = b.Close()

	mu.Lock()
	defer mu.Unlock()
	return stats, first
}

// copyOneWay copies src into dst, reporting read and write failures separately.
//
// io.Copy folds both into one error, which is not enough here: a read failure and
// a write failure call for the same teardown, but a clean EOF calls for a very
// different one, and only an explicit split makes that distinguishable.
func copyOneWay(dst io.Writer, src io.Reader) (n int64, rerr, werr error) {
	buf := make([]byte, bufferSize)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			n += int64(nw)
			if ew != nil {
				return n, nil, ew
			}
			if nw != nr {
				return n, nil, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return n, nil, nil // orderly end of this direction
			}
			return n, er, nil
		}
	}
}

func halfClose(c io.ReadWriteCloser) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func reset(c io.ReadWriteCloser, reason proto.Reason) {
	if r, ok := c.(resetter); ok {
		_ = r.Reset(reason)
		return
	}
	_ = c.Close()
}
