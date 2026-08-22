// Package bridge joins two connections and copies bytes between them.
//
// It is used wherever this system forwards traffic: operator to relay, relay to
// agent, agent to the local target. Keeping it in one place means the teardown
// rules are written once and behave the same everywhere.
package bridge

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/rilegu/secure-access-relay/internal/proto"
)

// ErrBudgetExhausted means a bridged pair reached its byte budget and was cut.
//
// A distinct error because it is not a failure: the limit did exactly what it
// was configured to do, and an operator reading the record must be able to tell
// "your transfer cap was reached" from "the connection broke".
var ErrBudgetExhausted = errors.New("bridge: transfer budget exhausted")

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
	return JoinWithBudget(a, b, 0)
}

// JoinWithBudget is Join with a cap on total bytes carried in both directions.
//
// A budget of zero means unlimited, which is the default and must stay an
// explicit choice in configuration rather than an accident.
//
// The cap is exact, not approximate: the final write is clamped to whatever
// remains rather than being allowed to overshoot by up to a frame. A limit that
// can be exceeded by 64 KiB is a limit that has to be explained, and this one is
// cheap to make precise.
//
// Both directions share one budget. A grant authorizes a session, not a
// direction, and a cap that applied per-direction would let twice as much
// through as the number in the policy says.
func JoinWithBudget(a, b io.ReadWriteCloser, maxBytes uint64) (Stats, error) {
	var (
		stats Stats
		mu    sync.Mutex
		first error
		wg    sync.WaitGroup
		spent atomic.Uint64
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

	// take reserves up to want bytes of the shared budget, reporting how many are
	// available. Zero means the budget is gone and the pair must be cut.
	take := func(want int) int {
		if maxBytes == 0 {
			return want
		}
		for {
			used := spent.Load()
			if used >= maxBytes {
				return 0
			}
			left := maxBytes - used
			grant := uint64(want)
			if grant > left {
				grant = left
			}
			if spent.CompareAndSwap(used, used+grant) {
				return int(grant)
			}
		}
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		n, rerr, werr := copyOneWay(b, a, take)
		mu.Lock()
		stats.AToB = n
		mu.Unlock()

		switch {
		case errors.Is(werr, ErrBudgetExhausted):
			record(werr)
			abort(proto.ReasonLimitBytesExceeded)
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
		n, rerr, werr := copyOneWay(a, b, take)
		mu.Lock()
		stats.BToA = n
		mu.Unlock()

		switch {
		case errors.Is(werr, ErrBudgetExhausted):
			record(werr)
			abort(proto.ReasonLimitBytesExceeded)
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
// take reserves budget for a chunk about to be written. It returns how many of
// the requested bytes may go, and zero when the budget is spent.
func copyOneWay(dst io.Writer, src io.Reader, take func(int) int) (n int64, rerr, werr error) {
	buf := make([]byte, bufferSize)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// The budget is claimed before the write, not counted after it, so the
			// cap holds exactly rather than being discovered once it is already
			// exceeded.
			allowed := take(nr)
			if allowed < nr {
				if allowed > 0 {
					nw, _ := dst.Write(buf[:allowed])
					n += int64(nw)
				}
				return n, nil, ErrBudgetExhausted
			}
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
