package netwatch

import (
	"context"
	"syscall"
	"unsafe"
)

// The Windows watcher uses the operating system's own notification rather than
// polling, so a returning link is noticed immediately instead of within
// PollInterval.
//
// Reached through the standard library's syscall package, not a third-party
// Windows binding — the same rule the DPAPI, service control manager, and Event
// Log bindings follow (ADR-0012).
var (
	iphlpapi              = syscall.NewLazyDLL("iphlpapi.dll")
	procNotifyAddrChange  = iphlpapi.NewProc("NotifyAddrChange")
	procNotifyRouteChange = iphlpapi.NewProc("NotifyRouteChange")
)

// watch blocks in NotifyAddrChange, waking whenever an address is added or
// removed.
//
// # Why this runs in its own goroutine and never gets cancelled
//
// Called with two null pointers, NotifyAddrChange blocks the calling thread
// until something changes. There is no way to cancel it, so the goroutine may
// outlive ctx — it is parked in a kernel wait, costing one OS thread and no CPU,
// and it exits at process teardown. That is acceptable for a call that fires at
// most a handful of times in a process's life, and the alternative is the
// overlapped-I/O form: an event handle, an OVERLAPPED structure, and a
// completion wait, which is a great deal more syscall surface to get subtly
// wrong for the same result.
//
// The consequence is handled rather than ignored: every send is non-blocking and
// the receiving loop treats the channel as advisory, so a late wakeup after
// cancellation cannot block anything or be mistaken for a live signal.
func watch(ctx context.Context, ch chan<- struct{}) {
	// Route changes matter as well as address changes: a machine can keep its
	// address and lose its default gateway, which looks identical from the
	// address list and is exactly as fatal to reaching a relay.
	events := make(chan struct{}, 2)

	go blockingNotify(procNotifyAddrChange, events)
	go blockingNotify(procNotifyRouteChange, events)

	// The address poller runs too, as a backstop. If the native calls are
	// unavailable — an unusual system image, a stripped container — the watcher
	// degrades to polling rather than to silence.
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		pollAddresses(ctx, ch)
	}()

	for {
		select {
		case <-ctx.Done():
			<-pollDone
			return
		case <-events:
			notify(ch)
		}
	}
}

// blockingNotify calls a Notify*Change entry point in a loop, signalling each
// time it returns.
//
// A failure is terminal for this goroutine rather than retried: if the call is
// not available, retrying it in a tight loop would spin, and the poller running
// alongside already covers the gap.
func blockingNotify(proc *syscall.LazyProc, events chan<- struct{}) {
	if err := proc.Find(); err != nil {
		return
	}
	for {
		// Both parameters null: the synchronous form, which blocks until the
		// next change rather than registering an overlapped request.
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(nil)), uintptr(unsafe.Pointer(nil)))

		// NO_ERROR is success. Anything else means the notification cannot be
		// relied on, and continuing would spin on the same failure.
		if r != 0 {
			return
		}
		select {
		case events <- struct{}{}:
		default:
		}
	}
}
