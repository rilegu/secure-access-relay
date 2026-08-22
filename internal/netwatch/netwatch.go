// Package netwatch reports when this machine's network configuration changes.
//
// # Why a reconnect loop needs this
//
// Backoff and reachability are answers to different questions. Backoff asks
// "how hard should I retry something that keeps failing"; a network change
// answers "the reason it was failing may have just gone away".
//
// Without it, an endpoint that loses its link and regains it thirty seconds
// later sits out the remainder of a backoff that grew while the cable was
// unplugged — up to the maximum, for a relay that has been reachable the whole
// time. A support engineer waiting on that endpoint sees a system that looks
// broken. With it, the wait is cut short the moment an address appears.
//
// # What this is not
//
// It is a hint, never a decision. A change signal does not mean the relay is
// reachable, and the absence of one does not mean it is unreachable — a route
// change upstream is invisible here. The reconnect loop must work correctly if
// this package never fires at all, which is exactly what it does on a platform
// with no implementation.
package netwatch

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

// PollInterval is how often the portable watcher re-reads the interface list.
//
// Ten seconds is a compromise: short enough that a returning link is noticed
// well inside a grown backoff, long enough that the syscall is not a background
// cost worth thinking about. The native Windows watcher does not poll at all.
const PollInterval = 10 * time.Second

// Watch returns a channel that receives when the local network configuration
// changes.
//
// The channel is buffered and lossy on purpose: the consumer only needs to know
// that *something* changed since it last looked, and a burst of adapter events
// during a suspend/resume should wake it once rather than queue five wakeups it
// will act on identically.
//
// The channel is closed when ctx is cancelled.
func Watch(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		defer close(ch)
		watch(ctx, ch)
	}()
	return ch
}

// notify performs a non-blocking send, dropping the signal if one is already
// pending. See Watch for why coalescing is correct here.
func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// pollAddresses is the portable watcher: it compares a fingerprint of the
// machine's addresses and reports when it changes.
//
// Used on every platform without a native notification, and as the fallback on
// Windows when the native call is unavailable. Polling is not elegant, but the
// alternative on a platform with no notification API is not noticing at all.
func pollAddresses(ctx context.Context, ch chan<- struct{}) {
	last := addressFingerprint()

	ticker := time.NewTicker(PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if current := addressFingerprint(); current != last {
				last = current
				notify(ch)
			}
		}
	}
}

// addressFingerprint summarises every usable address on the machine.
//
// Loopback is excluded: it is always present and never indicates a change in
// reachability, so including it would add noise to every comparison without
// ever contributing a signal. Down interfaces are excluded for the same reason
// an unplugged cable is not news until it is plugged back in.
//
// The result is sorted, because the order interfaces are reported in is not
// guaranteed to be stable and an unsorted join would report a change every time
// the operating system felt like reordering them.
func addressFingerprint() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		// An error is reported as a distinct fingerprint rather than as "no
		// change". If the interface list becomes readable again, that transition
		// is itself worth waking up for.
		return "error:" + err.Error()
	}

	var parts []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			parts = append(parts, iface.Name+"="+a.String())
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
