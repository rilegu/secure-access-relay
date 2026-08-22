//go:build !windows

package netwatch

import "context"

// watch polls the interface list on platforms with no native notification.
//
// The relay runs on Linux, so this is not a stub for an unsupported case — it is
// the implementation that runs in the deployment where an address change matters
// least, because a relay sits on a stable address by definition. The agent, where
// it matters most, is on Windows and gets the native watcher.
func watch(ctx context.Context, ch chan<- struct{}) {
	pollAddresses(ctx, ch)
}
