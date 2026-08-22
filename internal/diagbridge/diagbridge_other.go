//go:build !windows

package diagbridge

// Library is the non-Windows placeholder.
//
// The diagnostics library collects Windows network state through the IP Helper
// and WinHTTP APIs, which have no counterpart worth emulating elsewhere. The
// relay runs on Linux and has no use for it; the agent, which does, runs on
// Windows.
//
// This exists so the agent and its tests compile on every platform CI builds,
// rather than the callers guarding each use with a build tag.
type Library struct{}

// Open always reports that no library is available.
//
// ErrUnsupportedPlatform rather than ErrUnavailable, so a Linux build that
// somehow reaches this says why instead of implying the file is missing.
func Open(cfg Config) (*Library, error) { return nil, ErrUnsupportedPlatform }

// Close is a no-op.
func (l *Library) Close() error { return nil }

// Snapshot always fails on this platform.
func (l *Library) Snapshot() (*Snapshot, error) { return nil, ErrUnsupportedPlatform }

// InterfaceMetrics always fails on this platform.
func (l *Library) InterfaceMetrics(luid uint64) ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}
