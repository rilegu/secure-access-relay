//go:build !windows

package winsvc

import (
	"context"
	"time"
)

// On platforms without a service manager the program simply runs. The
// management calls return an error rather than silently succeeding, so a script
// written for Windows fails visibly instead of appearing to work.

func supported() bool { return false }

func isService() bool { return false }

func run(_ string, f func(context.Context) error) error {
	// Not an error: an agent running in the foreground on Linux is a normal way
	// to run it, and a systemd unit is the equivalent arrangement there.
	return f(context.Background())
}

func install(Config) error             { return ErrUnsupported }
func uninstall(string) error           { return ErrUnsupported }
func start(string) error               { return ErrUnsupported }
func stop(string, time.Duration) error { return ErrUnsupported }
func status(string) (State, error)     { return StateUnknown, ErrUnsupported }
