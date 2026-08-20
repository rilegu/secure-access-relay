// Package winsvc runs a program under the Windows Service Control Manager and
// registers, starts, and removes the service itself.
//
// The endpoint agent has to survive reboots, start before anyone logs in, and be
// restarted automatically when it dies. On Windows that means being a service,
// which means answering the SCM's control requests correctly rather than merely
// running in the background.
//
// # Deliberately no third-party dependency
//
// The SCM is reached through the standard library's syscall package rather than
// an external Windows binding, for the same reason DPAPI is in internal/keystore:
// the project has no external dependencies, and every one added has to survive
// the question "why not the standard library?". The cost is that the structure
// layouts and calling conventions below are written out by hand and have to be
// exactly right — see docs/decisions/0005 for the general rule about ABI
// boundaries.
//
// # Behaviour off Windows
//
// Everything here compiles everywhere. On other platforms Supported reports
// false, Run executes the function directly, and the management calls return an
// error rather than pretending to succeed.
package winsvc

import (
	"context"
	"errors"
	"time"
)

// ErrUnsupported means this platform has no service manager.
var ErrUnsupported = errors.New("winsvc: not supported on this platform")

// ErrNotInstalled means the named service does not exist.
var ErrNotInstalled = errors.New("winsvc: service is not installed")

// ErrAlreadyInstalled means the named service already exists.
var ErrAlreadyInstalled = errors.New("winsvc: service is already installed")

// ErrAccessDenied means the operation needs Administrator rights.
var ErrAccessDenied = errors.New("winsvc: access denied; run as Administrator")

// State is a service's current state as the SCM sees it.
type State string

const (
	StateStopped      State = "stopped"
	StateStartPending State = "start_pending"
	StateStopPending  State = "stop_pending"
	StateRunning      State = "running"
	StateUnknown      State = "unknown"
)

// Config describes a service to install.
type Config struct {
	// Name is the service name used by sc.exe and the SCM.
	Name string

	// DisplayName is what appears in the services list.
	DisplayName string

	// Description is the longer text shown in the service properties.
	Description string

	// ExePath is the absolute path to the binary. It must be absolute: the SCM
	// starts services with an unpredictable working directory, so a relative
	// path would resolve somewhere nobody intended.
	ExePath string

	// Args are passed to the binary on every start.
	Args []string

	// DelayedAutoStart starts the service shortly after boot rather than during
	// it. Preferred here: an agent that starts before networking is ready will
	// fail its first connection and log an error on every single boot, which
	// trains whoever reads those logs to ignore them.
	DelayedAutoStart bool

	// RestartOnFailure configures the SCM to restart the service if it exits
	// unexpectedly. This is the mechanism that makes a crashed agent recover
	// without anyone noticing.
	RestartOnFailure bool
}

// Supported reports whether this platform has a service manager.
func Supported() bool { return supported() }

// IsService reports whether this process was started by the service manager
// rather than from a console.
//
// It matters because the two require different behaviour: a service must report
// its status to the SCM within seconds of starting or be killed, while a console
// process must not try to talk to a service controller that is not there.
func IsService() bool { return isService() }

// Run executes f under the service manager when started by it, and directly
// otherwise.
//
// The same binary therefore works as a service and as a foreground process, which
// is what makes a service debuggable: the console path is not a separate code
// path with its own bugs.
//
// f must return promptly once its context is cancelled. The SCM gives a service a
// bounded time to stop and kills it if that time is exceeded.
func Run(name string, f func(context.Context) error) error { return run(name, f) }

// Install registers the service with the SCM.
func Install(cfg Config) error { return install(cfg) }

// Uninstall removes the service. It does not delete state or configuration; the
// caller decides what happens to those.
func Uninstall(name string) error { return uninstall(name) }

// Start starts an installed service.
func Start(name string) error { return start(name) }

// Stop asks an installed service to stop and waits for it to do so.
func Stop(name string, timeout time.Duration) error { return stop(name, timeout) }

// Status reports a service's current state.
func Status(name string) (State, error) { return status(name) }
