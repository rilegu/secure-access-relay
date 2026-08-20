//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// scmHandle is an open handle to the service control manager or to a service.
type scmHandle uintptr

func (h scmHandle) close() {
	if h != 0 {
		procCloseServiceHandle.Call(uintptr(h))
	}
}

// openSCM opens the service control manager.
//
// Every management operation needs Administrator rights, and the failure is
// reported as such rather than as a generic error: "access denied" without that
// hint sends people looking for the wrong problem.
func openSCM() (scmHandle, error) {
	h, _, err := procOpenSCManagerW.Call(0, 0, scManagerAllAccess)
	if h == 0 {
		return 0, wrapErr("OpenSCManager", err)
	}
	return scmHandle(h), nil
}

func openService(scm scmHandle, name string) (scmHandle, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, _, callErr := procOpenServiceW.Call(uintptr(scm), uintptr(unsafe.Pointer(namePtr)), serviceAllAccess)
	if h == 0 {
		return 0, wrapErr("OpenService", callErr)
	}
	return scmHandle(h), nil
}

// wrapErr turns a Win32 error into one of this package's sentinels where the
// distinction matters to a caller.
func wrapErr(op string, err error) error {
	errno, ok := err.(syscall.Errno)
	if !ok {
		return fmt.Errorf("winsvc: %s: %w", op, err)
	}
	switch uintptr(errno) {
	case errServiceDoesNotExist:
		return ErrNotInstalled
	case errServiceExists, errServiceMarkedForDelete:
		return ErrAlreadyInstalled
	case errAccessDenied:
		return ErrAccessDenied
	default:
		return fmt.Errorf("winsvc: %s: %w", op, err)
	}
}

// install registers the service.
//
// The binary path and its arguments are quoted into a single command line, which
// is what CreateService expects. Quoting the executable is not optional: an
// unquoted path containing a space is a long-standing Windows privilege
// escalation, because the SCM will try each prefix in turn and run whichever
// binary it finds first.
func install(cfg Config) error {
	if cfg.Name == "" {
		return errors.New("winsvc: service name is required")
	}
	if !filepath.IsAbs(cfg.ExePath) {
		return fmt.Errorf("winsvc: executable path %q must be absolute", cfg.ExePath)
	}

	scm, err := openSCM()
	if err != nil {
		return err
	}
	defer scm.close()

	// The executable is quoted unconditionally, not only when it contains a
	// space. Quoting a path that does not need it is harmless; failing to quote
	// one that does is a privilege escalation, and "does it contain a space" is
	// not a question worth getting subtly wrong at install time.
	cmdline := quoteAlways(cfg.ExePath)
	for _, a := range cfg.Args {
		cmdline += " " + quoteArg(a)
	}

	namePtr, err := syscall.UTF16PtrFromString(cfg.Name)
	if err != nil {
		return err
	}
	display := cfg.DisplayName
	if display == "" {
		display = cfg.Name
	}
	displayPtr, err := syscall.UTF16PtrFromString(display)
	if err != nil {
		return err
	}
	cmdPtr, err := syscall.UTF16PtrFromString(cmdline)
	if err != nil {
		return err
	}

	h, _, callErr := procCreateServiceW.Call(
		uintptr(scm),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(displayPtr)),
		serviceAllAccess,
		serviceWin32OwnProcess,
		serviceAutoStart,
		serviceErrorNormal,
		uintptr(unsafe.Pointer(cmdPtr)),
		0, // load order group
		0, // tag id
		0, // dependencies
		0, // account: LocalSystem
		0, // password
	)
	if h == 0 {
		return wrapErr("CreateService", callErr)
	}
	svc := scmHandle(h)
	defer svc.close()

	if cfg.Description != "" {
		if err := setDescription(svc, cfg.Description); err != nil {
			return err
		}
	}
	if cfg.DelayedAutoStart {
		if err := setDelayedAutoStart(svc, true); err != nil {
			return err
		}
	}
	if cfg.RestartOnFailure {
		if err := setRestartOnFailure(svc); err != nil {
			return err
		}
	}
	return nil
}

func setDescription(svc scmHandle, description string) error {
	ptr, err := syscall.UTF16PtrFromString(description)
	if err != nil {
		return err
	}
	d := serviceDescription{Description: ptr}
	r, _, callErr := procChangeServiceConfig2W.Call(uintptr(svc), configDescription, uintptr(unsafe.Pointer(&d)))
	if r == 0 {
		return fmt.Errorf("winsvc: set description: %w", callErr)
	}
	return nil
}

// setDelayedAutoStart asks the SCM to start the service shortly after boot
// rather than during it.
//
// Boot-time start competes with networking coming up, so an agent started then
// fails its first connection on every single boot. A log full of expected errors
// is worse than a few seconds of delay, because it teaches whoever reads it that
// errors are normal.
func setDelayedAutoStart(svc scmHandle, delayed bool) error {
	info := serviceDelayedAutoStartInfo{}
	if delayed {
		info.DelayedAutostart = 1
	}
	r, _, callErr := procChangeServiceConfig2W.Call(uintptr(svc), configDelayedAutoStart, uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return fmt.Errorf("winsvc: set delayed auto start: %w", callErr)
	}
	return nil
}

// setRestartOnFailure configures the SCM to restart the service if it exits
// unexpectedly.
//
// Three escalating delays, then a steady interval: restart quickly for a
// transient fault, but back off so a service that crashes on startup does not
// spin, filling the event log and burning CPU. The reset period returns the
// counter to zero after a day of health.
func setRestartOnFailure(svc scmHandle) error {
	actions := []scAction{
		{Type: scActionRestart, Delay: 5_000},
		{Type: scActionRestart, Delay: 30_000},
		{Type: scActionRestart, Delay: 60_000},
	}
	fa := serviceFailureActions{
		ResetPeriod:  86_400, // one day, in seconds
		ActionsCount: uint32(len(actions)),
		Actions:      &actions[0],
	}
	r, _, callErr := procChangeServiceConfig2W.Call(uintptr(svc), configFailureActions, uintptr(unsafe.Pointer(&fa)))
	if r == 0 {
		return fmt.Errorf("winsvc: set failure actions: %w", callErr)
	}
	return nil
}

func uninstall(name string) error {
	scm, err := openSCM()
	if err != nil {
		return err
	}
	defer scm.close()

	svc, err := openService(scm, name)
	if err != nil {
		return err
	}
	defer svc.close()

	r, _, callErr := procDeleteService.Call(uintptr(svc))
	if r == 0 {
		return wrapErr("DeleteService", callErr)
	}
	return nil
}

func start(name string) error {
	scm, err := openSCM()
	if err != nil {
		return err
	}
	defer scm.close()

	svc, err := openService(scm, name)
	if err != nil {
		return err
	}
	defer svc.close()

	r, _, callErr := procStartServiceW.Call(uintptr(svc), 0, 0)
	if r == 0 {
		return wrapErr("StartService", callErr)
	}
	return nil
}

// stop asks the service to stop and waits for it to reach the stopped state.
//
// Waiting matters: an uninstall or upgrade that runs while the old process is
// still holding its state directory will fail in confusing ways.
func stop(name string, timeout time.Duration) error {
	scm, err := openSCM()
	if err != nil {
		return err
	}
	defer scm.close()

	svc, err := openService(scm, name)
	if err != nil {
		return err
	}
	defer svc.close()

	var st serviceStatus
	r, _, callErr := procControlService.Call(uintptr(svc), controlStop, uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && uintptr(errno) == errServiceNotActive {
			return nil // already stopped; nothing to do
		}
		return wrapErr("ControlService", callErr)
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state, err := queryStatus(svc)
		if err != nil {
			return err
		}
		if state == svcStopped {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("winsvc: %s did not stop within %s", name, timeout)
}

func status(name string) (State, error) {
	scm, err := openSCM()
	if err != nil {
		return StateUnknown, err
	}
	defer scm.close()

	svc, err := openService(scm, name)
	if err != nil {
		return StateUnknown, err
	}
	defer svc.close()

	raw, err := queryStatus(svc)
	if err != nil {
		return StateUnknown, err
	}
	switch raw {
	case svcStopped:
		return StateStopped, nil
	case svcStartPending:
		return StateStartPending, nil
	case svcStopPending:
		return StateStopPending, nil
	case svcRunning:
		return StateRunning, nil
	default:
		return StateUnknown, nil
	}
}

func queryStatus(svc scmHandle) (uint32, error) {
	var st serviceStatus
	r, _, callErr := procQueryServiceStatus.Call(uintptr(svc), uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return 0, wrapErr("QueryServiceStatus", callErr)
	}
	return st.CurrentState, nil
}

// quoteArg wraps an argument in quotes so a path containing spaces survives the
// SCM's command-line parsing.
//
// The unquoted-service-path problem is a real and long-standing Windows
// privilege escalation: given C:\Program Files\App\app.exe unquoted, the loader
// tries C:\Program.exe first, and a writable C:\ turns that into arbitrary code
// running as LocalSystem.
func quoteArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			// A backslash only needs escaping when it precedes the closing quote.
			b.WriteByte('\\')
			if i == len(s)-1 {
				b.WriteByte('\\')
			}
		default:
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

// quoteAlways quotes unconditionally, for values where the cost of a missing
// quote is worse than the cost of a redundant one.
func quoteAlways(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " \t\"") {
		return quoteArg(s)
	}
	return `"` + s + `"`
}
