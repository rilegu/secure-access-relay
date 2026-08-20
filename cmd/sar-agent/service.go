package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rilegu/secure-access-relay/internal/logging"
	"github.com/rilegu/secure-access-relay/internal/winsvc"
)

// Service identity, fixed so that install, uninstall, and the running service
// all agree without being told.
const (
	serviceName        = "SecureAccessRelayAgent"
	serviceDisplayName = "Secure Access Relay Agent"
	serviceDescription = "Provides time-limited, audited access to approved local " +
		"services through an outbound relay connection. Opens no inbound port."
)

// stopTimeout bounds how long we wait for the service to stop.
//
// Longer than the agent needs to close its session, shorter than the SCM's own
// patience, so a stuck service is reported here rather than by Windows.
const stopTimeout = 30 * time.Second

func cmdService(args []string) error {
	if len(args) == 0 {
		return errors.New("service: give one of install, uninstall, start, stop, status")
	}
	switch args[0] {
	case "install":
		return cmdServiceInstall(args[1:])
	case "uninstall":
		return cmdServiceUninstall(args[1:])
	case "start":
		return requireWindows(func() error { return winsvc.Start(serviceName) })
	case "stop":
		return requireWindows(func() error { return winsvc.Stop(serviceName, stopTimeout) })
	case "status":
		return cmdServiceStatus()
	default:
		return fmt.Errorf("service: unknown subcommand %q", args[0])
	}
}

func requireWindows(f func() error) error {
	if !winsvc.Supported() {
		return winsvc.ErrUnsupported
	}
	return f()
}

// cmdServiceInstall registers the agent with the service manager.
//
// The arguments the service will run with are captured here, at install time,
// rather than read from a config file at start time. That keeps the SCM's
// command line the single record of how the service runs, which is what
// `sc.exe qc` shows an administrator trying to understand a machine.
func cmdServiceInstall(args []string) error {
	fs := flag.NewFlagSet("service install", flag.ExitOnError)
	var (
		relayAddr = fs.String("relay-addr", "127.0.0.1:17070", "relay address the service connects out to")
		stateDir  = fs.String("state-dir", "", "directory holding the key and certificate (default: alongside the executable)")
		target    = fs.String("target", "127.0.0.1:8080", "local service to expose; must be a loopback literal")
		logLevel  = fs.String("log-level", "info", "log level the service runs with")
	)
	_ = fs.Parse(args)

	if !winsvc.Supported() {
		return winsvc.ErrUnsupported
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}

	// An absolute state directory, always. A service starts with an
	// unpredictable working directory, so a relative path would resolve
	// somewhere nobody intended — and the agent would silently look enrolled or
	// not depending on where the SCM happened to start it.
	dir := *stateDir
	if dir == "" {
		dir = filepath.Join(filepath.Dir(exe), "agent-state")
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}

	err = winsvc.Install(winsvc.Config{
		Name:        serviceName,
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		ExePath:     exe,
		Args: []string{
			"run",
			"-relay-addr", *relayAddr,
			"-state-dir", dir,
			"-target", *target,
			"-log-level", *logLevel,
		},
		DelayedAutoStart: true,
		RestartOnFailure: true,
	})
	if err != nil {
		return err
	}

	// Registering the event source needs Administrator rights, which the install
	// already required. Failing here is reported but not fatal: an agent without
	// an event source still logs structured JSON, and refusing to install over it
	// would be a worse outcome than a missing convenience.
	if err := logging.RegisterEventSource(serviceName); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not register the event log source: %v\n", err)
	}

	fmt.Printf("installed %s\n", serviceName)
	fmt.Printf("  executable: %s\n", exe)
	fmt.Printf("  state dir:  %s\n", dir)
	fmt.Printf("  target:     %s\n", *target)
	fmt.Println()
	fmt.Println("the service starts shortly after boot, and is restarted if it exits unexpectedly")
	fmt.Printf("start it now with: %s service start\n", filepath.Base(exe))
	return nil
}

// cmdServiceUninstall removes the service, stopping it first.
//
// State is deliberately left in place. Removing an enrolled identity because
// someone uninstalled a service would turn a reinstall into a re-enrollment, and
// an upgrade into an outage.
func cmdServiceUninstall(args []string) error {
	fs := flag.NewFlagSet("service uninstall", flag.ExitOnError)
	_ = fs.Parse(args)

	if !winsvc.Supported() {
		return winsvc.ErrUnsupported
	}

	// Stopping first avoids deleting a service that is still holding its state
	// directory open.
	if err := winsvc.Stop(serviceName, stopTimeout); err != nil &&
		!errors.Is(err, winsvc.ErrNotInstalled) {
		fmt.Fprintf(os.Stderr, "warning: could not stop the service first: %v\n", err)
	}

	if err := winsvc.Uninstall(serviceName); err != nil {
		return err
	}
	if err := logging.DeregisterEventSource(serviceName); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not remove the event log source: %v\n", err)
	}

	fmt.Printf("removed %s\n", serviceName)
	fmt.Println("state and certificates were left in place; delete the state directory to remove them")
	return nil
}

func cmdServiceStatus() error {
	if !winsvc.Supported() {
		return winsvc.ErrUnsupported
	}
	state, err := winsvc.Status(serviceName)
	if err != nil {
		if errors.Is(err, winsvc.ErrNotInstalled) {
			fmt.Printf("%s: not installed\n", serviceName)
			return nil
		}
		return err
	}
	fmt.Printf("%s: %s\n", serviceName, state)
	return nil
}
