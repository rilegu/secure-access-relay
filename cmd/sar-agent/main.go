// Command sar-agent is the secure-access-relay endpoint agent.
//
// It holds a persistent outbound session to sar-server, authenticated with a
// certificate obtained by enrolling, and dials only loopback targets it has been
// configured to allow. It never listens on a network interface, which is what
// removes the need for an inbound firewall rule at the endpoint.
//
// It does not yet run as a Windows Service or verify signed grants. Any enrolled
// operator may reach its configured target.
//
// Usage:
//
//	sar-agent enroll -code sar1...        obtain a certificate, once
//	sar-agent run -target 127.0.0.1:8080  serve the configured resource
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rilegu/secure-access-relay/internal/agent"
	"github.com/rilegu/secure-access-relay/internal/control/enrollment"
	"github.com/rilegu/secure-access-relay/internal/identity"
	"github.com/rilegu/secure-access-relay/internal/keystore"
	"github.com/rilegu/secure-access-relay/internal/logging"
	"github.com/rilegu/secure-access-relay/internal/winsvc"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sar-agent: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return errors.New("no command given")
	}
	switch os.Args[1] {
	case "enroll":
		return cmdEnroll(os.Args[2:])
	case "run":
		return cmdRun(os.Args[2:])
	case "service":
		return cmdService(os.Args[2:])
	case "-version", "--version", "version":
		fmt.Println(version)
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sar-agent - secure-access-relay endpoint agent

  enroll    obtain a certificate using an enrollment code
  run       connect to the relay and serve the configured resource
  service   install, uninstall, start, stop, or query the Windows service

The same binary runs as a Windows service and in the foreground. Started by the
service manager it reports status and answers stop and shutdown; started from a
console it runs directly, which is how it is debugged.

Run a command with -h for its options.
`)
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	var (
		code     = fs.String("code", "", "enrollment code from sar-server token")
		stateDir = fs.String("state-dir", "agent-state", "directory to store the key and certificate in")
		logLevel = fs.String("log-level", "info", "log level: debug, info, warn, error")
	)
	_ = fs.Parse(args)

	if *code == "" {
		return errors.New("an enrollment code is required")
	}

	log := logging.New(*logLevel)

	parsed, err := enrollment.DecodeCode(*code)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	id, err := identity.Enroll(ctx, parsed, *stateDir)
	if err != nil {
		return err
	}

	log.Info("enrolled",
		"identity", id.ID.String(),
		"state_dir", *stateDir,
		"key_protection", string(id.Protection),
		"certificate_expires", id.NotAfter.UTC().Format(time.RFC3339),
	)
	// Said out loud where the key is not encrypted at rest, so the weaker
	// protection is never something a reader has to infer.
	if id.Protection != keystore.ProtectionDPAPI {
		log.Warn("private key is protected by file permissions only on this platform")
	}
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var (
		relayAddr  = fs.String("relay-addr", "127.0.0.1:17070", "relay address to connect out to")
		stateDir   = fs.String("state-dir", "agent-state", "directory holding the key and certificate")
		target     = fs.String("target", "127.0.0.1:8080", "local service to expose; must be a loopback literal with an explicit port")
		maxStreams = fs.Uint("max-streams", 16, "maximum concurrent streams the relay may open")
		retry      = fs.Duration("retry-interval", 2*time.Second, "delay between reconnection attempts")
		logLevel   = fs.String("log-level", "info", "log level: debug, info, warn, error")
	)
	_ = fs.Parse(args)

	// Mirror warnings and errors to the platform's native log as well as to
	// structured JSON. If the event source is unavailable — not Windows, not
	// registered, not enough rights — this returns the plain logger and the
	// reason, and the agent carries on: an endpoint must not go offline over a
	// logging problem.
	log, closeLog, evtErr := logging.NewWithEventLog(*logLevel, serviceName)
	defer closeLog()
	if evtErr != nil {
		log.Debug("event log unavailable; logging to stderr only", "error", evtErr)
	}

	id, err := identity.Load(*stateDir)
	if err != nil {
		if errors.Is(err, identity.ErrNotEnrolled) {
			return fmt.Errorf("not enrolled: run 'sar-agent enroll -code ...' first (state dir %s)", *stateDir)
		}
		return err
	}

	// A target that is not loopback fails startup rather than being rejected
	// later at stream time. A misconfigured allowlist must never produce a
	// running agent (invariant 4).
	a, err := agent.New(agent.Config{
		RelayAddr:     *relayAddr,
		Identity:      id,
		Target:        *target,
		MaxStreams:    uint32(*maxStreams),
		RetryInterval: *retry,
		Logger:        log,
	})
	if err != nil {
		return err
	}

	// winsvc.Run connects to the service control manager when the process was
	// started by it, and runs the function directly otherwise. The same code path
	// therefore serves both, which is what keeps the console mode a genuine way
	// to debug the service rather than a separate program with its own bugs.
	return winsvc.Run(serviceName, func(ctx context.Context) error {
		// Signal handling is derived from the service context, so a stop from the
		// SCM and a Ctrl-C from a console both cancel the same thing.
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()

		log.Info("agent starting",
			"service", winsvc.IsService(),
			"device_id", id.ID.ID,
			"relay_addr", *relayAddr,
		)

		err := a.Run(ctx)
		if err != nil && ctx.Err() == nil {
			// Returned rather than swallowed: a non-nil error becomes a non-zero
			// service exit code, which is what makes the SCM restart policy fire.
			log.Error("agent stopped with an error", "error", err)
			return err
		}
		log.Info("shutdown complete")
		return nil
	})
}
