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

	log := logging.New(*logLevel)

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := a.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	log.Info("shutdown complete")
	return nil
}
