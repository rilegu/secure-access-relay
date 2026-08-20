// Command sar-agent is the secure-access-relay endpoint agent.
//
// It holds a persistent outbound connection to sar-server and dials only
// loopback targets that it has been configured to allow. It never listens on a
// network interface, which is what removes the need for an inbound firewall rule
// at the endpoint.
//
// It does not yet run as a Windows Service, authenticate itself, or verify
// signed grants. Until it does, it will open a stream to its configured target
// for anything the relay asks, so it must only be run against a development
// relay on a machine where that is acceptable.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rilegu/secure-access-relay/internal/agent"
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
	var (
		relayAddr = flag.String("relay-addr", "127.0.0.1:17070", "relay address to connect out to")
		target    = flag.String("target", "127.0.0.1:8080", "local service to expose; must be a loopback literal with an explicit port")
		retry     = flag.Duration("retry-interval", 2*time.Second, "delay between reconnection attempts")
		logLevel  = flag.String("log-level", "info", "log level: debug, info, warn, error")

		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	log := logging.New(*logLevel)
	log.Warn("development build: no encryption, no authentication, no grant verification")

	// A target that is not loopback fails startup rather than being rejected
	// later at stream time. A misconfigured allowlist must never produce a
	// running agent (invariant 4).
	a, err := agent.New(agent.Config{
		RelayAddr:     *relayAddr,
		Target:        *target,
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
