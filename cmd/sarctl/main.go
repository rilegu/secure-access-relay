// Command sarctl is the secure-access-relay operator CLI.
//
// It opens a local listener and carries traffic through the relay to an approved
// service on an endpoint. The operator names a resource; they never supply a
// target address, because resolving a name to an address is the endpoint agent's
// job against its own allowlist.
//
// There is no login, no grant request, and no audit trail yet, and the local
// listener is unauthenticated: anything that can reach it on this machine can
// use the forward.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rilegu/secure-access-relay/internal/logging"
	"github.com/rilegu/secure-access-relay/internal/operator"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sarctl: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		relayAddr = flag.String("relay-addr", "127.0.0.1:17071", "relay address to connect out to")
		listen    = flag.String("listen", "127.0.0.1:18080", "local address to accept connections on; must be loopback")
		resource  = flag.String("resource", "default", "name of the resource to reach on the endpoint")
		logLevel  = flag.String("log-level", "info", "log level: debug, info, warn, error")

		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	log := logging.New(*logLevel)
	log.Warn("development build: no encryption, no authentication, no access grants")

	// A non-loopback listen address fails startup. Binding a forward to a
	// routable interface would republish someone else's private service onto the
	// operator's own network.
	f, err := operator.New(operator.Config{
		RelayAddr:  *relayAddr,
		ListenAddr: *listen,
		Resource:   *resource,
		Logger:     log,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := f.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	log.Info("shutdown complete")
	return nil
}
