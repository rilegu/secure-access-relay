// Command sar-server is the secure-access-relay control plane and relay.
//
// The control plane owns identity, enrollment, the resource registry, policy
// evaluation, grant issuance, and audit. The relay pairs already-authorized
// streams between operators and agents. They are separate package trees with no
// cross-imports: the relay makes no authorization decisions and the control
// plane carries no payload traffic. See
// docs/decisions/0007-one-binary-two-package-trees.md.
//
// Only the relay half exists so far. There is no transport encryption, no peer
// authentication, and no authorization: anything that reaches the operator port
// gets a stream. Run it on a development machine, never on a reachable network.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rilegu/secure-access-relay/internal/logging"
	"github.com/rilegu/secure-access-relay/internal/relay"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sar-server: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		addr        = flag.String("addr", "127.0.0.1:17070", "address to accept agent and operator connections on")
		maxStreams  = flag.Uint("max-streams", 16, "maximum concurrent streams per session")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	log := logging.New(*logLevel)
	log.Warn("development build: no encryption, no authentication, no authorization")

	// Signal handling is the whole shutdown story: cancelling the context closes
	// the listeners, which unblocks the accept loops. Without it a Ctrl-C would
	// kill the process with connections mid-flight and no closing audit lines.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// One listener for both roles. A peer states whether it is an agent or an
	// operator in its handshake, so port separation is no longer needed.
	srv := relay.New(relay.Config{
		Addr:       *addr,
		MaxStreams: uint32(*maxStreams),
		Logger:     log,
	})

	err := srv.Run(ctx)
	if err != nil && ctx.Err() == nil {
		return err
	}
	log.Info("shutdown complete")
	return nil
}
