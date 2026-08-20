// Command sarctl is the secure-access-relay operator CLI.
//
// It opens a local listener and carries traffic through the relay to an approved
// service on an endpoint. The operator names a resource; they never supply a
// target address, because resolving a name to an address is the endpoint agent's
// job against its own allowlist.
//
// The operator's identity comes from a certificate obtained by enrolling, so the
// relay knows who is connecting rather than being told. There is no policy engine
// yet, which means an enrolled operator may reach any enrolled device.
//
// Usage:
//
//	sarctl enroll -code sar1...          obtain a certificate, once
//	sarctl connect -device panel-01 ...  open a local forward
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

	"github.com/rilegu/secure-access-relay/internal/control/enrollment"
	"github.com/rilegu/secure-access-relay/internal/identity"
	"github.com/rilegu/secure-access-relay/internal/keystore"
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
	if len(os.Args) < 2 {
		usage()
		return errors.New("no command given")
	}
	switch os.Args[1] {
	case "enroll":
		return cmdEnroll(os.Args[2:])
	case "connect":
		return cmdConnect(os.Args[2:])
	case "-version", "--version", "version":
		fmt.Println(version)
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sarctl - secure-access-relay operator client

  enroll    obtain a certificate using an enrollment code
  connect   open a local forward to a resource on an endpoint

Run a command with -h for its options.
`)
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	var (
		code     = fs.String("code", "", "enrollment code from sar-server token")
		stateDir = fs.String("state-dir", "operator-state", "directory to store the key and certificate in")
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
	if id.Protection != keystore.ProtectionDPAPI {
		log.Warn("private key is protected by file permissions only on this platform")
	}
	return nil
}

func cmdConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	var (
		relayAddr = fs.String("relay-addr", "127.0.0.1:17070", "relay address to connect out to")
		stateDir  = fs.String("state-dir", "operator-state", "directory holding the key and certificate")
		listen    = fs.String("listen", "127.0.0.1:18080", "local address to accept connections on; must be loopback")
		device    = fs.String("device", "", "identifier of the endpoint to reach (required)")
		resource  = fs.String("resource", "default", "name of the resource to reach on the endpoint")
		logLevel  = fs.String("log-level", "info", "log level: debug, info, warn, error")
	)
	_ = fs.Parse(args)

	if *device == "" {
		return errors.New("a device is required")
	}

	log := logging.New(*logLevel)

	id, err := identity.Load(*stateDir)
	if err != nil {
		if errors.Is(err, identity.ErrNotEnrolled) {
			return fmt.Errorf("not enrolled: run 'sarctl enroll -code ...' first (state dir %s)", *stateDir)
		}
		return err
	}

	// A non-loopback listen address fails startup. Binding a forward to a
	// routable interface would republish someone else's private service onto the
	// operator's own network.
	f, err := operator.New(operator.Config{
		RelayAddr:  *relayAddr,
		Identity:   id,
		ListenAddr: *listen,
		DeviceID:   *device,
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
