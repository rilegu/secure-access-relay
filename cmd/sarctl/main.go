// Command sarctl is the secure-access-relay operator CLI.
//
// It opens a local listener and carries traffic through the relay to an approved
// service on an endpoint. The operator names a resource; they never supply a
// target address, because resolving a name to an address is the endpoint agent's
// job against its own allowlist.
//
// The operator's identity comes from a certificate obtained by enrolling, so the
// relay knows who is connecting rather than being told. What that identity may
// reach is decided by policy on the control plane and enforced again by the
// endpoint agent.
//
// Work happens inside a session. A session is not a second authentication
// factor — the certificate is the authentication — it is what makes access
// revocable as a group and attributable to a period of work: ending it revokes
// the grants issued under it and drops the streams they opened.
//
// Usage:
//
//	sarctl enroll -code sar1...          obtain a certificate, once
//	sarctl login                         open a session
//	sarctl connect -device panel-01 ...  open a local forward
//	sarctl logout                        end the session and the access it gave
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
	"github.com/rilegu/secure-access-relay/internal/control/login"
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
	case "login":
		return cmdLogin(os.Args[2:])
	case "logout":
		return cmdLogout(os.Args[2:])
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
  login     open an operator session
  connect   open a local forward to a resource on an endpoint
  logout    end the session, revoking the grants issued under it

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
		relayAddr   = fs.String("relay-addr", "127.0.0.1:17070", "relay address to connect out to")
		controlAddr = fs.String("control-addr", "127.0.0.1:17071", "control-plane address where grants are requested")
		stateDir    = fs.String("state-dir", "operator-state", "directory holding the key and certificate")
		listen      = fs.String("listen", "127.0.0.1:18080", "local address to accept connections on; must be loopback")
		device      = fs.String("device", "", "identifier of the endpoint to reach (required)")
		resource    = fs.String("resource", "", "identifier of the resource to reach on the endpoint (required)")
		ttl         = fs.Duration("ttl", 20*time.Minute, "grant lifetime to request; the control plane caps it by policy")
		sessionTTL  = fs.Duration("session-ttl", login.DefaultTTL, "session lifetime to request if a new session is needed")
		logLevel    = fs.String("log-level", "info", "log level: debug, info, warn, error")
	)
	_ = fs.Parse(args)

	if *device == "" {
		return errors.New("a device is required")
	}
	if *resource == "" {
		return errors.New("a resource is required")
	}

	log := logging.New(*logLevel)

	id, err := identity.Load(*stateDir)
	if err != nil {
		if errors.Is(err, identity.ErrNotEnrolled) {
			return fmt.Errorf("not enrolled: run 'sarctl enroll -code ...' first (state dir %s)", *stateDir)
		}
		return err
	}

	// A session is opened if there is not already a usable one. Automatic
	// because a session is not a second factor: requiring an explicit login
	// before every forward would add a step without adding a check, and what it
	// would actually add is an operator who scripts around it.
	//
	// Supplied as a function rather than a token because a forward can outlive a
	// session, and a token captured once at startup would stop working part way
	// through a shift.
	session := func(ctx context.Context) (string, error) {
		sess, err := operator.EnsureSession(ctx, id, *stateDir, *controlAddr, id.ServerName, *sessionTTL)
		if err != nil {
			return "", err
		}
		return sess.Token, nil
	}

	// A non-loopback listen address fails startup. Binding a forward to a
	// routable interface would republish someone else's private service onto the
	// operator's own network.
	f, err := operator.New(operator.Config{
		RelayAddr:   *relayAddr,
		ControlAddr: *controlAddr,
		Identity:    id,
		ListenAddr:  *listen,
		DeviceID:    *device,
		Resource:    *resource,
		GrantTTL:    *ttl,
		Session:     session,
		Logger:      log,
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

// cmdLogin opens an operator session.
//
// The certificate does the authenticating. What this adds is a bounded, revocable
// handle on the work about to happen: every grant requested under it is tagged
// with it in the audit trail, and ending it takes back the access it gave.
func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	var (
		controlAddr = fs.String("control-addr", "127.0.0.1:17071", "control-plane address")
		stateDir    = fs.String("state-dir", "operator-state", "directory holding the key and certificate")
		ttl         = fs.Duration("ttl", login.DefaultTTL, "session lifetime to request; the control plane caps it")
		logLevel    = fs.String("log-level", "info", "log level: debug, info, warn, error")
	)
	_ = fs.Parse(args)

	log := logging.New(*logLevel)

	id, err := identity.Load(*stateDir)
	if err != nil {
		if errors.Is(err, identity.ErrNotEnrolled) {
			return fmt.Errorf("not enrolled: run 'sarctl enroll -code ...' first (state dir %s)", *stateDir)
		}
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sess, err := operator.Login(ctx, id, *controlAddr, id.ServerName, *ttl)
	if err != nil {
		return err
	}
	if err := operator.SaveSession(*stateDir, sess); err != nil {
		return err
	}

	// The token is never printed. It is a bearer credential, and a terminal is a
	// place things get copied out of — into a chat window, a ticket, a
	// screenshot. The session identifier is printed instead, which is what an
	// administrator needs in order to revoke it.
	log.Info("session opened",
		"user_id", sess.UserID,
		"session_id", sess.SessionID,
		"expires_at", sess.ExpiresAt.Format(time.RFC3339),
	)
	fmt.Printf("session %s for %s, valid until %s\n",
		sess.SessionID, sess.UserID, sess.ExpiresAt.Local().Format(time.RFC3339))
	return nil
}

// cmdLogout ends the stored session.
//
// It reports how many grants were revoked, because that is the difference
// between logging out of a system that forgets you and one that also takes back
// what it gave you.
func cmdLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	var (
		controlAddr = fs.String("control-addr", "127.0.0.1:17071", "control-plane address")
		stateDir    = fs.String("state-dir", "operator-state", "directory holding the key and certificate")
		logLevel    = fs.String("log-level", "info", "log level: debug, info, warn, error")
	)
	_ = fs.Parse(args)

	log := logging.New(*logLevel)

	id, err := identity.Load(*stateDir)
	if err != nil {
		return err
	}

	sess, err := operator.LoadSession(*stateDir)
	if err != nil {
		fmt.Println("no session stored")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	revoked, logoutErr := operator.Logout(ctx, id, *controlAddr, id.ServerName, sess)

	// The local copy goes whether or not the control plane could be reached. A
	// token kept on disk after the operator asked to be logged out is the wrong
	// default even if it still works — and if the control plane is unreachable,
	// the session expires on its own.
	if err := operator.ClearSession(*stateDir); err != nil {
		return err
	}
	if logoutErr != nil {
		return fmt.Errorf("local session discarded, but the control plane could not be told: %w", logoutErr)
	}

	log.Info("session ended", "session_id", sess.SessionID, "grants_revoked", revoked)
	fmt.Printf("session %s ended; %d grant(s) revoked\n", sess.SessionID, revoked)
	return nil
}
