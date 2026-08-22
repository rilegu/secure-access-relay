// Command sar-server is the secure-access-relay control plane and relay.
//
// The control plane owns identity and enrollment; the relay joins authorized
// streams. They are separate package trees with no cross-imports and are wired
// together only here — see docs/decisions/0007-one-binary-two-package-trees.md.
//
// Every data-plane connection is mutual TLS. A peer's identity comes from its
// certificate, so an unenrolled peer is refused during the TLS handshake, before
// it can send a single protocol frame.
//
// Access is decided here: policy is evaluated and a signed, expiring grant is
// issued. The relay carries traffic under that grant, and the endpoint agent
// verifies it independently before dialing anything.
//
// Every authorization decision is recorded in an append-only audit trail, and a
// grant can be revoked before it expires — which drops the streams it opened
// rather than only refusing the next one.
//
// Usage:
//
//	sar-server run                       serve the control plane and relay
//	sar-server token -device panel-01    mint an enrollment code for a device
//	sar-server token -operator maria     mint an enrollment code for an operator
//	sar-server revoke -device panel-01   revoke an identity
//	sar-server list                      show enrolled identities
//	sar-server audit -device panel-01    query the audit trail
//	sar-server grants -active            show issued grants
//	sar-server grants -revoke grn_...    revoke a grant before it expires
//	sar-server sessions -active          show operator sessions
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/control/enrollment"
	"github.com/rilegu/secure-access-relay/internal/control/grants"
	"github.com/rilegu/secure-access-relay/internal/control/httpapi"
	"github.com/rilegu/secure-access-relay/internal/control/login"
	"github.com/rilegu/secure-access-relay/internal/control/policy"
	"github.com/rilegu/secure-access-relay/internal/keystore"
	"github.com/rilegu/secure-access-relay/internal/logging"
	"github.com/rilegu/secure-access-relay/internal/relay"
	"github.com/rilegu/secure-access-relay/internal/relay/authorization"
	"github.com/rilegu/secure-access-relay/internal/storage"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// version is set at build time via -ldflags.
var version = "dev"

// caTTL is the authority's lifetime. Long, because rotating it means re-enrolling
// every device in the deployment.
const caTTL = 10 * 365 * 24 * time.Hour

// serverCertTTL is the relay's own certificate lifetime. Short: it is re-issued
// on every start and never written to disk.
const serverCertTTL = 90 * 24 * time.Hour

// grantKeyID names the signing key inside every grant, so keys can be rotated
// without invalidating everything at once.
const grantKeyID = "key_1"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sar-server: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return errors.New("no command given")
	}

	switch os.Args[1] {
	case "run":
		return cmdRun(os.Args[2:])
	case "token":
		return cmdToken(os.Args[2:])
	case "revoke":
		return cmdRevoke(os.Args[2:])
	case "list":
		return cmdList(os.Args[2:])
	case "audit":
		return cmdAudit(os.Args[2:])
	case "grants":
		return cmdGrants(os.Args[2:])
	case "sessions":
		return cmdSessions(os.Args[2:])
	case "-version", "--version", "version":
		fmt.Println(version)
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sar-server - secure-access-relay control plane and relay

  run       serve the control plane and relay
  token     mint a single-use enrollment code
  revoke    revoke an enrolled identity
  list      show enrolled identities
  audit     query the audit trail
  grants    list or revoke issued grants
  sessions  list or revoke operator sessions

Run a command with -h for its options.
`)
}

// deployment holds the state every command shares: the authority and the store.
type deployment struct {
	authority *ca.CA
	store     *storage.Store
	enroll    *enrollment.Service
	issuer    *grants.Issuer
	login     *login.Service
	audit     *audit.Recorder
}

// close releases the database. Every command that opens a deployment must call
// it: SQLite in WAL mode leaves a journal behind, and a control plane that shut
// down without closing looks corrupt to the next tool that opens it.
func (d *deployment) close() {
	if d.store != nil {
		_ = d.store.Close()
	}
}

// openDeployment loads the authority and store, creating them on first use.
//
// The authority is generated once and then reused. Regenerating it would
// invalidate every certificate already issued, so its absence means first run and
// its presence is authoritative.
func openDeployment(stateDir string) (*deployment, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}

	certPath := filepath.Join(stateDir, "ca.crt")
	keyPath := filepath.Join(stateDir, "ca.key")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, _, keyErr := keystore.Load(keyPath)

	var authority *ca.CA
	switch {
	case certErr == nil && keyErr == nil:
		var err error
		if authority, err = ca.Load(certPEM, keyPEM); err != nil {
			return nil, err
		}

	case os.IsNotExist(certErr) && errors.Is(keyErr, keystore.ErrNotFound):
		var err error
		if authority, err = ca.Create("secure-access-relay development authority", caTTL); err != nil {
			return nil, err
		}
		newKeyPEM, err := authority.KeyPEM()
		if err != nil {
			return nil, err
		}
		// The key goes through the keystore, so on Windows the authority key is
		// sealed to this account exactly like a device key.
		if _, err := keystore.Save(keyPath, newKeyPEM); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certPath, authority.CertPEM(), 0o600); err != nil {
			return nil, fmt.Errorf("write authority certificate: %w", err)
		}

	default:
		// One half present, the other missing. Refusing is deliberate: creating a
		// fresh authority over a half-written one would silently orphan every
		// device already enrolled.
		return nil, fmt.Errorf("authority state in %s is incomplete; refusing to guess", stateDir)
	}

	store, err := storage.Open(filepath.Join(stateDir, "control.db"))
	if err != nil {
		return nil, err
	}

	// A deployment upgraded from the JSON store keeps its enrolled identities.
	// Losing them would leave every device holding a certificate the control
	// plane no longer recognises, and the only symptom would be endpoints that
	// silently stop connecting.
	imported, err := store.ImportLegacyJSON(context.Background(), filepath.Join(stateDir, "control.json"))
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	if imported > 0 {
		fmt.Fprintf(os.Stderr, "imported %d records from control.json into control.db\n", imported)
	}

	issuer, err := openIssuer(stateDir)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	// Attached here rather than at construction: the signing key and the database
	// are opened by different code paths, and threading one through the other
	// would couple two things with no reason to know about each other.
	issuer = issuer.WithStore(store)

	return &deployment{
		authority: authority,
		store:     store,
		enroll:    enrollment.New(store, authority, issuer.PublicKey()),
		issuer:    issuer,
		login:     login.New(store, login.DefaultTTL),
		audit:     audit.NewRecorder(store, logging.New("info")),
	}, nil
}

// openIssuer loads the grant signing key, creating it on first use.
//
// The signing key is the most valuable secret in the deployment: anyone holding
// it can mint authorization for any operator to reach any resource. It goes
// through the keystore — sealed with DPAPI on Windows — and never into the
// database. A database compromise must not be a key compromise.
func openIssuer(stateDir string) (*grants.Issuer, error) {
	keyPath := filepath.Join(stateDir, "grant-signing.key")

	keyPEM, _, err := keystore.Load(keyPath)
	switch {
	case err == nil:
		block, _ := pem.Decode(keyPEM)
		if block == nil {
			return nil, fmt.Errorf("grant signing key in %s is not valid PEM", keyPath)
		}
		parsed, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("parse grant signing key: %w", perr)
		}
		priv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("grant signing key is %T, want ed25519", parsed)
		}
		return grants.NewIssuer(priv, grantKeyID)

	case errors.Is(err, keystore.ErrNotFound):
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, fmt.Errorf("generate grant signing key: %w", gerr)
		}
		der, merr := x509.MarshalPKCS8PrivateKey(priv)
		if merr != nil {
			return nil, merr
		}
		encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if _, serr := keystore.Save(keyPath, encoded); serr != nil {
			return nil, serr
		}
		return grants.NewIssuer(priv, grantKeyID)

	default:
		return nil, err
	}
}

// loadRules reads the policy file.
//
// A missing policy file is not an error at startup, because a deployment that
// has enrolled devices but written no policy yet is a legitimate state. It is
// reported loudly, though: with no rules, every request is denied, and an
// operator seeing nothing but denials should be told why.
func loadRules(stateDir string, log *slog.Logger) []policy.Rule {
	path := filepath.Join(stateDir, "policy.json")

	rules, err := policy.LoadRules(path)
	if err != nil {
		if os.IsNotExist(errors.Unwrap(err)) || os.IsNotExist(err) {
			log.Warn("no policy file; every request will be denied",
				"path", path, "hint", "write policy.json to allow anything")
			return nil
		}
		// A malformed policy file is fatal in effect: it produces no rules, which
		// denies everything. Saying so is better than letting an operator wonder.
		log.Error("policy file could not be read; every request will be denied",
			"path", path, "error", err)
		return nil
	}
	log.Info("policy loaded", "path", path, "rules", len(rules))
	return rules
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var (
		addr        = fs.String("addr", "127.0.0.1:17070", "data-plane address for agents and operators")
		controlAddr = fs.String("control-addr", "127.0.0.1:17071", "control-plane address for enrollment")
		stateDir    = fs.String("state-dir", "state", "directory holding the authority and enrollment store")
		tlsNames    = fs.String("tls-names", "localhost,127.0.0.1,::1", "comma-separated names and IPs the server certificate is valid for")
		maxStreams  = fs.Uint("max-streams", 16, "maximum concurrent streams per session")
		logLevel    = fs.String("log-level", "info", "log level: debug, info, warn, error")
	)
	_ = fs.Parse(args)

	log := logging.New(*logLevel)

	dep, err := openDeployment(*stateDir)
	if err != nil {
		return err
	}
	defer dep.close()

	serverCert, err := dep.authority.IssueServerCertificate(splitList(*tlsNames), serverCertTTL)
	if err != nil {
		return err
	}

	log.Info("authority ready",
		"state_dir", *stateDir,
		"fingerprint", enrollment.Fingerprint(dep.authority.Certificate()),
		"grant_key_id", dep.issuer.KeyID(),
		"database", dep.store.Path(),
		"schema_version", storage.SchemaVersion,
		"recording_grants", dep.issuer.Recording(),
		"session_ttl", dep.login.TTL().String(),
	)

	rules := loadRules(*stateDir, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The relay is constructed first because the control plane holds a reference
	// into it: revoking a grant has to drop the streams that grant opened, and
	// the relay is what holds those connections. The dependency runs one way —
	// the control plane decides, the relay is told — which is why this is a
	// function value and not an import.
	srv, err := relay.New(relay.Config{
		Addr:     *addr,
		TLS:      transport.ServerTLS(serverCert, dep.authority.Pool()),
		Verify:   dep.enroll,
		GrantKey: dep.issuer.PublicKey(),

		// Revocation lookup. The relay asks whether a grant is still wanted; a
		// signature cannot answer that, because it was produced before anyone
		// decided to take the access away.
		Grants: authorization.CheckerFunc(func(ctx context.Context, grantID string) (authorization.GrantState, error) {
			st, err := grants.StateOf(ctx, dep.store, grantID)
			if err != nil {
				return authorization.GrantState{}, err
			}
			return authorization.GrantState{
				Known:     st.Known,
				Revoked:   st.Revoked,
				SessionID: st.SessionID,
				UserID:    st.UserID,
			}, nil
		}),

		Audit:      dep.audit,
		MaxStreams: uint32(*maxStreams),
		Logger:     log,
	})
	if err != nil {
		return err
	}

	// Control plane: server-authenticated TLS only. A peer that is enrolling has
	// no certificate yet, so requiring one here would make enrollment impossible.
	control, err := httpapi.New(httpapi.Config{
		Addr: *controlAddr,
		// Client certificates are verified if presented but not required.
		// Enrollment cannot demand one — a peer enrolls precisely because it has
		// none — so each route decides for itself, and the grants route requires
		// one.
		TLS: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   transport.MinTLSVersion,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    dep.authority.Pool(),
		},
		Issuer: dep.issuer,
		Rules:  func() []policy.Rule { return rules },
		Login:  dep.login,
		Audit:  dep.audit,

		// What makes revocation reach a session already running. Without this a
		// revoked grant would stop the next stream and leave the current one
		// alone, which is precisely the case revocation exists for.
		Terminate: srv.TerminateGrants,

		Logger: log,
	}, dep.enroll)
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)
	go func() { errCh <- control.Run(ctx) }()
	go func() { errCh <- srv.Run(ctx) }()

	// Either component failing takes the process down: a relay with no control
	// plane can enroll nobody, and a control plane with no relay serves nobody.
	err = <-errCh
	stop()
	<-errCh

	if err != nil && ctx.Err() == nil {
		return err
	}
	log.Info("shutdown complete")
	return nil
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	var (
		device      = fs.String("device", "", "device identifier to enroll")
		operator    = fs.String("operator", "", "operator identifier to enroll")
		stateDir    = fs.String("state-dir", "state", "directory holding the authority and enrollment store")
		controlAddr = fs.String("control-addr", "127.0.0.1:17071", "control-plane address the peer will enroll against")
		serverName  = fs.String("server-name", "localhost", "name the peer verifies the server certificate against")
	)
	_ = fs.Parse(args)

	if (*device == "") == (*operator == "") {
		return errors.New("give exactly one of -device or -operator")
	}

	role, id := ca.RoleDevice, *device
	if *operator != "" {
		role, id = ca.RoleOperator, *operator
	}

	dep, err := openDeployment(*stateDir)
	if err != nil {
		return err
	}

	token, err := dep.enroll.IssueToken(role, id)
	if err != nil {
		return err
	}

	code, err := enrollment.Code{
		Addr:          *controlAddr,
		Token:         token,
		CAFingerprint: enrollment.Fingerprint(dep.authority.Certificate()),
		ServerName:    *serverName,
	}.Encode()
	if err != nil {
		return err
	}

	binary := "sar-agent"
	if role == ca.RoleOperator {
		binary = "sarctl"
	}

	// The code goes to stdout so it can be piped; everything explanatory goes to
	// stderr. It is shown exactly once and cannot be recovered afterwards, because
	// only its hash was stored.
	fmt.Fprintf(os.Stderr, "enrollment code for %s/%s (single use, valid %s):\n\n",
		role, id, enrollment.DefaultTokenTTL)
	fmt.Println(code)
	fmt.Fprintf(os.Stderr, "\nrun on the target machine:\n  %s enroll -code %s\n", binary, code)
	return nil
}

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	var (
		device   = fs.String("device", "", "device identifier to revoke")
		operator = fs.String("operator", "", "operator identifier to revoke")
		stateDir = fs.String("state-dir", "state", "directory holding the authority and enrollment store")
	)
	_ = fs.Parse(args)

	if (*device == "") == (*operator == "") {
		return errors.New("give exactly one of -device or -operator")
	}

	role, id := "device", *device
	if *operator != "" {
		role, id = "operator", *operator
	}

	dep, err := openDeployment(*stateDir)
	if err != nil {
		return err
	}
	defer dep.close()

	ctx := context.Background()
	if err := dep.store.Revoke(role, id); err != nil {
		return err
	}
	dep.audit.Record(ctx, storage.AuditEvent{
		Event:     revokeEvent(role),
		ActorRole: audit.RoleAdmin,
		ActorID:   id,
		DeviceID:  deviceOf(role, id),
		Reason:    login.ReasonIdentityRevoked,
	})
	fmt.Printf("revoked %s/%s\n", role, id)

	// Revoking the identity is not enough on its own. Grants already issued stay
	// signed and valid, so an operator cut off at the certificate would keep the
	// access they were given until it expired — which is the opposite of what
	// revoking them was meant to do.
	switch role {
	case "operator":
		revoked, err := dep.login.EndAllForUser(ctx, id, "admin", login.ReasonIdentityRevoked)
		if err != nil {
			return fmt.Errorf("identity revoked, but its sessions and grants were not: %w", err)
		}
		fmt.Printf("ended their sessions and revoked %d grant(s)\n", len(revoked))
	case "device":
		revoked, err := dep.store.RevokeGrantsWhere(ctx, storage.ScopeDevice, id,
			login.ReasonIdentityRevoked, storage.AuditEvent{
				Event:     audit.EventGrantRevoked,
				ActorRole: audit.RoleAdmin,
				ActorID:   "admin",
			})
		if err != nil {
			return fmt.Errorf("identity revoked, but grants naming it were not: %w", err)
		}
		fmt.Printf("revoked %d grant(s) naming this device\n", len(revoked))
	}

	// Said plainly, because it is the remaining gap. A running relay drops the
	// streams itself; this command only writes to the database, so a relay in
	// another process learns on its next lookup — which happens when a stream is
	// opened, not while one is already running.
	fmt.Fprintln(os.Stderr,
		"note: a running relay drops affected streams on its next grant check; streams already joined")
	fmt.Fprintln(os.Stderr,
		"      end when this command is run against the same process, or when the grant expires")
	return nil
}

// revokeEvent names the audit event for revoking an identity of a given role.
func revokeEvent(role string) string {
	if role == "operator" {
		return audit.EventOperatorRevoked
	}
	return audit.EventDeviceRevoked
}

// deviceOf fills the device column only when the subject actually is a device,
// so a query by device does not return operator events.
func deviceOf(role, id string) string {
	if role == "device" {
		return id
	}
	return ""
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	stateDir := fs.String("state-dir", "state", "directory holding the authority and enrollment store")
	_ = fs.Parse(args)

	dep, err := openDeployment(*stateDir)
	if err != nil {
		return err
	}
	defer dep.close()

	for _, role := range []string{"device", "operator"} {
		records := dep.store.List(role)
		if len(records) == 0 {
			continue
		}
		fmt.Printf("%ss:\n", role)
		for _, r := range records {
			status := "active"
			if r.Revoked {
				status = "REVOKED"
			}
			fmt.Printf("  %-24s %-8s enrolled %s\n", r.ID, status, r.EnrolledAt.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
