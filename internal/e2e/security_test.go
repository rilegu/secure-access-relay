package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/agent"
	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/mux"
	"github.com/rilegu/secure-access-relay/internal/operator"
	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// These are the deny cases from docs/e2e-test-plan.md that identity makes
// testable. Each must fail closed: the connection is refused, and the relay's
// view of the world is unchanged afterwards.
//
// They matter more than the golden path. A forwarding bug is visible the first
// time someone uses the system; an authentication bug is invisible until it is
// exploited.

// dialRelay attempts a data-plane session with a given identity, returning the
// error if any. It bypasses the agent and operator packages so a test can present
// credentials those packages would refuse to construct.
func dialRelay(t *testing.T, addr string, id *identityLike, role proto.Role, auth proto.Auth) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := transport.DialTLS(ctx, addr, transport.ClientTLS(id.cert, id.pool, "localhost"))
	if err != nil {
		return err // refused during the TLS handshake, which is the earliest and best place
	}
	defer func() { _ = conn.Close() }()

	sess, err := mux.Dial(ctx, conn, mux.Config{Role: role, Logger: discardLogger()}, auth)
	if err != nil {
		return err
	}
	_ = sess.Close(proto.ReasonShutdown)
	return nil
}

// TestUnenrolledPeerRefused is deny case D1.
//
// A peer holding a perfectly valid certificate from a *different* authority must
// not be admitted. This is what makes "enrolled" mean something: possessing a
// certificate is not enough, it has to be one this deployment issued.
func TestUnenrolledPeerRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	relaySrv := dep.startRelay(ctx, 16)

	// A complete, self-consistent deployment that this relay has never heard of.
	stranger := newDeployment(t)
	strangerID := stranger.enrollIdentity(ca.RoleDevice, "dev_stranger")

	err := dialRelay(t, relaySrv.Addr(), &identityLike{
		cert: strangerID.Certificate,
		// Trusts its own authority, so the failure is on the relay's side rather
		// than this peer refusing the server.
		pool: stranger.authority.Pool(),
	}, proto.RoleAgent, proto.Auth{DeviceID: "dev_stranger"})

	if err == nil {
		t.Fatal("a peer from an unknown authority was admitted")
	}
	if n := relaySrv.AgentCount(); n != 0 {
		t.Fatalf("relay registered %d agents after refusing a stranger", n)
	}
}

// TestRevokedDeviceRefused is deny case D4.
//
// A certificate that was valid remains cryptographically valid after revocation —
// nothing about the signature changes. Only the control plane knows it should no
// longer be honoured, which is why the relay asks rather than trusting the chain
// alone.
func TestRevokedDeviceRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	relaySrv := dep.startRelay(ctx, 16)

	id := dep.enrollIdentity(ca.RoleDevice, "dev_condemned")

	// Works before revocation, so the test proves revocation caused the refusal
	// rather than something else being wrong all along.
	if err := dialRelay(t, relaySrv.Addr(), &identityLike{cert: id.Certificate, pool: dep.authority.Pool()},
		proto.RoleAgent, proto.Auth{DeviceID: "dev_condemned"}); err != nil {
		t.Fatalf("enrolled device refused before revocation: %v", err)
	}

	if err := dep.store.Revoke("device", "dev_condemned"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if err := dialRelay(t, relaySrv.Addr(), &identityLike{cert: id.Certificate, pool: dep.authority.Pool()},
		proto.RoleAgent, proto.Auth{DeviceID: "dev_condemned"}); err == nil {
		t.Fatal("a revoked device was admitted")
	}
}

// TestSupersededCertificateRefused checks that re-enrolling invalidates the
// previous certificate.
//
// Without this, an endpoint that was re-enrolled after a suspected compromise
// would still be impersonable with the certificate that was compromised — which
// would make re-enrollment a ritual rather than a remedy.
func TestSupersededCertificateRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	relaySrv := dep.startRelay(ctx, 16)

	old := dep.enrollIdentity(ca.RoleDevice, "dev_rotating")
	if err := dialRelay(t, relaySrv.Addr(), &identityLike{cert: old.Certificate, pool: dep.authority.Pool()},
		proto.RoleAgent, proto.Auth{DeviceID: "dev_rotating"}); err != nil {
		t.Fatalf("first certificate refused: %v", err)
	}

	// Re-enroll the same identity: a new certificate, and the store now records
	// the new serial.
	fresh := dep.enrollIdentity(ca.RoleDevice, "dev_rotating")

	if err := dialRelay(t, relaySrv.Addr(), &identityLike{cert: fresh.Certificate, pool: dep.authority.Pool()},
		proto.RoleAgent, proto.Auth{DeviceID: "dev_rotating"}); err != nil {
		t.Fatalf("re-enrolled certificate refused: %v", err)
	}
	if err := dialRelay(t, relaySrv.Addr(), &identityLike{cert: old.Certificate, pool: dep.authority.Pool()},
		proto.RoleAgent, proto.Auth{DeviceID: "dev_rotating"}); err == nil {
		t.Fatal("a superseded certificate was still accepted")
	}
}

// TestIdentityClaimMustMatchCertificate checks that a peer cannot present one
// identity and claim another.
//
// The certificate is the identity. A handshake claim that disagrees with it is
// refused rather than reconciled, because there is no benign reason for the two
// to differ.
func TestIdentityClaimMustMatchCertificate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	relaySrv := dep.startRelay(ctx, 16)

	// Enrol two devices, then have one claim to be the other.
	impostor := dep.enrollIdentity(ca.RoleDevice, "dev_impostor")
	_ = dep.enrollIdentity(ca.RoleDevice, "dev_victim")

	err := dialRelay(t, relaySrv.Addr(),
		&identityLike{cert: impostor.Certificate, pool: dep.authority.Pool()},
		proto.RoleAgent, proto.Auth{DeviceID: "dev_victim"})
	if err == nil {
		t.Fatal("a device claiming another device's identity was admitted")
	}

	// The victim's slot must be untouched: an impersonation attempt must not
	// evict or shadow the identity it targeted.
	if n := relaySrv.AgentCount(); n != 0 {
		t.Fatalf("relay registered %d agents after refusing an impostor", n)
	}
}

// TestRoleMustMatchCertificate checks that a device certificate cannot open an
// operator session.
//
// Roles carry different authority: an operator may ask to reach devices. If the
// role were taken from the handshake rather than the certificate, every enrolled
// device could act as an operator.
func TestRoleMustMatchCertificate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	relaySrv := dep.startRelay(ctx, 16)

	deviceID := dep.enrollIdentity(ca.RoleDevice, "dev_ambitious")

	err := dialRelay(t, relaySrv.Addr(),
		&identityLike{cert: deviceID.Certificate, pool: dep.authority.Pool()},
		proto.RoleOperator, // certificate says device
		proto.Auth{DeviceID: "dev_ambitious", Resource: "anything"})
	if err == nil {
		t.Fatal("a device certificate opened an operator session")
	}
}

// TestNoClientCertificateRefused checks that a peer presenting no certificate is
// refused during the TLS handshake, before it can send a protocol frame.
func TestNoClientCertificateRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	relaySrv := dep.startRelay(ctx, 16)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	// Correct authority, correct server name, no client certificate.
	cfg := transport.ClientTLS(emptyCert(), dep.authority.Pool(), "localhost")
	conn, err := transport.DialTLS(dialCtx, relaySrv.Addr(), cfg)
	if err == nil {
		// Some stacks defer the peer's rejection until the first read.
		_, err = conn.R.ReadFrame()
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("a peer with no client certificate was admitted")
	}
}

// TestAgentRefusesUntrustedRelay checks the other direction: an agent must not
// connect to a relay it cannot verify.
//
// Mutual means mutual. If the agent accepted any server, an attacker who could
// redirect its traffic would receive its streams — and, once grants exist, would
// be positioned to replay them.
func TestAgentRefusesUntrustedRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// A relay belonging to a different deployment entirely.
	hostile := newDeployment(t)
	hostileRelay := hostile.startRelay(ctx, 16)

	// An agent enrolled with our authority, pointed at the hostile relay.
	ours := newDeployment(t)
	a, err := agent.New(agent.Config{
		RelayAddr:     hostileRelay.Addr(),
		Identity:      ours.enrollIdentity(ca.RoleDevice, "dev_ours"),
		Resources:     testAllowlist("127.0.0.1:1"),
		RetryInterval: 20 * time.Millisecond,
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}

	runCtx, runCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer runCancel()
	_ = a.Run(runCtx)

	// The hostile relay must never have seen it as an agent.
	if n := hostileRelay.AgentCount(); n != 0 {
		t.Fatalf("agent connected to a relay from an unknown authority (%d sessions)", n)
	}
}

// TestOperatorRefusesUntrustedRelay is the operator-side counterpart.
func TestOperatorRefusesUntrustedRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	hostile := newDeployment(t)
	hostileRelay := hostile.startRelay(ctx, 16)

	ours := newDeployment(t)
	ours.startControlPlane(ctx)
	ourOperator := ours.enrollIdentity(ca.RoleOperator, testUserID)
	f, err := operator.New(operator.Config{
		RelayAddr:   hostileRelay.Addr(),
		ControlAddr: ours.controlAddr,
		Identity:    ourOperator,
		ListenAddr:  "127.0.0.1:0",
		DeviceID:    "dev_anything",
		Resource:    testResourceID,
		Session:     ours.sessionTokenFor(ourOperator),
		Logger:      discardLogger(),
	})
	if err != nil {
		t.Fatalf("create forwarder: %v", err)
	}
	go func() { _ = f.Run(ctx) }()
	waitReady(t, f.Ready(), "forwarder")

	client := &http.Client{Timeout: 5 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Get("http://" + f.Addr() + "/health")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("forward succeeded through a relay from an unknown authority")
	}
}
