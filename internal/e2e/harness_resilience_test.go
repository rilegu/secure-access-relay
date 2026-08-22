package e2e

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/agent"
	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/grants"
	"github.com/rilegu/secure-access-relay/internal/identity"
	"github.com/rilegu/secure-access-relay/internal/operator"
	"github.com/rilegu/secure-access-relay/internal/relay"
	"github.com/rilegu/secure-access-relay/internal/relay/authorization"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// Helpers for tests that stop and restart components.
//
// The rest of the harness builds a chain and tears it down with the test. These
// build the pieces separately, because a failure-injection test needs to take
// one away while the others keep running.

// reserveAddr picks a loopback port and releases it.
//
// A restarted relay has to come back on the same address, because the agent's
// configuration names it and the point of the test is that the *agent* recovers
// without being reconfigured. Port 0 cannot do that: the second listener would
// get a different port.
//
// There is a race — something else could take the port between the release and
// the next bind. On a loopback range with ephemeral ports it is remote enough to
// live with, and the alternative is a hard-coded port that collides with a
// parallel package instead.
func reserveAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved address: %v", err)
	}
	return addr
}

// startRelayAt runs a relay on a specific address, so it can be stopped and
// restarted in the same place.
func (d *deployment) startRelayAt(ctx context.Context, addr string, maxStreams uint32) *relay.Server {
	d.t.Helper()

	srv, err := relay.New(relay.Config{
		Addr:     addr,
		TLS:      transport.ServerTLS(d.serverCert, d.authority.Pool()),
		Verify:   d.enroll,
		GrantKey: d.issuer.PublicKey(),
		Grants: authorization.CheckerFunc(func(ctx context.Context, grantID string) (authorization.GrantState, error) {
			st, err := grants.StateOf(ctx, d.store, grantID)
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
		Audit:      d.audit,
		MaxStreams: maxStreams,
		Logger:     discardLogger(),
	})
	if err != nil {
		d.t.Fatalf("create relay: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitReady(d.t, srv.Ready(), "relay")
	d.relay = srv
	return srv
}

// startAgentAt runs an endpoint agent against a relay address.
//
// The retry interval is short so a reconnect test finishes in seconds rather
// than in the production backoff's tens of seconds. The jitter and growth are
// still exercised; only the scale changes.
func (d *deployment) startAgentAt(ctx context.Context, relayAddr string, resources agent.Allowlist) *agent.Agent {
	d.t.Helper()

	a, err := agent.New(agent.Config{
		RelayAddr:        relayAddr,
		Identity:         d.enrollIdentity(ca.RoleDevice, testDeviceID),
		Resources:        resources,
		RetryInterval:    20 * time.Millisecond,
		MaxRetryInterval: 200 * time.Millisecond,
		Logger:           discardLogger(),
	})
	if err != nil {
		d.t.Fatalf("create agent: %v", err)
	}
	go func() { _ = a.Run(ctx) }()
	return a
}

// startForwarder runs an operator forward against a relay address.
func (d *deployment) startForwarder(ctx context.Context, relayAddr string,
	id *identity.Identity, deviceID, resourceID string) *operator.Forwarder {
	d.t.Helper()

	f, err := operator.New(operator.Config{
		RelayAddr:   relayAddr,
		ControlAddr: d.controlAddr,
		Identity:    id,
		ListenAddr:  "127.0.0.1:0",
		DeviceID:    deviceID,
		Resource:    resourceID,
		Session:     d.sessionTokenFor(id),
		Logger:      discardLogger(),
	})
	if err != nil {
		d.t.Fatalf("create forwarder: %v", err)
	}
	go func() { _ = f.Run(ctx) }()
	waitReady(d.t, f.Ready(), "forwarder")
	return f
}

// waitForAgentCount waits until the deployment's current relay holds n agents.
func waitForAgentCount(t *testing.T, d *deployment, n int) {
	t.Helper()
	waitFor(t, 10*time.Second, "the relay to hold the expected agent count", func() bool {
		return d.relay != nil && d.relay.AgentCount() == n
	})
}

// insecureTLS is for reachability probes only.
//
// It never appears on a path that carries traffic or credentials: the question
// it answers is "is anything listening", and verifying a certificate would make
// a stopped server and a misconfigured one indistinguishable.
func insecureTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
}
