package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/policy"
	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// Failure injection.
//
// Every component here is expected to fail: relays restart, links drop, control
// planes go down. What matters is that each failure has a defined outcome, and
// that none of them widens access — invariant 6. The tempting bug under
// partition is to fail open so that support still works, and that is exactly the
// bug that turns an outage into an incident.

// TestAgentReturnsAfterTheRelayRestarts completes what
// TestAgentReconnectsAfterRelayRestart can only half-check.
//
// That test stops the relay and asserts the agent drops the dead session, and
// says so plainly: it cannot verify the return, because there is nothing to
// return to. This one reserves the address first, so the relay can come back on
// it and the agent — whose configuration is untouched — has somewhere to go.
//
// It is the whole promise of running as a service: a relay can be restarted
// during business hours and the fleet comes back on its own.
func TestAgentReturnsAfterTheRelayRestarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	// A fixed address, so the relay can be restarted on the same one and the
	// agent's configuration stays valid across the restart.
	addr := reserveAddr(t)

	relayCtx, stopRelay := context.WithCancel(ctx)
	dep.startRelayAt(relayCtx, addr, 16)

	fx := newCountingFixture(t)
	dep.startAgentAt(ctx, addr, testAllowlist(fx.addr))
	waitForAgentCount(t, dep, 1)

	// Drop the relay and confirm the agent notices.
	stopRelay()
	waitFor(t, 10*time.Second, "the agent to lose its session", func() bool {
		return dep.relay.AgentCount() == 0
	})

	// Bring it back on the same address. The agent must return by itself.
	restartCtx, stopAgain := context.WithCancel(ctx)
	t.Cleanup(stopAgain)
	dep.startRelayAt(restartCtx, addr, 16)

	waitFor(t, 30*time.Second, "the agent to reconnect after the relay restarted", func() bool {
		return dep.relay.AgentCount() == 1
	})
}

// TestControlPlaneOutageKeepsIssuedAccessAndRefusesNewAccess pins what a
// control-plane outage does, in both directions.
//
// The two halves are easy to get backwards, and getting either backwards is
// serious:
//
//   - An operator holding a valid grant keeps working. This is not a leak, it is
//     the entire point of verifying grants offline: the agent must not need to
//     ask permission per stream, or control-plane availability becomes a
//     precondition for support. The grant is signed, short-lived, and bounded by
//     its own expiry.
//   - An operator who needs a *new* grant is refused. There is nothing to
//     authenticate the request against and nothing to record it in, and under
//     invariant 6 a failure must never widen access. The tempting bug is to let
//     it through because the endpoint is right there and the operator is
//     obviously legitimate.
//
// So an outage does not revoke access already granted, and does not hand out
// any more. Both are asserted here, because a test of only the second would pass
// on a system that had simply stopped working.
func TestControlPlaneOutageKeepsIssuedAccessAndRefusesNewAccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)

	// The control plane runs on its own context so it can be taken away.
	controlCtx, stopControl := context.WithCancel(ctx)
	dep.startControlPlane(controlCtx)

	relaySrv := dep.startRelay(ctx, 16)
	fx := newCountingFixture(t)
	dep.startAgentAt(ctx, relaySrv.Addr(), testAllowlist(fx.addr))
	waitForAgent(t, relaySrv, 1)

	client := func() *http.Client {
		return &http.Client{Timeout: 10 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: true}}
	}

	// An operator who is already working, with a grant in hand.
	established := dep.enrollIdentity(ca.RoleOperator, testUserID)
	working := dep.startForwarder(ctx, relaySrv.Addr(), established, testDeviceID, testResourceID)

	resp, err := client().Get("http://" + working.Addr() + "/health")
	if err != nil {
		t.Fatalf("request before the outage failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// An operator who has not asked for anything yet. Started before the outage
	// so the listener exists, but it holds no grant.
	newcomer := dep.enrollIdentity(ca.RoleOperator, "usr_newcomer")
	dep.rules = append(dep.rules, policy.Rule{
		PolicyID:   "pol_newcomer",
		Principals: []string{"usr_newcomer"},
		Devices:    []string{testDeviceID},
		Resources:  []string{testResourceID},
		MaxTTL:     policy.Duration(20 * time.Minute),
		Effect:     policy.EffectAllow,
	})
	fresh := dep.startForwarder(ctx, relaySrv.Addr(), newcomer, testDeviceID, testResourceID)

	stopControl()
	waitFor(t, 10*time.Second, "the control plane to stop accepting", func() bool {
		return !controlReachable(dep.controlAddr)
	})

	// Half one: the established operator keeps working on the grant it holds.
	servedBefore := fx.hits()
	resp, err = client().Get("http://" + working.Addr() + "/health")
	if err != nil {
		t.Fatalf("an operator holding a valid grant was cut off by a control-plane outage: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if fx.hits() <= servedBefore {
		t.Fatal("the request reported success but never reached the endpoint")
	}

	// Half two: the newcomer cannot obtain a grant, so it is refused — and
	// nothing reaches the endpoint on its behalf.
	servedBefore = fx.hits()
	if _, err := client().Get("http://" + fresh.Addr() + "/health"); err == nil {
		t.Fatal("an operator with no grant was served while the control plane was down")
	}
	if got := fx.hits(); got != servedBefore {
		t.Fatalf("the fixture received %d request(s) for an operator that could not be authorized",
			got-servedBefore)
	}
}

// TestClockSkewBeyondToleranceIsDenied checks that a grant from a machine whose
// clock disagrees is refused, with a reason that says which way.
//
// Short-lived grants make clock skew a real weakness rather than a theoretical
// one: thirty minutes of validity means little if two machines disagree by an
// hour. The system bounds the tolerance and denies outside it rather than
// pretending to have a trusted time source.
func TestClockSkewBeyondToleranceIsDenied(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	cases := []struct {
		name    string
		issued  time.Time
		expires time.Time
		want    proto.Reason
	}{
		{
			name:    "issued far in the future",
			issued:  now.Add(2 * time.Hour),
			expires: now.Add(2*time.Hour + 20*time.Minute),
			want:    proto.ReasonGrantNotYetValid,
		},
		{
			name:    "expired well in the past",
			issued:  now.Add(-2 * time.Hour),
			expires: now.Add(-90 * time.Minute),
			want:    proto.ReasonGrantExpired,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := proto.Grant{
				KeyID: "key_test", GrantID: "grn_skew",
				UserID: testUserID, DeviceID: testDeviceID, ResourceID: testResourceID,
				IssuedAt: tc.issued, ExpiresAt: tc.expires,
			}.Sign(priv)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			err = signed.Verify(pub, now, testDeviceID)
			if err == nil {
				t.Fatal("a grant outside the tolerated skew was accepted")
			}
			// The reason matters as much as the refusal: an operator whose clock
			// is wrong needs to be told that, not handed a generic denial that
			// sends them looking at policy.
			if got := proto.ReasonForGrant(err); got != tc.want {
				t.Fatalf("reason = %s, want %s (error: %v)", got, tc.want, err)
			}
		})
	}

	// Inside the tolerance it is accepted, which is what stops this from being a
	// test that would pass with any clock handling at all.
	within, err := proto.Grant{
		KeyID: "key_test", GrantID: "grn_ok",
		UserID: testUserID, DeviceID: testDeviceID, ResourceID: testResourceID,
		IssuedAt: now.Add(proto.ClockSkewTolerance / 2), ExpiresAt: now.Add(20 * time.Minute),
	}.Sign(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := within.Verify(pub, now, testDeviceID); err != nil {
		t.Fatalf("a grant inside the tolerated skew was refused: %v", err)
	}
}

// TestReconnectDoesNotDuplicateSessions checks that a reconnecting endpoint
// replaces its session rather than accumulating one.
//
// After a network blip the relay may still be holding a session that is a corpse
// it has not noticed. Refusing the new connection would keep the endpoint
// unreachable until a timeout; keeping both would route to whichever the
// registry happened to return.
func TestReconnectDoesNotDuplicateSessions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)
	relaySrv := dep.startRelay(ctx, 16)

	fx := newCountingFixture(t)

	// Two agents for the same device, as a reconnect that raced its own cleanup
	// would produce.
	dep.startAgentAt(ctx, relaySrv.Addr(), testAllowlist(fx.addr))
	waitForAgent(t, relaySrv, 1)
	dep.startAgentAt(ctx, relaySrv.Addr(), testAllowlist(fx.addr))

	// The count must settle at one, not two.
	waitFor(t, 10*time.Second, "the relay to settle on one session for the device", func() bool {
		return relaySrv.AgentCount() == 1
	})
	time.Sleep(200 * time.Millisecond)
	if n := relaySrv.AgentCount(); n != 1 {
		t.Fatalf("relay holds %d sessions for one device, want 1", n)
	}
}

// TestAuditRetentionRemovesOldEventsAndRecordsItself checks the one deliberate
// exception to the append-only rule.
//
// Unbounded growth is not a safe default: a control plane that has run out of
// disk cannot write the audit event for the decision it is about to make, and
// under invariant 11 that means it must refuse the decision. Retention is
// therefore necessary — but it is explicit, administrator-invoked, and records
// its own execution, so a gap in the history never looks like a quiet period.
func TestAuditRetentionRemovesOldEventsAndRecordsItself(t *testing.T) {
	ctx := context.Background()
	dep := newDeployment(t)

	old := time.Now().Add(-90 * 24 * time.Hour)
	for range 5 {
		if err := dep.store.AppendAudit(ctx, storage.AuditEvent{
			At: old, Event: "stream.opened", ActorID: testUserID, DeviceID: testDeviceID,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if err := dep.store.AppendAudit(ctx, storage.AuditEvent{
		Event: "stream.opened", ActorID: testUserID, DeviceID: testDeviceID,
	}); err != nil {
		t.Fatalf("seed recent: %v", err)
	}

	cutoff := time.Now().Add(-24 * time.Hour)
	removed, err := dep.store.PruneAudit(ctx, cutoff, "admin")
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 5 {
		t.Fatalf("pruned %d events, want 5", removed)
	}

	// The recent event survives.
	remaining, err := dep.store.QueryAudit(ctx, storage.AuditFilter{Limit: storage.MaxAuditLimit})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var kept, pruneRecords int
	for _, e := range remaining {
		switch {
		case e.Event == "admin.action" && e.Reason == "audit_retention":
			pruneRecords++
		default:
			kept++
		}
	}
	if kept != 1 {
		t.Fatalf("%d ordinary events survived, want 1", kept)
	}

	// The prune is itself in the trail. Without this a gap in the history is
	// indistinguishable from a period when nothing happened.
	if pruneRecords != 1 {
		t.Fatalf("the prune recorded %d events describing itself, want 1", pruneRecords)
	}
}

// TestPruneWithoutACutoffIsRefused checks that retention cannot be invoked to
// mean "everything".
func TestPruneWithoutACutoffIsRefused(t *testing.T) {
	dep := newDeployment(t)
	if _, err := dep.store.PruneAudit(context.Background(), time.Time{}, "admin"); err == nil {
		t.Fatal("a prune with no cutoff was accepted")
	}
}

// TestPruneRecordsItselfEvenWhenNothingMatched checks the distinction between
// "retention ran and removed nothing" and "retention was never run".
func TestPruneRecordsItselfEvenWhenNothingMatched(t *testing.T) {
	ctx := context.Background()
	dep := newDeployment(t)

	removed, err := dep.store.PruneAudit(ctx, time.Now().Add(-365*24*time.Hour), "admin")
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 0 {
		t.Fatalf("removed %d events from an empty trail", removed)
	}

	events, err := dep.store.QueryAudit(ctx, storage.AuditFilter{Event: "admin.action"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("a prune that matched nothing recorded %d events, want 1", len(events))
	}
}

// controlReachable reports whether the control plane still accepts connections.
func controlReachable(addr string) bool {
	client := &http.Client{Timeout: 500 * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: insecureTLS()}}
	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}
