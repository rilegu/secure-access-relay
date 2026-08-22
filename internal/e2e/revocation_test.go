package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/control/login"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// Revocation before expiry, end to end.
//
// The property that matters is not that a revoked grant is refused on the next
// request — expiry already achieves that eventually. It is that access which is
// *already running* stops. A revocation that leaves the current session alone
// fails in exactly the case revocation exists for: a credential believed to be
// compromised right now.

// TestGrantRequiresASession checks that a certificate alone does not obtain a
// grant once the deployment uses sessions.
func TestGrantRequiresASession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	operatorID := dep.enrollIdentity(ca.RoleOperator, testUserID)

	// No session token: refused, even though the certificate is valid and policy
	// would allow it.
	body, status, err := postGrant(t, dep.controlAddr, operatorID, testDeviceID, testResourceID)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status == http.StatusOK {
		t.Fatalf("a grant was issued without a session: %s", body)
	}

	// The same request with a session succeeds, which is what proves the refusal
	// above was about the session and not about something else.
	sess := dep.session(ctx, operatorID)
	_, status, err = postGrant(t, dep.controlAddr, operatorID, testDeviceID, testResourceID, sess.Token)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("a grant was refused to an operator holding a valid session: status %d", status)
	}
}

// TestSessionTokenIsBoundToItsCertificate checks that a stolen session token is
// useless without the certificate it was issued to.
//
// Both are needed. A token that worked on its own would be a bearer credential
// with none of the certificate's protections, which would make sessions a
// weakening rather than an addition.
func TestSessionTokenIsBoundToItsCertificate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	victim := dep.enrollIdentity(ca.RoleOperator, testUserID)
	stolen := dep.session(ctx, victim)

	// A different enrolled operator presents somebody else's token.
	thief := dep.enrollIdentity(ca.RoleOperator, "usr_thief")
	_, status, err := postGrant(t, dep.controlAddr, thief, testDeviceID, testResourceID, stolen.Token)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status == http.StatusOK {
		t.Fatal("a session token was accepted from a certificate it was not issued to")
	}
}

// TestRevokedGrantIsRefusedByTheRelay checks the fast-fail path.
func TestRevokedGrantIsRefusedByTheRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	h := newHarness(t, options{})

	// One request establishes that the chain works and produces a grant to revoke.
	resp, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health")
	if err != nil {
		t.Fatalf("request before revocation failed: %v", err)
	}
	_ = resp.Body.Close()

	issued := activeGrants(t, h)
	if len(issued) == 0 {
		t.Fatal("no grant was recorded for a request that succeeded")
	}

	for _, g := range issued {
		if _, err := h.Dep.store.RevokeGrant(ctx, g.GrantID, "revoked_by_admin", storage.AuditEvent{
			Event:     audit.EventGrantRevoked,
			ActorRole: audit.RoleAdmin,
			ActorID:   "admin",
		}); err != nil {
			t.Fatalf("revoke %s: %v", g.GrantID, err)
		}
	}

	// The forwarder caches its grant, so the next request presents the revoked
	// one. That is the case being tested: the relay must refuse it rather than
	// trusting a signature that was valid when it was made.
	if _, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health"); err == nil {
		t.Fatal("a request succeeded using a revoked grant")
	}
}

// TestRevocationDropsALiveStream is the property revocation exists for.
//
// A slow response is in flight when the grant is revoked. The stream must be
// cut, not allowed to finish: an operator who is being cut off mid-transfer is
// the whole reason revocation is not just "wait for expiry".
func TestRevocationDropsALiveStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	h := newHarness(t, options{})

	// Warm the chain so a grant exists and is cached by the forwarder.
	warm, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health")
	if err != nil {
		t.Fatalf("warm-up request failed: %v", err)
	}
	_ = warm.Body.Close()

	issued := activeGrants(t, h)
	if len(issued) == 0 {
		t.Fatal("no grant was recorded")
	}
	grantID := issued[0].GrantID

	// A request that will not finish on its own. The fixture holds the response
	// open, so the stream is live and carrying nothing when revocation lands.
	errCh := make(chan error, 1)
	go func() {
		_, err := h.client(20 * time.Second).Get(h.ForwardURL + "/slow")
		errCh <- err
	}()

	// Wait until the relay is actually carrying the stream, rather than sleeping
	// and hoping. A revocation that arrived before the stream existed would pass
	// this test for the wrong reason.
	waitFor(t, 5*time.Second, "a live stream on the relay", func() bool {
		return h.Relay.LiveStreamCount() > 0
	})

	if _, err := h.Dep.store.RevokeGrant(ctx, grantID, "revoked_by_admin", storage.AuditEvent{
		Event:     audit.EventGrantRevoked,
		ActorRole: audit.RoleAdmin,
		ActorID:   "admin",
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	h.Relay.TerminateGrants([]string{grantID})

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("a request in flight completed after its grant was revoked")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("revoking a grant did not drop the stream it authorized")
	}

	// Nothing left behind. A register that kept the pair would report the wrong
	// count to an administrator and try to reset a corpse on the next revocation.
	waitFor(t, 5*time.Second, "the live-stream register to drain", func() bool {
		return h.Relay.LiveStreamCount() == 0
	})
}

// TestEndingASessionRevokesItsGrants checks that logout means what it says.
//
// Ending a session that left its grants valid would stop the next request and
// none of the access already given, which is not what logout means anywhere else.
func TestEndingASessionRevokesItsGrants(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	operatorID := dep.enrollIdentity(ca.RoleOperator, testUserID)
	sess := dep.session(ctx, operatorID)

	if _, status, err := postGrant(t, dep.controlAddr, operatorID, testDeviceID, testResourceID, sess.Token); err != nil || status != http.StatusOK {
		t.Fatalf("grant request: status %d, err %v", status, err)
	}

	revoked, err := dep.login.End(ctx, sess.Record.SessionID, operatorID.ID.ID, login.ReasonLogout)
	if err != nil {
		t.Fatalf("end session: %v", err)
	}
	if len(revoked) != 1 {
		t.Fatalf("ending a session revoked %d grants, want 1", len(revoked))
	}

	// The token is dead too, so the operator cannot simply ask again.
	if _, status, err := postGrant(t, dep.controlAddr, operatorID, testDeviceID, testResourceID, sess.Token); err != nil {
		t.Fatalf("request: %v", err)
	} else if status == http.StatusOK {
		t.Fatal("a grant was issued under a session that had been ended")
	}
}

// TestRevokingAnOperatorEndsTheirSessionsAndGrants checks the cascade an
// administrator relies on when a laptop is reported stolen.
//
// Revoking the identity alone would leave signed grants valid until they expired,
// so the operator would keep the access they had for up to half an hour after
// being revoked.
func TestRevokingAnOperatorEndsTheirSessionsAndGrants(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	operatorID := dep.enrollIdentity(ca.RoleOperator, testUserID)
	sess := dep.session(ctx, operatorID)

	if _, status, err := postGrant(t, dep.controlAddr, operatorID, testDeviceID, testResourceID, sess.Token); err != nil || status != http.StatusOK {
		t.Fatalf("grant request: status %d, err %v", status, err)
	}

	if err := dep.store.Revoke("operator", testUserID); err != nil {
		t.Fatalf("revoke identity: %v", err)
	}
	revoked, err := dep.login.EndAllForUser(ctx, testUserID, "admin", login.ReasonIdentityRevoked)
	if err != nil {
		t.Fatalf("cascade: %v", err)
	}
	if len(revoked) == 0 {
		t.Fatal("revoking an operator left their grants valid")
	}

	// Nothing of theirs is active any more.
	active, err := dep.store.ListGrants(ctx, storage.GrantFilter{UserID: testUserID, ActiveOnly: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("%d grant(s) survived revoking the operator who held them", len(active))
	}

	sessions, err := dep.store.ActiveSessionsForUser(ctx, testUserID)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("%d session(s) survived revoking the operator who held them", len(sessions))
	}
}

// activeGrants returns the grants a harness has caused to be issued.
func activeGrants(t *testing.T, h *harness) []storage.GrantRecord {
	t.Helper()
	list, err := h.Dep.store.ListGrants(context.Background(), storage.GrantFilter{ActiveOnly: true})
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	return list
}

// waitFor polls until cond holds, so a test waits on the condition it means
// rather than on a sleep that is either flaky or slow.
func waitFor(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
