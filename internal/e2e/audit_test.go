package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/agent"
	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/control/policy"
	"github.com/rilegu/secure-access-relay/internal/operator"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// The audit trail.
//
// An audit trail is only worth having if it can be queried afterwards and if it
// can be trusted not to contain the traffic it describes. Both are checked here:
// the first because a log nobody can ask questions of is a file that grows, the
// second because a trail holding payload bytes would turn every read of the
// evidence into a second disclosure of whatever was being protected.

// TestAuditTrailRecordsTheGoldenPath checks that a successful request leaves the
// record an investigator would need.
func TestAuditTrailRecordsTheGoldenPath(t *testing.T) {
	h := newHarness(t, options{})

	resp, err := h.client(10 * time.Second).Get(h.ForwardURL + "/bytes/4096")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if len(body) != 4096 {
		t.Fatalf("got %d bytes, want 4096", len(body))
	}

	// The stream has to finish before its closing record exists.
	waitFor(t, 5*time.Second, "the stream.closed record", func() bool {
		return len(queryAudit(t, h, storage.AuditFilter{Event: audit.EventStreamClosed})) > 0
	})

	for _, want := range []string{
		audit.EventOperatorLogin,
		audit.EventGrantCreated,
		audit.EventDeviceConnected,
		audit.EventStreamOpened,
		audit.EventStreamClosed,
	} {
		if got := queryAudit(t, h, storage.AuditFilter{Event: want}); len(got) == 0 {
			t.Errorf("no %s event was recorded for a successful request", want)
		}
	}

	// The closing record must carry what was actually moved. Byte counts are the
	// part of an audit record that answers "how much did they take", and a record
	// without them says only that something happened.
	closed := queryAudit(t, h, storage.AuditFilter{Event: audit.EventStreamClosed})
	last := closed[0]
	if last.BytesOut < 4096 {
		t.Errorf("stream.closed recorded %d bytes to the operator, want at least 4096", last.BytesOut)
	}
	if last.GrantID == "" || last.DeviceID != testDeviceID || last.ResourceID != testResourceID {
		t.Errorf("stream.closed is missing its subjects: grant %q device %q resource %q",
			last.GrantID, last.DeviceID, last.ResourceID)
	}
	if last.ActorID != testUserID {
		t.Errorf("stream.closed actor is %q, want %q", last.ActorID, testUserID)
	}

	// A grant event must name the session it was issued under. Without it the
	// trail can say what happened but not group it into a period of work, which
	// is half of what sessions are for.
	created := queryAudit(t, h, storage.AuditFilter{Event: audit.EventGrantCreated})
	if created[0].SessionID == "" {
		t.Error("grant.created does not name the session it was issued under")
	}
}

// TestAuditTrailRecordsDenials checks that a refusal is recorded with its reason.
//
// Denials matter more than successes. One is somebody doing their job; a run of
// them is somebody probing, or a policy that is wrong, and neither is visible
// without a record.
func TestAuditTrailRecordsDenials(t *testing.T) {
	h := newHarnessWithRules(t, []policy.Rule{{
		PolicyID:   "pol_somebody_else",
		Principals: []string{"usr_not_this_one"},
		Devices:    []string{testDeviceID},
		Resources:  []string{testResourceID},
		MaxTTL:     policy.Duration(10 * time.Minute),
		Effect:     policy.EffectAllow,
	}})

	// The request is refused at the control plane, so nothing reaches the fixture.
	if _, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health"); err == nil {
		t.Fatal("a request with no matching policy was served")
	}
	assertFixtureUntouched(t, h)

	denied := queryAudit(t, h, storage.AuditFilter{Event: audit.EventGrantDenied})
	if len(denied) == 0 {
		t.Fatal("a denied grant request left no audit record")
	}
	e := denied[0]
	if e.Reason == "" {
		t.Error("grant.denied carries no reason code")
	}
	if e.ActorID != testUserID || e.DeviceID != testDeviceID || e.ResourceID != testResourceID {
		t.Errorf("grant.denied does not record what was asked for: actor %q device %q resource %q",
			e.ActorID, e.DeviceID, e.ResourceID)
	}
}

// TestAuditTrailNeverContainsPayload is invariant 7 checked directly.
//
// A recognisable string is sent through the forward in both directions. No audit
// row may contain it, in any column. This is the check that stops a well-meaning
// change from adding a "detail" field that quietly captures request bodies.
func TestAuditTrailNeverContainsPayload(t *testing.T) {
	h := newHarness(t, options{})

	const secret = "PAYLOAD-CANARY-e3b0c44298fc1c14"

	resp, err := h.client(10*time.Second).Post(
		h.ForwardURL+"/echo", "text/plain", strings.NewReader(secret))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	echoed, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(echoed), secret) {
		t.Fatalf("the fixture did not echo the canary; the test would pass vacuously")
	}

	waitFor(t, 5*time.Second, "the stream.closed record", func() bool {
		return len(queryAudit(t, h, storage.AuditFilter{Event: audit.EventStreamClosed})) > 0
	})

	// Every row, every column.
	all := queryAudit(t, h, storage.AuditFilter{Limit: storage.MaxAuditLimit})
	if len(all) == 0 {
		t.Fatal("the trail is empty; the test would pass vacuously")
	}
	for _, e := range all {
		row := strings.Join([]string{
			e.Event, e.OrgID, e.ActorRole, e.ActorID, e.DeviceID,
			e.ResourceID, e.GrantID, e.SessionID, e.Reason, e.Detail,
		}, "\x00")
		if strings.Contains(row, secret) {
			t.Fatalf("audit event %q contains payload bytes: %+v", e.Event, e)
		}
	}
}

// TestSessionTokenNeverReachesTheAuditTrail checks that the trail records who
// logged in without recording what would let somebody log in as them.
func TestSessionTokenNeverReachesTheAuditTrail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	operatorID := dep.enrollIdentity(ca.RoleOperator, testUserID)
	sess := dep.session(ctx, operatorID)

	events, err := dep.store.QueryAudit(ctx, storage.AuditFilter{Limit: storage.MaxAuditLimit})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("logging in recorded nothing")
	}
	for _, e := range events {
		row := strings.Join([]string{e.ActorID, e.SessionID, e.Detail, e.Reason}, "\x00")
		if strings.Contains(row, sess.Token) {
			t.Fatalf("audit event %q contains the session token", e.Event)
		}
	}

	// The identifier is present, though: it is what an administrator needs in
	// order to end the session, and it is useless as a credential.
	found := false
	for _, e := range events {
		if e.SessionID == sess.Record.SessionID {
			found = true
		}
	}
	if !found {
		t.Error("no audit event names the session that was opened")
	}
}

// TestByteBudgetIsEnforced is deny case D17.
//
// A resource declaring max_bytes must cut a transfer that exceeds it. Carrying
// the limit in the grant and never applying it would mean a policy field that
// reads as a control and is decoration.
func TestByteBudgetIsEnforced(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	const budget = 8 << 10 // 8 KiB, several frames but far below the response

	dep := newDeployment(t)
	dep.startControlPlane(ctx)
	relaySrv := dep.startRelay(ctx, 16)

	fx := newCountingFixture(t)

	// The same allowlist the other tests use, with a byte cap on the resource.
	resources := testAllowlist(fx.addr)
	limited := resources[testResourceID]
	limited.MaxBytes = budget
	resources[testResourceID] = limited

	a, err := agent.New(agent.Config{
		RelayAddr:     relaySrv.Addr(),
		Identity:      dep.enrollIdentity(ca.RoleDevice, testDeviceID),
		Resources:     resources,
		RetryInterval: 20 * time.Millisecond,
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	go func() { _ = a.Run(ctx) }()
	waitForAgent(t, relaySrv, 1)

	operatorID := dep.enrollIdentity(ca.RoleOperator, testUserID)
	f, err := operator.New(operator.Config{
		RelayAddr:   relaySrv.Addr(),
		ControlAddr: dep.controlAddr,
		Identity:    operatorID,
		ListenAddr:  "127.0.0.1:0",
		DeviceID:    testDeviceID,
		Resource:    testResourceID,
		Session:     dep.sessionTokenFor(operatorID),
		Logger:      discardLogger(),
	})
	if err != nil {
		t.Fatalf("create forwarder: %v", err)
	}
	go func() { _ = f.Run(ctx) }()
	waitReady(t, f.Ready(), "forwarder")

	// Ask for far more than the budget allows.
	const requested = 1 << 20
	resp, err := (&http.Client{Timeout: 20 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true}}).
		Get(fmt.Sprintf("http://%s/bytes/%d", f.Addr(), requested))
	if err != nil {
		// Being cut mid-response is a legitimate outcome: the transport sees the
		// stream abort before the body is complete.
		return
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if readErr == nil && len(body) >= requested {
		t.Fatalf("the full %d bytes were delivered despite a %d byte budget", len(body), budget)
	}
	if uint64(len(body)) > budget {
		// The cap is exact, not approximate. Claiming a byte limit that can be
		// overshot by a frame is a limit that has to be explained every time.
		t.Fatalf("%d bytes were delivered under a %d byte budget; the cap must hold exactly",
			len(body), budget)
	}
}

// queryAudit reads the trail, newest first.
func queryAudit(t *testing.T, h *harness, f storage.AuditFilter) []storage.AuditEvent {
	t.Helper()
	events, err := h.Dep.store.QueryAudit(context.Background(), f)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	return events
}
