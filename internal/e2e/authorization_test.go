package e2e

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/agent"
	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/grants"
	"github.com/rilegu/secure-access-relay/internal/control/policy"
	"github.com/rilegu/secure-access-relay/internal/operator"
)

// The authorization deny cases from docs/e2e-test-plan.md.
//
// These matter more than the golden path. A forwarding bug is visible the first
// time someone uses the system; an authorization bug is invisible until it is
// exploited, and by then it has been invisible for a while.
//
// Every case must fail closed, and — the part that is easy to forget — must
// deliver **zero bytes** to the target. A denial that still opened a connection
// would be a denial in the logs only.

// newAuthHarness starts a chain with an explicit rule set and a fixture that
// counts every request reaching it.
//
// The counter is the assertion that matters for a denial: it proves nothing got
// through, rather than only that the client saw an error.
func newAuthHarness(t *testing.T, rules []policy.Rule) *harness {
	t.Helper()
	return newHarnessWithRules(t, rules)
}

// TestDeniedWhenNoPolicyMatches is deny case D12.
func TestDeniedWhenNoPolicyMatches(t *testing.T) {
	// A rule set that allows somebody else entirely.
	h := newAuthHarness(t, []policy.Rule{{
		PolicyID:   "pol_other",
		Principals: []string{"usr_somebody_else"},
		Devices:    []string{testDeviceID},
		Resources:  []string{testResourceID},
		MaxTTL:     policy.Duration(10 * time.Minute),
		Effect:     policy.EffectAllow,
	}})

	assertRefused(t, h, "a request with no matching policy was served")
	assertFixtureUntouched(t, h)
}

// TestDeniedForWrongDevice is deny case D13: the right user and resource, the
// wrong endpoint.
func TestDeniedForWrongDevice(t *testing.T) {
	h := newAuthHarness(t, []policy.Rule{{
		PolicyID:   "pol_other_device",
		Principals: []string{testUserID},
		Devices:    []string{"dev_a_completely_different_endpoint"},
		Resources:  []string{testResourceID},
		MaxTTL:     policy.Duration(10 * time.Minute),
		Effect:     policy.EffectAllow,
	}})

	assertRefused(t, h, "an operator reached a device no policy allowed")
	assertFixtureUntouched(t, h)
}

// TestDeniedForWrongResource is deny case D14: the right user and device, the
// wrong resource.
func TestDeniedForWrongResource(t *testing.T) {
	h := newAuthHarness(t, []policy.Rule{{
		PolicyID:   "pol_other_resource",
		Principals: []string{testUserID},
		Devices:    []string{testDeviceID},
		Resources:  []string{"res_something_else_entirely"},
		MaxTTL:     policy.Duration(10 * time.Minute),
		Effect:     policy.EffectAllow,
	}})

	assertRefused(t, h, "an operator reached a resource no policy allowed")
	assertFixtureUntouched(t, h)
}

// TestDeniedWhenPolicyIsEmpty checks the deny-by-default posture directly.
//
// No rules at all is the state a deployment is in before anyone configures it,
// and before configuration nothing should be reachable.
func TestDeniedWhenPolicyIsEmpty(t *testing.T) {
	h := newAuthHarness(t, nil)
	assertRefused(t, h, "an empty policy allowed access")
	assertFixtureUntouched(t, h)
}

// TestAgentRefusesUndeclaredResource is deny case D10.
//
// The control plane happily issues a grant, because its policy names the
// resource. The agent has never heard of it. The agent's view wins — which is
// the property that makes the agent, not the control plane, the enforcement
// point.
func TestAgentRefusesUndeclaredResource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.rules = []policy.Rule{{
		PolicyID:   "pol_phantom",
		Principals: []string{testUserID},
		Devices:    []string{testDeviceID},
		Resources:  []string{"res_the_agent_does_not_serve"},
		MaxTTL:     policy.Duration(10 * time.Minute),
		Effect:     policy.EffectAllow,
	}}
	dep.startControlPlane(ctx)
	relaySrv := dep.startRelay(ctx, 16)

	fx := newCountingFixture(t)

	a, err := agent.New(agent.Config{
		RelayAddr:     relaySrv.Addr(),
		Identity:      dep.enrollIdentity(ca.RoleDevice, testDeviceID),
		Resources:     testAllowlist(fx.addr), // declares res_fixture, not the phantom
		RetryInterval: 20 * time.Millisecond,
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	go func() { _ = a.Run(ctx) }()
	waitForAgent(t, relaySrv, 1)

	f, err := operator.New(operator.Config{
		RelayAddr:   relaySrv.Addr(),
		ControlAddr: dep.controlAddr,
		Identity:    dep.enrollIdentity(ca.RoleOperator, testUserID),
		ListenAddr:  "127.0.0.1:0",
		DeviceID:    testDeviceID,
		Resource:    "res_the_agent_does_not_serve",
		Logger:      discardLogger(),
	})
	if err != nil {
		t.Fatalf("create forwarder: %v", err)
	}
	go func() { _ = f.Run(ctx) }()
	waitReady(t, f.Ready(), "forwarder")

	client := &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Get("http://" + f.Addr() + "/health")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the agent served a resource it never declared")
	}
	if n := fx.hits(); n != 0 {
		t.Fatalf("the fixture received %d requests during a denial; zero bytes must reach the target", n)
	}
}

// TestExpiredGrantIsRefused is deny case D6.
//
// The grant is issued legitimately and then allowed to lapse. Nothing about it
// changes — it stays correctly signed — so this is the case where only the
// expiry check stands between an old authorization and continued access.
func TestExpiredGrantIsRefused(t *testing.T) {
	h := newHarnessWithRules(t, []policy.Rule{{
		PolicyID:   "pol_brief",
		Principals: []string{testUserID},
		Devices:    []string{testDeviceID},
		Resources:  []string{testResourceID},
		// The shortest a policy can express. The issuer floors at the system
		// ceiling when a rule asks for something unusable, so this exercises a
		// real short-lived grant rather than a degenerate one.
		MaxTTL: policy.Duration(time.Minute),
		Effect: policy.EffectAllow,
	}})

	// Works while the grant is live.
	resp, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health")
	if err != nil {
		t.Fatalf("request failed while the grant was valid: %v", err)
	}
	_ = resp.Body.Close()

	// Verify the expiry logic directly rather than waiting a minute: issue a
	// grant, then check that a verifier at a later time refuses it.
	signed, _, err := h.Dep.issuer.Issue(h.Dep.rules, grants.Request{
		UserID:       testUserID,
		DeviceID:     testDeviceID,
		ResourceID:   testResourceID,
		RequestedTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	later := signed.ExpiresAt.Add(2 * time.Minute)
	if err := signed.Verify(h.Dep.issuer.PublicKey(), later, testDeviceID); err == nil {
		t.Fatal("a grant verified after its expiry")
	}
}

// TestGrantIsBoundToItsRequester checks that a grant issued to one operator
// cannot be used by another.
//
// Both operators are enrolled and both certificates are valid, so this is not an
// authentication question. The user identifier is inside the grant's signature
// and the relay compares it against the certificate that presented it.
func TestGrantIsBoundToItsRequester(t *testing.T) {
	h := newHarnessWithRules(t, []policy.Rule{
		{
			PolicyID:   "pol_first",
			Principals: []string{testUserID},
			Devices:    []string{testDeviceID},
			Resources:  []string{testResourceID},
			MaxTTL:     policy.Duration(10 * time.Minute),
			Effect:     policy.EffectAllow,
		},
	})

	// A grant legitimately issued to the permitted operator.
	signed, _, err := h.Dep.issuer.Issue(h.Dep.rules, grants.Request{
		UserID:       testUserID,
		DeviceID:     testDeviceID,
		ResourceID:   testResourceID,
		RequestedTTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// A second, differently identified operator presents it.
	other := h.Dep.enrollIdentity(ca.RoleOperator, "usr_borrower")
	err = dialAndOpen(t, h.Relay.Addr(), other, testDeviceID, signed.Encode())
	if err == nil {
		t.Fatal("an operator used a grant issued to somebody else")
	}
}

// TestOperatorCannotRequestGrantAsAnotherUser checks that the control plane
// takes the requester's identity from the certificate.
//
// The request body has no user field at all, which is the structural version of
// this guarantee — there is nothing to forge. This test confirms the identity
// actually used is the certificate's.
func TestOperatorCannotRequestGrantAsAnotherUser(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.rules = []policy.Rule{{
		PolicyID:   "pol_only_maria",
		Principals: []string{"usr_maria"},
		Devices:    []string{testDeviceID},
		Resources:  []string{testResourceID},
		MaxTTL:     policy.Duration(10 * time.Minute),
		Effect:     policy.EffectAllow,
	}}
	dep.startControlPlane(ctx)

	// An enrolled operator who is not maria asks for the same access.
	intruder := dep.enrollIdentity(ca.RoleOperator, "usr_intruder")
	body, status, err := postGrant(t, dep.controlAddr, intruder, testDeviceID, testResourceID)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status == http.StatusOK {
		t.Fatalf("the control plane issued a grant to an operator no policy names: %s", body)
	}
	if !strings.Contains(body, "policy_denied") {
		t.Errorf("denial body = %q, want it to name policy_denied", body)
	}
}

// TestDeviceCannotRequestGrant checks that a device certificate cannot obtain
// authorization.
//
// Devices serve resources; they do not request access to them. If a device could
// obtain a grant, an endpoint compromise would become a way to reach every other
// endpoint.
func TestDeviceCannotRequestGrant(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	device := dep.enrollIdentity(ca.RoleDevice, testDeviceID)
	_, status, err := postGrant(t, dep.controlAddr, device, testDeviceID, testResourceID)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status == http.StatusOK {
		t.Fatal("a device certificate obtained a grant")
	}
}

// TestGrantRequiresClientCertificate checks the grants route refuses an
// unauthenticated caller.
//
// Enrollment deliberately accepts connections without a client certificate, so
// the TLS listener cannot require one. Each route decides for itself, and this
// confirms the grants route decided correctly.
func TestGrantRequiresClientCertificate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	_, status, err := postGrant(t, dep.controlAddr, nil, testDeviceID, testResourceID)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status == http.StatusOK {
		t.Fatal("a grant was issued to a caller with no client certificate")
	}
}

// assertRefused drives a request through the chain and requires it to fail.
func assertRefused(t *testing.T, h *harness, msg string) {
	t.Helper()
	resp, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health")
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("%s (status %d, body %q)", msg, resp.StatusCode, body)
	}
}

// assertFixtureUntouched requires that nothing reached the endpoint service.
//
// This is the assertion a denial test is actually for. A request that failed at
// the client while still opening a connection to the target would be a denial in
// name only.
func assertFixtureUntouched(t *testing.T, h *harness) {
	t.Helper()
	if n := h.FixtureHits(); n != 0 {
		t.Fatalf("the endpoint service received %d requests during a denial; zero must reach it", n)
	}
}
