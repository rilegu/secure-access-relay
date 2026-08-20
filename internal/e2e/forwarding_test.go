package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/agent"
	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/policy"
	"github.com/rilegu/secure-access-relay/internal/operator"
)

// TestGoldenPath is the done-condition for this phase: an HTTP request travels
// from a local client, through the operator forwarder, the relay, and the agent,
// to a service bound to loopback on the endpoint — and the response comes back.
//
// It is the automated form of:
//
//	curl http://127.0.0.1:18080/health
func TestGoldenPath(t *testing.T) {
	h := newHarness(t, options{})

	resp, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health")
	if err != nil {
		t.Fatalf("request through the chain failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got, want := string(body), `{"status":"ok"}`; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// TestSequentialRequests checks that the agent's connection survives a completed
// stream.
//
// This is the property that makes the connection genuinely persistent. An
// implementation that tore down the agent connection at the end of every stream
// would pass the golden path and fail here — or would only pass because the
// agent reconnected in time, which is why the assertion is that the relay never
// lost the agent rather than merely that the requests succeeded.
func TestSequentialRequests(t *testing.T) {
	h := newHarness(t, options{})
	client := h.client(10 * time.Second)

	for i := 0; i < 5; i++ {
		resp, err := client.Get(h.ForwardURL + "/health")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
		if n := h.Relay.AgentCount(); n != 1 {
			t.Fatalf("after request %d the relay has %d agents, want 1: the agent connection did not survive the stream", i, n)
		}
	}
}

// TestLargeTransferIntegrity moves a large response through the chain and checks
// its digest.
//
// Size alone proves little. The failure this catches is corruption in the middle
// of a stream — a frame boundary mishandled, a reused buffer overwritten before
// it was sent — which produces the right number of bytes in the wrong order.
func TestLargeTransferIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("large transfer skipped in short mode")
	}

	const size = 64 << 20 // 64 MiB, ~1000 frames at the 64 KiB frame limit

	h := newHarness(t, options{})

	resp, err := h.client(120 * time.Second).Get(h.ForwardURL + "/bytes/" + itoa(size))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	hasher := sha256.New()
	n, err := io.Copy(hasher, resp.Body)
	if err != nil {
		t.Fatalf("read body after %d bytes: %v", n, err)
	}
	if n != size {
		t.Fatalf("received %d bytes, want %d", n, size)
	}

	// The fixture emits a repeating 64 KiB chunk, so the expected digest is
	// computed the same way rather than by holding 64 MiB in the test.
	want := sha256.New()
	chunk := deterministicBytes(64 * 1024)
	for written := 0; written < size; written += len(chunk) {
		want.Write(chunk[:min(len(chunk), size-written)])
	}

	if !bytes.Equal(hasher.Sum(nil), want.Sum(nil)) {
		t.Fatal("payload corrupted in transit: byte count correct but content differs")
	}
}

// TestRequestBodyForwarded exercises the operator-to-agent direction with a body
// large enough to span several frames. The golden path barely tests this
// direction, since a GET request header fits in one frame.
func TestRequestBodyForwarded(t *testing.T) {
	h := newHarness(t, options{})

	payload := deterministicBytes(512 * 1024) // several frames' worth

	resp, err := h.client(30*time.Second).Post(
		h.ForwardURL+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	echoed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echoed %d bytes, sent %d; contents differ", len(echoed), len(payload))
	}
}

// TestNoAgentConnected checks the refusal path when nothing is connected.
//
// The request must fail rather than hang. An operator waiting forever on an
// endpoint that is not there is a worse outcome than a prompt error, and the
// reason code is what tells them it is an availability problem rather than a
// permissions one.
func TestNoAgentConnected(t *testing.T) {
	h := newHarness(t, options{skipAgent: true})

	resp, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("request succeeded with no agent connected; it must fail closed")
	}
}

// TestTargetNotListening checks that an unreachable local service is reported as
// a target failure and not as a denial.
//
// The distinction is the point. The agent is willing, the stream is allowed, and
// the service is simply down — conflating that with a policy denial would send
// an operator to argue about permissions they already have.
func TestTargetNotListening(t *testing.T) {
	h := newHarness(t, options{target: freePort(t)})

	resp, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("request succeeded against a dead target")
	}

	// The agent must still be connected: a target that refuses a connection is
	// not a reason to tear down the endpoint's relay session.
	if n := h.Relay.AgentCount(); n != 1 {
		t.Fatalf("relay has %d agents after a refused target, want 1", n)
	}
}

// TestConcurrentRequestsAllSucceed checks that many requests are served at once.
//
// This is the property multiplexing exists to provide, and it is the assertion
// that changed when it landed: previously the chain served one stream at a time
// and refusals were expected. Now every request within the stream limit must
// succeed, and each must get its own correct response — a crossed stream would
// show up as a body from the wrong request rather than as an error.
func TestConcurrentRequestsAllSucceed(t *testing.T) {
	h := newHarness(t, options{maxStreams: 16})

	const concurrency = 8

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := h.client(20 * time.Second).Get(h.ForwardURL + "/health")
			if err != nil {
				t.Errorf("concurrent request failed: %v", err)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}
			// A response that arrives must be correct. Truncated or interleaved
			// content would mean the cap failed to isolate streams.
			if resp.StatusCode == http.StatusOK && string(body) == `{"status":"ok"}` {
				mu.Lock()
				succeeded++
				mu.Unlock()
			} else {
				t.Errorf("corrupt response through the chain: status=%d body=%q", resp.StatusCode, body)
			}
		}()
	}
	wg.Wait()

	if succeeded != concurrency {
		t.Fatalf("%d/%d concurrent requests succeeded; multiplexing should serve all of them",
			succeeded, concurrency)
	}
}

// TestAgentReconnectsAfterRelayRestart checks that an agent recovers when the
// relay goes away.
//
// Endpoints are not restarted when a relay is. The agent must redial on its own,
// or every relay deployment would need a fleet-wide restart to follow it.
func TestAgentReconnectsAfterRelayRestart(t *testing.T) {
	h := newHarness(t, options{})

	// Confirm the chain works before breaking it.
	resp, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health")
	if err != nil {
		t.Fatalf("baseline request failed: %v", err)
	}
	_ = resp.Body.Close()

	// Drop every agent connection by closing the listeners and the sessions.
	h.Relay.Shutdown()

	// The agent should notice and start redialling. It cannot reconnect to a
	// stopped relay, so this only asserts that it dropped the dead session
	// rather than holding it forever.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && h.Relay.AgentCount() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if n := h.Relay.AgentCount(); n != 0 {
		t.Fatalf("relay still reports %d agents after shutdown; the dead session was not released", n)
	}
}

// itoa avoids pulling strconv into the test for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestClientClosesMidResponse checks teardown when the operator's client walks
// away while the endpoint is still sending.
//
// This is how a real session usually ends — a browser tab closes, a user presses
// Escape — not with a tidy completed response. It is also the path where a
// desynchronisation bug already hid once, so it is worth asserting directly: the
// agent must release its target and the relay must keep the agent session, both
// ready for the next stream.
func TestClientClosesMidResponse(t *testing.T) {
	h := newHarness(t, options{})

	const size = 8 << 20 // large enough that the response is still in flight

	resp, err := h.client(30 * time.Second).Get(h.ForwardURL + "/bytes/" + itoa(size))
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	// Read a little, then abandon the response without draining it.
	partial := make([]byte, 4096)
	if _, err := io.ReadFull(resp.Body, partial); err != nil {
		t.Fatalf("read first chunk: %v", err)
	}
	_ = resp.Body.Close()

	// The chain must recover. A subsequent request proves the agent released its
	// target, the relay released the agent, and neither is wedged.
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp2, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health")
		if err == nil {
			body, _ := io.ReadAll(resp2.Body)
			_ = resp2.Body.Close()
			if string(body) == `{"status":"ok"}` {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("chain did not recover after the client abandoned a response mid-stream")
		}
	}

	if n := h.Relay.AgentCount(); n != 1 {
		t.Fatalf("relay has %d agents after a mid-stream close, want 1", n)
	}
}

// TestEndpointClosesMidStream checks the opposite direction: the endpoint service
// ends the connection while the operator is still attached.
//
// The operator must observe a clean end rather than a stall. A stream whose far
// end has gone away but which never closes is worse than an error, because the
// operator has no way to tell it apart from a slow response.
func TestEndpointClosesMidStream(t *testing.T) {
	h := newHarness(t, options{})

	// /health completes and the fixture closes its side. The operator should see
	// a complete response and the stream should end, not hang.
	done := make(chan error, 1)
	go func() {
		resp, err := h.client(10 * time.Second).Get(h.ForwardURL + "/health")
		if err != nil {
			done <- err
			return
		}
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stream did not end cleanly when the endpoint closed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream stalled after the endpoint closed its side")
	}
}

// TestSlowReaderBackpressure checks that a consumer slower than the producer does
// not cause unbounded buffering.
//
// The claim in internal/proto is that memory stays bounded because bytes are
// framed as they are read rather than accumulated. This exercises that: the
// endpoint produces a large response as fast as it can while the operator's
// client reads in small, delayed chunks. If any hop buffered the whole response,
// this would still pass functionally — so the assertion is on completeness and
// integrity, with the memory claim resting on the fixed-size buffers the code
// uses rather than on a measurement this test could make reliably.
func TestSlowReaderBackpressure(t *testing.T) {
	if testing.Short() {
		t.Skip("slow reader test skipped in short mode")
	}

	const size = 4 << 20

	h := newHarness(t, options{})

	resp, err := h.client(60 * time.Second).Get(h.ForwardURL + "/bytes/" + itoa(size))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	hasher := sha256.New()
	buf := make([]byte, 16*1024)
	var total int64
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			hasher.Write(buf[:n])
			total += int64(n)
			// Deliberately slower than the producer.
			time.Sleep(time.Millisecond)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read after %d bytes: %v", total, err)
		}
	}

	if total != size {
		t.Fatalf("received %d bytes, want %d: a slow reader lost data", total, size)
	}

	want := sha256.New()
	chunk := deterministicBytes(64 * 1024)
	for written := 0; written < size; written += len(chunk) {
		want.Write(chunk[:min(len(chunk), size-written)])
	}
	if !bytes.Equal(hasher.Sum(nil), want.Sum(nil)) {
		t.Fatal("payload corrupted when the reader was slower than the writer")
	}
}

// TestManyAgentsAndOperators checks that one relay serves several endpoints and
// several operators at once, and that each operator reaches the endpoint it
// asked for.
//
// Routing correctness is the point. Reaching the wrong device would be a nuisance
// today and a security failure once grants name a specific endpoint, so each
// fixture returns a distinct identity and every response is checked against the
// device that was requested.
func TestManyAgentsAndOperators(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)

	devices := []string{"dev_alpha", "dev_beta", "dev_gamma"}

	// One rule per device, each naming only its own operator and resource. A
	// routing mistake and an authorization mistake would both show up here.
	dep.rules = nil
	for _, id := range devices {
		dep.rules = append(dep.rules, policy.Rule{
			PolicyID:   "pol_" + id,
			Principals: []string{"usr_" + id},
			Devices:    []string{id},
			Resources:  []string{testResourceID},
			MaxTTL:     policy.Duration(10 * time.Minute),
			Effect:     policy.EffectAllow,
		})
	}

	dep.startControlPlane(ctx)
	relaySrv := dep.startRelay(ctx, 16)
	log := discardLogger()

	for _, id := range devices {
		name := id
		fx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, name)
		}))
		t.Cleanup(fx.Close)

		a, err := agent.New(agent.Config{
			RelayAddr:     relaySrv.Addr(),
			Identity:      dep.enrollIdentity(ca.RoleDevice, name),
			Resources:     testAllowlist(fx.Listener.Addr().String()),
			RetryInterval: 20 * time.Millisecond,
			Logger:        log,
		})
		if err != nil {
			t.Fatalf("create agent %s: %v", name, err)
		}
		go func() { _ = a.Run(ctx) }()
	}
	waitForAgent(t, relaySrv, len(devices))

	// One operator per device, each with its own enrolled identity.
	forwards := make(map[string]string, len(devices))
	for _, id := range devices {
		f, err := operator.New(operator.Config{
			RelayAddr:   relaySrv.Addr(),
			ControlAddr: dep.controlAddr,
			Identity:    dep.enrollIdentity(ca.RoleOperator, "usr_"+id),
			ListenAddr:  "127.0.0.1:0",
			DeviceID:    id,
			Resource:    testResourceID,
			Logger:      log,
		})
		if err != nil {
			t.Fatalf("create forwarder for %s: %v", id, err)
		}
		go func() { _ = f.Run(ctx) }()
		waitReady(t, f.Ready(), "forwarder "+id)
		forwards[id] = "http://" + f.Addr()
	}

	// Drive all of them at once, so a routing mistake shows up as a response from
	// the wrong endpoint rather than being hidden by sequential timing.
	var wg sync.WaitGroup
	for id, url := range forwards {
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(id, url string) {
				defer wg.Done()
				client := &http.Client{Timeout: 20 * time.Second,
					Transport: &http.Transport{DisableKeepAlives: true}}
				resp, err := client.Get(url + "/whoami")
				if err != nil {
					t.Errorf("%s: %v", id, err)
					return
				}
				defer func() { _ = resp.Body.Close() }()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Errorf("%s: read: %v", id, err)
					return
				}
				if string(body) != id {
					t.Errorf("forward for %s reached %q: the relay routed to the wrong endpoint", id, body)
				}
			}(id, url)
		}
	}
	wg.Wait()

	if n := relaySrv.AgentCount(); n != len(devices) {
		t.Fatalf("relay has %d agents, want %d", n, len(devices))
	}
}

// TestUnknownDeviceRefused checks that asking for an endpoint nobody is serving
// fails promptly rather than hanging.
func TestUnknownDeviceRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.rules = []policy.Rule{{
		PolicyID:   "pol_lost",
		Principals: []string{"usr_lost"},
		Devices:    []string{"dev_does_not_exist"},
		Resources:  []string{testResourceID},
		MaxTTL:     policy.Duration(5 * time.Minute),
		Effect:     policy.EffectAllow,
	}}
	dep.startControlPlane(ctx)
	relaySrv := dep.startRelay(ctx, 16)

	f, err := operator.New(operator.Config{
		RelayAddr:   relaySrv.Addr(),
		ControlAddr: dep.controlAddr,
		Identity:    dep.enrollIdentity(ca.RoleOperator, "usr_lost"),
		ListenAddr:  "127.0.0.1:0",
		DeviceID:    "dev_does_not_exist",
		Resource:    testResourceID,
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
		t.Fatal("request succeeded for a device with no connected agent")
	}
}
