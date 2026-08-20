// Package e2e wires the three components together in one process and exercises
// the whole forwarding path.
//
// These tests are deliberately not behind a build tag. They are the only place
// the components are checked against each other rather than in isolation, they
// run in a second or two over loopback, and they are deterministic — so they
// belong in the default test run where a regression is caught immediately rather
// than in a slower tier someone remembers to run.
package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/agent"
	"github.com/rilegu/secure-access-relay/internal/operator"
	"github.com/rilegu/secure-access-relay/internal/relay"
)

// harness is a complete chain: fixture, relay, agent, and operator forwarder.
//
//	client -> forwarder -> relay -> agent -> fixture
type harness struct {
	t *testing.T

	Fixture   *httptest.Server
	Relay     *relay.Server
	Forwarder *operator.Forwarder

	// ForwardURL is the base URL a test client should call. Requests to it
	// traverse the entire chain.
	ForwardURL string
}

// testDeviceID is the endpoint identity used throughout these tests. Nothing
// verifies it; it exists so the relay can route an operator to the right agent.
const testDeviceID = "dev_test_endpoint"

// options adjusts how a harness is built, for tests that need a broken chain.
type options struct {
	// skipAgent leaves no endpoint agent connected, to exercise the refusal path.
	skipAgent bool
	// target overrides the agent's target, for pointing it at a dead port.
	target string
	// maxStreams overrides the concurrent stream limit.
	maxStreams uint32
}

// newHarness starts every component and waits until the chain is ready.
//
// Everything binds to port 0 and every component is shut down through the test's
// cleanup, so tests can run in parallel and leave nothing behind.
func newHarness(t *testing.T, opt options) *harness {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Discard component logs by default. A failing test gets its diagnosis from
	// assertions; the log volume from three chatty components would bury it.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	h := &harness{t: t}

	// The approved local service. httptest binds 127.0.0.1, which is the point:
	// it is only reachable from this machine.
	h.Fixture = httptest.NewServer(fixtureHandler())
	t.Cleanup(h.Fixture.Close)

	target := h.Fixture.Listener.Addr().String()
	if opt.target != "" {
		target = opt.target
	}

	maxStreams := uint32(16)
	if opt.maxStreams > 0 {
		maxStreams = opt.maxStreams
	}

	// One listener for both roles now; peers state their role in the handshake.
	h.Relay = relay.New(relay.Config{
		Addr:       "127.0.0.1:0",
		MaxStreams: maxStreams,
		Logger:     log,
	})
	go func() { _ = h.Relay.Run(ctx) }()
	waitReady(t, h.Relay.Ready(), "relay")

	if !opt.skipAgent {
		a, err := agent.New(agent.Config{
			RelayAddr:     h.Relay.Addr(),
			DeviceID:      testDeviceID,
			Target:        target,
			MaxStreams:    maxStreams,
			RetryInterval: 20 * time.Millisecond, // fast reconnect keeps tests brief
			Logger:        log,
		})
		if err != nil {
			t.Fatalf("create agent: %v", err)
		}
		go func() { _ = a.Run(ctx) }()
		waitForAgent(t, h.Relay, 1)
	}

	f, err := operator.New(operator.Config{
		RelayAddr:  h.Relay.Addr(),
		ListenAddr: "127.0.0.1:0",
		DeviceID:   testDeviceID,
		UserID:     "usr_test",
		Resource:   "fixture",
		Logger:     log,
	})
	if err != nil {
		t.Fatalf("create forwarder: %v", err)
	}
	h.Forwarder = f
	go func() { _ = f.Run(ctx) }()
	waitReady(t, f.Ready(), "forwarder")

	h.ForwardURL = "http://" + f.Addr()
	return h
}

// client returns an HTTP client that will not reuse connections.
//
// Connection reuse would hide bugs: each request should exercise the full
// open-and-close path through a fresh stream rather than riding one that is
// already established.
func (h *harness) client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
}

func waitReady(t *testing.T, ready <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not become ready", what)
	}
}

// waitForAgent blocks until the relay reports the expected number of connected
// agents. Polling, because agent registration is asynchronous and there is no
// notification channel for it yet.
func waitForAgent(t *testing.T, r *relay.Server, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r.AgentCount() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("relay never registered %d agent(s); have %d", want, r.AgentCount())
}

// freePort returns a port with nothing listening on it.
//
// Used to point the agent at a target that will refuse a connection. The
// listener is opened and immediately closed so the port is known to be valid and
// almost certainly still free.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// fixtureHandler mirrors testdata/fixtures/httpfixture.go so the automated tests
// and the manual demo exercise the same endpoints.
func fixtureHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/bytes/", func(w http.ResponseWriter, r *http.Request) {
		var n int
		if _, err := fmt.Sscanf(r.URL.Path, "/bytes/%d", &n); err != nil || n < 0 {
			http.Error(w, "usage: /bytes/{count}", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		// Written in chunks rather than one buffer so a large response actually
		// spans many frames, which is what the transfer test is checking.
		chunk := deterministicBytes(64 * 1024)
		for written := 0; written < n; {
			size := min(len(chunk), n-written)
			if _, err := w.Write(chunk[:size]); err != nil {
				return
			}
			written += size
		}
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		_, _ = io.Copy(w, r.Body)
	})

	return mux
}

// deterministicBytes returns n bytes of a repeating pattern, so a caller can
// verify content without transmitting an expected copy.
func deterministicBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251) // prime stride, so the pattern never aligns with a frame boundary
	}
	return b
}
