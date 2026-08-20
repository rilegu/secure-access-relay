// Package e2e wires the components together in one process and exercises the
// whole path, including enrollment and mutual TLS.
//
// These tests are deliberately not behind a build tag. They are the only place
// the components are checked against each other rather than in isolation, they
// run in a second or two over loopback, and they are deterministic — so they
// belong in the run that happens on every commit rather than in a slower tier
// someone has to remember.
package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/agent"
	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/enrollment"
	"github.com/rilegu/secure-access-relay/internal/identity"
	"github.com/rilegu/secure-access-relay/internal/operator"
	"github.com/rilegu/secure-access-relay/internal/relay"
	"github.com/rilegu/secure-access-relay/internal/storage"
	"github.com/rilegu/secure-access-relay/internal/transport"
)

// testDeviceID is the endpoint identity used throughout these tests.
const testDeviceID = "dev_test_endpoint"

// discardLogger keeps component output out of test results. A failing test is
// diagnosed by its assertions; the log volume from four chatty components would
// bury them.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// deployment is a control plane: an authority, a store, and an enrollment
// service, plus the relay's server certificate.
type deployment struct {
	t          *testing.T
	authority  *ca.CA
	store      *storage.Store
	enroll     *enrollment.Service
	serverCert tls.Certificate
}

func newDeployment(t *testing.T) *deployment {
	t.Helper()

	authority, err := ca.Create("test authority", time.Hour)
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	store, err := storage.Open(filepath.Join(t.TempDir(), "control.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	serverCert, err := authority.IssueServerCertificate([]string{"localhost", "127.0.0.1", "::1"}, time.Hour)
	if err != nil {
		t.Fatalf("issue server certificate: %v", err)
	}

	return &deployment{
		t:          t,
		authority:  authority,
		store:      store,
		enroll:     enrollment.New(store, authority),
		serverCert: serverCert,
	}
}

// enrollIdentity issues credentials the way a real peer obtains them.
//
// It goes through the enrollment service rather than signing directly, because
// the relay verifies that an identity is *recorded* as enrolled, not merely that
// its certificate is signed. Shortcutting that would exercise a path production
// never takes.
func (d *deployment) enrollIdentity(role ca.Role, id string) *identity.Identity {
	d.t.Helper()

	token, err := d.enroll.IssueToken(role, id)
	if err != nil {
		d.t.Fatalf("issue token for %s/%s: %v", role, id, err)
	}

	priv, csrPEM := newCSR(d.t)

	result, err := d.enroll.Enroll(token, csrPEM)
	if err != nil {
		d.t.Fatalf("enroll %s/%s: %v", role, id, err)
	}
	return d.identityFrom(result.CertificatePEM, priv)
}

// identityFrom assembles a usable identity from a certificate and its key.
func (d *deployment) identityFrom(certPEM []byte, priv ed25519.PrivateKey) *identity.Identity {
	d.t.Helper()

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		d.t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		d.t.Fatalf("build key pair: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		d.t.Fatal(err)
	}
	cert.Leaf = leaf

	certID, err := ca.IdentityOf(leaf)
	if err != nil {
		d.t.Fatalf("identity of issued certificate: %v", err)
	}

	return &identity.Identity{
		Certificate: cert,
		CAPool:      d.authority.Pool(),
		ID:          certID,
		ServerName:  "localhost",
		NotAfter:    leaf.NotAfter,
	}
}

// startRelay runs a relay against this deployment.
func (d *deployment) startRelay(ctx context.Context, maxStreams uint32) *relay.Server {
	d.t.Helper()

	srv, err := relay.New(relay.Config{
		Addr:       "127.0.0.1:0",
		TLS:        transport.ServerTLS(d.serverCert, d.authority.Pool()),
		Verify:     d.enroll,
		MaxStreams: maxStreams,
		Logger:     discardLogger(),
	})
	if err != nil {
		d.t.Fatalf("create relay: %v", err)
	}
	go func() { _ = srv.Run(ctx) }()
	waitReady(d.t, srv.Ready(), "relay")
	return srv
}

// newCSR generates a key and a certificate request for it.
func newCSR(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "req"},
		SignatureAlgorithm: x509.PureEd25519,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// harness is a complete chain: deployment, fixture, relay, agent, and forwarder.
type harness struct {
	t *testing.T

	Dep       *deployment
	Fixture   *httptest.Server
	Relay     *relay.Server
	Forwarder *operator.Forwarder

	// ForwardURL is the base URL a test client should call. Requests to it
	// traverse the entire chain.
	ForwardURL string
}

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

	log := discardLogger()
	h := &harness{t: t, Dep: newDeployment(t)}

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

	h.Relay = h.Dep.startRelay(ctx, maxStreams)

	if !opt.skipAgent {
		a, err := agent.New(agent.Config{
			RelayAddr:     h.Relay.Addr(),
			Identity:      h.Dep.enrollIdentity(ca.RoleDevice, testDeviceID),
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
		Identity:   h.Dep.enrollIdentity(ca.RoleOperator, "usr_test"),
		ListenAddr: "127.0.0.1:0",
		DeviceID:   testDeviceID,
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
// Used to point the agent at a target that will refuse a connection. The listener
// is opened and immediately closed so the port is known to be valid and almost
// certainly still free.
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

// identityLike is a minimal credential pair for tests that need to present
// credentials the agent and operator packages would refuse to construct.
type identityLike struct {
	cert tls.Certificate
	pool *x509.CertPool
}

// emptyCert is a credential with no certificate, for testing that the relay
// requires one.
func emptyCert() tls.Certificate { return tls.Certificate{} }
