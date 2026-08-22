package e2ee

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/identity"
)

const (
	testDevice   = "dev_panel_01"
	testOperator = "usr_maria"
)

// TestRelaySeesOnlyCiphertext is the property this package exists for.
//
// The relay is modelled exactly as it behaves: a copier in the middle that reads
// every byte in both directions. A canary is sent each way, and the bytes the
// relay handled must not contain it.
//
// This is the test that would have failed before the inner session existed, and
// the one that fails if anybody removes it later — the golden-path tests pass
// either way, because forwarding works whether or not the middle can read.
func TestRelaySeesOnlyCiphertext(t *testing.T) {
	authority := newAuthority(t)
	operatorID := authority.enroll(t, ca.RoleOperator, testOperator)
	deviceID := authority.enroll(t, ca.RoleDevice, testDevice)

	const (
		fromOperator = "CANARY-REQUEST-a3f1c88e2b04d7"
		fromAgent    = "CANARY-RESPONSE-77be04c1af92"
	)

	relayed := relay(t)

	var wg sync.WaitGroup
	var opConn, agConn *Conn
	var opErr, agErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		opConn, opErr = Client(context.Background(), relayed.operatorSide, operatorID,
			ca.Identity{Role: ca.RoleDevice, ID: testDevice})
	}()
	go func() {
		defer wg.Done()
		agConn, agErr = Server(context.Background(), relayed.agentSide, deviceID,
			ca.Identity{Role: ca.RoleOperator, ID: testOperator})
	}()
	wg.Wait()

	if opErr != nil || agErr != nil {
		t.Fatalf("handshake failed: operator=%v agent=%v", opErr, agErr)
	}

	// Traffic in both directions.
	exchange(t, opConn, agConn, fromOperator, fromAgent)

	seen := relayed.recorded()
	if len(seen) == 0 {
		t.Fatal("the relay recorded nothing; the test would pass vacuously")
	}
	for _, canary := range []string{fromOperator, fromAgent} {
		if bytes.Contains(seen, []byte(canary)) {
			t.Fatalf("the relay saw plaintext: %q appears in the %d bytes it carried",
				canary, len(seen))
		}
	}
}

// TestOperatorRefusesTheWrongEndpoint is what stops a relay routing a stream
// somewhere the grant did not authorize.
//
// A relay chooses which agent a stream reaches. If the operator did not check
// which endpoint answered, a compromised relay could connect it to a different
// enrolled device — every certificate genuine, every signature valid, and the
// operator reaching a machine nobody authorized.
func TestOperatorRefusesTheWrongEndpoint(t *testing.T) {
	authority := newAuthority(t)
	operatorID := authority.enroll(t, ca.RoleOperator, testOperator)

	// The relay connects the operator to a different device than it asked for.
	otherDevice := authority.enroll(t, ca.RoleDevice, "dev_somewhere_else")

	relayed := relay(t)

	var wg sync.WaitGroup
	var opErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, opErr = Client(context.Background(), relayed.operatorSide, operatorID,
			ca.Identity{Role: ca.RoleDevice, ID: testDevice})
	}()
	go func() {
		defer wg.Done()
		_, _ = Server(context.Background(), relayed.agentSide, otherDevice,
			ca.Identity{Role: ca.RoleOperator, ID: testOperator})
	}()
	wg.Wait()

	if opErr == nil {
		t.Fatal("the operator accepted an endpoint the grant did not name")
	}
	if !errors.Is(opErr, ErrPeerIdentity) {
		t.Fatalf("error = %v, want ErrPeerIdentity", opErr)
	}
}

// TestAgentRefusesTheWrongOperator is the half that makes a captured grant
// useless.
//
// A grant travels through the relay. Before the inner session, a relay could
// replay one it observed and the agent would serve it: the grant verifies, the
// device matches, the user matches. What the agent could not check was whether
// the peer holding the grant was the operator it names.
func TestAgentRefusesTheWrongOperator(t *testing.T) {
	authority := newAuthority(t)
	deviceID := authority.enroll(t, ca.RoleDevice, testDevice)

	// An enrolled operator who is not the one the grant names — which is also the
	// shape of a relay using its own credentials with somebody else's grant.
	intruder := authority.enroll(t, ca.RoleOperator, "usr_intruder")

	relayed := relay(t)

	var wg sync.WaitGroup
	var agErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = Client(context.Background(), relayed.operatorSide, intruder,
			ca.Identity{Role: ca.RoleDevice, ID: testDevice})
	}()
	go func() {
		defer wg.Done()
		_, agErr = Server(context.Background(), relayed.agentSide, deviceID,
			ca.Identity{Role: ca.RoleOperator, ID: testOperator})
	}()
	wg.Wait()

	if agErr == nil {
		t.Fatal("the agent served a peer that is not the operator the grant names")
	}
	if !errors.Is(agErr, ErrPeerIdentity) {
		t.Fatalf("error = %v, want ErrPeerIdentity", agErr)
	}
}

// TestCertificateFromAnotherAuthorityIsRefused checks that the inner session
// trusts exactly one authority.
//
// A certificate that is perfectly valid somewhere else is worthless here. This
// is the check that stops an attacker who can obtain a certificate — from a
// public CA, or from their own deployment — from using it.
func TestCertificateFromAnotherAuthorityIsRefused(t *testing.T) {
	ours := newAuthority(t)
	theirs := newAuthority(t)

	deviceID := ours.enroll(t, ca.RoleDevice, testDevice)

	// Right identity, right role, wrong authority.
	foreign := theirs.enroll(t, ca.RoleOperator, testOperator)
	// It must verify against its own authority, or the test proves nothing.
	foreign.CAPool = ours.ca.Pool()

	relayed := relay(t)

	var wg sync.WaitGroup
	var agErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = Client(context.Background(), relayed.operatorSide, foreign,
			ca.Identity{Role: ca.RoleDevice, ID: testDevice})
	}()
	go func() {
		defer wg.Done()
		_, agErr = Server(context.Background(), relayed.agentSide, deviceID,
			ca.Identity{Role: ca.RoleOperator, ID: testOperator})
	}()
	wg.Wait()

	if agErr == nil {
		t.Fatal("a certificate from a different authority was accepted")
	}
}

// TestUnauthenticatedPeerIsRefused checks that the agent will not serve a peer
// presenting no certificate at all.
//
// An inner session that accepted an anonymous client would encrypt the traffic
// and authenticate nobody, which closes the confidentiality hole and leaves the
// captured-grant one wide open.
func TestUnauthenticatedPeerIsRefused(t *testing.T) {
	authority := newAuthority(t)
	deviceID := authority.enroll(t, ca.RoleDevice, testDevice)

	relayed := relay(t)

	var wg sync.WaitGroup
	var agErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		// A bare TLS client with no certificate, as anything that had only
		// observed the protocol would attempt.
		bare := tls.Client(streamConn{relayed.operatorSide}, &tls.Config{
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{ALPN},
			InsecureSkipVerify: true,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = bare.HandshakeContext(ctx)
		_ = bare.Close()
	}()
	go func() {
		defer wg.Done()
		_, agErr = Server(context.Background(), relayed.agentSide, deviceID,
			ca.Identity{Role: ca.RoleOperator, ID: testOperator})
	}()
	wg.Wait()

	if agErr == nil {
		t.Fatal("the agent established an inner session with an unauthenticated peer")
	}
}

// TestMismatchedProtocolIsRefused checks the ALPN guard.
func TestMismatchedProtocolIsRefused(t *testing.T) {
	authority := newAuthority(t)
	operatorID := authority.enroll(t, ca.RoleOperator, testOperator)
	deviceID := authority.enroll(t, ca.RoleDevice, testDevice)

	relayed := relay(t)

	var wg sync.WaitGroup
	var agErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		wrong := tls.Client(streamConn{relayed.operatorSide}, &tls.Config{
			Certificates:       []tls.Certificate{operatorID.Certificate},
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{"sar/e2ee/99"},
			InsecureSkipVerify: true,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = wrong.HandshakeContext(ctx)
		_ = wrong.Close()
	}()
	go func() {
		defer wg.Done()
		_, agErr = Server(context.Background(), relayed.agentSide, deviceID,
			ca.Identity{Role: ca.RoleOperator, ID: testOperator})
	}()
	wg.Wait()

	if agErr == nil {
		t.Fatal("a peer offering a different inner protocol was accepted")
	}
}

// ---------------------------------------------------------------- helpers

// relayedPair models the relay: two ends joined by a copier that sees everything.
type relayedPair struct {
	operatorSide io.ReadWriteCloser
	agentSide    io.ReadWriteCloser

	mu   sync.Mutex
	seen bytes.Buffer
}

func (r *relayedPair) recorded() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.seen.Bytes()...)
}

// relay wires an operator end to an agent end through a recording copier.
//
// net.Pipe rather than a loopback socket, so the test cannot pass by accident on
// a machine where something buffers differently — and so every byte that crosses
// the middle is observed rather than sampled.
func relay(t *testing.T) *relayedPair {
	t.Helper()

	opEnd, relayOp := net.Pipe()
	agEnd, relayAg := net.Pipe()

	p := &relayedPair{operatorSide: opEnd, agentSide: agEnd}

	tee := func(dst, src net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				p.mu.Lock()
				p.seen.Write(buf[:n])
				p.mu.Unlock()
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go tee(relayAg, relayOp)
	go tee(relayOp, relayAg)

	t.Cleanup(func() {
		_ = opEnd.Close()
		_ = agEnd.Close()
		_ = relayOp.Close()
		_ = relayAg.Close()
	})
	return p
}

// exchange sends a message each way and checks both arrive intact.
func exchange(t *testing.T, opConn, agConn *Conn, fromOperator, fromAgent string) {
	t.Helper()

	var wg sync.WaitGroup
	wg.Add(2)

	var agentGot, operatorGot string
	var agentErr, operatorErr error

	go func() {
		defer wg.Done()
		if _, err := opConn.Write([]byte(fromOperator)); err != nil {
			operatorErr = err
			return
		}
		buf := make([]byte, len(fromAgent))
		if _, err := io.ReadFull(opConn, buf); err != nil {
			operatorErr = err
			return
		}
		operatorGot = string(buf)
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, len(fromOperator))
		if _, err := io.ReadFull(agConn, buf); err != nil {
			agentErr = err
			return
		}
		agentGot = string(buf)
		if _, err := agConn.Write([]byte(fromAgent)); err != nil {
			agentErr = err
		}
	}()

	wg.Wait()

	if agentErr != nil || operatorErr != nil {
		t.Fatalf("exchange failed: agent=%v operator=%v", agentErr, operatorErr)
	}
	if agentGot != fromOperator {
		t.Fatalf("the agent received %q, want %q", agentGot, fromOperator)
	}
	if operatorGot != fromAgent {
		t.Fatalf("the operator received %q, want %q", operatorGot, fromAgent)
	}
}

// testAuthority issues identities for the tests.
type testAuthority struct{ ca *ca.CA }

func newAuthority(t *testing.T) *testAuthority {
	t.Helper()
	authority, err := ca.Create("test authority", time.Hour)
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	return &testAuthority{ca: authority}
}

// enroll issues a certificate and assembles a usable identity around it.
func (a *testAuthority) enroll(t *testing.T, role ca.Role, id string) *identity.Identity {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "req"},
		SignatureAlgorithm: x509.PureEd25519,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	certPEM, err := a.ca.Sign(csr, ca.Identity{Role: role, ID: id}, time.Hour)
	if err != nil {
		t.Fatalf("sign %s/%s: %v", role, id, err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert.Leaf = leaf

	return &identity.Identity{
		Certificate: cert,
		CAPool:      a.ca.Pool(),
		ID:          ca.Identity{Role: role, ID: id},
		NotAfter:    leaf.NotAfter,
	}
}
