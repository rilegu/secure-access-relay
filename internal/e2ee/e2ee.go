// Package e2ee establishes an encrypted, mutually authenticated session between
// an operator and an endpoint agent, inside the stream the relay carries.
//
// # What this changes
//
// Every hop is already mutual TLS, but the relay *terminates* it: two separate
// sessions, decrypted and re-encrypted in the middle. Mutual TLS authenticates
// both ends to the relay; it does not hide anything from it. Until this existed,
// the relay was trusted for confidentiality and the README said so.
//
// A second TLS session runs inside the relayed stream, between the two ends that
// actually matter. The relay copies its records without being able to read them.
//
// # It closes a second hole, not only confidentiality
//
// The grant travels through the relay. Before this, a compromised relay could
// take a grant presented by one operator and open its own stream to the agent
// with it: the grant would verify, the device and user would match, and the
// agent would dial the local service for the relay. The agent's check proved the
// *grant* was genuine, not that the peer holding it was.
//
// The inner handshake requires each end to prove possession of the private key
// for the identity the grant names. A relay that captured a grant still cannot
// produce the operator's key, so it cannot use what it captured.
//
// # Why nested TLS rather than a purpose-built protocol
//
// Custom cryptography is a stated non-goal, and a protocol framework would be a
// second cryptographic dependency. The certificates needed for this already
// exist — every peer is enrolled with one carrying both client and server
// extended key usages — and crypto/tls is already the transport. See ADR-0018.
//
// # What this package must never do
//
//   - It must never fall back to an unauthenticated or unencrypted session. A
//     downgrade that "works" is worse than a failure, because it looks like it
//     worked.
//   - It must never accept an identity it was not told to expect. The whole
//     value is that the peer is the one the grant names.
package e2ee

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/identity"
	"github.com/rilegu/secure-access-relay/internal/proto"
)

// ALPN identifies this inner protocol and its version.
//
// Both ends require it, so a session that somehow reached the wrong kind of peer
// fails at the handshake rather than part way through the first exchange. It is
// also the version marker: a future incompatible change becomes a new string
// instead of a silent misinterpretation.
const ALPN = "sar/e2ee/1"

// Errors this package reports.
var (
	// ErrPeerIdentity means the far end authenticated correctly but is not who
	// the grant said it would be.
	ErrPeerIdentity = errors.New("e2ee: peer is not the identity the grant names")

	// ErrHandshake means the inner session could not be established.
	ErrHandshake = errors.New("e2ee: inner handshake failed")
)

// Conn is an established inner session.
//
// It behaves as the stream did — the same io.ReadWriteCloser the bridge expects —
// with the same half-close and abort semantics, so nothing downstream has to know
// it is wrapped.
type Conn struct {
	*tls.Conn

	// stream is the carrier, kept so a reason code can still reach the relay.
	stream io.ReadWriteCloser

	// Peer is the verified identity at the far end.
	Peer ca.Identity
}

// Reset aborts the underlying stream with a reason.
//
// Delegated rather than inherited: tls.Conn has no notion of a reason code, and
// without this the bridge would fall back to a plain Close and every abort would
// arrive at the operator as an unexplained disconnection. The reason codes are
// the difference between "you may not" and "it is down", so they are worth
// carrying through the extra layer.
func (c *Conn) Reset(r proto.Reason) error {
	if rs, ok := c.stream.(interface{ Reset(proto.Reason) error }); ok {
		return rs.Reset(r)
	}
	return c.Conn.Close()
}

// Client establishes the inner session from the operator's end.
//
// expect is the identity the operator was authorized to reach. Verifying it is
// what stops a relay from answering on the endpoint's behalf: a relay can route
// the stream anywhere it likes, and this is the check that notices.
func Client(ctx context.Context, stream io.ReadWriteCloser, id *identity.Identity, expect ca.Identity) (*Conn, error) {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{id.Certificate},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPN},

		// Verification is replaced here, not skipped.
		//
		// Identity in this system lives in a URI SAN (sar://device/...), which
		// Go's hostname verification does not understand — it checks DNS names
		// and IP addresses. Leaving the default on would fail every handshake;
		// leaving it off without VerifyPeerCertificate would accept any
		// certificate at all. VerifyConnection below does the full job: chain
		// verification against this deployment's authority, then an exact
		// identity match.
		InsecureSkipVerify: true,
		VerifyConnection:   verifyPeer(id.CAPool, expect, x509.ExtKeyUsageServerAuth),
	}

	tc := tls.Client(streamConn{stream}, cfg)
	return finish(ctx, tc, stream, expect)
}

// Server establishes the inner session from the agent's end.
//
// expect is the operator named in the grant. A client certificate is required:
// an inner session that accepted an anonymous peer would authenticate nobody and
// leave the captured-grant hole open.
func Server(ctx context.Context, stream io.ReadWriteCloser, id *identity.Identity, expect ca.Identity) (*Conn, error) {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{id.Certificate},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPN},

		// Required, not optional. See the package doc: proving possession of the
		// operator's key is what makes a captured grant useless to a relay.
		ClientAuth: tls.RequireAnyClientCert,

		// RequireAnyClientCert rather than RequireAndVerifyClientCert because the
		// verification that matters is not "signed by the authority" but "is this
		// exact identity", and that is done in VerifyConnection along with the
		// chain. Using the built-in verifier as well would check the chain twice
		// and still not check the identity.
		VerifyConnection: verifyPeer(id.CAPool, expect, x509.ExtKeyUsageClientAuth),
	}

	tc := tls.Server(streamConn{stream}, cfg)
	return finish(ctx, tc, stream, expect)
}

// finish completes the handshake under a deadline and confirms the negotiated
// protocol.
func finish(ctx context.Context, tc *tls.Conn, stream io.ReadWriteCloser, expect ca.Identity) (*Conn, error) {
	hsCtx, cancel := context.WithTimeout(ctx, proto.HandshakeTimeout)
	defer cancel()

	if err := tc.HandshakeContext(hsCtx); err != nil {
		// Both errors stay in the chain. A caller needs to tell "the handshake
		// did not complete" from "it completed against the wrong peer": the first
		// is a network or version problem, the second means something routed this
		// stream somewhere it should not have gone, and reporting them alike would
		// hide the one worth investigating.
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	// Belt and braces. Both ends offer exactly one protocol, so a mismatch should
	// be impossible — which is why reaching it would mean something more
	// interesting than a version skew.
	if state := tc.ConnectionState(); state.NegotiatedProtocol != ALPN {
		_ = tc.Close()
		return nil, fmt.Errorf("%w: negotiated %q, want %q",
			ErrHandshake, state.NegotiatedProtocol, ALPN)
	}

	return &Conn{Conn: tc, stream: stream, Peer: expect}, nil
}

// verifyPeer builds the verification callback: chain first, then identity.
//
// The order matters for the same reason it does when verifying a grant. Nothing
// a certificate asserts about itself means anything until the chain is checked,
// so the identity is read only after the authority has vouched for it.
func verifyPeer(roots *x509.CertPool, expect ca.Identity, usage x509.ExtKeyUsage) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("%w: peer presented no certificate", ErrPeerIdentity)
		}

		leaf := state.PeerCertificates[0]

		intermediates := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}

		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{usage},
		}); err != nil {
			return fmt.Errorf("%w: %v", ErrPeerIdentity, err)
		}

		// Only now is anything the certificate says worth reading.
		got, err := ca.IdentityOf(leaf)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrPeerIdentity, err)
		}
		if got != expect {
			// The certificate is genuine and belongs to somebody else. That is
			// the interesting failure: a relay routing the stream to a different
			// endpoint than the grant authorized, or answering as one itself.
			return fmt.Errorf("%w: presented %s, expected %s", ErrPeerIdentity, got, expect)
		}
		return nil
	}
}

// streamConn adapts a multiplexed stream to net.Conn for crypto/tls.
//
// A stream is an io.ReadWriteCloser with no addresses and no deadlines, and
// crypto/tls wants a net.Conn. The missing pieces are supplied honestly rather
// than plausibly:
//
//   - The addresses describe the relayed path, because there is no socket here
//     to name and inventing one would mislead anything that logged it.
//   - The deadline methods report success without doing anything, which is safe
//     only because every use in this package is bounded some other way:
//     HandshakeContext cancels the handshake through the context, and after that
//     the stream's own lifetime is bounded by the grant's expiry, the byte
//     budget, and revocation. A deadline that silently did nothing on a path
//     that *relied* on it would be a hang waiting to happen, so this must be
//     re-examined if this adapter is ever used elsewhere.
type streamConn struct {
	rw io.ReadWriteCloser
}

func (s streamConn) Read(b []byte) (int, error)  { return s.rw.Read(b) }
func (s streamConn) Write(b []byte) (int, error) { return s.rw.Write(b) }
func (s streamConn) Close() error                { return s.rw.Close() }

func (s streamConn) LocalAddr() net.Addr  { return relayedAddr{} }
func (s streamConn) RemoteAddr() net.Addr { return relayedAddr{} }

func (s streamConn) SetDeadline(time.Time) error      { return nil }
func (s streamConn) SetReadDeadline(time.Time) error  { return nil }
func (s streamConn) SetWriteDeadline(time.Time) error { return nil }

// relayedAddr names the path rather than pretending to be a socket address.
type relayedAddr struct{}

func (relayedAddr) Network() string { return "sar-stream" }
func (relayedAddr) String() string  { return "relayed" }
