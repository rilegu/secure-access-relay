package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
)

// TLS configuration for the data plane.
//
// Every setting here is chosen rather than defaulted, because the defaults are
// designed for the public web and this is not the public web: there is exactly
// one certificate authority, exactly two kinds of peer, and no reason to accept
// anything older than the current protocol version.

// MinTLSVersion is the floor for every connection.
//
// TLS 1.3 only. Older versions bring cipher-suite negotiation, renegotiation,
// and downgrade dances that exist for compatibility with software this project
// does not need to talk to. Both ends are built from this repository, so there is
// no compatibility argument for accepting less.
const MinTLSVersion = tls.VersionTLS13

// ServerTLS builds a configuration for the relay's listener.
//
// Client certificates are required and verified. Not optional, not
// verify-if-given: a connection without a certificate from this authority is
// refused during the handshake, before any protocol frame is read. That is what
// makes an unenrolled peer unable to reach the framing layer at all.
func ServerTLS(cert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   MinTLSVersion,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
}

// ClientTLS builds a configuration for an agent or operator.
//
// The root pool contains only this deployment's authority, so a certificate from
// any public CA is worthless here. serverName must match a SAN on the relay's
// certificate; it is what stops a peer that can redirect traffic from presenting
// a different — but still validly signed — server certificate.
func ClientTLS(cert tls.Certificate, roots *x509.CertPool, serverName string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   serverName,
		MinVersion:   MinTLSVersion,
	}
}

// DialTLS opens a framed connection protected by TLS.
//
// The handshake is completed here rather than lazily on first write, so that a
// certificate problem surfaces as a connection error with a usable message
// instead of as a confusing failure in the middle of the protocol handshake.
func DialTLS(ctx context.Context, addr string, cfg *tls.Config) (*Conn, error) {
	d := &tls.Dialer{Config: cfg}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	return NewConn(nc), nil
}

// CompleteHandshake forces the TLS handshake to finish.
//
// Go completes a TLS handshake lazily, on the first read or write. That means a
// freshly accepted connection has no peer certificate yet: ConnectionState
// reports an empty chain, and code that inspects it sees an authenticated peer as
// an anonymous one.
//
// Every path that authenticates a peer must call this first. It is separate from
// PeerCertificate rather than folded into it so that the deadline is explicit —
// a peer that opens a connection and never handshakes must not be able to hold
// resources indefinitely.
func CompleteHandshake(ctx context.Context, c net.Conn) error {
	tc, ok := c.(*tls.Conn)
	if !ok {
		return fmt.Errorf("transport: connection is not TLS")
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}
	return nil
}

// PeerCertificate returns the certificate the far end presented.
//
// Call CompleteHandshake first: before the handshake finishes there is no peer
// certificate to return, and this reports that as an error rather than as an
// absent identity.
//
// It returns an error for a connection that is not TLS, rather than nil, so that
// a caller which forgets to check cannot silently treat an unauthenticated
// connection as an authenticated one.
func PeerCertificate(c net.Conn) (*x509.Certificate, error) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("transport: connection is not TLS")
	}
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		// Unreachable with RequireAndVerifyClientCert, which is exactly why it is
		// worth failing loudly: reaching it means the TLS configuration changed.
		return nil, fmt.Errorf("transport: peer presented no certificate")
	}
	return state.PeerCertificates[0], nil
}

// NetConn exposes the underlying connection, for peer certificate inspection.
func (c *Conn) NetConn() net.Conn { return c.nc }
