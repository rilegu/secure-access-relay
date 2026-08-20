package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

// Role distinguishes the two kinds of identity this authority issues.
//
// The role is carried inside the certificate rather than alongside it, so a peer
// cannot present a device certificate and then claim to be an operator. What the
// certificate says is what the peer is.
type Role string

const (
	// RoleDevice is an endpoint agent.
	RoleDevice Role = "device"
	// RoleOperator is a client that reaches resources on devices.
	RoleOperator Role = "operator"
)

// identityScheme is the URI scheme used in the certificate's SAN.
//
// Identity lives in a URI SAN rather than the Common Name because CN is a
// free-text field with no agreed structure: two implementations can parse the
// same CN differently, and TLS stacks have been deprecating its use as an
// identity for years. A URI is unambiguous — sar://device/panel-lab-01 has
// exactly one reading.
const identityScheme = "sar"

// Identity is who a certificate says its holder is.
type Identity struct {
	Role Role
	ID   string
}

// URI renders the identity as it appears in a certificate SAN.
func (i Identity) URI() *url.URL {
	return &url.URL{Scheme: identityScheme, Host: string(i.Role), Path: "/" + i.ID}
}

// String renders the identity for logs and audit records.
func (i Identity) String() string { return string(i.Role) + "/" + i.ID }

// ErrNoIdentity means a certificate carried no usable identity SAN.
var ErrNoIdentity = errors.New("ca: certificate has no identity")

// IdentityOf extracts the identity a certificate asserts.
//
// A certificate with no identity URI, or with more than one, is rejected rather
// than guessed at. Ambiguity in an identity is worse than its absence: a caller
// that has to choose between two identities will eventually choose the one an
// attacker wanted.
func IdentityOf(cert *x509.Certificate) (Identity, error) {
	var found []Identity
	for _, u := range cert.URIs {
		if u.Scheme != identityScheme {
			continue
		}
		role := Role(u.Host)
		if role != RoleDevice && role != RoleOperator {
			continue
		}
		id := strings.TrimPrefix(u.Path, "/")
		if id == "" {
			continue
		}
		found = append(found, Identity{Role: role, ID: id})
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return Identity{}, ErrNoIdentity
	default:
		return Identity{}, fmt.Errorf("%w: certificate asserts %d identities", ErrNoIdentity, len(found))
	}
}

// CA is a certificate authority that can sign certificate requests.
type CA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	der  []byte
}

// Create generates a new authority.
//
// Ed25519 throughout: keys and signatures are small, signing is fast, there are
// no parameters to choose badly, and it is the same algorithm the grant format
// uses, so the project has one signature primitive rather than two.
func Create(commonName string, ttl time.Duration) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute), // tolerate small clock skew at startup
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// This authority signs leaves and nothing else. Without the constraint a
		// leaf could in principle be used to sign further certificates.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("create ca certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse ca certificate: %w", err)
	}
	return &CA{cert: cert, key: priv, der: der}, nil
}

// Load restores an authority from PEM.
func Load(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("ca: certificate PEM is missing or not a CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("ca: certificate is not a certificate authority")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, errors.New("ca: key PEM is missing or not a PRIVATE KEY block")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ca: key is %T, want ed25519", key)
	}
	return &CA{cert: cert, key: ed, der: certBlock.Bytes}, nil
}

// CertPEM returns the authority certificate.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// KeyPEM returns the authority private key.
//
// The caller is responsible for protecting it. This package deliberately does no
// file I/O, so there is exactly one place in the codebase that decides where a
// private key is written and how.
func (c *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return nil, fmt.Errorf("marshal ca key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Certificate returns the authority certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// Pool returns a certificate pool trusting only this authority.
//
// Only this authority: peers are verified against a pool containing one root,
// not against the host's trust store. A device certificate must come from this
// deployment, and a certificate from any public CA is worthless here.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// Sign issues a leaf certificate for a certificate request.
//
// The identity is supplied by the caller and is **not** read from the request.
// A certificate request is written by the party asking for a certificate, so
// anything inside it is a request rather than a fact; letting a requester choose
// its own identity would make enrollment meaningless. The only thing taken from
// the request is the public key, and even that is checked.
func (c *CA) Sign(csr *x509.CertificateRequest, id Identity, ttl time.Duration) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		// Proves the requester holds the private key for the public key it sent.
		return nil, fmt.Errorf("csr signature: %w", err)
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("ca: csr public key is %T, want ed25519", csr.PublicKey)
	}
	if id.ID == "" {
		return nil, errors.New("ca: refusing to sign a certificate with an empty identity")
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: id.String()},
		URIs:         []*url.URL{id.URI()},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Both usages on every leaf: an agent is a TLS client to the relay, and
		// the relay is a TLS server to it, but the relay also dials nothing and
		// an operator is only ever a client. Issuing both keeps one code path,
		// and the identity in the SAN is what authorizes, not the usage bits.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// SignServer issues a certificate for the relay's TLS listener.
//
// Separate from Sign because a server certificate is validated by hostname
// rather than by identity URI, and conflating the two would mean a device
// certificate could be presented as a server certificate.
func (c *CA) SignServer(csr *x509.CertificateRequest, dnsNames []string, ips []string, ttl time.Duration) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	parsedIPs := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil {
			parsedIPs = append(parsedIPs, ip)
		}
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sar-server"},
		DNSNames:              dnsNames,
		IPAddresses:           parsedIPs,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign server certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// randomSerial returns a serial number with enough entropy that two independent
// issuers would not collide.
//
// Serials must be unpredictable, not merely unique: a predictable serial has
// historically been an ingredient in certificate forgery against weak signature
// algorithms.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

// IssueServerCertificate mints a TLS certificate for a listener.
//
// The key is generated here and kept only in memory: the relay's server key is
// re-issued on every start rather than persisted. A key that never reaches disk
// cannot be stolen from disk, and re-issuing costs microseconds. The trade is
// that restarting the relay invalidates nothing a client caches, which is fine
// because clients verify against the authority rather than pinning the leaf.
func (c *CA) IssueServerCertificate(hosts []string, ttl time.Duration) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}

	var dnsNames []string
	var ips []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, h)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sar-server"},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sign server certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		// The authority certificate is included in the chain so that an enrolling
		// peer, which has only a fingerprint and no trust store yet, can find and
		// match it. See internal/control/enrollment.Code.
		Certificate: [][]byte{der, c.der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}
