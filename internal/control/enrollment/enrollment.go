package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// Token lifetime and certificate lifetime defaults.
//
// An enrollment token is short-lived because it is the one credential that can
// create an identity: the window in which a leaked token is useful should be
// measured against how long it takes a human to install an agent, not how long
// it is convenient to leave one lying around.
const (
	// DefaultTokenTTL is how long a freshly minted enrollment token remains
	// usable.
	DefaultTokenTTL = 1 * time.Hour

	// DefaultCertTTL is how long an issued identity certificate is valid.
	//
	// Short by PKI standards, on purpose. Certificate lifetime is the backstop
	// when revocation does not reach a peer, so a shorter life means a smaller
	// window in which a stolen certificate still works. Renewal is not yet
	// automatic, which is why this is not shorter still.
	DefaultCertTTL = 30 * 24 * time.Hour

	// tokenBytes is the entropy in an enrollment token. 256 bits: the token is
	// the only thing standing between an attacker and an enrolled identity, and
	// it is never rate-limited by a human typing it.
	tokenBytes = 32
)

// Errors surfaced to callers.
var (
	// ErrInvalidCSR means the certificate request was malformed or unusable.
	ErrInvalidCSR = errors.New("enrollment: invalid certificate request")
)

// Service issues enrollment tokens and turns them into certificates.
type Service struct {
	store *storage.Store
	ca    *ca.CA

	// grantPub is the public half of the grant signing key, handed to every peer
	// at enrollment.
	//
	// Distributing it here rather than through a separate channel is what lets an
	// agent verify grants offline: by the time it can connect at all, it already
	// holds the key it needs to check what it is asked to do.
	grantPub ed25519.PublicKey

	tokenTTL time.Duration
	certTTL  time.Duration
}

// New creates an enrollment service.
func New(store *storage.Store, authority *ca.CA, grantPub ed25519.PublicKey) *Service {
	return &Service{
		store:    store,
		ca:       authority,
		grantPub: grantPub,
		tokenTTL: DefaultTokenTTL,
		certTTL:  DefaultCertTTL,
	}
}

// IssueToken mints a single-use enrollment token for an identity.
//
// The token is returned to the caller and immediately forgotten: only its hash
// is stored. If it is lost before it reaches the person installing the agent, it
// cannot be recovered and a new one must be issued — which is the correct
// behaviour for a credential, and the reason this returns it exactly once.
func (s *Service) IssueToken(role ca.Role, id string) (string, error) {
	if id == "" {
		return "", errors.New("enrollment: identity is required")
	}

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	// URL-safe and unpadded, so the token survives being pasted into a command
	// line, a config file, or a URL without escaping.
	token := base64.RawURLEncoding.EncodeToString(raw)

	now := time.Now()
	rec := storage.Token{
		Hash:      storage.HashToken(token),
		Role:      string(role),
		ID:        id,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.tokenTTL),
	}
	if err := s.store.PutToken(rec); err != nil {
		return "", err
	}
	return token, nil
}

// Result is what a successful enrollment produces.
type Result struct {
	// CertificatePEM is the newly issued identity certificate.
	CertificatePEM []byte
	// CAPEM is the authority certificate, so the enrolling peer can verify the
	// relay it is about to connect to.
	CAPEM []byte
	// Identity is what the certificate asserts.
	Identity ca.Identity
	// NotAfter is when the certificate stops being valid.
	NotAfter time.Time
	// GrantPublicKey verifies grants. An agent cannot enforce authorization
	// without it, so it is delivered with the certificate rather than fetched
	// later.
	GrantPublicKey ed25519.PublicKey
}

// Enroll consumes a token and issues a certificate for the identity it names.
//
// The identity comes from the **token**, never from the certificate request. A
// request is written by the party asking for a certificate, so anything in it is
// a claim; if a requester could name itself, a token issued for one device would
// enroll any device the holder chose. The only thing taken from the request is
// the public key.
func (s *Service) Enroll(token string, csrPEM []byte) (*Result, error) {
	// Consumed first, and atomically. A failure after this point burns the token,
	// which is the safe direction: a lost enrollment costs an operator one more
	// token, while a reusable one costs an identity.
	rec, err := s.store.ConsumeToken(token)
	if err != nil {
		return nil, err
	}

	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, err
	}

	id := ca.Identity{Role: ca.Role(rec.Role), ID: rec.ID}
	certPEM, err := s.ca.Sign(csr, id, s.certTTL)
	if err != nil {
		return nil, err
	}

	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, err
	}

	// Recording the serial is what makes re-enrollment replace an identity rather
	// than duplicate it: a previously issued certificate no longer matches the
	// serial on file.
	if err := s.store.PutRecord(storage.Record{
		ID:         rec.ID,
		Role:       rec.Role,
		EnrolledAt: time.Now(),
		SerialHex:  cert.SerialNumber.Text(16),
	}); err != nil {
		return nil, err
	}

	return &Result{
		CertificatePEM: certPEM,
		CAPEM:          s.ca.CertPEM(),
		Identity:       id,
		NotAfter:       cert.NotAfter,
		GrantPublicKey: s.grantPub,
	}, nil
}

// VerifyEnrolled checks that a presented certificate belongs to a live identity.
//
// A valid signature from the authority is not sufficient on its own. A
// certificate can be signed and still be worthless: the identity may have been
// revoked, or the certificate may have been superseded by a re-enrollment. TLS
// proves the chain; this proves the identity is still one the control plane
// recognises.
func (s *Service) VerifyEnrolled(cert *x509.Certificate) (ca.Identity, error) {
	id, err := ca.IdentityOf(cert)
	if err != nil {
		return ca.Identity{}, err
	}

	rec, err := s.store.Lookup(string(id.Role), id.ID)
	if err != nil {
		return ca.Identity{}, err
	}

	if rec.SerialHex != cert.SerialNumber.Text(16) {
		// Signed by us, for this identity, but superseded. Accepting it would
		// mean a re-enrolled device could still be impersonated with its old
		// certificate.
		return ca.Identity{}, fmt.Errorf("%w: certificate superseded by a later enrollment", storage.ErrNotEnrolled)
	}
	return id, nil
}

func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: not a CERTIFICATE REQUEST block", ErrInvalidCSR)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	return csr, nil
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("enrollment: issued certificate is not valid PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
