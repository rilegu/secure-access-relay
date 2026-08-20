// Package identity manages a peer's own key, certificate, and trust anchor.
//
// It is the endpoint-side counterpart to the control plane's enrollment service:
// it generates a key that never leaves the machine, asks for a certificate, and
// stores the result so the peer can authenticate on every later connection.
//
// # What this package must never do
//
//   - It must never transmit a private key. The key is generated locally and only
//     the public half is ever sent, inside a certificate request.
//   - It must never write a key except through the keystore, which is the one
//     place that decides how a key is protected at rest.
package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/enrollment"
	"github.com/rilegu/secure-access-relay/internal/keystore"
)

// File names within the state directory.
const (
	keyFile      = "identity.key"
	certFile     = "identity.crt"
	caFile       = "ca.crt"
	metaFile     = "identity.json"
	grantKeyFile = "grant-signing.pub"
)

// ErrNotEnrolled means this peer has no identity yet.
var ErrNotEnrolled = errors.New("identity: not enrolled")

// Identity is a peer's own credentials plus the anchor it verifies others with.
type Identity struct {
	// Certificate is the TLS certificate presented to peers.
	Certificate tls.Certificate

	// CAPool trusts exactly one authority: the one that enrolled this peer.
	CAPool *x509.CertPool

	// ID is what this peer's certificate asserts about itself.
	ID ca.Identity

	// ServerName is the name to verify the relay's certificate against.
	ServerName string

	// Protection records how the private key is protected at rest, so the peer
	// can state it at startup rather than leaving it to be assumed.
	Protection keystore.Protection

	// NotAfter is when the certificate expires.
	NotAfter time.Time

	// GrantKey verifies grants. An agent that authenticates but cannot verify
	// grants would have to trust the relay's word about what is authorized,
	// which is exactly what invariant 2 forbids.
	GrantKey ed25519.PublicKey
}

type meta struct {
	ServerName string `json:"server_name"`
}

// Load restores an identity from a state directory.
func Load(dir string) (*Identity, error) {
	keyPEM, protection, err := keystore.Load(filepath.Join(dir, keyFile))
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, ErrNotEnrolled
		}
		return nil, err
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotEnrolled
		}
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	caPEM, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotEnrolled
		}
		return nil, fmt.Errorf("read authority certificate: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}
	leaf, err := leafOf(certPEM)
	if err != nil {
		return nil, err
	}
	cert.Leaf = leaf

	id, err := ca.IdentityOf(leaf)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("identity: stored authority certificate is unusable")
	}

	var m meta
	if b, err := os.ReadFile(filepath.Join(dir, metaFile)); err == nil {
		_ = json.Unmarshal(b, &m)
	}

	// The grant key is optional on load so that an identity enrolled before
	// grants existed still loads. A component that needs it checks for itself
	// rather than every caller being forced to handle its absence here.
	var grantKey ed25519.PublicKey
	if b, err := os.ReadFile(filepath.Join(dir, grantKeyFile)); err == nil {
		if raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); derr == nil &&
			len(raw) == ed25519.PublicKeySize {
			grantKey = ed25519.PublicKey(raw)
		}
	}

	return &Identity{
		Certificate: cert,
		CAPool:      pool,
		ID:          id,
		ServerName:  m.ServerName,
		Protection:  protection,
		NotAfter:    leaf.NotAfter,
		GrantKey:    grantKey,
	}, nil
}

// Enroll obtains a certificate using an enrollment code and stores the result.
//
// The private key is generated here and never leaves this machine — only a
// certificate request containing the public half is transmitted. That is what
// makes a compromised control plane unable to impersonate an endpoint it
// enrolled: it never held the key.
func Enroll(ctx context.Context, code enrollment.Code, dir string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	csrPEM, err := makeCSR(pub, priv)
	if err != nil {
		return nil, err
	}

	resp, err := postEnroll(ctx, code, csrPEM)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}

	// The key is written first and through the keystore, so that a failure
	// afterwards leaves an unusable but protected key rather than a certificate
	// with no key to match it.
	if _, err := keystore.Save(filepath.Join(dir, keyFile), keyPEM); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), []byte(resp.Certificate), 0o600); err != nil {
		return nil, fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, caFile), []byte(resp.CA), 0o600); err != nil {
		return nil, fmt.Errorf("write authority certificate: %w", err)
	}
	m, _ := json.Marshal(meta{ServerName: code.ServerName})
	if err := os.WriteFile(filepath.Join(dir, metaFile), m, 0o600); err != nil {
		return nil, fmt.Errorf("write identity metadata: %w", err)
	}
	if resp.GrantKey != "" {
		if err := os.WriteFile(filepath.Join(dir, grantKeyFile), []byte(resp.GrantKey), 0o600); err != nil {
			return nil, fmt.Errorf("write grant verification key: %w", err)
		}
	}

	return Load(dir)
}

func makeCSR(pub ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
	// The subject is deliberately empty of identity. Whatever a requester writes
	// here is ignored by the authority, which takes the identity from the
	// enrollment token instead; leaving it blank makes that explicit rather than
	// implying the request has a say.
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "enrollment-request"},
		SignatureAlgorithm: x509.PureEd25519,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return nil, fmt.Errorf("create certificate request: %w", err)
	}
	_ = pub
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

type enrollResponse struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
	Identity    string `json:"identity"`
	NotAfter    string `json:"not_after"`
	GrantKey    string `json:"grant_key"`
	Error       string `json:"error"`
}

// postEnroll sends the request, verifying the server against the fingerprint in
// the enrollment code.
//
// This is where the bootstrap problem is solved. The peer has no trust anchor
// yet, so it cannot verify the server the normal way. Instead it pins the
// authority fingerprint carried in the code: the chain is checked by hand, and
// the token is only sent once the server has proved it belongs to the authority
// the code names.
func postEnroll(ctx context.Context, code enrollment.Code, csrPEM []byte) (*enrollResponse, error) {
	var verifyErr error

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				// Verification is done in the callback below instead of by the
				// standard path, because the anchor is a fingerprint rather than a
				// pool. This is the one place in the codebase where that is
				// acceptable, and only because the callback is stricter than the
				// default: it requires the chain to end at one specific certificate.
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					verifyErr = verifyAgainstFingerprint(rawCerts, code)
					return verifyErr
				},
			},
		},
	}

	body, err := json.Marshal(map[string]string{"token": code.Token, "csr": string(csrPEM)})
	if err != nil {
		return nil, err
	}

	url := "https://" + code.Addr + "/v1/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if verifyErr != nil {
			return nil, fmt.Errorf("control plane verification failed: %w", verifyErr)
		}
		return nil, fmt.Errorf("enrollment request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode enrollment response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return nil, fmt.Errorf("enrollment refused: %s", out.Error)
		}
		return nil, fmt.Errorf("enrollment refused: status %d", resp.StatusCode)
	}
	if out.Certificate == "" || out.CA == "" {
		return nil, errors.New("enrollment response is missing a certificate")
	}
	return &out, nil
}

// verifyAgainstFingerprint checks that the presented chain ends at the authority
// named by the enrollment code, and that the leaf is valid for it.
func verifyAgainstFingerprint(rawCerts [][]byte, code enrollment.Code) error {
	if len(rawCerts) == 0 {
		return errors.New("server presented no certificate")
	}

	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse server certificate: %w", err)
		}
		certs = append(certs, c)
	}

	// The authority must be in the presented chain and must match the pinned
	// fingerprint exactly.
	var authority *x509.Certificate
	for _, c := range certs {
		if c.IsCA && enrollment.VerifyFingerprint(c, code.CAFingerprint) {
			authority = c
			break
		}
	}
	if authority == nil {
		return errors.New("server certificate does not chain to the authority named by the enrollment code")
	}

	pool := x509.NewCertPool()
	pool.AddCert(authority)

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if code.ServerName != "" {
		opts.DNSName = code.ServerName
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}
	return nil
}

func leafOf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("identity: stored certificate is not a CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}
