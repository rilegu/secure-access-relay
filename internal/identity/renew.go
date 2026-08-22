package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rilegu/secure-access-relay/internal/keystore"
)

// RenewBefore is how much remaining life triggers a renewal.
//
// Certificates last thirty days, so this renews at the two-thirds mark and
// leaves ten days of margin. The margin is the point: an endpoint that is off
// for a week, or a control plane that is down for a few days, must still have
// room to renew before the certificate it is renewing stops being accepted.
// Renewing at the last moment would turn any outage near the expiry date into a
// fleet that needs re-enrolling by hand.
const RenewBefore = 10 * 24 * time.Hour

// RenewCheckInterval is how often a long-running peer reconsiders.
//
// An agent that holds one session for weeks never reconnects, so renewal cannot
// be driven by the reconnect loop alone. Hourly is far more often than needed
// for a ten-day window and costs one comparison against a stored time.
const RenewCheckInterval = time.Hour

// DueForRenewal reports whether a certificate is close enough to expiry to
// replace.
//
// A certificate that has *already* expired is not renewable: the control plane
// authenticates a renewal with the certificate being replaced, and TLS will
// refuse to present an expired one. That case needs re-enrollment, and saying so
// here keeps the caller from retrying something that cannot succeed.
func (i *Identity) DueForRenewal(now time.Time) bool {
	if i.NotAfter.IsZero() {
		return false
	}
	if !now.Before(i.NotAfter) {
		return false // already expired; renewal cannot authenticate
	}
	return i.NotAfter.Sub(now) < RenewBefore
}

// Expired reports whether the certificate can no longer be used at all, which is
// the state that requires a human and an enrollment token.
func (i *Identity) Expired(now time.Time) bool {
	return !i.NotAfter.IsZero() && !now.Before(i.NotAfter)
}

// Renew obtains a fresh certificate using the one this identity already holds,
// and replaces the stored credentials with it.
//
// # Why the key is rotated too
//
// A renewal that reused the key would refresh only the expiry date, leaving one
// key in place for the life of the deployment. Since a new certificate has to be
// written anyway, generating a new key alongside it costs nothing and bounds how
// long any single key is in use to the certificate lifetime.
//
// # Why losing the write is survivable
//
// The control plane records a renewed certificate as *pending* and keeps
// accepting the current one until the new one is actually presented. So a
// failure anywhere in this function — the request, the key write, the
// certificate write, a power loss between them — leaves the peer still able to
// authenticate with what it had, and the next attempt simply issues another.
// That property is what makes unattended renewal safe; see ADR-0016.
func Renew(ctx context.Context, current *Identity, controlAddr, dir string) (*Identity, error) {
	if current == nil {
		return nil, ErrNotEnrolled
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	csrPEM, err := makeCSR(pub, priv)
	if err != nil {
		return nil, err
	}

	resp, err := postRenew(ctx, current, controlAddr, csrPEM)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Verified before anything is overwritten. A control plane that returned a
	// certificate this key does not match would otherwise replace working
	// credentials with a pair that cannot be loaded, and the peer would discover
	// it at the next restart rather than now.
	if _, err := tls.X509KeyPair([]byte(resp.Certificate), keyPEM); err != nil {
		return nil, fmt.Errorf("renewed certificate does not match the new key: %w", err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}

	// Same order as enrollment: key first, through the keystore, so an
	// interruption leaves a protected key without a certificate rather than a
	// certificate with no key to match it. Neither half is usable on its own, and
	// the old pair keeps working either way because the control plane has not
	// superseded it.
	if _, err := keystore.Save(filepath.Join(dir, keyFile), keyPEM); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), []byte(resp.Certificate), 0o600); err != nil {
		return nil, fmt.Errorf("write renewed certificate: %w", err)
	}
	if resp.CA != "" {
		if err := os.WriteFile(filepath.Join(dir, caFile), []byte(resp.CA), 0o600); err != nil {
			return nil, fmt.Errorf("write authority certificate: %w", err)
		}
	}
	if resp.GrantKey != "" {
		if err := os.WriteFile(filepath.Join(dir, grantKeyFile), []byte(resp.GrantKey), 0o600); err != nil {
			return nil, fmt.Errorf("write grant verification key: %w", err)
		}
	}

	return Load(dir)
}

// RenewIfDue renews when the certificate is close to expiry, and reports whether
// it did.
//
// It returns the identity to keep using either way, so a caller can assign the
// result unconditionally rather than branching. A renewal that fails is reported
// but is not fatal: the existing certificate is still valid — that is what "due"
// means — and the next check will try again.
func RenewIfDue(ctx context.Context, current *Identity, controlAddr, dir string) (*Identity, bool, error) {
	if current == nil || controlAddr == "" || !current.DueForRenewal(time.Now()) {
		return current, false, nil
	}
	renewed, err := Renew(ctx, current, controlAddr, dir)
	if err != nil {
		return current, false, err
	}
	return renewed, true, nil
}

// postRenew calls the control plane, authenticating with the certificate being
// replaced.
func postRenew(ctx context.Context, current *Identity, controlAddr string, csrPEM []byte) (*enrollResponse, error) {
	body, err := json.Marshal(map[string]string{"csr": string(csrPEM)})
	if err != nil {
		return nil, err
	}

	serverName := current.ServerName
	if serverName == "" {
		serverName = hostOf(controlAddr)
	}

	// The authority this peer enrolled with is the only root, and the current
	// certificate is the credential. There is no path here that skips
	// verification: a renewal is where an attacker would most like to be handed a
	// certificate, and trusting an unverified server would hand them one.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{current.Certificate},
				RootCAs:      current.CAPool,
				ServerName:   serverName,
				MinVersion:   tls.VersionTLS13,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+controlAddr+"/v1/renew", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request renewal: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil && resp.StatusCode == http.StatusOK {
		return nil, fmt.Errorf("decode renewal response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return nil, fmt.Errorf("renewal refused: %s", out.Error)
		}
		return nil, fmt.Errorf("renewal refused: status %d", resp.StatusCode)
	}
	if out.Certificate == "" {
		return nil, fmt.Errorf("renewal returned no certificate")
	}
	return &out, nil
}

// hostOf strips the port from an address, for use as a TLS server name when
// enrollment did not record one.
func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
