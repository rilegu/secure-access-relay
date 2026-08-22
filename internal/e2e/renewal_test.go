package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rilegu/secure-access-relay/internal/ca"
	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/identity"
	"github.com/rilegu/secure-access-relay/internal/keystore"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// Certificate renewal.
//
// Certificates last thirty days. Without renewal a deployment goes dark on the
// thirtieth day — every endpoint at once, silently, with no symptom but agents
// that stop connecting. That is a resilience failure, not a missing convenience.
//
// The property that makes unattended renewal safe is that a renewed certificate
// is *pending* until it is used. Superseding at issue would mean an endpoint
// that failed to store what it was handed — a crash, a full disk, a power loss
// in the window between the response and the write — could never authenticate
// again and would need re-enrolling by hand. These tests pin that behaviour.

// TestRenewalIssuesAWorkingCertificate is the happy path.
func TestRenewalIssuesAWorkingCertificate(t *testing.T) {
	dep := newDeployment(t)

	original := dep.enrollIdentity(ca.RoleDevice, testDeviceID)
	oldSerial := original.Certificate.Leaf.SerialNumber.Text(16)

	renewed := dep.renew(original)
	newSerial := renewed.Certificate.Leaf.SerialNumber.Text(16)

	if newSerial == oldSerial {
		t.Fatal("renewal returned the same certificate")
	}
	if renewed.ID != original.ID {
		t.Fatalf("renewal changed the identity from %v to %v", original.ID, renewed.ID)
	}
	// Not "later than", because x509 expiry has second precision and a test
	// issues both inside one second. The property that matters is that renewal
	// never shortens the remaining life; in production, where time passes between
	// the two, it extends it.
	if renewed.Certificate.Leaf.NotAfter.Before(original.Certificate.Leaf.NotAfter) {
		t.Fatalf("renewal shortened the certificate life from %s to %s",
			original.Certificate.Leaf.NotAfter, renewed.Certificate.Leaf.NotAfter)
	}

	// It authenticates.
	if _, err := dep.enroll.VerifyEnrolled(renewed.Certificate.Leaf); err != nil {
		t.Fatalf("the renewed certificate was refused: %v", err)
	}
}

// TestOldCertificateWorksUntilTheNewOneIsUsed is the property that stops renewal
// bricking an endpoint.
//
// Between issue and the endpoint storing the result there is a window in which
// the endpoint still holds only the old certificate. If issuing superseded
// immediately, any failure in that window would be unrecoverable without a human
// and a new enrollment token — for every endpoint that hit it.
func TestOldCertificateWorksUntilTheNewOneIsUsed(t *testing.T) {
	dep := newDeployment(t)

	original := dep.enrollIdentity(ca.RoleDevice, testDeviceID)
	renewed := dep.renew(original)

	// The endpoint has not presented the new certificate yet, so the old one is
	// still its credential.
	if _, err := dep.enroll.VerifyEnrolled(original.Certificate.Leaf); err != nil {
		t.Fatalf("the old certificate stopped working before the new one was used: %v", err)
	}

	// Using the new one is the signal that the endpoint has it.
	if _, err := dep.enroll.VerifyEnrolled(renewed.Certificate.Leaf); err != nil {
		t.Fatalf("the renewed certificate was refused: %v", err)
	}

	// From that moment the old one is retired: leaving both valid would mean one
	// identity with two usable certificates for the rest of the month.
	if _, err := dep.enroll.VerifyEnrolled(original.Certificate.Leaf); err == nil {
		t.Fatal("the old certificate still works after the renewed one was used")
	}
}

// TestRenewalIsRecordedAsPendingUntilCollected checks what an administrator sees.
//
// "Issued but not collected" is a real state worth being able to observe: it is
// either a renewal in flight or an endpoint that failed to store what it was
// given and is still running on the old certificate.
func TestRenewalIsRecordedAsPendingUntilCollected(t *testing.T) {
	dep := newDeployment(t)

	original := dep.enrollIdentity(ca.RoleDevice, testDeviceID)
	renewed := dep.renew(original)

	before := dep.record(t, "device", testDeviceID)
	if before.PendingSerialHex == "" {
		t.Fatal("a renewed certificate was not recorded as pending")
	}
	if before.PendingIssuedAt == nil {
		t.Error("a pending renewal has no issue time")
	}

	if _, err := dep.enroll.VerifyEnrolled(renewed.Certificate.Leaf); err != nil {
		t.Fatalf("verify renewed: %v", err)
	}

	after := dep.record(t, "device", testDeviceID)
	if after.PendingSerialHex != "" {
		t.Fatal("the pending certificate was not cleared once it had been used")
	}
	if after.SerialHex != renewed.Certificate.Leaf.SerialNumber.Text(16) {
		t.Fatal("the renewed certificate was not promoted to current")
	}
}

// TestRevokedIdentityCannotRenew is the check that keeps renewal from being a
// way back in.
//
// Renewal is authenticated by the certificate being replaced. If a revoked
// identity could use its old certificate to mint a current one, revocation would
// last exactly until the endpoint next tried to renew.
func TestRevokedIdentityCannotRenew(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	id := dep.enrollIdentity(ca.RoleDevice, testDeviceID)
	if err := dep.store.Revoke("device", testDeviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	_, csrPEM := newCSR(t)
	if _, err := dep.enroll.Renew(id.Certificate.Leaf, csrPEM); err == nil {
		t.Fatal("a revoked identity renewed its certificate")
	}
}

// TestSupersededCertificateCannotRenew checks the other direction: an old
// certificate that has already been replaced cannot mint a new one.
func TestSupersededCertificateCannotRenew(t *testing.T) {
	dep := newDeployment(t)

	original := dep.enrollIdentity(ca.RoleDevice, testDeviceID)
	renewed := dep.renew(original)

	// Collect the renewal, which retires the original.
	if _, err := dep.enroll.VerifyEnrolled(renewed.Certificate.Leaf); err != nil {
		t.Fatalf("verify renewed: %v", err)
	}

	_, csrPEM := newCSR(t)
	if _, err := dep.enroll.Renew(original.Certificate.Leaf, csrPEM); err == nil {
		t.Fatal("a superseded certificate was able to renew")
	}
}

// TestRenewalCannotChangeIdentity is the check that a certificate request cannot
// smuggle in a different subject.
//
// The authority takes the identity from the verified certificate, never from the
// CSR. If it did not, any enrolled endpoint could mint a certificate for any
// other — including an operator certificate from a device one.
func TestRenewalCannotChangeIdentity(t *testing.T) {
	dep := newDeployment(t)

	device := dep.enrollIdentity(ca.RoleDevice, testDeviceID)

	// A certificate request that asks to become an operator called somebody else.
	_, csrPEM := newNamedCSR(t, "operator/usr_root")

	result, err := dep.enroll.Renew(device.Certificate.Leaf, csrPEM)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if result.Identity.Role != ca.RoleDevice || result.Identity.ID != testDeviceID {
		t.Fatalf("the certificate request changed the identity to %v", result.Identity)
	}
}

// TestRenewalOverHTTPUsesTheCertificateAsCredential exercises the real route,
// including that no token is needed.
func TestRenewalOverHTTPUsesTheCertificateAsCredential(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	dir := t.TempDir()
	original := dep.enrollToDir(t, ca.RoleDevice, testDeviceID, dir)

	renewed, err := identity.Renew(ctx, original, dep.controlAddr, dir)
	if err != nil {
		t.Fatalf("renew over http: %v", err)
	}
	if renewed.ID != original.ID {
		t.Fatalf("identity changed from %v to %v", original.ID, renewed.ID)
	}

	// The key was rotated, not just the certificate. Renewal has to write a new
	// certificate anyway, so rotating the key alongside it costs nothing and
	// bounds how long any one key is in use.
	oldKey, ok1 := original.Certificate.PrivateKey.(ed25519.PrivateKey)
	newKey, ok2 := renewed.Certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok1 || !ok2 {
		t.Fatal("expected ed25519 keys")
	}
	if bytes.Equal(oldKey, newKey) {
		t.Error("renewal reused the private key; it should be rotated with the certificate")
	}

	// Reloading from disk yields the renewed certificate, which is what proves it
	// was actually persisted rather than only returned.
	reloaded, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Certificate.Leaf.SerialNumber.Cmp(renewed.Certificate.Leaf.SerialNumber) != 0 {
		t.Fatal("the renewed certificate was not written to the state directory")
	}

	// And it is recorded.
	events, err := dep.store.QueryAudit(ctx, storage.AuditFilter{Event: audit.EventDeviceRenewed})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) == 0 {
		t.Error("a renewal left no audit record")
	}
}

// TestRenewalWithoutACertificateIsRefused checks the route cannot be used to
// obtain a first certificate.
func TestRenewalWithoutACertificateIsRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dep := newDeployment(t)
	dep.startControlPlane(ctx)

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true},
	}}
	resp, err := client.Post("https://"+dep.controlAddr+"/v1/renew", "application/json",
		strings.NewReader(`{"csr":""}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("renewal succeeded with no client certificate")
	}
}

// TestDueForRenewalWindow checks the decision that drives all of the above.
func TestDueForRenewalWindow(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name     string
		notAfter time.Time
		want     bool
	}{
		{"fresh", now.Add(30 * 24 * time.Hour), false},
		{"just outside the window", now.Add(identity.RenewBefore + time.Hour), false},
		{"inside the window", now.Add(identity.RenewBefore - time.Hour), true},
		{"nearly expired", now.Add(time.Minute), true},
		// An expired certificate cannot authenticate a renewal, so reporting it
		// as due would send the caller into a loop that can never succeed.
		{"already expired", now.Add(-time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := &identity.Identity{NotAfter: tc.notAfter}
			if got := id.DueForRenewal(now); got != tc.want {
				t.Fatalf("DueForRenewal = %v, want %v", got, tc.want)
			}
		})
	}
}

// renew issues a renewal through the service, as the HTTP route does.
func (d *deployment) renew(current *identity.Identity) *identity.Identity {
	d.t.Helper()

	priv, csrPEM := newCSR(d.t)
	result, err := d.enroll.Renew(current.Certificate.Leaf, csrPEM)
	if err != nil {
		d.t.Fatalf("renew: %v", err)
	}
	return d.identityFrom(result.CertificatePEM, priv)
}

// record reads an identity straight from the store, for assertions about state
// the API does not expose.
func (d *deployment) record(t *testing.T, role, id string) storage.Record {
	t.Helper()
	for _, r := range d.store.List(role) {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no %s record for %s", role, id)
	return storage.Record{}
}

// enrollToDir enrolls an identity and writes the credentials to a state
// directory in the layout identity.Load expects.
//
// Written directly rather than by replaying the pinned enrollment handshake: the
// handshake is covered elsewhere, and what this test needs is credentials on
// disk for a renewal to overwrite.
func (d *deployment) enrollToDir(t *testing.T, role ca.Role, id, dir string) *identity.Identity {
	t.Helper()

	token, err := d.enroll.IssueToken(role, id)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	priv, csrPEM := newCSR(t)
	result, err := d.enroll.Enroll(token, csrPEM)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := keystore.Save(filepath.Join(dir, "identity.key"), keyPEM); err != nil {
		t.Fatalf("store key: %v", err)
	}
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("identity.crt", result.CertificatePEM)
	write("ca.crt", d.authority.CertPEM())
	write("identity.json", []byte(`{"server_name":"127.0.0.1"}`))
	write("grant-signing.pub",
		[]byte(base64.StdEncoding.EncodeToString(d.issuer.PublicKey())))

	loaded, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("load written identity: %v", err)
	}
	return loaded
}

// newNamedCSR builds a certificate request that asks for a particular subject,
// so a test can check the subject is ignored.
func newNamedCSR(t *testing.T, commonName string) (ed25519.PrivateKey, []byte) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		SignatureAlgorithm: x509.PureEd25519,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
