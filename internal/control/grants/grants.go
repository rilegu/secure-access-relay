// Package grants issues signed, short-lived authorizations.
//
// A grant is the only thing that lets a stream be opened. It is produced here,
// after policy has said yes, and verified by the agent offline — so an agent
// never has to ask the control plane whether a stream is allowed.
//
// # What this package must never do
//
//   - It must never issue without a policy decision. Deciding is
//     internal/control/policy's job; this package signs what it was told.
//   - It must never write the signing key anywhere. The key arrives from the
//     keystore and stays in memory.
package grants

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/rilegu/secure-access-relay/internal/control/policy"
	"github.com/rilegu/secure-access-relay/internal/proto"
)

// Issuer signs grants with one key.
type Issuer struct {
	key   ed25519.PrivateKey
	keyID string
}

// NewIssuer creates an issuer.
//
// The key identifier travels inside every grant so that keys can be rotated
// without invalidating everything at once: a verifier holding several public
// keys picks the one the grant names.
func NewIssuer(key ed25519.PrivateKey, keyID string) (*Issuer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("grants: signing key is %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	if keyID == "" {
		return nil, errors.New("grants: key id is required")
	}
	return &Issuer{key: key, keyID: keyID}, nil
}

// PublicKey returns the verification key, which is distributed to agents at
// enrollment.
func (i *Issuer) PublicKey() ed25519.PublicKey {
	return i.key.Public().(ed25519.PublicKey)
}

// KeyID returns this issuer's key identifier.
func (i *Issuer) KeyID() string { return i.keyID }

// Request is what an operator asks for.
type Request struct {
	OrgID      string
	UserID     string
	DeviceID   string
	ResourceID string

	// RequestedTTL is what the operator asked for. It is a request, not an
	// instruction: the issued lifetime is the smallest of this, the policy's
	// ceiling, and the system maximum.
	RequestedTTL time.Duration

	// MaxBytes caps transfer for streams opened under the grant. Zero defers to
	// the resource's own limit on the agent.
	MaxBytes uint64
}

// ErrDenied means policy refused the request.
var ErrDenied = errors.New("grants: policy denied the request")

// Issue evaluates policy and, if allowed, signs a grant.
//
// Evaluation and signing are in one function on purpose. Separating them would
// create a call site that could sign without having evaluated, and that call site
// would eventually exist.
func (i *Issuer) Issue(rules []policy.Rule, req Request) (*proto.SignedGrant, policy.Decision, error) {
	decision := policy.Evaluate(rules, req.UserID, req.DeviceID, req.ResourceID)
	if !decision.Allowed {
		return nil, decision, ErrDenied
	}

	ttl := req.RequestedTTL
	if ttl <= 0 || ttl > decision.MaxTTL {
		ttl = decision.MaxTTL
	}
	if ttl > proto.MaxGrantTTL {
		// Belt and braces: the policy layer already caps at the system maximum,
		// and this stops a future change there from silently lifting the ceiling.
		ttl = proto.MaxGrantTTL
	}

	grantID, err := newGrantID()
	if err != nil {
		return nil, decision, err
	}

	now := time.Now().UTC().Truncate(time.Second)
	signed, err := proto.Grant{
		KeyID:      i.keyID,
		GrantID:    grantID,
		OrgID:      req.OrgID,
		UserID:     req.UserID,
		DeviceID:   req.DeviceID,
		ResourceID: req.ResourceID,
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
		MaxBytes:   req.MaxBytes,
	}.Sign(i.key)
	if err != nil {
		return nil, decision, err
	}
	return signed, decision, nil
}

// newGrantID returns an identifier unique enough that two issuers would not
// collide.
//
// Random rather than sequential: a grant identifier appears in audit records and
// is quoted in revocations, and a sequential one would leak how many grants a
// deployment has issued and let an observer guess neighbouring ones.
func newGrantID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("grants: generate identifier: %w", err)
	}
	return "grn_" + hex.EncodeToString(b), nil
}
