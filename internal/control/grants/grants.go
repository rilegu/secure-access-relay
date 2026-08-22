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
//   - It must never issue without recording what it issued. A grant nobody has
//     a record of is access nobody can revoke or account for, so the grant and
//     its audit event commit in one transaction before the bytes are returned.
//   - It must never write the signing key anywhere. The key arrives from the
//     keystore and stays in memory.
package grants

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/control/policy"
	"github.com/rilegu/secure-access-relay/internal/proto"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// Issuer signs grants with one key and records every one it signs.
type Issuer struct {
	key   ed25519.PrivateKey
	keyID string

	// store persists issued grants and their audit events. Optional: a nil store
	// signs without recording, which is only ever right in a test. A deployment
	// wiring one without a store gets a warning at startup, not silence.
	store *storage.Store
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

// WithStore attaches the store that issued grants are recorded in.
//
// Separate from NewIssuer because the signing key and the database are opened by
// different code paths at startup, and threading a half-built store through key
// loading would couple two things that have no reason to know about each other.
func (i *Issuer) WithStore(store *storage.Store) *Issuer {
	i.store = store
	return i
}

// Recording reports whether issued grants are being persisted, so a caller can
// say so at startup rather than leaving an operator to discover that the grant
// list is empty when they need it.
func (i *Issuer) Recording() bool { return i.store != nil }

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

	// SessionID is the operator session this request was made under. Empty when
	// a deployment allows grants without a session; recorded either way, so the
	// audit trail can group an operator's activity by the session it happened in.
	SessionID string
}

// ErrDenied means policy refused the request.
var ErrDenied = errors.New("grants: policy denied the request")

// Issue evaluates policy and, if allowed, signs and records a grant.
//
// Evaluation, signing, and recording are in one function on purpose. Separating
// any of them would create a call site that could sign without having evaluated,
// or hand out a grant nothing has a record of — and both of those call sites
// would eventually exist.
//
// A denial is recorded too. A run of denials is the signal that somebody is
// probing or that a policy is wrong, and neither is visible without the record.
func (i *Issuer) Issue(ctx context.Context, rules []policy.Rule, req Request) (*proto.SignedGrant, policy.Decision, error) {
	decision := policy.Evaluate(rules, req.UserID, req.DeviceID, req.ResourceID)
	if !decision.Allowed {
		i.recordDenial(ctx, req, decision)
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

	// Recorded before the bytes are returned. If this fails the operator gets no
	// grant, which is the right trade: unrecorded access is worse than refused
	// access, and the operator can retry.
	if i.store != nil {
		rec := storage.GrantRecord{
			GrantID:    signed.GrantID,
			OrgID:      signed.OrgID,
			UserID:     signed.UserID,
			DeviceID:   signed.DeviceID,
			ResourceID: signed.ResourceID,
			PolicyID:   decision.PolicyID,
			SessionID:  req.SessionID,
			IssuedAt:   signed.IssuedAt,
			ExpiresAt:  signed.ExpiresAt,
			MaxBytes:   signed.MaxBytes,
		}
		event := storage.AuditEvent{
			At:         signed.IssuedAt,
			Event:      audit.EventGrantCreated,
			OrgID:      signed.OrgID,
			ActorRole:  audit.RoleOperator,
			ActorID:    signed.UserID,
			DeviceID:   signed.DeviceID,
			ResourceID: signed.ResourceID,
			GrantID:    signed.GrantID,
			SessionID:  req.SessionID,
			Detail:     "policy " + decision.PolicyID,
		}
		if err := i.store.RecordGrant(ctx, rec, event); err != nil {
			return nil, decision, fmt.Errorf("grants: refusing to issue a grant that could not be recorded: %w", err)
		}
	}

	return signed, decision, nil
}

// recordDenial writes the audit event for a refused request.
//
// A failure here is swallowed rather than turned into a different error: the
// request was denied either way, and reporting a storage fault to the caller
// would tell an operator their access failed for a reason that is not the reason.
func (i *Issuer) recordDenial(ctx context.Context, req Request, decision policy.Decision) {
	if i.store == nil {
		return
	}
	_ = i.store.AppendAudit(ctx, storage.AuditEvent{
		Event:      audit.EventGrantDenied,
		OrgID:      req.OrgID,
		ActorRole:  audit.RoleOperator,
		ActorID:    req.UserID,
		DeviceID:   req.DeviceID,
		ResourceID: req.ResourceID,
		SessionID:  req.SessionID,
		Reason:     decision.Reason.String(),
	})
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

// State is a grant's current standing, in the terms the relay's fast-fail check
// needs and nothing more.
//
// It exists so the relay can ask about a grant without importing the control
// plane's storage types. The relay declares its own interface; a composition
// root adapts this function to it in three lines. That indirection is what keeps
// the dependency running one way — the control plane decides, the relay is
// told — and lets a relay be deployed apart from the control plane later
// (ADR-0007).
type State struct {
	Known     bool
	Revoked   bool
	SessionID string
	UserID    string
}

// StateOf reports a grant's current standing.
//
// A grant nobody has a record of is reported as unknown rather than as an error.
// The distinction matters: unknown means the signing key produced something this
// control plane never issued, which is worth a loud log line, while an error
// means the database could not answer and the caller should fall back to the
// agent's authoritative check rather than denying everybody.
func StateOf(ctx context.Context, store *storage.Store, grantID string) (State, error) {
	rec, err := store.LookupGrant(ctx, grantID)
	if errors.Is(err, storage.ErrGrantUnknown) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	return State{
		Known:     true,
		Revoked:   rec.Revoked(),
		SessionID: rec.SessionID,
		UserID:    rec.UserID,
	}, nil
}
