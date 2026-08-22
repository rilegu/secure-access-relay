// Package login issues and ends operator sessions.
//
// # What a session is, and what it is not
//
// An operator already authenticates with a client certificate. A session does
// **not** add a second factor: anyone holding the certificate can open one, and
// no additional secret is required. Saying otherwise would be the most damaging
// kind of security claim, so it is said plainly here and in the README.
//
// What a session adds is a handle on access that the certificate cannot provide:
//
//  1. A revocation lever shorter than the certificate. Certificates last 30 days
//     and ending one means re-enrolling an operator. A session lasts a shift and
//     can be ended immediately, and ending it revokes the grants issued under it
//     and drops the streams those grants opened.
//  2. Attribution in the audit trail. Every grant carries the session it was
//     issued under, so "what did this operator do during Tuesday's incident" is
//     one query rather than a reconstruction from timestamps.
//  3. The seam an identity provider plugs into later. When login means OIDC, the
//     thing it produces is this session; nothing downstream has to change.
//
// # What this package must never do
//
//   - It must never store a token in the clear. The store holds a hash.
//   - It must never accept an identity from a request body. Who is logging in
//     comes from the certificate, always.
package login

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// DefaultTTL is how long a session lasts if none is requested.
//
// One working shift. Long enough that an operator is not logging in during an
// incident, short enough that a laptop left unattended overnight is not a live
// credential in the morning.
const DefaultTTL = 8 * time.Hour

// MaxTTL is the ceiling on any session, whatever is asked for.
//
// A session is a bearer credential written to disk. Beyond a day it stops being
// a session and becomes a second, weaker certificate with none of the
// protections the real one has.
const MaxTTL = 24 * time.Hour

// TokenBytes is the entropy in a session token.
//
// 32 bytes from crypto/rand. The token is a bearer value with no rate limit in
// front of it beyond the TLS handshake, so guessing must be infeasible rather
// than merely difficult.
const TokenBytes = 32

// ErrNotOperator means a non-operator identity tried to log in.
var ErrNotOperator = errors.New("login: only operators hold sessions")

// Service opens and ends operator sessions.
type Service struct {
	store *storage.Store
	ttl   time.Duration
}

// New creates the service. A TTL of zero uses DefaultTTL; anything above MaxTTL
// is capped rather than rejected, because a deployment asking for too long
// should get a working system with a sane bound, not a startup failure.
func New(store *storage.Store, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}
	return &Service{store: store, ttl: ttl}
}

// TTL reports the session lifetime this service issues.
func (s *Service) TTL() time.Duration { return s.ttl }

// Session is what a successful login produces.
type Session struct {
	// Token is the bearer value, returned exactly once. It is never stored and
	// cannot be recovered — an operator who loses it logs in again.
	Token string

	Record storage.SessionRecord
}

// Begin opens a session for an authenticated operator.
//
// The record and its audit event commit together, so a session cannot exist
// without a record of who opened it and from where.
func (s *Service) Begin(ctx context.Context, userID, remote string) (Session, error) {
	if userID == "" {
		return Session{}, errors.New("login: refusing to open a session with no identity")
	}

	token, err := newToken()
	if err != nil {
		return Session{}, err
	}
	sessionID, err := newSessionID()
	if err != nil {
		return Session{}, err
	}

	now := time.Now().UTC().Truncate(time.Second)
	rec := storage.SessionRecord{
		SessionID: sessionID,
		TokenHash: storage.HashToken(token),
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
		Remote:    remote,
	}

	if err := s.store.CreateSession(ctx, rec, storage.AuditEvent{
		At:        now,
		Event:     audit.EventOperatorLogin,
		ActorRole: audit.RoleOperator,
		ActorID:   userID,
		SessionID: sessionID,
		Detail:    "from " + remote,
	}); err != nil {
		return Session{}, err
	}
	return Session{Token: token, Record: rec}, nil
}

// Resolve validates a bearer token and returns the session it names.
//
// The error distinguishes unknown, expired, and revoked. An operator whose
// session was ended by an administrator mid-incident should be told that, not
// handed the same message as somebody typing a token that never existed.
func (s *Service) Resolve(ctx context.Context, token string) (storage.SessionRecord, error) {
	if token == "" {
		return storage.SessionRecord{}, storage.ErrSessionUnknown
	}
	return s.store.LookupSession(ctx, token)
}

// End revokes a session and every live grant issued under it, and reports which
// grants were revoked so the caller can drop the streams they authorized.
//
// Three separate steps, deliberately: the session row, the grants, and the live
// connections are three kinds of state. Collapsing them would hide which one
// failed, and the connections are held by a component that has no database.
func (s *Service) End(ctx context.Context, sessionID, actorID, reason string) ([]storage.GrantRecord, error) {
	// The owner is read first so the audit trail can say whether an operator
	// ended their own session or an administrator ended it for them. Those are
	// different events, and conflating them would mislead in exactly the case
	// the trail exists for.
	owner, err := s.store.LookupSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	role := actorRole(actorID, owner.UserID)

	rec, err := s.store.RevokeSession(ctx, sessionID, reason, storage.AuditEvent{
		Event:     eventForReason(reason),
		ActorRole: role,
		ActorID:   actorID,
	})
	if err != nil {
		return nil, err
	}

	revoked, err := s.store.RevokeGrantsWhere(ctx, storage.ScopeSession, rec.SessionID, reason,
		storage.AuditEvent{
			Event:     audit.EventGrantRevoked,
			ActorRole: role,
			ActorID:   actorID,
		})
	if err != nil {
		// The session is already ended, which is the part that stops new grants
		// being issued. Reporting the failure matters because the grants already
		// issued stay live until they expire on their own.
		return nil, fmt.Errorf("session %s ended but its grants could not be revoked: %w", sessionID, err)
	}
	return revoked, nil
}

// EndAllForUser ends every live session a user holds. Used when an identity is
// revoked, where leaving the sessions alive would leave the revocation
// meaningless until they expired on their own.
func (s *Service) EndAllForUser(ctx context.Context, userID, actorID, reason string) ([]storage.GrantRecord, error) {
	sessions, err := s.store.ActiveSessionsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	var all []storage.GrantRecord
	for _, sess := range sessions {
		revoked, err := s.End(ctx, sess.SessionID, actorID, reason)
		if err != nil {
			return all, err
		}
		all = append(all, revoked...)
	}

	// Grants issued without a session still belong to this user and must go too.
	direct, err := s.store.RevokeGrantsWhere(ctx, storage.ScopeUser, userID, reason,
		storage.AuditEvent{
			Event:     audit.EventGrantRevoked,
			ActorRole: audit.RoleAdmin,
			ActorID:   actorID,
		})
	if err != nil {
		return all, err
	}
	return append(all, direct...), nil
}

// eventForReason picks the audit name for how a session ended, so the trail
// distinguishes an operator logging out from an administrator cutting them off.
func eventForReason(reason string) string {
	if reason == ReasonLogout {
		return audit.EventOperatorLogout
	}
	return audit.EventOperatorSessionEnded
}

// Reasons a session can end. They appear verbatim in the audit trail.
const (
	// ReasonLogout is the operator ending their own session.
	ReasonLogout = "logout"

	// ReasonRevokedByAdmin is an administrator ending somebody else's.
	ReasonRevokedByAdmin = "revoked_by_admin"

	// ReasonIdentityRevoked is the cascade from revoking the operator itself.
	ReasonIdentityRevoked = "identity_revoked"
)

// actorRole reports whether the actor is the session's own owner or somebody
// acting on it. The distinction is the difference between a logout and a
// termination, and an audit trail that conflated them would be misleading in
// exactly the case it exists for.
func actorRole(actorID, ownerID string) string {
	if actorID != "" && actorID == ownerID {
		return audit.RoleOperator
	}
	return audit.RoleAdmin
}

// newToken returns a bearer value.
//
// base64url so it survives being pasted into a shell, a config file, or an HTTP
// header without escaping. Prefixed so that a token found in a log or a
// screenshot is immediately recognisable as one — which is what lets somebody
// notice it needs revoking.
func newToken() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("login: generate session token: %w", err)
	}
	return "sar_ses_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// newSessionID returns a session identifier.
//
// Separate from the token and safe to log: the identifier is what an audit
// record and a revocation name, and it must be quotable in a support ticket
// without handing over the credential.
func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("login: generate session identifier: %w", err)
	}
	return "ses_" + hex.EncodeToString(b), nil
}
