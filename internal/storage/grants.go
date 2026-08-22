package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// GrantRecord is what the control plane remembers about a grant it issued.
//
// The signature is not here. A grant's bytes are a usable authorization, and
// keeping a second copy at rest would mean a database read produced something
// that could be presented to an agent. Revocation matches on GrantID, and
// verification happens against the bytes the operator presents, so nothing here
// needs the signature.
type GrantRecord struct {
	GrantID    string
	OrgID      string
	UserID     string
	DeviceID   string
	ResourceID string
	PolicyID   string

	// SessionID is the operator session the grant was issued under. Empty for a
	// grant issued without one, which a deployment can still be configured to
	// allow.
	SessionID string

	IssuedAt  time.Time
	ExpiresAt time.Time
	MaxBytes  uint64

	RevokedAt    *time.Time
	RevokeReason string
}

// Revoked reports whether the grant has been explicitly revoked.
func (g GrantRecord) Revoked() bool { return g.RevokedAt != nil }

// Expired reports whether the grant's own lifetime has run out.
//
// Separate from Revoked because they are different facts about a grant, and an
// operator asking why access stopped deserves to be told which one happened.
func (g GrantRecord) Expired(now time.Time) bool { return now.After(g.ExpiresAt) }

// Usable reports whether a grant is currently good, which is the question the
// relay actually asks.
func (g GrantRecord) Usable(now time.Time) bool { return !g.Revoked() && !g.Expired(now) }

// RecordGrant stores an issued grant and its audit event in one transaction.
//
// Together or not at all. A grant persisted without its audit event is access
// nothing accounts for; an audit event without the grant is a fiction in the
// evidence. Failing the request is better than either, so the caller gets an
// error and the operator gets no grant.
func (s *Store) RecordGrant(ctx context.Context, g GrantRecord, e AuditEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var session any
	if g.SessionID != "" {
		session = g.SessionID
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO grants
		    (grant_id, org_id, user_id, device_id, resource_id, policy_id,
		     session_id, issued_at, expires_at, max_bytes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.GrantID, g.OrgID, g.UserID, g.DeviceID, g.ResourceID, g.PolicyID,
		session, unix(g.IssuedAt), unix(g.ExpiresAt), int64(g.MaxBytes)); err != nil {
		return fmt.Errorf("storage: record grant: %w", err)
	}

	if err := AppendAuditTx(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit()
}

// LookupGrant returns what is known about one grant.
//
// This is the relay's revocation check on stream open. It is a primary-key point
// read, which is cheap next to the Ed25519 verification the same code path
// already performs — so the check is done live rather than against a cached set
// that could be stale exactly when revocation matters most.
func (s *Store) LookupGrant(ctx context.Context, grantID string) (GrantRecord, error) {
	var g GrantRecord
	var issued, expires int64
	var maxBytes int64
	var session sql.NullString
	var revoked sql.NullInt64

	err := s.db.QueryRowContext(ctx,
		`SELECT grant_id, org_id, user_id, device_id, resource_id, policy_id,
		        session_id, issued_at, expires_at, max_bytes, revoked_at, revoke_reason
		   FROM grants WHERE grant_id = ?`, grantID).
		Scan(&g.GrantID, &g.OrgID, &g.UserID, &g.DeviceID, &g.ResourceID, &g.PolicyID,
			&session, &issued, &expires, &maxBytes, &revoked, &g.RevokeReason)
	if errors.Is(err, sql.ErrNoRows) {
		return GrantRecord{}, ErrGrantUnknown
	}
	if err != nil {
		return GrantRecord{}, fmt.Errorf("storage: read grant: %w", err)
	}

	g.SessionID = session.String
	g.IssuedAt, g.ExpiresAt = fromUnix(issued), fromUnix(expires)
	g.MaxBytes = uint64(maxBytes)
	g.RevokedAt = fromNullUnix(revoked)
	return g, nil
}

// RevokeGrant marks one grant revoked and records why, in one transaction.
//
// It returns the grant as it now stands so the caller can act on the live
// streams it authorized. Revoking in the database and dropping the connections
// are two different jobs: this one is durable, the other is immediate, and the
// caller owns the second.
func (s *Store) RevokeGrant(ctx context.Context, grantID, reason string, actor AuditEvent) (GrantRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GrantRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var g GrantRecord
	var issued, expires, maxBytes int64
	var session sql.NullString
	var revoked sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`SELECT grant_id, org_id, user_id, device_id, resource_id, policy_id,
		        session_id, issued_at, expires_at, max_bytes, revoked_at, revoke_reason
		   FROM grants WHERE grant_id = ?`, grantID).
		Scan(&g.GrantID, &g.OrgID, &g.UserID, &g.DeviceID, &g.ResourceID, &g.PolicyID,
			&session, &issued, &expires, &maxBytes, &revoked, &g.RevokeReason)
	if errors.Is(err, sql.ErrNoRows) {
		return GrantRecord{}, ErrGrantUnknown
	}
	if err != nil {
		return GrantRecord{}, fmt.Errorf("storage: read grant: %w", err)
	}
	g.SessionID = session.String
	g.IssuedAt, g.ExpiresAt = fromUnix(issued), fromUnix(expires)
	g.MaxBytes = uint64(maxBytes)
	g.RevokedAt = fromNullUnix(revoked)

	if g.Revoked() {
		// Already revoked. Not an error — revoking twice is a reasonable thing for
		// a worried administrator to do — but no second audit event, because
		// nothing changed.
		return g, nil
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx,
		`UPDATE grants SET revoked_at = ?, revoke_reason = ?
		  WHERE grant_id = ? AND revoked_at IS NULL`,
		unix(now), reason, grantID); err != nil {
		return GrantRecord{}, fmt.Errorf("storage: revoke grant: %w", err)
	}

	actor.GrantID = g.GrantID
	actor.DeviceID = g.DeviceID
	actor.ResourceID = g.ResourceID
	actor.SessionID = g.SessionID
	actor.Reason = reason
	if err := AppendAuditTx(ctx, tx, actor); err != nil {
		return GrantRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return GrantRecord{}, err
	}

	g.RevokedAt = &now
	g.RevokeReason = reason
	return g, nil
}

// GrantFilter narrows a grant listing. Zero values mean "no constraint".
type GrantFilter struct {
	UserID    string
	DeviceID  string
	SessionID string

	// ActiveOnly excludes grants that are revoked or already expired, which is
	// the listing an administrator wants when asking "what access exists right
	// now".
	ActiveOnly bool

	Limit int
}

// ListGrants returns matching grants, newest first.
func (s *Store) ListGrants(ctx context.Context, f GrantFilter) ([]GrantRecord, error) {
	var where []string
	var args []any
	add := func(clause string, value any) {
		where = append(where, clause)
		args = append(args, value)
	}
	if f.UserID != "" {
		add("user_id = ?", f.UserID)
	}
	if f.DeviceID != "" {
		add("device_id = ?", f.DeviceID)
	}
	if f.SessionID != "" {
		add("session_id = ?", f.SessionID)
	}
	if f.ActiveOnly {
		where = append(where, "revoked_at IS NULL")
		add("expires_at > ?", unix(time.Now()))
	}

	limit := f.Limit
	if limit <= 0 {
		limit = DefaultAuditLimit
	}
	if limit > MaxAuditLimit {
		limit = MaxAuditLimit
	}

	query := `SELECT grant_id, org_id, user_id, device_id, resource_id, policy_id,
	                 session_id, issued_at, expires_at, max_bytes, revoked_at, revoke_reason
	            FROM grants`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY issued_at DESC, grant_id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []GrantRecord
	for rows.Next() {
		var g GrantRecord
		var issued, expires, maxBytes int64
		var session sql.NullString
		var revoked sql.NullInt64
		if err := rows.Scan(&g.GrantID, &g.OrgID, &g.UserID, &g.DeviceID, &g.ResourceID,
			&g.PolicyID, &session, &issued, &expires, &maxBytes, &revoked, &g.RevokeReason); err != nil {
			return nil, fmt.Errorf("storage: scan grant row: %w", err)
		}
		g.SessionID = session.String
		g.IssuedAt, g.ExpiresAt = fromUnix(issued), fromUnix(expires)
		g.MaxBytes = uint64(maxBytes)
		g.RevokedAt = fromNullUnix(revoked)
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeGrantsWhere revokes every live grant matching one column, and returns
// what it revoked.
//
// This is what makes cascading revocation possible: ending an operator session
// or revoking an identity has to reach the grants already issued under it, or
// the revocation only stops the next request and not the access already granted.
//
// The column is chosen from a fixed set inside this function. It is never a
// caller's string, which is the one thing that would turn this into an injection
// point.
func (s *Store) RevokeGrantsWhere(ctx context.Context, by GrantScope, value, reason string, actor AuditEvent) ([]GrantRecord, error) {
	var column string
	switch by {
	case ScopeUser:
		column = "user_id"
	case ScopeDevice:
		column = "device_id"
	case ScopeSession:
		column = "session_id"
	default:
		return nil, fmt.Errorf("storage: unknown grant scope %d", by)
	}

	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// Selected first so the caller learns which live streams to drop. Inside the
	// transaction, so a grant issued concurrently is either included here or
	// blocked until this commits — never issued and then missed.
	rows, err := tx.QueryContext(ctx,
		`SELECT grant_id, user_id, device_id, resource_id, session_id, expires_at
		   FROM grants
		  WHERE `+column+` = ? AND revoked_at IS NULL AND expires_at > ?`,
		value, unix(now))
	if err != nil {
		return nil, fmt.Errorf("storage: select grants to revoke: %w", err)
	}

	var affected []GrantRecord
	for rows.Next() {
		var g GrantRecord
		var session sql.NullString
		var expires int64
		if err := rows.Scan(&g.GrantID, &g.UserID, &g.DeviceID, &g.ResourceID, &session, &expires); err != nil {
			_ = rows.Close()
			return nil, err
		}
		g.SessionID = session.String
		g.ExpiresAt = fromUnix(expires)
		affected = append(affected, g)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	if len(affected) == 0 {
		return nil, tx.Commit()
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE grants SET revoked_at = ?, revoke_reason = ?
		  WHERE `+column+` = ? AND revoked_at IS NULL AND expires_at > ?`,
		unix(now), reason, value, unix(now)); err != nil {
		return nil, fmt.Errorf("storage: cascade revoke grants: %w", err)
	}

	// One audit event per grant, not one for the cascade. An administrator asking
	// later why a particular grant stopped working must find that grant's own
	// record, not a summary line naming a different subject.
	for i := range affected {
		e := actor
		e.At = now
		e.GrantID = affected[i].GrantID
		e.DeviceID = affected[i].DeviceID
		e.ResourceID = affected[i].ResourceID
		e.SessionID = affected[i].SessionID
		e.Reason = reason
		if err := AppendAuditTx(ctx, tx, e); err != nil {
			return nil, err
		}
		affected[i].RevokedAt = &now
		affected[i].RevokeReason = reason
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return affected, nil
}

// GrantScope names the column a cascading revocation matches on.
type GrantScope int

// The scopes a cascading revocation may use.
const (
	ScopeUser GrantScope = iota + 1
	ScopeDevice
	ScopeSession
)
