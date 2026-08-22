package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SessionRecord is a logged-in operator session.
//
// The session's bearer token is never stored, only its hash — the same rule
// enrollment tokens follow. Someone who reads this database learns that a
// session exists and whose it is, which is exactly what an audit trail is for,
// and cannot use it, which is exactly what a credential store must prevent.
type SessionRecord struct {
	SessionID string

	// TokenHash is HashToken of the bearer value handed to the operator.
	TokenHash string

	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time

	RevokedAt *time.Time

	// Remote is the address the login came from, recorded so an operator can be
	// told where their session was opened. Informational only — it is not an
	// authentication factor, because a network address is not one.
	Remote string
}

// Active reports whether a session may still be used.
func (r SessionRecord) Active(now time.Time) bool {
	return r.RevokedAt == nil && now.Before(r.ExpiresAt)
}

// CreateSession stores a new operator session and its audit event in one
// transaction, for the same reason grants are stored that way: a session that
// exists without a record of who opened it is unaccountable access.
func (s *Store) CreateSession(ctx context.Context, r SessionRecord, e AuditEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO operator_sessions
		    (session_id, token_hash, user_id, created_at, expires_at, remote)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.SessionID, r.TokenHash, r.UserID, unix(r.CreatedAt), unix(r.ExpiresAt), r.Remote); err != nil {
		return fmt.Errorf("storage: create operator session: %w", err)
	}
	if err := AppendAuditTx(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit()
}

// LookupSession resolves a bearer token to a live session.
//
// Expiry and revocation are distinguished in the returned error. They are
// different events — one is the passage of time, the other is a decision
// somebody made — and an operator whose session was cut short deserves to know
// which happened rather than being told to log in again with no explanation.
func (s *Store) LookupSession(ctx context.Context, token string) (SessionRecord, error) {
	var r SessionRecord
	var created, expires int64
	var revoked sql.NullInt64

	err := s.db.QueryRowContext(ctx,
		`SELECT session_id, token_hash, user_id, created_at, expires_at, revoked_at, remote
		   FROM operator_sessions WHERE token_hash = ?`, HashToken(token)).
		Scan(&r.SessionID, &r.TokenHash, &r.UserID, &created, &expires, &revoked, &r.Remote)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionRecord{}, ErrSessionUnknown
	}
	if err != nil {
		return SessionRecord{}, fmt.Errorf("storage: read operator session: %w", err)
	}

	r.CreatedAt, r.ExpiresAt = fromUnix(created), fromUnix(expires)
	r.RevokedAt = fromNullUnix(revoked)

	if r.RevokedAt != nil {
		return r, ErrSessionRevoked
	}
	if time.Now().After(r.ExpiresAt) {
		return r, ErrSessionExpired
	}
	return r, nil
}

// LookupSessionByID returns a session regardless of its state, for admin output.
func (s *Store) LookupSessionByID(ctx context.Context, sessionID string) (SessionRecord, error) {
	var r SessionRecord
	var created, expires int64
	var revoked sql.NullInt64

	err := s.db.QueryRowContext(ctx,
		`SELECT session_id, token_hash, user_id, created_at, expires_at, revoked_at, remote
		   FROM operator_sessions WHERE session_id = ?`, sessionID).
		Scan(&r.SessionID, &r.TokenHash, &r.UserID, &created, &expires, &revoked, &r.Remote)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionRecord{}, ErrSessionUnknown
	}
	if err != nil {
		return SessionRecord{}, fmt.Errorf("storage: read operator session: %w", err)
	}
	r.CreatedAt, r.ExpiresAt = fromUnix(created), fromUnix(expires)
	r.RevokedAt = fromNullUnix(revoked)
	return r, nil
}

// RevokeSession ends one session and records it.
//
// Only the session row is touched here. The grants issued under it are revoked
// by the caller through RevokeGrantsWhere, and the live streams are dropped by
// whoever holds the connections — three separate steps because they are three
// separate kinds of state, and collapsing them would hide which one failed.
func (s *Store) RevokeSession(ctx context.Context, sessionID, reason string, actor AuditEvent) (SessionRecord, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SessionRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var r SessionRecord
	var created, expires int64
	var revoked sql.NullInt64
	err = tx.QueryRowContext(ctx,
		`SELECT session_id, token_hash, user_id, created_at, expires_at, revoked_at, remote
		   FROM operator_sessions WHERE session_id = ?`, sessionID).
		Scan(&r.SessionID, &r.TokenHash, &r.UserID, &created, &expires, &revoked, &r.Remote)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionRecord{}, ErrSessionUnknown
	}
	if err != nil {
		return SessionRecord{}, fmt.Errorf("storage: read operator session: %w", err)
	}
	r.CreatedAt, r.ExpiresAt = fromUnix(created), fromUnix(expires)
	r.RevokedAt = fromNullUnix(revoked)

	if r.RevokedAt != nil {
		return r, nil // already ended; no second audit event, nothing changed
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx,
		`UPDATE operator_sessions SET revoked_at = ?
		  WHERE session_id = ? AND revoked_at IS NULL`, unix(now), sessionID); err != nil {
		return SessionRecord{}, fmt.Errorf("storage: revoke operator session: %w", err)
	}

	actor.SessionID = r.SessionID
	actor.Reason = reason
	if err := AppendAuditTx(ctx, tx, actor); err != nil {
		return SessionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return SessionRecord{}, err
	}
	r.RevokedAt = &now
	return r, nil
}

// SessionFilter narrows a session listing.
type SessionFilter struct {
	UserID string

	// ActiveOnly excludes revoked and expired sessions.
	ActiveOnly bool

	Limit int
}

// ListSessions returns matching operator sessions, newest first.
func (s *Store) ListSessions(ctx context.Context, f SessionFilter) ([]SessionRecord, error) {
	var where []string
	var args []any
	if f.UserID != "" {
		where = append(where, "user_id = ?")
		args = append(args, f.UserID)
	}
	if f.ActiveOnly {
		where = append(where, "revoked_at IS NULL", "expires_at > ?")
		args = append(args, unix(time.Now()))
	}

	limit := f.Limit
	if limit <= 0 {
		limit = DefaultAuditLimit
	}
	if limit > MaxAuditLimit {
		limit = MaxAuditLimit
	}

	query := `SELECT session_id, token_hash, user_id, created_at, expires_at, revoked_at, remote
	            FROM operator_sessions`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC, session_id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: list operator sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []SessionRecord
	for rows.Next() {
		var r SessionRecord
		var created, expires int64
		var revoked sql.NullInt64
		if err := rows.Scan(&r.SessionID, &r.TokenHash, &r.UserID,
			&created, &expires, &revoked, &r.Remote); err != nil {
			return nil, fmt.Errorf("storage: scan session row: %w", err)
		}
		r.CreatedAt, r.ExpiresAt = fromUnix(created), fromUnix(expires)
		r.RevokedAt = fromNullUnix(revoked)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveSessionsForUser lists a user's live sessions, which is what a cascading
// revocation of an identity has to end.
func (s *Store) ActiveSessionsForUser(ctx context.Context, userID string) ([]SessionRecord, error) {
	return s.ListSessions(ctx, SessionFilter{UserID: userID, ActiveOnly: true, Limit: MaxAuditLimit})
}
