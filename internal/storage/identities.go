package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Record is an enrolled identity.
type Record struct {
	ID         string    `json:"id"`
	Role       string    `json:"role"`
	EnrolledAt time.Time `json:"enrolled_at"`

	// SerialHex is the serial of the certificate currently issued to this
	// identity. Re-enrolling replaces it, which is what makes an old certificate
	// stop being accepted without needing a revocation list.
	SerialHex string `json:"serial_hex"`

	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Token is a single-use enrollment token.
//
// The token itself is never stored — only a hash of it. If this database is read
// by someone who should not have it, they learn which identities are pending
// enrollment but cannot enroll as any of them, because the value needed to do
// that was only ever held by whoever the token was issued to.
type Token struct {
	Hash       string     `json:"hash"`
	Role       string     `json:"role"`
	ID         string     `json:"id"`
	IssuedAt   time.Time  `json:"issued_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// HashToken returns the value stored for a token.
//
// SHA-256 with no salt or stretching, deliberately: tokens are high-entropy
// random values with a short lifetime, not user-chosen passwords, so there is
// nothing to brute-force and a slow hash would buy nothing.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// PutToken records a newly issued enrollment token.
func (s *Store) PutToken(t Token) error {
	_, err := s.db.Exec(
		`INSERT INTO enrollment_tokens (hash, role, id, issued_at, expires_at, consumed_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(hash) DO UPDATE SET
		     role = excluded.role, id = excluded.id,
		     issued_at = excluded.issued_at, expires_at = excluded.expires_at`,
		t.Hash, t.Role, t.ID, unix(t.IssuedAt), unix(t.ExpiresAt), nullUnix(t.ConsumedAt))
	if err != nil {
		return fmt.Errorf("storage: record enrollment token: %w", err)
	}
	return nil
}

// ConsumeToken validates a token and marks it used, in one transaction.
//
// Atomicity is the point of this method existing. If checking and marking were
// separate statements, two enrollment requests arriving together could both
// observe an unused token and both succeed — which is exactly the single-use
// property threat T8 depends on.
//
// The UPDATE carries the condition rather than trusting the SELECT that preceded
// it: `consumed_at IS NULL` in the WHERE clause means the database decides the
// race, and a caller that loses it sees zero rows affected.
func (s *Store) ConsumeToken(token string) (Token, error) {
	hash := HashToken(token)

	tx, err := s.db.Begin()
	if err != nil {
		return Token{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var t Token
	var issued, expires int64
	var consumed sql.NullInt64
	err = tx.QueryRow(
		`SELECT hash, role, id, issued_at, expires_at, consumed_at
		   FROM enrollment_tokens WHERE hash = ?`, hash).
		Scan(&t.Hash, &t.Role, &t.ID, &issued, &expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrTokenUnknown
	}
	if err != nil {
		return Token{}, fmt.Errorf("storage: read enrollment token: %w", err)
	}
	t.IssuedAt, t.ExpiresAt = fromUnix(issued), fromUnix(expires)
	t.ConsumedAt = fromNullUnix(consumed)

	if t.ConsumedAt != nil {
		return Token{}, ErrTokenConsumed
	}
	// Expiry is checked before consumption so that an expired token is reported
	// as expired rather than being consumed and then rejected, which would make
	// the audit trail say a token was used when it was not.
	if time.Now().After(t.ExpiresAt) {
		return Token{}, ErrTokenExpired
	}

	now := time.Now().UTC()
	res, err := tx.Exec(
		`UPDATE enrollment_tokens SET consumed_at = ?
		  WHERE hash = ? AND consumed_at IS NULL`, unix(now), hash)
	if err != nil {
		return Token{}, fmt.Errorf("storage: consume enrollment token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Token{}, err
	}
	if n == 0 {
		// Somebody else consumed it between the read and the write.
		return Token{}, ErrTokenConsumed
	}

	if err := tx.Commit(); err != nil {
		return Token{}, err
	}
	t.ConsumedAt = &now
	return t, nil
}

// PutRecord stores or replaces an enrolled identity.
//
// Re-enrolling an existing identity overwrites its serial and clears any
// revocation, because a fresh enrollment is a deliberate act by whoever holds
// the token — and the previous certificate stops being accepted the moment its
// serial is no longer the current one.
func (s *Store) PutRecord(r Record) error {
	_, err := s.db.Exec(
		`INSERT INTO identities (role, id, enrolled_at, serial_hex, revoked_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(role, id) DO UPDATE SET
		     enrolled_at = excluded.enrolled_at,
		     serial_hex  = excluded.serial_hex,
		     revoked_at  = excluded.revoked_at`,
		r.Role, r.ID, unix(r.EnrolledAt), r.SerialHex, nullUnix(r.RevokedAt))
	if err != nil {
		return fmt.Errorf("storage: record identity: %w", err)
	}
	return nil
}

// Lookup returns an enrolled identity, refusing revoked ones.
//
// Revocation is checked here rather than by callers, so that every path which
// resolves an identity gets the check without having to remember it.
func (s *Store) Lookup(role, id string) (Record, error) {
	r, err := s.lookupAny(role, id)
	if err != nil {
		return Record{}, err
	}
	if r.Revoked {
		return Record{}, ErrRevoked
	}
	return r, nil
}

// lookupAny returns an identity whether or not it is revoked, for admin output
// and for the revocation path itself.
func (s *Store) lookupAny(role, id string) (Record, error) {
	var r Record
	var enrolled int64
	var revoked sql.NullInt64
	err := s.db.QueryRow(
		`SELECT role, id, enrolled_at, serial_hex, revoked_at
		   FROM identities WHERE role = ? AND id = ?`, role, id).
		Scan(&r.Role, &r.ID, &enrolled, &r.SerialHex, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotEnrolled
	}
	if err != nil {
		return Record{}, fmt.Errorf("storage: read identity: %w", err)
	}
	r.EnrolledAt = fromUnix(enrolled)
	r.RevokedAt = fromNullUnix(revoked)
	r.Revoked = r.RevokedAt != nil
	return r, nil
}

// Revoke marks an identity revoked.
//
// Live sessions are not the store's concern; the caller terminates those. That
// split is deliberate — the database records the decision, and whoever holds the
// connections acts on it.
func (s *Store) Revoke(role, id string) error {
	res, err := s.db.Exec(
		`UPDATE identities SET revoked_at = ?
		  WHERE role = ? AND id = ? AND revoked_at IS NULL`,
		unix(time.Now()), role, id)
	if err != nil {
		return fmt.Errorf("storage: revoke identity: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		// Either it does not exist or it was already revoked. Distinguish, so an
		// administrator revoking a typo is told rather than reassured.
		if _, lerr := s.lookupAny(role, id); lerr != nil {
			return lerr
		}
		return nil // already revoked; revoking twice is not an error
	}
	return nil
}

// List returns every record for a role, revoked ones included, for admin output.
func (s *Store) List(role string) []Record {
	rows, err := s.db.Query(
		`SELECT role, id, enrolled_at, serial_hex, revoked_at
		   FROM identities WHERE role = ? ORDER BY id`, role)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()

	var out []Record
	for rows.Next() {
		var r Record
		var enrolled int64
		var revoked sql.NullInt64
		if err := rows.Scan(&r.Role, &r.ID, &enrolled, &r.SerialHex, &revoked); err != nil {
			return out
		}
		r.EnrolledAt = fromUnix(enrolled)
		r.RevokedAt = fromNullUnix(revoked)
		r.Revoked = r.RevokedAt != nil
		out = append(out, r)
	}
	return out
}
