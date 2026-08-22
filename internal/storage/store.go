// Package storage persists control-plane state in SQLite.
//
// It holds five kinds of data: enrolled identities, enrollment tokens, operator
// sessions, issued grants, and the audit trail. The first four are key-value
// shaped and would have been served by anything; the audit trail is what
// requires a database, because it is append-only, unbounded, and queried across
// several dimensions after the fact. See docs/decisions/0011.
//
// # What this package must never do
//
//   - It must never build SQL by concatenating a caller's string. Identifiers
//     reaching the control plane are attacker-influenced, and a query language
//     is the one failure this project would otherwise not have had at all.
//   - It must never hold key material. The authority key, device keys, and the
//     grant signing key belong to internal/keystore. A database compromise must
//     not be a key compromise.
//   - It must never delete or rewrite an audit row. Append only.
package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	// The pure-Go SQLite driver. Registered for its side effect; no cgo, so the
	// binaries stay static and cross-compilable (ADR-0006).
	_ "modernc.org/sqlite"
)

// Errors returned by the store. They are distinct because the caller must be
// able to tell them apart when deciding what reason code to return.
var (
	// ErrTokenUnknown means no such enrollment token exists.
	ErrTokenUnknown = errors.New("storage: unknown enrollment token")

	// ErrTokenConsumed means the token was already used. Enrollment tokens are
	// single-use; a second attempt is either a retry after a lost response or an
	// attacker replaying a token they observed (threat T8).
	ErrTokenConsumed = errors.New("storage: enrollment token already used")

	// ErrTokenExpired means the token outlived its validity window.
	ErrTokenExpired = errors.New("storage: enrollment token expired")

	// ErrRevoked means the identity exists but has been revoked.
	ErrRevoked = errors.New("storage: identity revoked")

	// ErrNotEnrolled means no such identity exists.
	ErrNotEnrolled = errors.New("storage: identity not enrolled")

	// ErrSessionUnknown means no operator session has that token.
	ErrSessionUnknown = errors.New("storage: unknown operator session")

	// ErrSessionExpired means the session outlived its window. Distinct from
	// revoked: one is the passage of time, the other is a decision somebody made,
	// and an audit trail must not conflate them.
	ErrSessionExpired = errors.New("storage: operator session expired")

	// ErrSessionRevoked means the session was explicitly ended.
	ErrSessionRevoked = errors.New("storage: operator session revoked")

	// ErrGrantUnknown means no grant has that identifier.
	ErrGrantUnknown = errors.New("storage: unknown grant")

	// ErrSchemaTooNew means the database was written by a newer build. Starting
	// against it would mean reading a schema this binary does not understand.
	ErrSchemaTooNew = errors.New("storage: database schema is newer than this build")
)

// Store is the control-plane database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens or creates the database and brings its schema up to date.
//
// A missing file is created; an existing one is migrated forward. A schema
// *newer* than this build understands is a startup failure rather than a
// best-effort read, which is the same rule configuration already follows: a
// control plane that half-understands its own authorization state is worse than
// one that refuses to start.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}

	// Connection parameters, all deliberate:
	//
	//   _pragma=journal_mode(WAL)  readers do not block the writer, which matters
	//                              because the audit trail is written on the hot
	//                              path of every authorization decision.
	//   _pragma=busy_timeout(5000) SQLite permits one writer at a time. Without a
	//                              busy timeout a concurrent write fails
	//                              immediately with "database is locked"; with
	//                              one it waits, which is what the caller wanted.
	//   _pragma=foreign_keys(1)    off by default in SQLite, so it has to be
	//                              asked for explicitly or the constraints below
	//                              are decoration.
	//   _txlock=immediate          a write transaction takes its lock at BEGIN
	//                              rather than on first write, so two concurrent
	//                              read-then-write transactions cannot deadlock
	//                              on upgrade.
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_txlock=immediate"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}

	// One writer is a property of SQLite, not of this pool, but capping the pool
	// keeps connection count bounded and predictable at the scale this runs at.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}

	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// Path reports where the database lives, for startup logging.
func (s *Store) Path() string { return s.path }

// DB exposes the handle for the few callers that need their own transaction.
// Kept narrow on purpose: everything else goes through a method here.
func (s *Store) DB() *sql.DB { return s.db }

// unix converts a time to the integer seconds stored in every timestamp column.
//
// Seconds, not nanoseconds: grants are already truncated to the second because
// that is what the signed encoding carries, and storing more precision than the
// protocol has would invite a comparison that disagrees with the signature.
func unix(t time.Time) int64 { return t.UTC().Truncate(time.Second).Unix() }

// fromUnix converts a stored timestamp back, always in UTC.
func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

// nullUnix stores an optional timestamp. A nil time is SQL NULL rather than
// zero, so "never revoked" and "revoked at the epoch" stay distinguishable.
func nullUnix(t *time.Time) any {
	if t == nil {
		return nil
	}
	return unix(*t)
}

// fromNullUnix reads an optional timestamp back.
func fromNullUnix(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromUnix(v.Int64)
	return &t
}
