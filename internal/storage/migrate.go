package storage

import (
	"fmt"
)

// migration is one forward step in the schema.
//
// Migrations are append-only and never edited once released. Editing one would
// mean two deployments claiming the same schema version with different tables,
// and the version number would stop meaning anything.
type migration struct {
	// description is what this step does, quoted in errors and in the startup log.
	description string

	// stmts run in order, inside one transaction with the version bump. A
	// migration is all-or-nothing: a half-applied schema is the state that
	// requires someone to repair a database by hand at the worst possible moment.
	stmts []string
}

// migrations is the ordered schema history. Index+1 is the schema version a
// migration produces, so appending a step is the only way to change the schema.
var migrations = []migration{
	{
		description: "identities, enrollment tokens, operator sessions, grants, audit trail",
		stmts: []string{
			// Enrolled identities. The primary key is (role, id) rather than id
			// alone: a device and an operator may legitimately share a name, and
			// collapsing them would let one authenticate as the other.
			`CREATE TABLE identities (
				role        TEXT    NOT NULL,
				id          TEXT    NOT NULL,
				enrolled_at INTEGER NOT NULL,
				serial_hex  TEXT    NOT NULL,
				revoked_at  INTEGER,
				PRIMARY KEY (role, id)
			)`,

			// Enrollment tokens. The token itself is never stored, only its hash,
			// so a reader of this database learns which identities are pending but
			// cannot enroll as any of them (threat T8).
			`CREATE TABLE enrollment_tokens (
				hash        TEXT    PRIMARY KEY,
				role        TEXT    NOT NULL,
				id          TEXT    NOT NULL,
				issued_at   INTEGER NOT NULL,
				expires_at  INTEGER NOT NULL,
				consumed_at INTEGER
			)`,
			`CREATE INDEX idx_tokens_identity ON enrollment_tokens(role, id)`,

			// Operator sessions. Same rule as enrollment tokens: the bearer value
			// is stored hashed, never in the clear.
			`CREATE TABLE operator_sessions (
				session_id TEXT    PRIMARY KEY,
				token_hash TEXT    NOT NULL UNIQUE,
				user_id    TEXT    NOT NULL,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				revoked_at INTEGER,
				remote     TEXT    NOT NULL DEFAULT ''
			)`,
			`CREATE INDEX idx_sessions_user ON operator_sessions(user_id)`,
			`CREATE INDEX idx_sessions_expires ON operator_sessions(expires_at)`,

			// Issued grants.
			//
			// The signature is deliberately absent. Storing it would create a
			// second copy of a usable authorization at rest, and nothing here
			// needs it: revocation matches on grant_id, and verification happens
			// against the bytes the operator presents.
			`CREATE TABLE grants (
				grant_id      TEXT    PRIMARY KEY,
				org_id        TEXT    NOT NULL DEFAULT '',
				user_id       TEXT    NOT NULL,
				device_id     TEXT    NOT NULL,
				resource_id   TEXT    NOT NULL,
				policy_id     TEXT    NOT NULL DEFAULT '',
				session_id    TEXT,
				issued_at     INTEGER NOT NULL,
				expires_at    INTEGER NOT NULL,
				max_bytes     INTEGER NOT NULL DEFAULT 0,
				revoked_at    INTEGER,
				revoke_reason TEXT    NOT NULL DEFAULT '',
				FOREIGN KEY (session_id) REFERENCES operator_sessions(session_id)
			)`,
			`CREATE INDEX idx_grants_user ON grants(user_id)`,
			`CREATE INDEX idx_grants_device ON grants(device_id)`,
			`CREATE INDEX idx_grants_session ON grants(session_id)`,
			`CREATE INDEX idx_grants_expires ON grants(expires_at)`,

			// The audit trail.
			//
			// seq is a monotonic identity column, so events have a total order even
			// when two land in the same second. Sorting by timestamp alone would
			// make a denial and the grant that preceded it look simultaneous.
			//
			// No foreign keys here on purpose: an audit row must survive the thing
			// it describes being removed, and referential integrity would make the
			// trail deletable by cascade.
			`CREATE TABLE audit_events (
				seq         INTEGER PRIMARY KEY AUTOINCREMENT,
				ts          INTEGER NOT NULL,
				event       TEXT    NOT NULL,
				org_id      TEXT    NOT NULL DEFAULT '',
				actor_role  TEXT    NOT NULL DEFAULT '',
				actor_id    TEXT    NOT NULL DEFAULT '',
				device_id   TEXT    NOT NULL DEFAULT '',
				resource_id TEXT    NOT NULL DEFAULT '',
				grant_id    TEXT    NOT NULL DEFAULT '',
				session_id  TEXT    NOT NULL DEFAULT '',
				reason      TEXT    NOT NULL DEFAULT '',
				bytes_in    INTEGER NOT NULL DEFAULT 0,
				bytes_out   INTEGER NOT NULL DEFAULT 0,
				duration_ms INTEGER NOT NULL DEFAULT 0,
				detail      TEXT    NOT NULL DEFAULT ''
			)`,
			`CREATE INDEX idx_audit_ts ON audit_events(ts)`,
			`CREATE INDEX idx_audit_event ON audit_events(event)`,
			`CREATE INDEX idx_audit_actor ON audit_events(actor_id)`,
			`CREATE INDEX idx_audit_device ON audit_events(device_id)`,
			`CREATE INDEX idx_audit_grant ON audit_events(grant_id)`,
		},
	},
}

// SchemaVersion is the schema this build expects: one per migration, so
// appending a migration is the only way to advance it.
var SchemaVersion = len(migrations)

// migrate brings the database up to SchemaVersion.
//
// The current version lives in SQLite's own user_version pragma rather than in a
// table of our own. It costs no table, it is set atomically inside the same
// transaction as the statements it describes, and it is readable by any standard
// tool — which matters, because the reason a database was chosen over a custom
// layout was that somebody with a normal client can inspect it.
func (s *Store) migrate() error {
	var current int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}

	if current > SchemaVersion {
		// Refusing is the whole point. A newer schema means columns this build
		// will not write and constraints it does not know about; proceeding would
		// corrupt authorization state rather than merely fail to read it.
		return fmt.Errorf("%w: database is at version %d, this build understands %d",
			ErrSchemaTooNew, current, SchemaVersion)
	}
	if current == SchemaVersion {
		return nil
	}

	for v := current; v < SchemaVersion; v++ {
		m := migrations[v]
		if err := s.applyMigration(v+1, m); err != nil {
			return fmt.Errorf("migrate to schema version %d (%s): %w", v+1, m.description, err)
		}
	}
	return nil
}

// applyMigration runs one step and its version bump in a single transaction.
func (s *Store) applyMigration(version int, m migration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range m.stmts {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}

	// PRAGMA does not accept a bound parameter, so this is the one place an
	// integer is formatted into SQL. It is a loop counter over a compile-time
	// constant slice, never anything a caller supplies.
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, version)); err != nil {
		return fmt.Errorf("set schema version: %w", err)
	}
	return tx.Commit()
}

// firstLine trims a statement down to something readable in an error message.
func firstLine(stmt string) string {
	for i, r := range stmt {
		if r == '\n' {
			return stmt[:i]
		}
	}
	return stmt
}
