package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// legacyState is the shape of the JSON file this package used before SQLite.
type legacyState struct {
	Devices   map[string]Record `json:"devices"`
	Operators map[string]Record `json:"operators"`
	Tokens    map[string]Token  `json:"tokens"`
}

// ImportLegacyJSON moves an existing JSON store into the database.
//
// A deployment that enrolled devices under the old file must not silently lose
// them when the binary is upgraded: every device would keep a certificate the
// control plane no longer recognises, and the only visible symptom would be
// endpoints that stop connecting. Importing is cheap; the alternative is a
// support incident that looks like a networking fault.
//
// It runs only when the database has no identities. A second run would either
// resurrect identities an administrator deliberately revoked or overwrite
// current serials with stale ones, so an already-populated database is left
// alone and the file is reported rather than merged.
//
// The old file is not deleted. Rolling back to the previous binary should still
// work, and deleting the only copy of enrollment state to save a few kilobytes
// would be a poor trade.
func (s *Store) ImportLegacyJSON(ctx context.Context, path string) (imported int, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read legacy store %s: %w", path, err)
	}

	var populated bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM identities)`).Scan(&populated); err != nil {
		return 0, err
	}
	if populated {
		return 0, nil
	}

	var st legacyState
	if err := json.Unmarshal(b, &st); err != nil {
		// A corrupt legacy file is a startup failure, not something to skip past.
		// Starting empty would let every enrolled device be replaced by whoever
		// asks next, which is the failure this whole store exists to prevent.
		return 0, fmt.Errorf("parse legacy store %s: %w", path, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	for role, records := range map[string]map[string]Record{
		"device":   st.Devices,
		"operator": st.Operators,
	} {
		for _, r := range records {
			// The role in the file's key is authoritative, not the one in the
			// record: the old format stored records in per-role maps and the field
			// was not always set.
			r.Role = role
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO identities (role, id, enrolled_at, serial_hex, revoked_at)
				 VALUES (?, ?, ?, ?, ?)`,
				r.Role, r.ID, unix(r.EnrolledAt), r.SerialHex, nullUnix(r.RevokedAt)); err != nil {
				return 0, fmt.Errorf("import identity %s/%s: %w", r.Role, r.ID, err)
			}
			imported++
		}
	}

	for _, t := range st.Tokens {
		// Unconsumed tokens carry forward; consumed ones do not. A consumed token
		// can never be used again, so the only thing importing it would preserve
		// is a row nobody reads.
		if t.ConsumedAt != nil {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO enrollment_tokens (hash, role, id, issued_at, expires_at, consumed_at)
			 VALUES (?, ?, ?, ?, ?, NULL)`,
			t.Hash, t.Role, t.ID, unix(t.IssuedAt), unix(t.ExpiresAt)); err != nil {
			return 0, fmt.Errorf("import enrollment token: %w", err)
		}
		imported++
	}

	if imported > 0 {
		if err := AppendAuditTx(ctx, tx, AuditEvent{
			At:        time.Now().UTC(),
			Event:     "admin.action",
			ActorRole: "admin",
			Detail:    fmt.Sprintf("imported %d records from the legacy JSON store at %s", imported, path),
		}); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return imported, nil
}
