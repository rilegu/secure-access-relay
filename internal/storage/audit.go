package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// AuditEvent is one row of the audit trail.
//
// The field set is fixed rather than a free-form map. An audit trail is evidence,
// and evidence that can carry arbitrary keys becomes a place where the important
// field is spelled differently in the one record somebody needs. Anything that
// does not fit goes in Detail, which is explicitly not queried.
//
// # What must never appear here
//
// Bearer tokens, private keys, grant signatures, target response bodies, or
// payload bytes. An audit trail records that access happened and under what
// authority; a trail that also contained the traffic would turn every read of it
// into a second disclosure of whatever was being protected.
type AuditEvent struct {
	// Seq is the monotonic identity assigned on insert. Zero until then.
	//
	// It exists because timestamps are stored to the second, and a grant and the
	// stream it authorized routinely land in the same second. Sorting by time
	// alone would present them as simultaneous and lose the causal order.
	Seq int64

	// At is when the event happened. Set on insert if left zero.
	At time.Time

	// Event is one of the names in this package's Event* constants, supplied by
	// internal/control/audit.
	Event string

	OrgID string

	// ActorRole and ActorID are who caused the event: an operator, a device, or
	// the administrator running the CLI.
	ActorRole string
	ActorID   string

	// DeviceID, ResourceID, GrantID, SessionID are the subjects, as applicable.
	DeviceID   string
	ResourceID string
	GrantID    string
	SessionID  string

	// Reason is a reason code from the fixed list in docs/protocol.md, present on
	// every denial and on every close.
	Reason string

	// BytesIn, BytesOut and DurationMS describe a finished stream.
	BytesIn    uint64
	BytesOut   uint64
	DurationMS int64

	// Detail is free text for anything the fixed fields cannot hold. Never
	// queried, never parsed — it is there for a human reading one record.
	Detail string
}

// AppendAudit writes one event.
//
// Append-only: there is no update and no delete anywhere in this package. A
// trail that can be edited by the software that writes it is not evidence.
func (s *Store) AppendAudit(ctx context.Context, e AuditEvent) error {
	return appendAudit(ctx, s.db, e)
}

// AppendAuditTx writes one event inside a caller's transaction.
//
// This is what lets a decision and the record of that decision commit together.
// Issuing a grant and failing to log it would leave access that nothing accounts
// for; logging one that was never issued would put a fiction in the evidence.
// Either is worse than failing the request, so both go in one transaction.
func AppendAuditTx(ctx context.Context, tx *sql.Tx, e AuditEvent) error {
	return appendAudit(ctx, tx, e)
}

// execer is satisfied by both *sql.DB and *sql.Tx, so the insert is written once.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func appendAudit(ctx context.Context, x execer, e AuditEvent) error {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if e.Event == "" {
		return fmt.Errorf("storage: refusing to append an audit event with no name")
	}
	_, err := x.ExecContext(ctx,
		`INSERT INTO audit_events
		    (ts, event, org_id, actor_role, actor_id, device_id, resource_id,
		     grant_id, session_id, reason, bytes_in, bytes_out, duration_ms, detail)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		unix(e.At), e.Event, e.OrgID, e.ActorRole, e.ActorID, e.DeviceID,
		e.ResourceID, e.GrantID, e.SessionID, e.Reason,
		int64(e.BytesIn), int64(e.BytesOut), e.DurationMS, e.Detail)
	if err != nil {
		return fmt.Errorf("storage: append audit event %q: %w", e.Event, err)
	}
	return nil
}

// AuditFilter narrows an audit query. Zero values mean "no constraint".
type AuditFilter struct {
	Since time.Time
	Until time.Time

	// Event, ActorID, DeviceID, ResourceID, GrantID match exactly. Exact match
	// rather than pattern match is deliberate: a wildcard over an audit trail is
	// a way to accidentally answer a narrower question than the one asked.
	Event      string
	ActorID    string
	DeviceID   string
	ResourceID string
	GrantID    string

	// Limit bounds the result. Zero applies DefaultAuditLimit, because an
	// unbounded query against an unbounded table is a way to run a control plane
	// out of memory from the CLI.
	Limit int
}

// DefaultAuditLimit is how many events a query returns when none is asked for.
const DefaultAuditLimit = 100

// MaxAuditLimit caps any single query.
const MaxAuditLimit = 10000

// QueryAudit returns matching events, newest first.
//
// Every filter becomes a bound parameter. The SQL itself is assembled only from
// this function's own string literals — a caller's value never becomes part of
// the statement text, only ever an argument to it.
func (s *Store) QueryAudit(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	var where []string
	var args []any

	add := func(clause string, value any) {
		where = append(where, clause)
		args = append(args, value)
	}
	if !f.Since.IsZero() {
		add("ts >= ?", unix(f.Since))
	}
	if !f.Until.IsZero() {
		add("ts <= ?", unix(f.Until))
	}
	if f.Event != "" {
		add("event = ?", f.Event)
	}
	if f.ActorID != "" {
		add("actor_id = ?", f.ActorID)
	}
	if f.DeviceID != "" {
		add("device_id = ?", f.DeviceID)
	}
	if f.ResourceID != "" {
		add("resource_id = ?", f.ResourceID)
	}
	if f.GrantID != "" {
		add("grant_id = ?", f.GrantID)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = DefaultAuditLimit
	}
	if limit > MaxAuditLimit {
		limit = MaxAuditLimit
	}

	query := `SELECT seq, ts, event, org_id, actor_role, actor_id, device_id,
	                 resource_id, grant_id, session_id, reason,
	                 bytes_in, bytes_out, duration_ms, detail
	            FROM audit_events`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	// Newest first, and seq breaks ties within a second so the order is total.
	query += " ORDER BY seq DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("storage: query audit: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var ts int64
		var in, outBytes int64
		if err := rows.Scan(&e.Seq, &ts, &e.Event, &e.OrgID, &e.ActorRole, &e.ActorID,
			&e.DeviceID, &e.ResourceID, &e.GrantID, &e.SessionID, &e.Reason,
			&in, &outBytes, &e.DurationMS, &e.Detail); err != nil {
			return nil, fmt.Errorf("storage: scan audit row: %w", err)
		}
		e.At = fromUnix(ts)
		e.BytesIn, e.BytesOut = uint64(in), uint64(outBytes)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountAudit reports how many events the trail holds, for status output.
func (s *Store) CountAudit(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&n)
	return n, err
}
