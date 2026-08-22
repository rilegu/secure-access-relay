package storage

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// open creates a store in a temporary directory.
func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestMigrationIsIdempotent checks that reopening an existing database does not
// try to create its tables again.
func TestMigrationIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := first.PutRecord(Record{Role: "device", ID: "dev_a", EnrolledAt: time.Now(), SerialHex: "01"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = second.Close() }()

	if _, err := second.Lookup("device", "dev_a"); err != nil {
		t.Fatalf("record did not survive reopen: %v", err)
	}
}

// TestSchemaNewerThanBuildIsRefused checks the startup rule from ADR-0011.
//
// A database written by a newer build has columns this one will not write and
// constraints it does not know about. Reading it best-effort would corrupt
// authorization state rather than merely fail, so refusing is the only safe
// answer.
func TestSchemaNewerThanBuildIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Pretend a future build has been here.
	if _, err := s.db.Exec(`PRAGMA user_version = 999`); err != nil {
		t.Fatalf("bump version: %v", err)
	}
	_ = s.Close()

	_, err = Open(path)
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Open against a newer schema returned %v, want ErrSchemaTooNew", err)
	}
}

// TestConsumeTokenIsSingleUseUnderConcurrency is the property threat T8 depends
// on.
//
// Two enrollment requests arriving together must not both succeed. The check and
// the mark are one transaction with the condition in the UPDATE, so the database
// decides the race rather than application code that read a stale value.
func TestConsumeTokenIsSingleUseUnderConcurrency(t *testing.T) {
	s := open(t)

	const token = "enrollment-token-value"
	if err := s.PutToken(Token{
		Hash:      HashToken(token),
		Role:      "device",
		ID:        "dev_race",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("put token: %v", err)
	}

	const racers = 8
	var wg sync.WaitGroup
	results := make([]error, racers)
	start := make(chan struct{})

	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, results[i] = s.ConsumeToken(token)
		}()
	}
	close(start)
	wg.Wait()

	succeeded := 0
	for i, err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrTokenConsumed):
			// The expected outcome for every loser.
		default:
			t.Fatalf("racer %d failed with an unexpected error: %v", i, err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent enrollments succeeded; a single-use token must be consumed exactly once", succeeded, racers)
	}
}

// TestExpiredTokenIsNotConsumed checks that an expired token is reported as
// expired rather than consumed.
//
// The distinction matters for the audit trail: consuming it first would record
// that a token was used when it was not.
func TestExpiredTokenIsNotConsumed(t *testing.T) {
	s := open(t)

	const token = "stale"
	if err := s.PutToken(Token{
		Hash:      HashToken(token),
		Role:      "device",
		ID:        "dev_stale",
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("put token: %v", err)
	}

	if _, err := s.ConsumeToken(token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("ConsumeToken on an expired token = %v, want ErrTokenExpired", err)
	}
}

// TestRevokedIdentityIsRefusedByLookup checks that revocation is enforced where
// identities are resolved, not left to each caller to remember.
func TestRevokedIdentityIsRefusedByLookup(t *testing.T) {
	s := open(t)

	if err := s.PutRecord(Record{Role: "operator", ID: "usr_a", EnrolledAt: time.Now(), SerialHex: "ab"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := s.Lookup("operator", "usr_a"); err != nil {
		t.Fatalf("lookup before revocation: %v", err)
	}
	if err := s.Revoke("operator", "usr_a"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.Lookup("operator", "usr_a"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("lookup after revocation = %v, want ErrRevoked", err)
	}
}

// TestRolesAreSeparateNamespaces checks that a device and an operator may share
// an identifier without one resolving as the other.
func TestRolesAreSeparateNamespaces(t *testing.T) {
	s := open(t)

	if err := s.PutRecord(Record{Role: "device", ID: "shared", EnrolledAt: time.Now(), SerialHex: "01"}); err != nil {
		t.Fatalf("put device: %v", err)
	}
	if err := s.PutRecord(Record{Role: "operator", ID: "shared", EnrolledAt: time.Now(), SerialHex: "02"}); err != nil {
		t.Fatalf("put operator: %v", err)
	}

	dev, err := s.Lookup("device", "shared")
	if err != nil {
		t.Fatalf("lookup device: %v", err)
	}
	op, err := s.Lookup("operator", "shared")
	if err != nil {
		t.Fatalf("lookup operator: %v", err)
	}
	if dev.SerialHex == op.SerialHex {
		t.Fatal("a device and an operator sharing a name resolved to the same record")
	}

	// Revoking one must not revoke the other.
	if err := s.Revoke("device", "shared"); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	if _, err := s.Lookup("operator", "shared"); err != nil {
		t.Fatalf("revoking the device also revoked the operator: %v", err)
	}
}

// TestAuditIsAppendOnlyAndOrdered checks that events keep their causal order
// even when several land in the same second.
//
// Timestamps are stored to the second, so a grant and the stream it authorized
// routinely share one. Ordering by sequence is what keeps them distinguishable.
func TestAuditIsAppendOnlyAndOrdered(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	at := time.Now().UTC()
	names := []string{"grant.created", "stream.opened", "stream.closed"}
	for _, name := range names {
		if err := s.AppendAudit(ctx, AuditEvent{
			At: at, Event: name, ActorID: "usr_a", DeviceID: "dev_a", GrantID: "grn_1",
		}); err != nil {
			t.Fatalf("append %s: %v", name, err)
		}
	}

	events, err := s.QueryAudit(ctx, AuditFilter{GrantID: "grn_1"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != len(names) {
		t.Fatalf("got %d events, want %d", len(events), len(names))
	}
	// Newest first, so the reverse of insertion order.
	for i, e := range events {
		want := names[len(names)-1-i]
		if e.Event != want {
			t.Fatalf("event %d is %q, want %q; same-second events lost their order", i, e.Event, want)
		}
	}
	if events[0].Seq <= events[1].Seq {
		t.Fatal("sequence numbers are not monotonic")
	}
}

// TestAuditFilters checks that each filter narrows on the dimension it names.
func TestAuditFilters(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	seed := []AuditEvent{
		{Event: "stream.opened", ActorID: "usr_a", DeviceID: "dev_1", ResourceID: "res_x"},
		{Event: "stream.opened", ActorID: "usr_b", DeviceID: "dev_2", ResourceID: "res_y"},
		{Event: "stream.denied", ActorID: "usr_a", DeviceID: "dev_2", ResourceID: "res_y"},
	}
	for _, e := range seed {
		if err := s.AppendAudit(ctx, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	cases := []struct {
		name   string
		filter AuditFilter
		want   int
	}{
		{"by actor", AuditFilter{ActorID: "usr_a"}, 2},
		{"by device", AuditFilter{DeviceID: "dev_2"}, 2},
		{"by event", AuditFilter{Event: "stream.denied"}, 1},
		{"by resource", AuditFilter{ResourceID: "res_y"}, 2},
		{"combined", AuditFilter{ActorID: "usr_a", DeviceID: "dev_2"}, 1},
		{"no match", AuditFilter{ActorID: "nobody"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.QueryAudit(ctx, tc.filter)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d events, want %d", len(got), tc.want)
			}
		})
	}
}

// TestAuditQuoteInFilterIsNotSQL checks that a value containing SQL syntax is
// treated as a value.
//
// The whole reason a query language was avoided until now is that it introduces
// this failure mode. Identifiers reach the control plane from certificates and
// request bodies, so the check is worth having explicitly.
func TestAuditQuoteInFilterIsNotSQL(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	hostile := `' OR 1=1 --`
	if err := s.AppendAudit(ctx, AuditEvent{Event: "stream.opened", ActorID: "usr_real"}); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := s.QueryAudit(ctx, AuditFilter{ActorID: hostile})
	if err != nil {
		t.Fatalf("query with a hostile filter failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a filter containing SQL syntax matched %d rows; it must match none", len(got))
	}
}
