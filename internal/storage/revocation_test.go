package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

// seedGrant stores a live grant belonging to one user, device and session.
func seedGrant(t *testing.T, s *Store, grantID, userID, deviceID, sessionID string) {
	t.Helper()
	now := time.Now().UTC()
	err := s.RecordGrant(context.Background(), GrantRecord{
		GrantID:    grantID,
		UserID:     userID,
		DeviceID:   deviceID,
		ResourceID: "res_fixture",
		PolicyID:   "pol_test",
		SessionID:  sessionID,
		IssuedAt:   now,
		ExpiresAt:  now.Add(30 * time.Minute),
	}, AuditEvent{Event: "grant.created", ActorID: userID, GrantID: grantID})
	if err != nil {
		t.Fatalf("record grant %s: %v", grantID, err)
	}
}

// seedSession stores a live operator session and returns its bearer token.
func seedSession(t *testing.T, s *Store, sessionID, userID string) string {
	t.Helper()
	token := "token-for-" + sessionID
	now := time.Now().UTC()
	err := s.CreateSession(context.Background(), SessionRecord{
		SessionID: sessionID,
		TokenHash: HashToken(token),
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Remote:    "127.0.0.1:1234",
	}, AuditEvent{Event: "operator.login", ActorID: userID, SessionID: sessionID})
	if err != nil {
		t.Fatalf("create session %s: %v", sessionID, err)
	}
	return token
}

// TestGrantAndItsAuditEventCommitTogether checks the property that makes the
// trail evidence rather than a log.
//
// A grant that exists without a record of it is access nothing accounts for.
// They are written in one transaction, so there is no window where one exists
// without the other.
func TestGrantAndItsAuditEventCommitTogether(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	seedGrant(t, s, "grn_1", "usr_a", "dev_1", "")

	events, err := s.QueryAudit(ctx, AuditFilter{GrantID: "grn_1"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 || events[0].Event != "grant.created" {
		t.Fatalf("a stored grant has %d audit events, want exactly one grant.created", len(events))
	}
}

// TestRevokedGrantIsNotUsable checks the state a relay reads on stream open.
func TestRevokedGrantIsNotUsable(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	seedGrant(t, s, "grn_live", "usr_a", "dev_1", "")

	before, err := s.LookupGrant(ctx, "grn_live")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !before.Usable(time.Now()) {
		t.Fatal("a freshly issued grant is not usable")
	}

	if _, err := s.RevokeGrant(ctx, "grn_live", "revoked_by_admin",
		AuditEvent{Event: "grant.revoked", ActorRole: "admin"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	after, err := s.LookupGrant(ctx, "grn_live")
	if err != nil {
		t.Fatalf("lookup after revocation: %v", err)
	}
	if after.Usable(time.Now()) {
		t.Fatal("a revoked grant is still usable")
	}
	if !after.Revoked() {
		t.Fatal("the grant does not report itself revoked")
	}
	if after.Expired(time.Now()) {
		t.Fatal("a revoked grant reported itself expired; the two must stay distinguishable")
	}
}

// TestRevokingTwiceRecordsOneEvent checks that a worried administrator revoking
// the same grant again does not add a second event describing a change that did
// not happen.
func TestRevokingTwiceRecordsOneEvent(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	seedGrant(t, s, "grn_x", "usr_a", "dev_1", "")
	for range 3 {
		if _, err := s.RevokeGrant(ctx, "grn_x", "revoked_by_admin",
			AuditEvent{Event: "grant.revoked", ActorRole: "admin"}); err != nil {
			t.Fatalf("revoke: %v", err)
		}
	}

	events, err := s.QueryAudit(ctx, AuditFilter{Event: "grant.revoked", GrantID: "grn_x"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("revoking three times recorded %d events, want 1", len(events))
	}
}

// TestUnknownGrantIsDistinguishable checks that a grant nobody issued is
// reported as unknown rather than as merely unusable.
//
// The relay needs the distinction: an unknown grant identifier with a valid
// signature would mean the signing key is being used somewhere this control
// plane cannot see.
func TestUnknownGrantIsDistinguishable(t *testing.T) {
	s := open(t)
	if _, err := s.LookupGrant(context.Background(), "grn_never_issued"); !errors.Is(err, ErrGrantUnknown) {
		t.Fatalf("LookupGrant for an unissued grant = %v, want ErrGrantUnknown", err)
	}
}

// TestRevokingASessionCascadesToItsGrants is what makes logout meaningful.
//
// Ending a session that leaves its grants valid would stop the next request and
// none of the access already granted, which is the opposite of what an operator
// pressing logout believes happened.
func TestRevokingASessionCascadesToItsGrants(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	seedSession(t, s, "ses_1", "usr_a")
	seedSession(t, s, "ses_2", "usr_a")
	seedGrant(t, s, "grn_a1", "usr_a", "dev_1", "ses_1")
	seedGrant(t, s, "grn_a2", "usr_a", "dev_2", "ses_1")
	seedGrant(t, s, "grn_b1", "usr_a", "dev_1", "ses_2")

	revoked, err := s.RevokeGrantsWhere(ctx, ScopeSession, "ses_1", "session_ended",
		AuditEvent{Event: "grant.revoked", ActorRole: "operator", ActorID: "usr_a"})
	if err != nil {
		t.Fatalf("cascade: %v", err)
	}
	if len(revoked) != 2 {
		t.Fatalf("cascading over ses_1 revoked %d grants, want 2", len(revoked))
	}

	// The other session's grant is untouched: ending one session must not end
	// another the same operator legitimately holds.
	other, err := s.LookupGrant(ctx, "grn_b1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if other.Revoked() {
		t.Fatal("revoking one session revoked a grant belonging to another")
	}

	// One audit event per grant, not one for the cascade.
	events, err := s.QueryAudit(ctx, AuditFilter{Event: "grant.revoked"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("a cascade over 2 grants recorded %d events, want one per grant", len(events))
	}
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.GrantID] = true
	}
	if !seen["grn_a1"] || !seen["grn_a2"] {
		t.Fatalf("cascade events do not name each grant: %v", seen)
	}
}

// TestRevokingAnIdentityCascadesToItsGrants checks the same for a revoked user.
func TestRevokingAnIdentityCascadesToItsGrants(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	seedGrant(t, s, "grn_a", "usr_gone", "dev_1", "")
	seedGrant(t, s, "grn_b", "usr_stays", "dev_1", "")

	revoked, err := s.RevokeGrantsWhere(ctx, ScopeUser, "usr_gone", "identity_revoked",
		AuditEvent{Event: "grant.revoked", ActorRole: "admin"})
	if err != nil {
		t.Fatalf("cascade: %v", err)
	}
	if len(revoked) != 1 || revoked[0].GrantID != "grn_a" {
		t.Fatalf("cascading over usr_gone revoked %v, want only grn_a", revoked)
	}

	kept, err := s.LookupGrant(ctx, "grn_b")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if kept.Revoked() {
		t.Fatal("revoking one identity revoked another identity's grant")
	}
}

// TestSessionLookupDistinguishesExpiredFromRevoked checks that an operator is
// told which of the two happened.
//
// One is the passage of time and the other is a decision somebody made. An
// operator cut off mid-incident deserves to know which.
func TestSessionLookupDistinguishesExpiredFromRevoked(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	live := seedSession(t, s, "ses_live", "usr_a")
	if _, err := s.LookupSession(ctx, live); err != nil {
		t.Fatalf("live session lookup: %v", err)
	}

	// Revoked.
	if _, err := s.RevokeSession(ctx, "ses_live", "logout",
		AuditEvent{Event: "operator.logout", ActorID: "usr_a"}); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if _, err := s.LookupSession(ctx, live); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("lookup of a revoked session = %v, want ErrSessionRevoked", err)
	}

	// Expired.
	expiredToken := "already-stale"
	now := time.Now().UTC()
	if err := s.CreateSession(ctx, SessionRecord{
		SessionID: "ses_old",
		TokenHash: HashToken(expiredToken),
		UserID:    "usr_a",
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}, AuditEvent{Event: "operator.login", ActorID: "usr_a"}); err != nil {
		t.Fatalf("create expired session: %v", err)
	}
	if _, err := s.LookupSession(ctx, expiredToken); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("lookup of an expired session = %v, want ErrSessionExpired", err)
	}
}

// TestSessionTokenIsNotStoredInTheClear checks that the database never holds a
// usable bearer value.
//
// Someone who reads this file must learn that a session exists — that is what an
// audit trail is for — and must not be able to use it.
func TestSessionTokenIsNotStoredInTheClear(t *testing.T) {
	s := open(t)
	token := seedSession(t, s, "ses_secret", "usr_a")

	var found int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM operator_sessions WHERE token_hash = ?`, token).Scan(&found)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if found != 0 {
		t.Fatal("the bearer token was stored verbatim; only its hash may be persisted")
	}
}

// TestActiveOnlyExcludesRevokedAndExpired checks the listing an administrator
// uses to answer "what access exists right now".
func TestActiveOnlyExcludesRevokedAndExpired(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	seedGrant(t, s, "grn_live", "usr_a", "dev_1", "")
	seedGrant(t, s, "grn_dead", "usr_a", "dev_1", "")
	if _, err := s.RevokeGrant(ctx, "grn_dead", "revoked_by_admin",
		AuditEvent{Event: "grant.revoked", ActorRole: "admin"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// A grant that simply ran out.
	past := time.Now().UTC().Add(-time.Hour)
	if err := s.RecordGrant(ctx, GrantRecord{
		GrantID: "grn_stale", UserID: "usr_a", DeviceID: "dev_1", ResourceID: "res_fixture",
		IssuedAt: past.Add(-30 * time.Minute), ExpiresAt: past,
	}, AuditEvent{Event: "grant.created", ActorID: "usr_a", GrantID: "grn_stale"}); err != nil {
		t.Fatalf("record stale grant: %v", err)
	}

	active, err := s.ListGrants(ctx, GrantFilter{UserID: "usr_a", ActiveOnly: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(active) != 1 || active[0].GrantID != "grn_live" {
		t.Fatalf("active listing returned %v, want only grn_live", active)
	}

	all, err := s.ListGrants(ctx, GrantFilter{UserID: "usr_a"})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("unfiltered listing returned %d grants, want 3", len(all))
	}
}
