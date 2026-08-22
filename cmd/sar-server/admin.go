package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rilegu/secure-access-relay/internal/control/audit"
	"github.com/rilegu/secure-access-relay/internal/control/login"
	"github.com/rilegu/secure-access-relay/internal/storage"
)

// cmdAudit queries the audit trail.
//
// This is the command that makes the trail worth keeping. A log nobody can ask
// questions of is a file that grows; being able to answer "who reached this
// endpoint last Tuesday, and how much did they move" is what makes it evidence.
func cmdAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	var (
		stateDir = fs.String("state-dir", "state", "directory holding the authority and control database")
		since    = fs.Duration("since", 24*time.Hour, "how far back to look")
		event    = fs.String("event", "", "match one event name exactly, for example grant.denied")
		actor    = fs.String("actor", "", "match one actor identifier exactly")
		device   = fs.String("device", "", "match one device identifier exactly")
		resource = fs.String("resource", "", "match one resource identifier exactly")
		grant    = fs.String("grant", "", "match one grant identifier exactly")
		limit    = fs.Int("limit", storage.DefaultAuditLimit, "maximum events to show")
		denials  = fs.Bool("denials", false, "show only refusals: denied grants, denied streams, refused enrollments")
		names    = fs.Bool("events", false, "list the event names the trail can contain, and exit")
		stats    = fs.Bool("stats", false, "report how many events the trail holds and how far back it reaches")
		pruneAge = fs.Duration("prune-older-than", 0, "remove events older than this age; requires -confirm")
		confirm  = fs.Bool("confirm", false, "actually perform a prune")
	)
	_ = fs.Parse(args)

	if *names {
		listEventNames()
		return nil
	}

	dep, err := openDeployment(*stateDir)
	if err != nil {
		return err
	}
	defer dep.close()

	ctx := context.Background()

	if *stats {
		return auditStats(ctx, dep)
	}
	if *pruneAge > 0 {
		return auditPrune(ctx, dep, *pruneAge, *confirm)
	}

	filter := storage.AuditFilter{
		Since:      time.Now().Add(-*since),
		Event:      *event,
		ActorID:    *actor,
		DeviceID:   *device,
		ResourceID: *resource,
		GrantID:    *grant,
		Limit:      *limit,
	}

	var events []storage.AuditEvent
	if *denials {
		// Three queries rather than one, because the filter matches an event name
		// exactly. Pattern matching over an audit trail is a way to accidentally
		// answer a narrower question than the one asked, so the set of denial
		// events is named explicitly here instead.
		for _, name := range []string{
			audit.EventGrantDenied,
			audit.EventStreamDenied,
			audit.EventEnrollDenied,
			audit.EventOperatorLoginDenied,
		} {
			f := filter
			f.Event = name
			batch, err := dep.store.QueryAudit(ctx, f)
			if err != nil {
				return err
			}
			events = append(events, batch...)
		}
		sortBySeqDesc(events)
		if len(events) > *limit {
			events = events[:*limit]
		}
	} else {
		if events, err = dep.store.QueryAudit(ctx, filter); err != nil {
			return err
		}
	}

	total, err := dep.store.CountAudit(ctx)
	if err != nil {
		return err
	}

	if len(events) == 0 {
		fmt.Printf("no matching events in the last %s (%d in the trail)\n", *since, total)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tEVENT\tACTOR\tDEVICE\tRESOURCE\tGRANT\tREASON\tDETAIL")
	for _, e := range events {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			e.At.Local().Format("2006-01-02 15:04:05"),
			e.Event,
			dash(e.ActorID),
			dash(e.DeviceID),
			dash(e.ResourceID),
			dash(shortGrant(e.GrantID)),
			dash(e.Reason),
			dash(transferOrDetail(e)),
		)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Printf("\n%d event(s) shown; %d in the trail\n", len(events), total)
	if len(events) == *limit {
		// Said rather than left to be inferred. A truncated result that looks
		// complete is how somebody concludes an incident was smaller than it was.
		fmt.Fprintf(os.Stderr, "note: output was capped at -limit %d; there may be more\n", *limit)
	}
	return nil
}

// cmdGrants lists or revokes issued grants.
func cmdGrants(args []string) error {
	fs := flag.NewFlagSet("grants", flag.ExitOnError)
	var (
		stateDir = fs.String("state-dir", "state", "directory holding the authority and control database")
		active   = fs.Bool("active", false, "show only grants that are neither revoked nor expired")
		user     = fs.String("user", "", "match one operator identifier exactly")
		device   = fs.String("device", "", "match one device identifier exactly")
		session  = fs.String("session", "", "match one session identifier exactly")
		revoke   = fs.String("revoke", "", "revoke this grant identifier before it expires")
		limit    = fs.Int("limit", storage.DefaultAuditLimit, "maximum grants to show")
	)
	_ = fs.Parse(args)

	dep, err := openDeployment(*stateDir)
	if err != nil {
		return err
	}
	defer dep.close()

	ctx := context.Background()

	if *revoke != "" {
		rec, err := dep.store.RevokeGrant(ctx, *revoke, "revoked_by_admin", storage.AuditEvent{
			Event:     audit.EventGrantRevoked,
			ActorRole: audit.RoleAdmin,
			ActorID:   "admin",
		})
		if errors.Is(err, storage.ErrGrantUnknown) {
			return fmt.Errorf("no grant %s was issued by this control plane", *revoke)
		}
		if err != nil {
			return err
		}
		fmt.Printf("revoked %s (%s -> %s/%s)\n", rec.GrantID, rec.UserID, rec.DeviceID, rec.ResourceID)
		fmt.Fprintln(os.Stderr,
			"note: a running relay drops the streams this grant opened on its next check")
		return nil
	}

	list, err := dep.store.ListGrants(ctx, storage.GrantFilter{
		UserID:     *user,
		DeviceID:   *device,
		SessionID:  *session,
		ActiveOnly: *active,
		Limit:      *limit,
	})
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no matching grants")
		return nil
	}

	now := time.Now()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "GRANT\tSTATE\tOPERATOR\tDEVICE\tRESOURCE\tPOLICY\tSESSION\tEXPIRES")
	for _, g := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			g.GrantID, grantState(g, now), g.UserID, g.DeviceID, g.ResourceID,
			dash(g.PolicyID), dash(shortSession(g.SessionID)),
			g.ExpiresAt.Local().Format("15:04:05"))
	}
	return w.Flush()
}

// cmdSessions lists or revokes operator sessions.
func cmdSessions(args []string) error {
	fs := flag.NewFlagSet("sessions", flag.ExitOnError)
	var (
		stateDir = fs.String("state-dir", "state", "directory holding the authority and control database")
		active   = fs.Bool("active", false, "show only sessions that are neither revoked nor expired")
		user     = fs.String("user", "", "match one operator identifier exactly")
		revoke   = fs.String("revoke", "", "end this session identifier, revoking the grants issued under it")
		limit    = fs.Int("limit", storage.DefaultAuditLimit, "maximum sessions to show")
	)
	_ = fs.Parse(args)

	dep, err := openDeployment(*stateDir)
	if err != nil {
		return err
	}
	defer dep.close()

	ctx := context.Background()

	if *revoke != "" {
		revoked, err := dep.login.End(ctx, *revoke, "admin", login.ReasonRevokedByAdmin)
		if errors.Is(err, storage.ErrSessionUnknown) {
			return fmt.Errorf("no session %s exists", *revoke)
		}
		if err != nil {
			return err
		}
		fmt.Printf("ended %s; revoked %d grant(s)\n", *revoke, len(revoked))
		fmt.Fprintln(os.Stderr,
			"note: a running relay drops the streams those grants opened on its next check")
		return nil
	}

	list, err := dep.store.ListSessions(ctx, storage.SessionFilter{
		UserID:     *user,
		ActiveOnly: *active,
		Limit:      *limit,
	})
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no matching sessions")
		return nil
	}

	now := time.Now()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SESSION\tSTATE\tOPERATOR\tOPENED\tEXPIRES\tFROM")
	for _, r := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.SessionID, sessionState(r, now), r.UserID,
			r.CreatedAt.Local().Format("2006-01-02 15:04"),
			r.ExpiresAt.Local().Format("2006-01-02 15:04"),
			dash(r.Remote))
	}
	return w.Flush()
}

// grantState renders why a grant is or is not usable.
//
// Three states, not two. "Revoked" and "expired" are different facts, and an
// operator asking why their access stopped deserves to be told which one applies
// rather than a single word that covers both.
func grantState(g storage.GrantRecord, now time.Time) string {
	switch {
	case g.Revoked():
		return "REVOKED"
	case g.Expired(now):
		return "expired"
	default:
		return "active"
	}
}

func sessionState(r storage.SessionRecord, now time.Time) string {
	switch {
	case r.RevokedAt != nil:
		return "ENDED"
	case !r.Active(now):
		return "expired"
	default:
		return "active"
	}
}

// listEventNames prints the closed set of event names, so an administrator can
// discover what is queryable without reading the source.
func listEventNames() {
	groups := []struct {
		title  string
		events []string
	}{
		{"enrollment and identity", []string{
			audit.EventDeviceEnrolled, audit.EventDeviceRevoked,
			audit.EventOperatorEnrolled, audit.EventOperatorRevoked,
			audit.EventEnrollDenied,
		}},
		{"connections", []string{
			audit.EventDeviceConnected, audit.EventDeviceDisconnected,
		}},
		{"operator sessions", []string{
			audit.EventOperatorLogin, audit.EventOperatorLoginDenied,
			audit.EventOperatorLogout, audit.EventOperatorSessionEnded,
		}},
		{"authorization", []string{
			audit.EventGrantCreated, audit.EventGrantDenied, audit.EventGrantRevoked,
		}},
		{"access", []string{
			audit.EventStreamOpened, audit.EventStreamDenied, audit.EventStreamClosed,
		}},
		{"administration", []string{audit.EventAdminAction}},
	}
	for _, g := range groups {
		fmt.Printf("%s:\n  %s\n", g.title, strings.Join(g.events, "  "))
	}
}

// transferOrDetail shows the transfer totals for a finished stream and the free
// text otherwise, so one column carries whichever is meaningful.
func transferOrDetail(e storage.AuditEvent) string {
	if e.Event == audit.EventStreamClosed {
		return fmt.Sprintf("%s in / %s out, %dms",
			humanBytes(e.BytesIn), humanBytes(e.BytesOut), e.DurationMS)
	}
	return e.Detail
}

// humanBytes renders a byte count compactly. Binary units, because the frame and
// window limits this system is built from are powers of two.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	value := float64(n)
	for _, suffix := range []string{"KiB", "MiB", "GiB", "TiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f%s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1fPiB", value/unit)
}

// shortGrant trims a grant identifier for tabular output. The full value is
// still what -grant matches on, and the prefix is enough to recognise one.
func shortGrant(id string) string {
	if len(id) > 14 {
		return id[:14] + "..."
	}
	return id
}

func shortSession(id string) string {
	if len(id) > 12 {
		return id[:12] + "..."
	}
	return id
}

// dash renders an empty column as a dash, so an absent value is visibly absent
// rather than looking like the column ran together with the next one.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// sortBySeqDesc puts the newest events first. Insertion sort: the slice is
// bounded by -limit, which is a hundred rows by default.
func sortBySeqDesc(events []storage.AuditEvent) {
	for i := 1; i < len(events); i++ {
		for j := i; j > 0 && events[j].Seq > events[j-1].Seq; j-- {
			events[j], events[j-1] = events[j-1], events[j]
		}
	}
}

// auditStats reports the size and reach of the trail.
//
// Growth is worth being able to see before it becomes a disk problem: a control
// plane that has run out of disk cannot write the audit event for the decision
// it is about to make, and under invariant 11 that means it must refuse the
// decision. Unbounded growth is a slow denial of service on the authorization
// path, not a safe default.
func auditStats(ctx context.Context, dep *deployment) error {
	count, oldest, err := dep.store.AuditSpan(ctx)
	if err != nil {
		return err
	}
	if count == 0 {
		fmt.Println("the audit trail is empty")
		return nil
	}
	fmt.Printf("events:  %d\n", count)
	fmt.Printf("oldest:  %s (%s ago)\n",
		oldest.Local().Format(time.RFC3339),
		time.Since(oldest).Round(time.Hour))
	fmt.Printf("database: %s\n", dep.store.Path())
	return nil
}

// auditPrune removes events older than an age, once an administrator has said so
// explicitly.
//
// Two gates, deliberately. The age must be given — there is no default retention
// period, because choosing one on an administrator's behalf is choosing how much
// evidence they keep. And -confirm must be passed, because the first invocation
// of a destructive command is usually someone finding out what it does.
func auditPrune(ctx context.Context, dep *deployment, age time.Duration, confirm bool) error {
	cutoff := time.Now().Add(-age)

	count, oldest, err := dep.store.AuditSpan(ctx)
	if err != nil {
		return err
	}
	if count == 0 {
		fmt.Println("the audit trail is empty; nothing to prune")
		return nil
	}

	if !confirm {
		// A dry run reports the damage before doing any. Counting is a separate
		// query from deleting, so this number can be stale by the time a real
		// prune runs - which is why it is described as an estimate rather than
		// printed as though it were the outcome.
		doomed, err := dep.store.QueryAudit(ctx, storage.AuditFilter{
			Until: cutoff,
			Limit: storage.MaxAuditLimit,
		})
		if err != nil {
			return err
		}
		fmt.Printf("would remove roughly %d of %d event(s) older than %s\n",
			len(doomed), count, cutoff.Local().Format(time.RFC3339))
		fmt.Printf("the trail currently reaches back to %s\n", oldest.Local().Format(time.RFC3339))
		if len(doomed) == storage.MaxAuditLimit {
			fmt.Printf("(the estimate is capped at %d; the real number may be larger)\n",
				storage.MaxAuditLimit)
		}
		fmt.Fprintln(os.Stderr, "nothing was removed; pass -confirm to proceed")
		return nil
	}

	removed, err := dep.store.PruneAudit(ctx, cutoff, "admin")
	if err != nil {
		return err
	}
	fmt.Printf("removed %d event(s) older than %s\n",
		removed, cutoff.Local().Format(time.RFC3339))
	// The prune itself is in the trail. That record is what stops a gap in the
	// history looking like a period when nothing happened.
	fmt.Println("the prune is recorded in the trail as admin.action")
	return nil
}
