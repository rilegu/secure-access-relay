// Package audit names the events the control plane records and writes them.
//
// The event vocabulary lives here rather than at each call site so that the set
// is closed and reviewable. An audit trail whose names are invented where they
// are emitted ends up with three spellings of the same event, and the query that
// matters finds two of them.
//
// Storage of the events, and the guarantee that a decision and its record commit
// together, belong to internal/storage. This package decides *what* is worth
// recording and with which name.
//
// # What must never be recorded
//
// Bearer tokens, private keys, grant signatures, target response bodies, or
// payload bytes. The trail says that access happened and under what authority.
// A trail that also held the traffic would make reading the evidence a second
// disclosure of whatever was being protected.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/rilegu/secure-access-relay/internal/storage"
)

// The closed set of audit event names.
//
// Names are dotted subject.verb, past tense: the trail records what happened,
// never what was attempted and might still be in progress.
const (
	// Enrollment and identity lifecycle.
	EventDeviceEnrolled   = "device.enrolled"
	EventDeviceRevoked    = "device.revoked"
	EventOperatorEnrolled = "operator.enrolled"
	EventOperatorRevoked  = "operator.revoked"
	EventEnrollDenied     = "enroll.denied"

	// Data-plane connection lifecycle.
	EventDeviceConnected    = "device.connected"
	EventDeviceDisconnected = "device.disconnected"

	// Operator sessions.
	EventOperatorLogin        = "operator.login"
	EventOperatorLoginDenied  = "operator.login_denied"
	EventOperatorLogout       = "operator.logout"
	EventOperatorSessionEnded = "operator.session_revoked"

	// Authorization.
	EventGrantCreated = "grant.created"
	EventGrantDenied  = "grant.denied"
	EventGrantRevoked = "grant.revoked"

	// Streams. A stream is the unit of actual access: opened says somebody
	// reached a resource, closed says how much they moved and why it ended.
	EventStreamOpened = "stream.opened"
	EventStreamDenied = "stream.denied"
	EventStreamClosed = "stream.closed"

	// Administration performed through the CLI.
	EventAdminAction = "admin.action"
)

// Actor roles, matching the certificate roles in internal/ca plus the
// administrator running the CLI, who holds no certificate at all.
const (
	RoleOperator = "operator"
	RoleDevice   = "device"
	RoleAdmin    = "admin"
	RoleSystem   = "system"
)

// Recorder writes audit events.
//
// A failure to record is logged and swallowed on the paths where the event
// describes something that already happened — a stream that closed, an endpoint
// that disconnected. Those are reports, and failing the operation after the fact
// would not un-happen it.
//
// Events that must not be lost do not come through here. A grant's record
// commits in the same transaction as the grant itself, through
// storage.RecordGrant, so there is no path where the access exists and the
// evidence does not.
type Recorder struct {
	store *storage.Store
	log   *slog.Logger
}

// NewRecorder creates a recorder. A nil store yields a recorder that does
// nothing, so a component can be constructed without persistence in tests
// without every call site checking.
func NewRecorder(store *storage.Store, log *slog.Logger) *Recorder {
	if log == nil {
		log = slog.Default()
	}
	return &Recorder{store: store, log: log}
}

// Record writes one event.
func (r *Recorder) Record(ctx context.Context, e storage.AuditEvent) {
	if r == nil || r.store == nil {
		return
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if err := r.store.AppendAudit(ctx, e); err != nil {
		// Logged loudly. An audit trail that quietly stops accepting writes is
		// worse than one that was never there, because the gap looks like an
		// absence of activity rather than an absence of recording.
		r.log.Error("audit event could not be recorded",
			"event", e.Event, "grant_id", e.GrantID, "error", err)
	}
}

// StreamOpened records that an operator reached a resource.
func (r *Recorder) StreamOpened(ctx context.Context, userID, deviceID, resourceID, grantID, sessionID string) {
	r.Record(ctx, storage.AuditEvent{
		Event:      EventStreamOpened,
		ActorRole:  RoleOperator,
		ActorID:    userID,
		DeviceID:   deviceID,
		ResourceID: resourceID,
		GrantID:    grantID,
		SessionID:  sessionID,
	})
}

// StreamDenied records a refused stream and why.
//
// Denials matter more than successes in an audit trail. A success is one person
// doing their job; a run of denials is somebody probing, or a policy that is
// wrong, and neither is visible without a record.
func (r *Recorder) StreamDenied(ctx context.Context, userID, deviceID, resourceID, grantID, reason, detail string) {
	r.Record(ctx, storage.AuditEvent{
		Event:      EventStreamDenied,
		ActorRole:  RoleOperator,
		ActorID:    userID,
		DeviceID:   deviceID,
		ResourceID: resourceID,
		GrantID:    grantID,
		Reason:     reason,
		Detail:     detail,
	})
}

// StreamClosed records a finished stream with its transfer totals.
func (r *Recorder) StreamClosed(ctx context.Context, userID, deviceID, resourceID, grantID string,
	bytesIn, bytesOut uint64, duration time.Duration, reason string) {
	r.Record(ctx, storage.AuditEvent{
		Event:      EventStreamClosed,
		ActorRole:  RoleOperator,
		ActorID:    userID,
		DeviceID:   deviceID,
		ResourceID: resourceID,
		GrantID:    grantID,
		BytesIn:    bytesIn,
		BytesOut:   bytesOut,
		DurationMS: duration.Milliseconds(),
		Reason:     reason,
	})
}

// DeviceConnected records an endpoint arriving on the relay.
func (r *Recorder) DeviceConnected(ctx context.Context, deviceID, detail string) {
	r.Record(ctx, storage.AuditEvent{
		Event:     EventDeviceConnected,
		ActorRole: RoleDevice,
		ActorID:   deviceID,
		DeviceID:  deviceID,
		Detail:    detail,
	})
}

// DeviceDisconnected records an endpoint leaving, with the reason it ended.
func (r *Recorder) DeviceDisconnected(ctx context.Context, deviceID, reason string) {
	r.Record(ctx, storage.AuditEvent{
		Event:     EventDeviceDisconnected,
		ActorRole: RoleDevice,
		ActorID:   deviceID,
		DeviceID:  deviceID,
		Reason:    reason,
	})
}

// Enrolled records a completed enrollment.
func (r *Recorder) Enrolled(ctx context.Context, role, id, detail string) {
	event := EventDeviceEnrolled
	if role == RoleOperator {
		event = EventOperatorEnrolled
	}
	e := storage.AuditEvent{
		Event:     event,
		ActorRole: role,
		ActorID:   id,
		Detail:    detail,
	}
	if role == RoleDevice {
		e.DeviceID = id
	}
	r.Record(ctx, e)
}

// EnrollDenied records a refused enrollment attempt.
//
// The token is never included, not even hashed. A refused attempt may carry a
// value the caller should not have had, and copying it into durable storage
// would preserve exactly the thing that should not be preserved.
func (r *Recorder) EnrollDenied(ctx context.Context, remote, reason string) {
	r.Record(ctx, storage.AuditEvent{
		Event:     EventEnrollDenied,
		ActorRole: RoleSystem,
		Reason:    reason,
		Detail:    "from " + remote,
	})
}
