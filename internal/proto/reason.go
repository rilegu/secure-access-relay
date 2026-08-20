package proto

// Reason is a stable, machine-readable explanation for why a stream closed or a
// request was refused. Reason codes travel in CLOSE_STREAM and ERROR frames, land
// in audit events, and are shown to operators.
//
// They are a compatibility surface: new codes may be added, but an existing code
// never changes meaning. The full list is documented in docs/protocol.md.
type Reason string

// Reason codes. Grouped by what went wrong, because the grouping matters: a
// caller must be able to distinguish "you are not allowed" from "the thing you
// are allowed to reach is not answering". Conflating those two leaves an operator
// unable to tell a policy problem from an outage, so they are deliberately
// separate codes and must never be substituted for one another.
const (
	// ReasonOK is a normal, complete close. Not an error.
	ReasonOK Reason = "ok"

	// Grant verification failures. Unused until signed grants land, defined here
	// so the vocabulary has one home and docs/protocol.md has one counterpart.
	ReasonGrantInvalidSignature Reason = "grant_invalid_signature"
	ReasonGrantExpired          Reason = "grant_expired"
	ReasonGrantNotYetValid      Reason = "grant_not_yet_valid"
	ReasonGrantDeviceMismatch   Reason = "grant_device_mismatch"
	ReasonGrantRevoked          Reason = "grant_revoked"

	// Resource resolution failures, raised by the agent against its own local
	// allowlist. ReasonResourceTargetNotLoopback enforces invariant 4: a resource
	// may only ever point at loopback.
	ReasonResourceUnknown           Reason = "resource_unknown"
	ReasonResourceTargetNotLoopback Reason = "resource_target_not_loopback"

	// ReasonPolicyDenied means authorization said no. It must never be used for a
	// network failure.
	ReasonPolicyDenied Reason = "policy_denied"

	// Limit violations, one code per limit so the peer learns which bound it hit.
	ReasonLimitStreamsExceeded Reason = "limit_streams_exceeded"
	ReasonLimitBytesExceeded   Reason = "limit_bytes_exceeded"
	ReasonLimitFrameTooLarge   Reason = "limit_frame_too_large"

	// Target failures. These describe the approved local service, not the policy
	// decision that allowed reaching it, and must never be reported as a denial.
	ReasonTargetConnectionRefused Reason = "target_connection_refused"
	ReasonTargetTimeout           Reason = "target_timeout"

	// Protocol failures.
	ReasonProtocolVersionUnsupported Reason = "protocol_version_unsupported"
	ReasonProtocolMalformedFrame     Reason = "protocol_malformed_frame"

	// ReasonFlowControlViolation means a peer sent more data than the window it
	// was granted. Distinct from a malformed frame: the frame was well formed,
	// the peer simply ignored a limit it had been told. Treating it as fatal is
	// deliberate, because the alternative is buffering without bound.
	ReasonFlowControlViolation Reason = "flow_control_violation"

	// Connection lifecycle.
	ReasonAuthFailed      Reason = "auth_failed"
	ReasonSessionReplaced Reason = "session_replaced"
	ReasonIdleTimeout     Reason = "idle_timeout"
	ReasonShutdown        Reason = "shutdown"

	// ReasonNoAgent means no endpoint agent is currently connected to serve the
	// request. It is an availability condition, not an authorization one.
	ReasonNoAgent Reason = "no_agent"
)

// String makes Reason satisfy fmt.Stringer so it formats cleanly in logs.
func (r Reason) String() string { return string(r) }
