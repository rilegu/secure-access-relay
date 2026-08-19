# ADR-0003: Ed25519-signed fixed-schema grants, not JWT

**Status:** accepted

## Context

The control plane issues short-lived authorizations that the agent verifies offline,
without calling back. The format needs to be tamper-evident, compact, and simple enough
to verify correctly.

## Decision

A fixed-schema struct signed with Ed25519 over a canonical encoding defined in
`internal/proto`. Verification requires every field to be present; unknown fields are
rejected rather than ignored. The schema carries an explicit `v` that verifiers check.

## Rejected: JWT

JWT drags in an `alg` header field that the verifier must decide about, and the history
of `alg: none` and RS256/HS256 confusion attacks is a history of verifiers making that
decision wrong. It also permits open-ended claim sets, so a verifier that ignores an
unknown claim can be made to ignore a meaningful one. Neither flexibility is needed
here: there is exactly one issuer, one algorithm, and one claim set.

## Rejected: opaque tokens with a control-plane lookup

That would require the agent to reach the control plane on every stream open, making
availability a precondition for access and adding latency to the hot path. Offline
verification with a short TTL gives better failure behavior — the control plane going
down denies *new* access without severing existing sessions.

## Consequences

- Rotation is handled by `key_id` in the grant plus a set of trusted keys at the agent.
- Revocation before expiry needs an explicit channel; the 30-minute maximum TTL bounds
  the window where that matters.
- Canonical encoding must be exact. Round-trip and tamper tests are mandatory, not optional.
- Verification code is small enough to read in one sitting, which is the point.
