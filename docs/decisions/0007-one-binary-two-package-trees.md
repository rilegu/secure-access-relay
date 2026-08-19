# ADR-0007: Control plane and relay ship as one binary, two package trees

**Status:** accepted

## Context

The control plane decides access; the relay carries already-authorized bytes. They have
opposite properties: the control plane is low-volume, database-bound, and private; the
relay is high-bandwidth, horizontally scalable, and internet-facing. Eventually they
should be separate deployables.

## Decision

For v1 they ship as one binary, `sar-server`, but live in two package trees —
`internal/control` and `internal/relay` — **with no cross-imports between them**. Shared
types live in `internal/proto` and `internal/storage`. Splitting them into two
deployables must be a wiring change in `cmd/`, never a refactor.

## Rejected: two binaries from day one

Two services means two deployments, two configs, service discovery, and an internal
authentication channel between them — operational overhead carried through all of early
development while proving nothing extra.

## Rejected: one package tree

Sharing a package tree is how the boundary erodes. The moment the relay can call the
policy engine directly, someone will let it decide something, and the property that
makes the design defensible — *a compromised relay cannot authorize access* — quietly
stops being true.

## Consequences

- The no-cross-import rule is a review invariant. A CI check should eventually enforce it.
- The relay reaches storage only through a narrow session-registry interface; it cannot
  query policies, users, or audit records.
- The relay never holds the grant signing key.
- Deploying them separately later requires new config and new transport wiring — but no
  change to either package tree.
