# ADR-0015: Revocation drops live streams from the relay, not the agent

**Status:** accepted

## Context

Until this decision, revoking anything took effect at the *next* connection. A grant
already issued stayed valid for its remaining life — up to thirty minutes — and a stream
already running was untouched.

That is a gap in the case revocation exists for. Nobody revokes a credential they believe
is fine; they revoke one they believe is compromised **right now**, and being told to wait
half an hour, or to restart the relay and disconnect every other endpoint, is not an
answer.

The question is *where* the interruption happens. There are three candidates, and each is
a different trust story.

## Decision

**The relay drops live streams; the agent is not involved.**

The relay registers every joined stream against the grant that authorized it. When a
revocation arrives, it resets both ends of every stream under that grant — the operator's
side and the agent's side — with reason `grant_revoked`.

The control plane records the revocation durably and then calls into the relay. The
dependency runs one way: the control plane decides, the relay is told, and the relay never
calls back. It is a function value passed at wiring time, not an import, so the two
package trees stay separable ([ADR-0007](0007-one-binary-two-package-trees.md)).

Both ends are reset, not just the operator's. Dropping only the operator's side would
leave the agent holding an open connection to the local service, which is precisely the
resource being taken away.

## Rejected: the agent polls the control plane for revocations

The intuitive design, and the one the earlier draft of `policy.md` described: the agent
syncs a revocation list and drops streams itself.

Rejected on three counts.

It **puts control-plane availability on the enforcement path**, which is the property
grants were designed to avoid. The whole reason a grant is signed and verified offline is
that an agent must not need to ask permission per stream
([ADR-0003](0003-ed25519-grants-not-jwt.md)). Adding a poll re-introduces the dependency
through a side door, and an agent that cannot reach the control plane would have to choose
between failing open and failing closed — both wrong.

It is **slower than the thing it replaces**. A poll interval short enough to be called
immediate is a poll interval that hammers the control plane from every endpoint; one long
enough to be cheap is one where "revoked" means "within a minute or two". The relay
already has the connection open and can act in microseconds.

It **adds an inbound control channel to the agent**, or a persistent subscription that has
to be secured, versioned, and reasoned about. The agent's surface is deliberately tiny.

## Rejected: pushing revocations to agents over the existing session

Better than polling — the mux session is already open, so a new frame type would carry it
with no new channel and no availability coupling.

Rejected as unnecessary rather than wrong. Every stream already passes through the relay,
so the relay can end it without the agent's cooperation, and the outcome at the local
service is identical: the connection closes. Adding a frame type would freeze a new piece
of protocol surface to achieve what an existing code path already achieves.

It becomes the right answer if agents ever hold streams the relay does not carry. They do
not, and [ADR-0001](0001-relay-first-transport.md) means they will not in v1.

## Rejected: relying on short TTLs alone

The prior state. Thirty minutes is a bound, not a response.

Short TTLs remain the mechanism that works when nothing else does — an agent that cannot
reach anything still stops honouring an expired grant — so this is a fast path in front of
expiry, never a replacement for it.

## Consequences

- **The relay holds a register keyed by grant.** It is memory-resident and lost on
  restart, which is correct: a restart drops every stream anyway.
- **Revocation is immediate only within the relay process that holds the streams.** In the
  shipped topology `sar-server run` starts the control plane and the relay together, so
  the call is in-process. A relay deployed separately would learn at its next grant check,
  which happens when a stream opens — meaning already-joined streams would survive.
  Splitting the two is not supported, and this is the reason it cannot be done casually.
- **The relay now reads from the control-plane store on stream open.** A primary-key point
  read, cheap next to the Ed25519 verification already on that path. A lookup that *fails*
  is not treated as a revocation: a database hiccup must not take access from everyone at
  once, and the agent's authoritative check still stands behind the relay's.
- **A correctly signed grant unknown to the control plane is logged loudly and allowed.**
  It means the signing key produced something this deployment never issued, which is worth
  noticing, but refusing on it would turn a lost database into a total outage.
- Cascades — session to grants, identity to sessions to grants — write one audit event per
  grant rather than one for the cascade, so a grant's own record explains why it stopped
  working.
