# ADR-0017: Audit retention is the single exception to append-only

**Status:** accepted

Amends invariant 11, recorded in `DEVELOPMENT.md`.

## Context

Invariant 11 says the audit trail is append-only: no `UPDATE`, no `DELETE`, ever.
That rule is what makes the trail evidence rather than a log, and
[ADR-0011](0011-sqlite-not-key-value.md) chose a database partly to enforce it.

It also means the trail grows without bound. Every stream opened, every stream
closed, every grant, every denial, every connection and disconnection, for the
life of the deployment.

The tempting response is that unbounded growth is the *safe* default — better a
full disk than deleted evidence. That is wrong here, and specifically wrong
because of how this system is built:

**A control plane that cannot write an audit event must refuse the decision it
was about to make.** That is not a policy choice, it is
`RecordGrant`: the grant and its audit event commit in one transaction, so a
failed write means no grant. When the disk fills, authorization stops. Not
degrades — stops.

So unbounded growth is a slow denial of service against the system's own
authorization path, with a countdown nobody is watching. "Fill the disk on the
endpoint" was already in the failure-injection table; the control plane deserved
the same question and answered it worse.

## Decision

Retention exists, as the single, narrow exception to invariant 11:

    sar-server audit -prune-older-than 90d -confirm

Every part of that is deliberate:

- **Never automatic.** Nothing calls it on a timer, on startup, or when the disk
  looks full. A system that silently deletes its own evidence when it decides the
  moment is right is worse than one that fills a disk, because the disk is
  visible and the deletion is not.
- **No default retention period.** The age must be given. Choosing one on an
  administrator's behalf is choosing how much evidence they keep, which is a
  compliance decision this software has no standing to make.
- **Only whole events, only by age.** It cannot edit an event, cannot select by
  actor, device, or grant, and cannot be pointed at a particular incident. The
  operation that would be most useful to someone covering their tracks is the one
  that does not exist.
- **`-confirm` is required.** Without it the command reports what it would remove
  and does nothing. The first run of a destructive command is usually somebody
  finding out what it does.
- **It records itself**, in the same transaction as the deletion, with the cutoff
  and the number of rows removed. A gap in the history is therefore never
  ambiguous: either there is a prune record explaining it, or the gap is a
  period when nothing happened.

Invariant 11 is amended to read: the software never modifies a recorded event,
and the only removal is this explicit, administrator-invoked, self-recording
retention operation.

## Rejected: keep append-only absolutely

The status quo, and the position the invariant originally took.

Rejected because it converts a disk-capacity problem into an authorization
outage, and does so at an unpredictable moment. An administrator who cannot
prune has exactly one option when the disk fills — delete the database file —
which loses *everything*, including the enrolled identities. The absolute rule
produces a worse outcome for the evidence than the bounded exception does.

## Rejected: automatic rolling retention

Delete anything older than N days, on a timer, with N configurable.

Rejected because it makes the software the actor. An audit trail that prunes
itself has, at every moment, a defensible-sounding reason for any gap in it, and
nobody has to have decided anything. Requiring a human to type a cutoff and
`-confirm` means every gap traces to a person.

It would also delete evidence during an incident, when the trail is being read
most and its oldest entries matter most.

## Rejected: rotate to files and archive

Move old events out to a file rather than deleting them.

Genuinely better for evidence, and not rejected on merit — it needs a defined
archive format, a place to put it, and a way to query across the boundary, none
of which exist. Deferred rather than dismissed: it composes with this decision
instead of replacing it, because the prune could archive before deleting.

## Consequences

- `PruneAudit` is the only statement in the codebase that deletes an audit row,
  and it takes a mandatory cutoff. A zero cutoff is an error, not "everything".
- The prune record itself is effectively un-prunable in practice: it is written
  with the current timestamp and every cutoff is in the past.
- `sar-server audit -stats` reports the event count and how far back the trail
  reaches, so growth is visible before it becomes a capacity problem rather than
  after.
- The dry run's count is an estimate. It is a separate query from the deletion,
  so events can arrive between the two — the output says "roughly" rather than
  presenting a number it cannot guarantee.
- **None of this addresses tampering.** Anyone with filesystem access to the
  database can edit it with a standard tool. That needs a hash chain or an
  external sink, and neither is built; the threat model says so plainly.
