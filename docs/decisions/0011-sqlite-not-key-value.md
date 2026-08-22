# ADR-0011: SQLite for control-plane state, not an embedded key-value store

**Status:** accepted

Complements [ADR-0006](0006-cgo-disabled-pure-go-sqlite.md), which chose a pure-Go SQLite
driver over a cgo one. That ADR never considered whether a relational database was the
right *shape*; this one does.

## Context

The control plane holds five kinds of data, and they do not all want the same thing:

| Data | Access pattern |
| ---- | -------------- |
| Enrolled identities | key-value lookup by role and identifier |
| Enrollment tokens | key-value lookup by hash |
| Policies | key-value lookup by organization |
| Grants | key-value lookup by grant identifier |
| Audit events | append-only, time-ordered, unbounded, **queried by several dimensions** |

The first four are pure key-value. Nothing joins, nothing aggregates. An embedded
key-value store — bbolt, for example — would serve them with roughly two orders of
magnitude less code than SQLite, and with no query language, therefore no injection
surface at all.

The current implementation is a JSON file rewritten on every mutation. That is adequate
for tens of records and cannot survive an audit trail, which grows without bound.

## Decision

Use `modernc.org/sqlite` for control-plane state **and** for the audit trail.

## Rejected: an embedded key-value store for state, plus an append-only log for audit

This is the better fit on paper and was seriously considered.

It loses on the audit trail, which is the data that actually matters. An audit record
exists to answer questions after the fact — *which operator reached this device last
Tuesday, how much did they transfer, why was that request denied* — and those questions
are multi-dimensional. A key-value store answers them by scanning and filtering in
application code, which means writing an index for every question anyone thinks to ask,
and writing it before they ask.

It also loses on inspection. When something goes wrong in a customer deployment, being
able to open the database with a standard tool and ask a question is worth more than the
elegance of the storage engine. A custom key-value layout needs custom tooling, written
by us, available only to us.

Two databases would avoid both problems and introduce a worse one: two storage engines,
two failure modes, two backup procedures, and a boundary where a policy decision and the
audit record of that decision cannot be written in one transaction.

## Rejected: keeping the JSON file

It rewrites everything on every mutation, which is quadratic in the number of records,
and an append-only audit trail is the opposite of a file that is rewritten whole. It was
never intended to survive past enrollment.

## Consequences

- **This ends the project's zero-dependency property.** That is a real cost: it is
  currently a verifiable claim, it is a strong answer during a customer security review,
  and it keeps the codebase readable end to end. It is paid deliberately, once, for the
  component where correctness is hardest to write and easiest to get subtly wrong.
- **A large amount of trusted code arrives with it.** `modernc.org/sqlite` is SQLite's C
  source machine-translated to Go. That removes the memory-safety bug class, which is
  the main reason it is preferred here over a cgo binding, but it is far more code than
  anything else in this repository and nobody on this project has read it.
- The README must stop describing zero dependencies as a design property and describe
  the actual rule instead: every dependency has to survive the question *"why not the
  standard library?"*, and this one does.
- Schema migrations become a thing that must exist. An unrecognised schema version is a
  startup failure, never a best-effort read — the same rule already applied to
  configuration.
- SQL means parameterised statements everywhere, without exception. Identifiers reaching
  the control plane are attacker-influenced, and string-built SQL is the failure this
  otherwise avoids by having had no query language at all.
- Audit becomes queryable, which is what makes it useful as evidence rather than as a
  log nobody reads.

## Implementation status

**Implemented.** `internal/storage` holds identities, enrollment tokens, operator
sessions, grants, and `audit_events`, with numbered migrations in `migrate.go` and the
schema version in SQLite's `user_version` pragma. A database newer than the binary is a
startup failure.

Two consequences this record predicted have been paid in full:

- The zero-dependency property is gone. The README now describes the rule — every
  dependency must survive *"why not the standard library?"* — rather than the number, and
  names the one that survived it.
- Migrations exist and are append-only. A released migration is never edited, because two
  deployments claiming the same schema version with different tables would make the
  version number meaningless.

The transactional argument turned out to be the load-bearing one. `RecordGrant` writes the
grant and its audit event in a single transaction, so there is no window in which access
exists without a record of it — which a key-value store plus a separate log file could not
have provided.

## Not affected

Key material does not go in the database. The authority key, device keys, and the grant
signing key are held by `internal/keystore`, sealed with DPAPI on Windows. A database
compromise must not be a key compromise, and encrypting the database would not change
that: the key for it would have to live on the same machine.
