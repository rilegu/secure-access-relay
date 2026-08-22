# ADR-0006: CGO_ENABLED=0 everywhere; pure-Go SQLite

**Status:** accepted

## Context

The control plane needs persistence for organizations, users, devices, resources,
policies, grants, and audit events. The obvious embedded choice is SQLite, whose usual
Go driver (`mattn/go-sqlite3`) requires cgo.

## Decision

`CGO_ENABLED=0` for all three binaries, enforced in the Makefile, the PowerShell task
runner, and CI. Storage uses `modernc.org/sqlite`, a pure-Go implementation, behind
interfaces in `internal/storage`.

## Rejected: mattn/go-sqlite3

It is the better-tested driver, but requiring cgo would contradict
[ADR-0005](0005-native-c-dynamically-loaded.md) and cost static binaries, trivial
cross-compilation, and fast reproducible builds — for a component whose v1 workload is
a few hundred rows.

## Implementation status

**Both halves are implemented.** `CGO_ENABLED=0` is enforced in the Makefile, the
PowerShell task runner, and CI. `internal/storage` is SQLite through `modernc.org/sqlite`,
holding identities, enrollment tokens, operator sessions, grants, and the audit trail,
with numbered migrations and parameterised statements throughout.

It came due exactly where this record predicted: with the audit trail, which is
append-only and unbounded and could not have been a rewritten JSON file. The
zero-dependency property ended when it landed, which was the anticipated cost.

An existing `control.json` from the previous store is imported on first open, so an
upgraded deployment does not silently lose the identities it had enrolled.

The interfaces this record mentions were not built. Storage is a concrete `*storage.Store`
rather than a set of interfaces with one implementation: the relay and the control plane
already communicate through narrow interfaces they define themselves, and adding a second
abstraction for a Postgres backend nobody has asked for would be scaffolding for an
imagined future. It is a mechanical change if that future arrives.

## Consequences

- All binaries are statically linked and copy-deployable, which matters most for the
  Windows agent and its installer.
- Cross-compiling the Windows agent from Linux CI works without a toolchain.
- `modernc.org/sqlite` is slower than the C library under load. Irrelevant at v1 scale;
  the storage interfaces exist so Postgres can replace it when it stops being irrelevant.
- Any future dependency requiring cgo needs an ADR superseding this one.
