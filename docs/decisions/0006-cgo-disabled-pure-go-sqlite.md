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

## Consequences

- All binaries are statically linked and copy-deployable, which matters most for the
  Windows agent and its installer.
- Cross-compiling the Windows agent from Linux CI works without a toolchain.
- `modernc.org/sqlite` is slower than the C library under load. Irrelevant at v1 scale;
  the storage interfaces exist so Postgres can replace it when it stops being irrelevant.
- Any future dependency requiring cgo needs an ADR superseding this one.
