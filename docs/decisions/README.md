# Architecture decision records

Short records of decisions that would otherwise be re-litigated. Each states the
context, the decision, and — most importantly — what was rejected and why.

New ADRs get the next number. ADRs are never edited after acceptance; they are
superseded by a later ADR that references them.

| # | Decision | Status |
| - | -------- | ------ |
| [0001](0001-relay-first-transport.md) | Relay-first transport; no NAT traversal in v1 | accepted |
| [0002](0002-loopback-only-targets.md) | Resource targets are loopback-only in v1 | accepted |
| [0003](0003-ed25519-grants-not-jwt.md) | Ed25519-signed fixed-schema grants, not JWT | accepted |
| [0004](0004-custom-data-plane-framing.md) | Hand-rolled binary framing for the data plane | accepted |
| [0005](0005-native-c-dynamically-loaded.md) | Native diagnostics in C, dynamically loaded, not cgo | accepted |
| [0006](0006-cgo-disabled-pure-go-sqlite.md) | CGO_ENABLED=0 everywhere; pure-Go SQLite | accepted |
| [0007](0007-one-binary-two-package-trees.md) | Control plane and relay ship as one binary, two package trees | accepted |
