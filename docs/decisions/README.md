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
| [0008](0008-no-existing-overlay-platform.md) | Build on TLS directly rather than adopt a zero-trust overlay | accepted |
| [0009](0009-half-close-and-abort.md) | Streams half-close; broken connections abort | accepted |
| [0010](0010-certificate-is-the-identity.md) | The certificate is the identity, not the claim | accepted |
| [0011](0011-sqlite-not-key-value.md) | SQLite for control-plane state, not a key-value store | accepted |
| [0012](0012-win32-through-stdlib.md) | Reach Win32 through the standard library | accepted |
| [0013](0013-canonical-grant-encoding.md) | Grants are signed over a hand-written canonical encoding | accepted |
