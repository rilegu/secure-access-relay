# ADR-0008: Build on TLS directly rather than adopt a zero-trust overlay

**Status:** accepted

## Context

This project is not the first to conclude that remote access should authorize an
application rather than a network, and that both ends should dial outward. Mature
implementations of that idea already exist, and one of them — OpenZiti — arrives at
almost exactly the same component split:

| OpenZiti | This project |
| -------- | ------------ |
| Controller | control plane |
| Routers | relay |
| Edge SDK / tunneler | `sar-agent` |
| Service | resource |
| One-time enrollment token, then a certificate | one-time enrollment token, then a certificate |
| Services with no inbound listener | agent never calls `Listen` |

Adopting it is a real option, not a strawman. It is Apache 2.0, it is more mature than
anything written here, and it would supply identity, enrollment, policy, routing, and
NAT traversal directly. Choosing to write those instead needs a reason.

## Decision

Build the data plane, enrollment, and authorization directly on TLS 1.3 and the Go
standard library. Do not adopt an overlay networking platform as the transport.

## Rejected: build on OpenZiti or a comparable application-layer overlay

Three reasons, in order of weight.

**The mechanics are the substance of this project.** Frame parsing, limit enforcement,
malformed-input handling, offline grant verification, and deny-by-default enforcement
are what this codebase exists to get right. Delegating them leaves an application
configured on someone else's platform, which shows integration and nothing about the
security engineering underneath. This is the same argument as
[ADR-0004](0004-custom-data-plane-framing.md), applied one layer up.

**It would absorb the control plane entirely.** Identity, enrollment, policy, and
service definitions all live in the overlay's controller. Adopting it does not simplify
this project's control plane; it replaces it, and what remains is configuration.

**A small implementation can be read.** The entire authorization path here is a few
hundred lines, and every bound on it is visible in the source. That is a property worth
having for software whose claim is "the blast radius is one service on one machine," and
it is the one advantage a small implementation holds over a mature platform.

Two lesser reasons: running a controller and a router fabric to demonstrate one
forwarded TCP stream is disproportionate, and inheriting a platform means inheriting its
release cadence and its vulnerabilities alongside its hardening.

## Rejected: WireGuard, or an overlay built on it

Rejected for a different and more basic reason: it operates at the wrong layer.

WireGuard provides an encrypted network interface. Access is expressed as IP
reachability, so scoping it back down to a single service requires firewall rules layered
on top — which reconstructs the model [ADR-0002](0002-loopback-only-targets.md) exists to
reject. Its identity model is a static peer key with no expiry, no revocation, and no
issuing authority, which cannot express a thirty-minute grant.

It also requires a virtual network adapter. On Windows that means shipping and
maintaining a signed driver, an elevated installer, and a new class of failure that
persists after a crash — precisely the risk that keeps this project in userspace.

Note that WireGuard's cryptographic core, the Noise protocol framework, remains a
candidate for the operator-to-agent encryption layer described in the threat model's
known limitations. Rejecting the networking model does not mean rejecting the
cryptography.

## Consequences

- Transport security is TLS 1.3 with mutual TLS, using `crypto/tls`. No third-party
  cryptography and no custom protocol.
- The three binaries stay dependency-free and copy-deployable. There is no controller or
  router fabric to operate.
- **Hardening is now this project's responsibility.** The enrollment flow, certificate
  handling, and revocation path get no benefit from another project's production
  exposure, and any weakness in them is a weakness here.
- NAT traversal, direct peer-to-peer paths, and high availability are not inherited.
  They remain out of scope; see [ADR-0001](0001-relay-first-transport.md).
- Interoperability with an existing overlay deployment is not a goal and is not provided.

## A note on the commercial case

This decision is made for a project whose purpose is to demonstrate the engineering. If
the goal were instead the shortest path to a shippable product, building on an existing
overlay would be defensible: it would trade differentiation and control over the security
posture for years of hardening and features this project explicitly does not have.

That trade is recorded here so that a future revisit starts from the reasoning rather
than from the conclusion. Superseding this ADR would be a legitimate decision, not a
reversal of a mistake.
