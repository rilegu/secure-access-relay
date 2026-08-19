# ADR-0001: Relay-first transport; no NAT traversal in v1

**Status:** accepted

## Context

Both the operator and the protected endpoint typically sit behind NAT and restrictive
firewalls. Neither has a stable reachable address. Overlay-network products solve this
with STUN-style hole punching plus a relay fallback.

## Decision

All traffic goes through the relay. Both sides open **outbound** connections to it.
There is no direct peer-to-peer path and no NAT traversal in v1.

## Rejected: NAT traversal first

Hole punching is a large, environment-sensitive subsystem — CGNAT, symmetric NAT,
enterprise middleboxes, and endpoint-independent mapping all behave differently, and
failures are hard to reproduce. Building it first would consume most of the effort on
protocol completeness while proving nothing about authorization, which is the actual
subject of this project. Established mesh-overlay products already solve traversal well;
duplicating that work adds risk without advancing the goal here.

## Consequences

- The relay is always on the data path and is a bandwidth and availability bottleneck.
- The relay sees connection metadata for every session. It is treated as untrusted for
  authorization (see [ADR-0002](0002-loopback-only-targets.md) and the threat model).
- Neither network needs an inbound firewall rule, which is the main deployment claim.
- A reachable coordination point is mandatory. It may be self-hosted; it cannot be absent.
- Direct peer-to-peer remains a documented roadmap item, not a hidden gap.
