# ADR-0002: Resource targets are loopback-only in v1

**Status:** accepted

## Context

The agent dials a local target on behalf of an authorized operator. The set of
addresses it is willing to dial defines the blast radius of every other bug in the
system.

## Decision

A resource target must be `127.0.0.1:<port>` or `[::1]:<port>`. Hostnames are rejected.
The agent validates this **at configuration load time** and refuses to start if any
resource violates it. The operator never supplies an address — they name a `resource_id`
that the agent resolves against its own local allowlist.

## Rejected: operator-supplied targets

Letting the operator name `host:port` turns the agent into a general-purpose SOCKS proxy
with an authentication step. Every authorization bug then becomes full lateral movement
across the customer subnet. The distinction this project is built around — a resource
proxy, not a tunnel — would be lost.

## Rejected: hostname targets

A hostname requires DNS, and DNS is attacker-influenceable. A resource pinned to
`127.0.0.1` cannot be moved by a poisoned answer; a resource pinned to `panel.local` can.

## Consequences

- Services on other LAN hosts are unreachable. That is intended for v1.
- Reaching a non-loopback service requires an agent on that host — which is the correct
  security posture, not a workaround.
- A misconfigured allowlist produces a failed startup, never a running agent with an
  over-broad target.
- Widening this later requires a new ADR and a threat-model revision, not a config flag.
