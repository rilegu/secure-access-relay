# ADR-0018: End-to-end encryption is a nested TLS session

**Status:** accepted

## Context

Every hop was mutual TLS, and the relay terminated it. Two sessions, decrypted
and re-encrypted in the middle. Mutual TLS authenticates both ends *to the
relay*; it does not hide anything *from* it.

That was the largest gap in the system and it was stated as such in the README,
the threat model, and the protocol document. It mattered because the relay is
the component most exposed to the network and deliberately trusted with the least
authority — except for confidentiality, where it was trusted completely.

There was a second problem, less obvious and arguably worse. The grant travels
through the relay. Nothing stopped a compromised relay taking a grant presented
by one operator and opening its own stream to the agent with it: the signature
verifies, the device matches, the user matches, and the agent dials the local
service. The agent's check proved the *grant* was genuine. It could not prove the
peer holding it was the operator it named.

So the relay could both read the traffic and manufacture the access.

## Decision

A second TLS 1.3 session runs inside the relayed stream, between the operator and
the agent. The relay copies its records without being able to read them.

It is **mutually authenticated with the certificates peers already hold**, and
each end verifies the identity the grant names:

- The operator requires the peer to be `device/<device_id>` — so a relay cannot
  route the stream to a different endpoint, or answer as one itself.
- The agent requires the peer to be `operator/<user_id>` — so a captured grant is
  useless without the operator's private key.

The agent establishes the inner session **before dialling the local service**. A
failed handshake therefore delivers zero bytes to the target, which is the
property every denial in this system holds to, and access is never opened on the
strength of a grant that anything with a copy could have presented.

Identity lives in a URI SAN, which Go's hostname verification does not
understand, so verification is *replaced* rather than skipped:
`InsecureSkipVerify` with a `VerifyConnection` callback that verifies the chain
against the deployment's authority and then requires an exact identity match.
Chain first, identity second — nothing a certificate asserts about itself means
anything until the authority has vouched for it.

There is no negotiation and no fallback. Both ends ship from this repository, so
a downgrade path would be a hole with no compatibility benefit.

## Rejected: the Noise protocol framework

The obvious purpose-built answer, and the one named in
[ADR-0008](0008-no-existing-overlay-platform.md) as the good part of WireGuard.
`Noise_IK` fits this shape almost exactly: mutual authentication, one round trip,
far less code on the wire than TLS.

Rejected on dependencies, not on merit. Using a Noise library adds a second
cryptographic dependency, and the rule every dependency must survive is *"why not
the standard library?"* — which `crypto/tls` answers by being the standard
library and already being the transport. Implementing Noise here instead would be
custom cryptography, a stated non-goal, and the worst possible place to take that
risk.

It would win on handshake size and on not carrying X.509 twice. Neither is a
problem this deployment has.

## Rejected: encrypt the payload with a key derived from the grant

Tempting because the grant is already shared, signed, and short-lived.

Rejected because the grant passes through the relay. Anything derivable from it
is derivable by the relay, so this would encrypt the traffic against everyone
except the one party it needs to be hidden from. The property required is
possession of a private key that never leaves the endpoint, which is what the
enrolled certificates already provide.

## Rejected: make it optional, negotiated in the handshake

Considered for compatibility with agents that predate it.

Rejected because a negotiated security property is a downgrade target, and there
is nothing to be compatible with: both ends are built and deployed from the same
repository. An operator cannot tell a session that negotiated encryption from one
that negotiated it away, which makes the option strictly worse than not having
it.

## Rejected: terminate the inner session at the relay for inspection

Not seriously, but worth recording as refused: some deployments want to inspect
support traffic. That is precisely the capability this removes, and offering it
as a switch would return the relay to being trusted for confidentiality while
letting the README claim otherwise. A deployment that needs traffic inspection
should do it at the endpoint service, where it is visible to the audit trail.

## Consequences

- **The relay is no longer trusted for confidentiality.** It sees metadata — who,
  which device, which resource, how many bytes, how long, when — and it has to,
  because that metadata is what the audit trail is built from. It no longer sees
  payload.
- **A compromised relay cannot use a grant it observed.** This is the change that
  matters most, and it was not the goal going in.
- **One extra round trip per stream.** TLS 1.3 is 1-RTT, and a stream is a TCP
  connection's worth of work, so the cost sits alongside a connection that was
  being set up anyway. Session resumption would remove it and is not built.
- **Double encryption on the wire.** The inner records are already encrypted when
  the outer session encrypts them again. Measurable, not noticeable at the scale
  this runs at, and the alternative is the relay reading the traffic.
- The bridge's abort semantics survive the extra layer: the inner connection
  delegates `Reset` to the stream underneath, so reason codes still reach the
  operator instead of every abort arriving as an unexplained disconnection.
- **Revocation is unaffected.** The relay resets the outer stream, which takes the
  inner session with it. It does not need to understand what it is carrying.
- The relay required no changes at all, which is the clearest evidence that the
  layering is right.
