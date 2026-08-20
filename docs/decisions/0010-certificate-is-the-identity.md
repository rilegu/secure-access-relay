# ADR-0010: The certificate is the identity

**Status:** accepted

## Context

Before mutual TLS, a peer stated who it was in the protocol handshake and nothing
checked it. Any peer that could reach the relay could assert any device identifier and
be routed to as that endpoint.

Closing that needs three separate decisions: where identity is carried, who decides it,
and what the relay does when a peer's claim disagrees with its credential.

## Decision

**Identity is carried in a URI SAN** on the certificate: `sar://device/panel-lab-01` or
`sar://operator/maria`. The role is part of it.

**The enrollment token decides the identity, not the certificate request.** The authority
takes only the public key from a request; everything else comes from the token being
redeemed.

**The relay reads identity from the certificate and refuses any claim that disagrees with
it.** A peer may still state a device in its handshake — an operator has to say which
endpoint it wants — but where that overlaps with identity, the certificate wins and a
mismatch ends the connection.

**Enrollment is bootstrapped by pinning the authority's fingerprint** inside the
enrollment code, so a peer with no trust anchor can still verify the control plane before
sending its token.

## Rejected: identity in the Common Name

CN is free text with no agreed structure. Two implementations can parse the same CN
differently, which turns identity into a parsing question, and the CN has been deprecated
as an identity by TLS stacks for years. A URI has exactly one reading, and encoding the
role in it means a device certificate cannot be reinterpreted as an operator one.

A certificate asserting more than one identity URI is refused rather than resolved.
Ambiguity is worse than absence: code forced to choose between two identities will
eventually choose the one an attacker wanted.

## Rejected: taking the identity from the certificate request

This is the obvious design and it is wrong. A certificate request is written by the party
asking for a certificate, so everything in it is a claim rather than a fact. If a
requester could name itself, a token issued to enroll one device would enroll whichever
device its holder chose, and enrollment would authenticate nothing.

## Rejected: trusting the handshake claim when it agrees with nothing

An earlier build let the peer state its device identifier and used it directly. Keeping
that as a fallback — believe the certificate, but accept the claim if no certificate says
otherwise — would preserve the original hole for any path where a certificate is missing.
There is no such path now, and there must not be one later, so the claim is only ever
checked against the certificate and never used in its place.

## Rejected: skipping verification on the first enrollment connection

An enrolling peer has no trust anchor yet, which is a genuine bootstrap problem. The
usual shortcuts are to disable verification for that one request, or to distribute the
authority certificate separately.

Disabling verification means the token — the one credential that creates an identity — is
sent to whoever answers the connection. Distributing the certificate separately works but
makes enrollment a two-artifact procedure, and the second artifact is the one people skip.

Carrying the authority fingerprint inside the enrollment code keeps it to one artifact
and still lets the peer verify the server before sending anything. The chain is checked
by hand against that fingerprint, which is stricter than the default path rather than
weaker: it requires the chain to end at one specific certificate.

## Consequences

- A peer's identity is established during the TLS handshake, before it can send a single
  protocol frame. An unenrolled peer never reaches the protocol.
- The relay must ask the control plane whether an identity is still live. A signature
  proves the certificate was issued; only the control plane knows whether it has been
  revoked or superseded by a re-enrollment.
- **Re-enrolling invalidates the previous certificate**, because the store records the
  serial currently issued to an identity. Without that, re-enrolling after a suspected
  compromise would be a ritual rather than a remedy.
- **Whoever hands over an enrollment code is trusted.** That is unavoidable at the bottom
  of a trust chain; it is at least a single, visible, human-scale step, and the code is
  single-use and short-lived.
- Revocation takes effect when a connection is established, not immediately. A session
  already running continues until it ends. Terminating live sessions on revocation is
  outstanding work, and is recorded in the threat model rather than implied to work.
- The role in a certificate is fixed at issue. Changing what a peer is means re-enrolling
  it, which is the correct amount of friction.
