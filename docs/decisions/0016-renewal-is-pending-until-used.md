# ADR-0016: A renewed certificate is pending until it is used

**Status:** accepted

## Context

Certificates last thirty days and were not renewed. The failure mode is not
gradual: every endpoint enrolled in the same week goes dark in the same week,
silently, and the only symptom is agents that stop connecting. Whoever
investigates finds a working relay, a working control plane, and endpoints that
appear to have nothing wrong with them.

Renewal is therefore not a convenience. It is the difference between a system
that runs unattended and one that needs a calendar reminder per endpoint.

The hard part is not issuing a new certificate. It is that
[ADR-0010](0010-certificate-is-the-identity.md) records the current serial for
each identity and refuses any other, which is what makes re-enrollment
*replace* rather than *duplicate*. Reusing that mechanism for renewal means the
old certificate stops being accepted the instant the new one is issued.

That creates a window. Between the control plane committing the new serial and
the endpoint writing the certificate to disk there is a network response, a
keystore write, and a file write. A crash, a full disk, or a power cut anywhere
in it leaves an endpoint holding only a certificate the control plane no longer
accepts — unable to authenticate, unable to renew, and unrecoverable without a
human minting a token and visiting it.

For one endpoint that is an annoyance. For a fleet renewing on a schedule it is
a fleet-wide outage waiting for an unlucky moment.

## Decision

A renewed certificate is recorded as **pending**. The identity keeps its current
serial, and both are accepted. The first time the new certificate is actually
presented, it is promoted to current and the previous one is retired.

Promotion is driven by *use*, not by a timer. Presenting the new certificate is
proof that the endpoint received it, stored it, and loaded it — which is exactly
the condition under which retiring the old one is safe.

Consequently, every way renewal can fail is survivable. The request never
arrives, the response is lost, the key write fails, the certificate write fails,
the machine loses power between them: in all of these the endpoint still holds a
certificate the control plane accepts, and the next attempt issues another.

Renewal is authenticated by the certificate being replaced, so it needs no token
and no human. The identity comes from the verified certificate and never from
the certificate request, so a device cannot renew itself into an operator.

## Rejected: supersede at issue

The obvious implementation, and the one re-enrollment already uses.

Rejected because of the window described above. The window is small and the
consequence is unrecoverable, which is the worst combination: it will not show
up in testing, and when it does show up in production it will look like a
hardware fault.

## Rejected: a grace period on a timer

Keep the previous serial valid for, say, ten minutes after issuing a renewal.

This was the first design and it is genuinely simpler — one extra column and a
comparison. It was rejected because the timer is arbitrary and wrong in both
directions. Too short and a slow endpoint that renewed just before a reboot is
still bricked. Too long and every renewal leaves two usable certificates for an
identity, on purpose, for a period nobody chose for a security reason.

Use-driven promotion has no such number in it. The old certificate is retired at
exactly the moment the new one is demonstrably in service, which is both later
than any safe timer would allow and earlier than any generous one would.

## Rejected: reuse the existing key and reissue only the certificate

Fewer files to write, so a smaller local failure surface.

Rejected because a certificate has to be written either way, and generating a
key alongside it costs one Ed25519 keygen. Reusing the key would leave a single
key in service for the life of the deployment, which throws away the main
hygiene benefit of having a renewal mechanism at all. With the pending scheme
the write is no longer a hazard, so the argument for reusing the key was
answered by the same decision that made renewal safe.

## Rejected: re-enrollment on a schedule

Mint a token per endpoint before each expiry and deliver it.

This is the status quo dressed up. It does not scale past the number of
endpoints a person is willing to think about, and the delivery channel for a
token is outside the system — so a scheduled re-enrollment is a scheduled manual
step, which is the thing being removed.

## Consequences

- `identities` gains `pending_serial_hex` and `pending_issued_at`
  (migration 2). An identity with a pending serial has two acceptable
  certificates until one is used.
- Verification does a write on first use of a renewed certificate. It happens
  once per renewal, on a path that already performs an Ed25519 verification.
- "Issued but not collected" becomes an observable state, shown by
  `sar-server list`. It distinguishes a renewal in flight from an endpoint that
  failed to store one and is still running on its old certificate — which is a
  fault worth seeing.
- Re-enrollment clears any pending renewal. A fresh enrollment is a deliberate
  act that replaces everything before it, including a certificate that was
  offered and never collected.
- A certificate that has **already expired** cannot renew: the renewal is
  authenticated by presenting it, and TLS will not present an expired
  certificate. That case still needs a human and a token, which is why the
  renewal window is ten days rather than ten minutes.
- Revoked identities cannot renew, and superseded certificates cannot renew.
  Both are checked by the same verification every other connection uses.
