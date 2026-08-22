# Threat model

Scope: `secure-access-relay` v1 — relay-first transport, loopback-only resources,
TCP only, single organization.

## Assets

| Asset | Why it matters |
| ----- | -------------- |
| Device private key | Impersonating the device grants access to everything the device exposes |
| Control-plane grant signing key | Forging grants defeats the entire authorization model |
| Control-plane CA private key | Signing rogue device certificates defeats enrollment |
| Enrollment tokens | Single-use; a leaked unused token enrolls an attacker device |
| Resource allowlist on the agent | The last line preventing arbitrary local access |
| Audit log | Evidence; must be complete and non-forgeable enough to be trusted |
| Payload traffic | Contents of the approved service session |

## Attacker model

Assumed **in scope**:

1. **Network attacker** on the path between any two components. Can observe, drop,
   delay, replay, and inject; cannot break TLS 1.3.
2. **Malicious or compromised relay.** Sees all data-plane connections and metadata.
   This is treated as a realistic case, not a worst case.
3. **Unprivileged local user** on the Windows endpoint. Can run processes, connect to
   named pipes, read world-readable paths.
4. **Malicious operator** holding valid credentials for *some* resource, attempting to
   reach a different device, resource, or time window.
5. **Revoked or expired principal** attempting to continue or re-establish access.
6. **Stolen agent state** — a copy of the endpoint's state directory taken to another machine.

Assumed **out of scope** (stated so the boundary is honest, not because they are unlikely):

- Local Administrator or SYSTEM compromise on the endpoint. That level of access can
  stop the service, patch the binary, or read protected state. Nothing here defends
  against it, and no claim is made that it does.
- Compromise of the control plane host itself.
- Supply-chain compromise of the Go toolchain or dependencies.
- Physical attack, firmware/UEFI implants, hypervisor escape.
- Denial of service against the relay as a resource-exhaustion goal.
- Traffic analysis of session timing and volume metadata by the relay.

## Threats and controls

| # | Threat | Control |
| - | ------ | ------- |
| T1 | Attacker reaches the endpoint directly from the internet | Agent never listens on a network interface. Outbound connections only. No inbound rule is created by the installer. |
| T2 | Compromised relay opens a stream on its own authority | Agent independently verifies the Ed25519 grant signature, expiry, and `device_id` before dialing. Relay possesses no signing key and its own check is a fast fail only. The agent additionally requires the peer to prove possession of the private key for the operator the grant names, so a grant the relay *carried for somebody else* is useless to it. **Implemented.** |
| T3 | Compromised relay reads payload | A second mutually authenticated TLS 1.3 session runs between the operator and the agent *inside* the relayed stream, so the relay forwards records it cannot decrypt. Each end verifies the identity the grant names, which also rules out the relay substituting itself for either. Connection metadata — who, which device and resource, how much, how long — remains visible and must, because it is what the audit trail is built from. **Implemented.** |
| T4 | Grant replayed after expiry | `expires_at` checked at the agent against local clock; max TTL 30 minutes; skew tolerance bounded and explicit. |
| T5 | Grant tampered with (extended TTL, swapped resource) | Whole grant is signed over a canonical encoding; any field change invalidates the signature. Coverage is checked by flipping every bit in turn. **Implemented.** |
| T6 | Grant for device A replayed at device B | `device_id` is inside the signed grant and compared with the agent's own identity. Device identity itself is now certificate-bound: a peer cannot present one identity and claim another. |
| T7 | Operator requests a LAN or internet target | Target address is never operator-supplied. The operator names a `resource_id`; the agent resolves it in its own local allowlist, and rejects any non-loopback target. |
| T8 | Enrollment token reused to enroll a second device | Tokens are single-use, short-lived, and marked consumed transactionally on first use. Only a hash is stored, so a leaked store yields no usable tokens. **Implemented.** |
| T9 | Device key extracted from disk | Key is DPAPI-protected under the service account; copying the directory to another host or reading it as another account yields an undecryptable key. **Implemented on Windows**; other platforms fall back to file permissions and say so at startup. |
| T10 | Revoked device continues an established session | Revocation is checked on every new connection, and a superseded certificate is refused. Revoking a grant, a session, or an identity revokes the grants beneath it and **drops the streams those grants opened, at both ends** — so a revoked peer can carry no traffic. What survives is the data-plane *connection* itself, which stays open, useless, until it ends or the relay restarts. **Mostly implemented**; the residual gap is the connection, not the access. |
| T11 | Unprivileged local user drives the service via named pipe | Pipe ACL restricted to Administrators and the interactive owner; every request is authorized, not merely accepted. |
| T12 | Resource exhaustion via stream or frame flooding | Per-connection max frame size, concurrent stream cap negotiated at the handshake, credit-based flow control, bounded buffers, read deadlines. A peer exceeding its window is disconnected rather than buffered for. **Implemented.** |
| T13 | Malformed protocol input causes crash or overread | Length-prefixed frames validated against limits before allocation; fuzz tests over the codec. |
| T14 | Secrets leak through logs or the support bundle | Central redaction layer; tokens, keys, signatures, and payload bytes never reach a log sink; support bundle is generated through the same redactor. |
| T15 | Failure of the control plane widens access | Deny-by-default on any authorization error, timeout, or signature-verification failure. No policy file means no access. Grants verify offline, so a control-plane outage stops new grants without severing sessions already authorized. **Implemented.** |
| T16 | Stale WFP filters persist after a crash and break networking | Dynamic WFP session — filters are removed by the OS when the engine handle closes. Boot-time filters are not used in v1. |
| T17 | Native DLL is replaced with a hostile one | DLL loaded by absolute path from the ACL-protected install directory, Authenticode signature verified before load, never from `%PATH%` or the working directory. |
| T18 | Audit gaps hide an incident | Security-relevant decisions emit an audit event before the action completes; denials are audited with the same weight as allows. |

## Not implemented in the current build

The controls in the table above describe the intended design. Some are now backed by
code and some are not, and the difference must be read before the table is.

**Enforced today:**

- **Every stream requires a signed grant**, verified by the endpoint agent itself against
  a key obtained at enrollment. The relay's check is a fast fail, not the decision.
- **Deny by default.** No policy means no access. There are no deny rules and no
  wildcards, so evaluation order cannot change an answer.
- **Resources are declared by the agent**, never named by an address on the wire. A
  resource file with a non-loopback target stops the agent starting.
- **Grant lifetime is capped at thirty minutes**, enforced when issued and again when
  verified, so a compromised issuer cannot mint a long-lived one.
- **Expiry closes running sessions**, not only new ones.
- **Mutual TLS on every data-plane connection.** A peer without a certificate from this
  deployment's authority is refused during the TLS handshake, before it can send a
  protocol frame.
- **Identity comes from the certificate**, never from what a peer says about itself. A
  handshake claim that disagrees with the certificate ends the connection, and the role
  is part of the certificate so a device credential cannot open an operator session.
- **Single-use enrollment tokens**, consumed atomically, stored only as hashes.
- **Revocation and supersession are checked on every connection.** Re-enrolling an
  identity invalidates its previous certificate.
- **Device keys are sealed with DPAPI on Windows**, so a copy of the state directory
  taken to another machine or read by another account is undecryptable.
- **Resource targets are loopback-only**; the agent refuses to start otherwise.
- **Flow control is mandatory**, not advisory: a peer exceeding its granted window has
  its session terminated rather than being buffered for.
- **Payload is end-to-end encrypted.** A second mutually authenticated TLS 1.3 session
  runs between the operator and the agent inside the relayed stream, so the relay copies
  records it cannot read. Each end verifies the identity the grant names, which also
  makes a grant the relay carried for somebody else useless to it.
- **Every decision is recorded**, in the same transaction as the decision itself: a grant
  whose audit event cannot be written is not issued.
- **Revocation reaches streams already running.** Revoking a grant, a session, or an
  identity revokes what is beneath it and drops the affected streams at both ends.
- **Certificates renew unattended**, and a renewal interrupted part way through leaves
  the endpoint using the certificate it already had.
- **Reconnection backs off with full jitter**, so a relay restart is not met by the whole
  fleet at the same instant.

**Not yet implemented:**

- **The audit trail is not tamper-evident.** It is append-only in the software — nothing
  in the code updates or deletes a row — and it is queryable by actor, device, resource,
  grant, and event. It is not hash-chained, not signed, and not shipped anywhere. Anyone
  with filesystem access to the control-plane database can edit it with a standard tool.
  T18 is therefore mitigated against an operator and not against whoever runs the control
  plane.
- **Operator sessions are not a second authentication factor.** A session bounds and
  groups access and can be revoked in one action; the certificate remains the only
  credential, and anyone holding it can open a session.
- **Revocation reaches live streams only within the relay process that holds them.** In
  the shipped topology the relay and control plane are one process, so revoking a grant
  drops its streams immediately. A relay deployed as a separate process would learn on
  its next grant check — which happens at stream open — so a stream already joined would
  continue until it ended or the grant expired.
- **On platforms without DPAPI the key is protected by file permissions only.** Reported
  at startup rather than left to be assumed.
- **A certificate that has already expired cannot renew itself.** Renewal is
  authenticated by presenting the certificate being replaced, so an endpoint that
  was off for longer than its remaining life needs a human and a new enrollment
  token. The renewal window is ten days of a thirty-day life, so this requires an
  endpoint to be offline for most of a month.
- **The control plane is a single node.** SQLite means one writer, one machine, no
  replication, and no failover.

## Known limitations of the design

These remain true even once the code above lands. A security tool that hides its
limitations is worse than one that names them.

- **The relay sees connection metadata and cannot see payload.** A second mutually
  authenticated TLS 1.3 session runs between the operator and the agent inside the
  relayed stream, so the relay copies records it cannot read. What remains visible to it
  is who connected, to which device and resource, how many bytes moved, how long it took,
  and when — which is unavoidable, because that metadata is exactly what the audit trail
  is built from. Traffic analysis against timing and volume is therefore possible and is
  not mitigated.
- **The relay can still deny service.** It carries every stream, so it can refuse to
  carry them. End-to-end encryption protects confidentiality and integrity, never
  availability, and no relay-based architecture can protect the latter from the relay.
- **Whoever hands over an enrollment code is trusted.** The code is single-use and
  short-lived and carries the authority fingerprint so the peer can verify the server,
  but the channel that delivers it is outside the system. That is unavoidable at the
  bottom of a trust chain.
- **Clock skew** is a real weakness for short-TTL grants. v1 bounds tolerated skew and
  denies outside it; it does not implement a trusted time source.
- **Audit log is append-only by construction, not cryptographically tamper-evident.**
  The software never updates or deletes a row, but nothing stops someone with access to
  the database file from doing so. Hash chaining and an external sink are deliberately
  deferred.
- **No device posture checks.** Enrollment proves key possession, not machine health.
- **Single organization.** `organization_id` exists in the schema from day one, but
  multi-tenant isolation is not tested or claimed.
- **Local Administrator on the endpoint defeats this system.** By design; see out of scope.
- **This system grants access; it does not restrict existing access.** Installing an
  agent adds an authorized path to a service. It does not remove any path that already
  existed. A service already listening on a routable interface stays reachable from that
  network, unaudited, exactly as before — the agent does not intercept, filter, or
  firewall it.

  The strong case is therefore a service bound to loopback, where the agent is the *only*
  path and every use of it is audited. Where a service also listens on the LAN, the audit
  trail covers the remote sessions and nothing else. Anyone evaluating this system for a
  particular deployment needs to know which of the two they have.

## Failure policy

| Condition | Behavior |
| --------- | -------- |
| Control plane unreachable | Existing streams continue until grant expiry; **no new streams** |
| Grant signature invalid | Deny, audit, close connection |
| Grant expired or not yet valid | Deny, audit, reason code distinguishes the two |
| Resource not in local allowlist | Deny, audit; the resource ID is logged, the requested target is not honored |
| Target refuses connection | Deny with a distinct reason code — must not be conflated with a policy denial |
| Relay restarts | Agent reconnects with backoff and jitter; in-flight streams are closed, not silently resumed |
| Agent process crashes | SCM restarts it; WFP dynamic filters are released by the OS; state on disk stays valid |

Every row above is a required test case in [e2e-test-plan.md](e2e-test-plan.md).
