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
| T2 | Compromised relay opens a stream on its own authority | Agent independently verifies the Ed25519 grant signature, expiry, and `device_id` before dialing. Relay possesses no signing key. |
| T3 | Compromised relay reads payload | Data plane is TLS between operator and agent; relay forwards ciphertext. (v1 caveat below.) |
| T4 | Grant replayed after expiry | `expires_at` checked at the agent against local clock; max TTL 30 minutes; skew tolerance bounded and explicit. |
| T5 | Grant tampered with (extended TTL, swapped resource) | Whole grant is signed; any field change invalidates the signature. |
| T6 | Grant for device A replayed at device B | `device_id` is inside the signed grant and compared with the agent's own identity. |
| T7 | Operator requests a LAN or internet target | Target address is never operator-supplied. The operator names a `resource_id`; the agent resolves it in its own local allowlist, and rejects any non-loopback target. |
| T8 | Enrollment token reused to enroll a second device | Tokens are single-use, short-lived, and marked consumed transactionally on first use. |
| T9 | Device key extracted from disk | Key is DPAPI-protected under the service account; state directory ACL'd to LocalSystem + Administrators. Copying the directory to another host yields an undecryptable key. |
| T10 | Revoked device continues an established session | Revocation terminates live sessions, not merely new ones. Agent enforces heartbeat timeout; loss of control-plane contact denies *new* streams. |
| T11 | Unprivileged local user drives the service via named pipe | Pipe ACL restricted to Administrators and the interactive owner; every request is authorized, not merely accepted. |
| T12 | Resource exhaustion via stream or frame flooding | Per-connection max frame size, per-agent concurrent stream cap, per-session byte and time budgets, bounded buffers, read deadlines. |
| T13 | Malformed protocol input causes crash or overread | Length-prefixed frames validated against limits before allocation; fuzz tests over the codec. |
| T14 | Secrets leak through logs or the support bundle | Central redaction layer; tokens, keys, signatures, and payload bytes never reach a log sink; support bundle is generated through the same redactor. |
| T15 | Failure of the control plane widens access | Deny-by-default on any authorization error, timeout, or signature-verification failure. There is no permissive fallback path. |
| T16 | Stale WFP filters persist after a crash and break networking | Dynamic WFP session — filters are removed by the OS when the engine handle closes. Boot-time filters are not used in v1. |
| T17 | Native DLL is replaced with a hostile one | DLL loaded by absolute path from the ACL-protected install directory, Authenticode signature verified before load, never from `%PATH%` or the working directory. |
| T18 | Audit gaps hide an incident | Security-relevant decisions emit an audit event before the action completes; denials are audited with the same weight as allows. |

## Known v1 limitations

Stated plainly. A security tool that hides its limitations is worse than one that names them.

- **End-to-end encryption between operator and agent is planned, not implemented.**
  Until the operator<->agent session key exchange lands, the relay terminates TLS and
  can see plaintext. T3 is therefore only partially mitigated today. The README and
  this document must not claim otherwise before the code is there.
- **Clock skew** is a real weakness for short-TTL grants. v1 bounds tolerated skew and
  denies outside it; it does not implement a trusted time source.
- **Audit log is append-only by convention, not cryptographically tamper-evident.**
  Hash chaining is deliberately deferred.
- **No device posture checks.** Enrollment proves key possession, not machine health.
- **Single organization.** `organization_id` exists in the schema from day one, but
  multi-tenant isolation is not tested or claimed.
- **Local Administrator on the endpoint defeats this system.** By design; see out of scope.

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
