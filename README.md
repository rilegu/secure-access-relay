# secure-access-relay

**Time-limited, audited, policy-scoped access to one approved local service on a
Windows endpoint — with no inbound firewall rule, no port forward, and no public IP.**

A VPN puts you *on a network*. `secure-access-relay` grants you *one resource, for a
bounded time, with an audit record*.

> Experimental project. Not production software. See
> [Non-goals](#non-goals) and [docs/threat-model.md](docs/threat-model.md).

## The problem

A vendor needs to reach a diagnostic service on a Windows machine inside a customer's
network. The usual options are both bad:

```
Open RDP/SSH to the internet          ->  permanent, scannable, unaudited
Give the vendor a full VPN account    ->  broad lateral access to the whole subnet
```

Neither expresses what was actually intended: *this engineer, this machine, this one
service, for thirty minutes, with a record*.

## How it works

```
Operator (Company A)                     Windows endpoint (Company B)
  sarctl connect                           sar-agent (Windows Service)
     |  outbound TLS                           |  outbound mTLS
     +--------->  sar-server (control + relay) -+
                  self-hosted VM / DMZ / cloud        |
                                                      v
                                              127.0.0.1:8080
```

Both sides dial **outward**, so neither network needs an inbound rule. The relay pairs
two already-authorized streams; it never decides policy. The agent verifies a
short-lived signed grant **locally** before it dials anything.

A reachable coordination point is required — but it can be entirely self-hosted (a DMZ
box, a VPS, your own Kubernetes). No third-party SaaS is involved.

## Components

| Binary       | Role |
| ------------ | ---- |
| `sar-agent`  | Windows Service on the protected endpoint |
| `sar-server` | Control plane (identity, enrollment, policy, grants, audit) + relay |
| `sarctl`     | Operator CLI |
| `sardiag`    | Optional C diagnostics library, loaded dynamically |

## Security model

Specified in full below. See [Status](#status) for what is actually implemented — today
that is nothing, so read this as the design rather than as shipped behavior.

- **Deny by default**; every denial has an explicit reason code.
- **Loopback-only targets in v1** — this is not a general-purpose LAN proxy.
- **Ed25519-signed grants**, max 30-minute TTL, carrying issuer, user, device,
  resource, validity window, and grant ID.
- **The agent verifies grants itself.** The relay is untrusted for authorization, and a
  compromised relay cannot open a stream.
- **The control plane never carries payload**, and the relay never decides policy.
- **End-to-end encryption between operator and agent is designed but not implemented.**
  Until it lands the relay terminates TLS and can see plaintext, so it is trusted for
  confidentiality today — never for authorization.
- **Every session is audited**: identity, resource, start/end, byte counts, decision,
  and error reason. Secrets and payloads are never logged.
- **Failure denies.** A control-plane outage cannot widen access.

Full detail: [architecture.md](docs/architecture.md) ·
[threat-model.md](docs/threat-model.md) · [policy.md](docs/policy.md) ·
[protocol.md](docs/protocol.md)

## Status

**Not yet functional.** The design is specified and the implementation has not started.
Nothing in this repository will grant access to anything today.

| Capability | State |
| ---------- | ----- |
| Protocol, threat model, and authorization design | specified |
| TCP forwarding through the relay | not implemented |
| Framed multiplexed protocol with flow control | not implemented |
| mTLS and device enrollment | not implemented |
| End-to-end encryption between operator and agent | not implemented |
| Windows Service packaging and installer | not implemented |
| Named resources and signed time-bound grants | not implemented |
| Operator CLI and audit trail | not implemented |
| WFP leak guard | not implemented |
| Native diagnostics library | not implemented |

Read [docs/threat-model.md](docs/threat-model.md) before drawing any security conclusion
from the design documents — several properties described there are not yet backed by code.

## Non-goals

These are deliberate scope decisions, not missing features:

WireGuard / full VPN mesh · NAT hole-punching and direct peer-to-peer · kernel-mode or
WFP callout drivers · arbitrary subnet routing · UDP and QUIC · SSH/RDP-specific
integrations · multi-region high availability · desktop GUI · SCIM / enterprise SSO /
MDM-EDR posture checks · custom cryptography · custom password authentication.

Rationale for each is recorded in [docs/decisions/](docs/decisions/).

## Why Go and a narrow C boundary

Go carries the service lifecycle, networking, TLS, policy evaluation, and CLI. A single
small C library (`sardiag`) collects Windows adapter, route, DNS, and proxy state behind
a stable `extern "C"` ABI, loaded dynamically so the agent stays pure Go and
`CGO_ENABLED=0`. Native code is used where it is justified and nowhere else — no kernel
driver, no C++ types across the boundary.

## Building

```sh
make build          # all three binaries
make test           # fast unit tests
make lint
```

Without GNU make (typical on Windows), `scripts/task.ps1` mirrors every target:

```powershell
.\scripts\task.ps1 all
```

Windows integration tests require a disposable VM — see
[docs/e2e-test-plan.md](docs/e2e-test-plan.md). Packaging, ACLs, and service
registration are described in
[docs/installer-and-updates.md](docs/installer-and-updates.md).

Invariants, layout, stack rationale, and code conventions are in
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
