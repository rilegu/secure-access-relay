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

**The data path works; none of the security does.** Traffic can be forwarded end to
end, but there is no encryption, no authentication, and no authorization — anything
that can reach the relay's operator port gets a stream.

| Capability | State |
| ---------- | ----- |
| Protocol, threat model, and authorization design | specified |
| Framed wire protocol with enforced limits | working |
| TCP forwarding, operator to endpoint | working, one stream at a time |
| Loopback-only target enforcement | working |
| Reconnect after a dropped relay connection | working |
| Stream multiplexing and flow control | not implemented |
| mTLS and device enrollment | not implemented |
| End-to-end encryption between operator and agent | not implemented |
| Windows Service packaging and installer | not implemented |
| Named resources and signed time-bound grants | not implemented |
| Operator login and audit trail | not implemented |
| WFP leak guard | not implemented |
| Native diagnostics library | not implemented |

Read [docs/threat-model.md](docs/threat-model.md) before drawing any security conclusion
from the design documents — most of the controls described there are not yet backed by
code.

## Trying it

Four processes on one machine. Nothing listens on a routable interface.

```sh
make build

# A local service to expose. Binds strictly to loopback.
go run ./testdata/fixtures/httpfixture.go -addr 127.0.0.1:8080

# The relay: one port for endpoint agents, one for operators.
./bin/sar-server -agent-addr 127.0.0.1:17070 -operator-addr 127.0.0.1:17071

# The endpoint agent. Dials out; never listens.
./bin/sar-agent -relay-addr 127.0.0.1:17070 -target 127.0.0.1:8080

# The operator forward.
./bin/sarctl -relay-addr 127.0.0.1:17071 -listen 127.0.0.1:18080 -resource fixture
```

Then:

```sh
curl http://127.0.0.1:18080/health
```

The request travels `curl -> sarctl -> relay -> agent -> 127.0.0.1:8080` and back. The
fixture is never reachable from outside the machine, and the endpoint opens no inbound
port.

To see the enforcement, point the agent somewhere it must not go:

```sh
./bin/sar-agent -target 192.168.1.10:8080   # refuses to start: target must be loopback
./bin/sarctl -listen 0.0.0.0:18080          # refuses to start: listen must be loopback
```

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
[DEVELOPMENT.md](DEVELOPMENT.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
