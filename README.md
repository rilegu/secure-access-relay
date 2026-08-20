# secure-access-relay

**Time-limited, audited, policy-scoped access to one approved service on a remote
machine — with no inbound firewall rule, no port forward, and no public IP.**

A VPN puts you *on a network*. `secure-access-relay` grants you *one resource, for a
bounded time, with an audit record*.

> **Experimental. Not production software.** The data path works; the security layers do
> not exist yet. See [Status](#status) for exactly what is implemented, and
> [Limitations](#limitations) for what this does not do even when finished.

---

## The problem

An engineer needs to reach a diagnostic service on a machine inside someone else's
network. Today that means one of these:

```
Open RDP/SSH to the internet     →  permanent, internet-scannable, unaudited
Give the vendor a VPN account    →  lands them on the network: file servers, cameras, PLCs
Commercial remote-desktop tool   →  the whole desktop, through a third-party cloud
Send someone to site             →  $500–2,000 and three days for a config change
```

None of them expresses what was actually intended:

> *this engineer, this machine, this one service, for thirty minutes, with a record.*

The hard part is not encryption — it is that the machine is behind NAT and a firewall
nobody will change, and that "access" is normally all-or-nothing.

## How it works

```
  OPERATOR                        RELAY                      PROTECTED MACHINE
 ┌────────────┐              ┌──────────────┐              ┌──────────────────┐
 │ browser /  │              │  sar-server  │              │    sar-agent     │
 │ ssh / psql │              │              │              │                  │
 │     │      │   outbound   │  public IP,  │   outbound   │  dials out only, │
 │     ▼      │─────────────▶│  the ONLY    │◀─────────────│  never listens   │
 │ 127.0.0.1: │              │  listener    │              │        │         │
 │   18080    │              │  anywhere    │              │        ▼         │
 │   sarctl   │              └──────────────┘              │  127.0.0.1:8080  │
 └────────────┘                                            │  the service     │
                                                           └──────────────────┘
   no inbound rule                                            no inbound rule
```

Both ends **dial outward**. The only machine that accepts an incoming connection is the
relay, which you place deliberately and harden. Neither network needs a firewall change.

The operator names a **resource**, never an address. The agent resolves that name against
its own local allowlist and refuses anything that is not loopback. That is the difference
between a resource proxy and a tunnel.

## Use cases

**Vendor support for deployed equipment.** A manufacturer ships Windows-based panels to
hundreds of customer sites. Each runs a diagnostics UI bound to `127.0.0.1:8080` so it is
not exposed on the customer LAN. Support reaches that UI for twenty minutes with an audit
record, and the customer's IT team changes nothing.

**Remote access to services that should stay loopback.** RDP on `127.0.0.1:3389` or
`sshd` on `127.0.0.1:22` are unreachable from anywhere — until an authorized session opens
a stream to them. Internet-exposed RDP is a leading ransomware entry vector; this reaches
it without the port ever being open.

**Edge and OT gateways.** A small Linux gateway or Raspberry Pi runs the agent and exposes
its own interfaces — a config UI, a log reader, an MQTT admin port. Downstream controllers
reached over RS-485 or USB need no IP address, no agent, and no firmware change. The
binary is a 4 MB static file and cross-compiles to every ARM variant.

**Internal IT without standing access.** A DBA gets twenty minutes to a database console
that binds loopback, instead of permanent SSH to a jump host.

In each case the shape is the same: the service stays where it is, bound where it is, and
becomes reachable only through an authorized, time-bounded, recorded session.

## Components

| Binary | Runs on | Role |
| ------ | ------- | ---- |
| `sar-agent` | the protected machine | Outbound session, local resource allowlist, dials only loopback. Never listens. |
| `sar-server` | a reachable VM you control | Relay: joins authorized streams. Later also the control plane. |
| `sarctl` | the operator's laptop | Opens a local loopback listener and carries it through the relay. |
| `sardiag` | the protected machine | Optional C diagnostics library, dynamically loaded. Not yet written. |

The relay can be entirely self-hosted — a DMZ box, a VPS, your own cloud account. No
third-party service is involved.

## Design

The parts that make this different from a tunnel with a login:

**Outbound-only, both ends.** The agent never calls `listen`. There is no port to scan,
no rule to request, and no exposure added to the protected machine.

**Loopback-only targets, enforced at startup.** A target must be a literal loopback
address with an explicit port. Hostnames are rejected outright, so **no DNS lookup is ever
performed for a target** — a resource pinned to `127.0.0.1` cannot be moved by a poisoned
answer. A misconfigured allowlist produces a failed startup, never a running agent.

**The relay is untrusted for authorization.** It joins streams and forwards bytes
opaquely. It holds no key material and makes no access decision. When grants land, the
agent verifies them itself, so a compromised relay still cannot reach a service.

**Deny by default, with distinguishable reasons.** Every refusal carries a stable reason
code. `target_connection_refused` is never reported as `policy_denied` — an operator must
be able to tell *"you may not"* from *"it is down"* without reading logs.

**A hand-written wire protocol.** Length-prefixed frames whose declared size is validated
against a hard limit **before any allocation**, so a four-byte length field cannot induce
a large one. The decoder has a fuzz target. Framing is written out rather than delegated
because its behaviour on hostile input is the substance of the system, not an
implementation detail — see [ADR-0004](docs/decisions/0004-custom-data-plane-framing.md).

**Multiplexing with real flow control.** Many streams share one connection, each with a
credit window. A writer blocks when its window is spent; a peer that exceeds the window it
was granted has its session terminated rather than being buffered for. Backpressure is
enforced, not advisory.

**Half-close and abort are different operations.** A clean end closes one direction so a
request/response exchange can complete. A broken connection aborts both, because
half-closing a broken peer leaves it blocked forever on credit that will never arrive —
[ADR-0009](docs/decisions/0009-half-close-and-abort.md).

**Zero external dependencies.** The entire system is the Go standard library. Binaries are
static, ~4 MB, `CGO_ENABLED=0`, and cross-compile to Linux, Windows, and ARM from any host.

## Status

**The data path works; the security layers do not exist yet.** Traffic is forwarded end to
end, but there is no encryption and no authorization. Device and user identities are
claims that nothing verifies, so any peer that can reach the relay may name any endpoint.

| Capability | State |
| ---------- | ----- |
| Protocol, threat model, and authorization design | specified |
| Framed wire protocol with enforced limits | working |
| TCP forwarding, operator to endpoint | working |
| Stream multiplexing over one connection | working |
| Many endpoints and operators on one relay | working |
| Credit-based flow control | working |
| Keepalives and idle-timeout detection | working |
| Loopback-only target enforcement | working |
| Reconnect after a dropped relay connection | working |
| mTLS and device enrollment | not implemented |
| End-to-end encryption between operator and agent | not implemented |
| Named resources and signed time-bound grants | not implemented |
| Operator login and audit trail | not implemented |
| Windows Service packaging and installer | not implemented |
| WFP leak guard | not implemented |
| Native diagnostics library | not implemented |

One relay serves many endpoints and many operators, but an endpoint is reachable only
through the relay it connected to. There is no failover between relays; see
[ADR-0001](docs/decisions/0001-relay-first-transport.md).

## Limitations

Beyond the unimplemented work above, these hold by design:

- **It grants access; it does not restrict existing access.** Installing an agent adds an
  authorized path. It removes none. A service already listening on a routable interface
  stays reachable there, unaudited, exactly as before. The strong case is a service bound
  to loopback, where the agent is the *only* path.
- **Local Administrator or root on the protected machine defeats it.** That level of
  access can stop the service, patch the binary, or read protected state. True of every
  endpoint agent; stated rather than glossed over.
- **A reachable coordination point is required.** Self-hosted, but it must exist. Two
  agents alone cannot connect across two NATed networks.
- **The relay sees connection metadata**, and until end-to-end encryption lands it will
  see plaintext once TLS terminates there.
- **Scoping is per port, not per operation.** The system controls who reaches which
  resource for how long. What is possible once connected is defined by the service behind
  that port.

Full analysis, including the attacker model and eighteen threats mapped to controls, is in
[docs/threat-model.md](docs/threat-model.md).

## Non-goals

Deliberate scope decisions, not missing features:

WireGuard / full VPN mesh · NAT hole-punching and direct peer-to-peer · kernel-mode or
WFP callout drivers · arbitrary subnet routing · UDP and QUIC · SSH/RDP-specific
integrations · multi-region high availability · desktop GUI · SCIM / enterprise SSO /
MDM-EDR posture checks · custom cryptography · custom password authentication.

Rationale for each is in [docs/decisions/](docs/decisions/) — including
[why this is not built on an existing zero-trust overlay](docs/decisions/0008-no-existing-overlay-platform.md).

## Technology

**Go** for the service lifecycle, networking, protocol, policy evaluation, and CLI.
Standard library only — `crypto/tls`, `net`, `log/slog`. Every dependency has to survive
the question *"why not the standard library?"*, and so far none have.

**A small C library** (`sardiag`, not yet written) will collect Windows adapter, route,
DNS, and proxy state behind a stable `extern "C"` ABI, loaded dynamically so the agent
stays pure Go. C rather than C++ because C++ has no stable ABI and would need an
`extern "C"` wrapper anyway — [ADR-0005](docs/decisions/0005-native-c-dynamically-loaded.md).

Transport security will be **TLS 1.3 with mutual TLS**; authorization will be
**Ed25519-signed grants** with a fixed claim set rather than JWT, because JWT's `alg`
field is a decision a verifier can get wrong —
[ADR-0003](docs/decisions/0003-ed25519-grants-not-jwt.md).

## Trying it

Four processes on one machine. Nothing listens on a routable interface.

```sh
make build

# A local service to expose. Binds strictly to loopback.
go run ./testdata/fixtures/httpfixture.go -addr 127.0.0.1:8080

# The relay. One listener; peers state their role in the handshake.
./bin/sar-server -addr 127.0.0.1:17070

# The endpoint agent. Dials out; never listens.
./bin/sar-agent -relay-addr 127.0.0.1:17070 -device-id panel-lab-01 -target 127.0.0.1:8080

# The operator forward. Names the endpoint it wants; never an address.
./bin/sarctl -relay-addr 127.0.0.1:17070 -device panel-lab-01 \
             -resource diagnostics -listen 127.0.0.1:18080
```

Then:

```sh
curl http://127.0.0.1:18080/health
```

The request travels `curl → sarctl → relay → agent → 127.0.0.1:8080` and back. The
fixture is never reachable from outside the machine, and the protected machine opens no
inbound port.

To see the enforcement, point things where they must not go:

```sh
./bin/sar-agent -device-id x -target 192.168.1.10:8080   # refuses to start: must be loopback
./bin/sar-agent -device-id x -target localhost:8080      # refuses to start: names are not resolved
./bin/sarctl -device x -listen 0.0.0.0:18080             # refuses to start: must be loopback
```

## Documentation

| Document | Contents |
| -------- | -------- |
| [architecture.md](docs/architecture.md) | Components, trust boundaries, data flow, deployment models |
| [threat-model.md](docs/threat-model.md) | Assets, attacker model, threats and controls, limitations |
| [protocol.md](docs/protocol.md) | Frame format, handshake, stream lifecycle, limits, reason codes |
| [policy.md](docs/policy.md) | Resource and authorization model, evaluation, revocation, audit |
| [e2e-test-plan.md](docs/e2e-test-plan.md) | Test layers, golden path, mandatory deny cases |
| [installer-and-updates.md](docs/installer-and-updates.md) | Install layout, ACLs, service registration, signing |
| [decisions/](docs/decisions/) | Architecture decision records, each with what was rejected and why |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Invariants, layout, conventions, how to build and test |

## Building

```sh
make lint       # go vet + gofmt check
make test       # fast unit and wiring tests
make test-race  # same, under the race detector
make build      # all three binaries
```

Without GNU make (typical on Windows), `scripts/task.ps1` mirrors every target:

```powershell
.\scripts\task.ps1 all
```

Windows integration tests require a disposable VM — see
[docs/e2e-test-plan.md](docs/e2e-test-plan.md).

This project is not accepting outside contributions; see [DEVELOPMENT.md](DEVELOPMENT.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
