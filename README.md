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
 │     │      │  outbound    │  public IP,  │   outbound   │  dials out only, │
 │     ▼      │  mutual TLS  │  the ONLY    │  mutual TLS  │  never listens   │
 │ 127.0.0.1: │═════════════▶│  listener    │◀═════════════│        │         │
 │   18080    │              │  anywhere    │              │        ▼         │
 │   sarctl   │              │              │              │  127.0.0.1:8080  │
 └────────────┘              │ + control    │              │  the service     │
                             │   plane      │              └──────────────────┘
   no inbound rule           └──────────────┘                 no inbound rule
```

Both ends **dial outward**. The only machine that accepts an incoming connection is the
relay, which you place deliberately and harden. Neither network needs a firewall change.

Every connection is mutual TLS, and a peer's identity comes from its certificate rather
than from anything it says about itself. An unenrolled peer is refused during the TLS
handshake, before it can send a single protocol frame.

The operator names a **resource**, never an address. The agent resolves that name against
its own local allowlist and refuses anything that is not loopback. That is the difference
between a resource proxy and a tunnel.

### What is on the wire

Two planes, two transports, chosen for different jobs:

| | Transport | Client auth | Carries |
| --- | --------- | ----------- | ------- |
| **Data plane** | **TLS 1.3 over TCP — not HTTP** | mutual TLS | custom binary frames: multiplexed streams, flow control |
| **Control plane** | **HTTPS** (HTTP over TLS 1.3) | server-authenticated only | JSON: enrollment |

The data plane carries bulk traffic and needs multiplexing, credit-based flow control,
and hard size limits — none of which HTTP provides. Nothing on it parses a request line
or a header; it is TCP, then TLS, then a ten-byte frame header, then payload.

The control plane is low-volume and human-facing, so it is ordinary HTTPS with JSON. You
can `curl` it, and it is trivial to document.

The one asymmetry: **enrollment cannot require a client certificate**, because a peer is
connecting precisely because it does not have one yet. That is the bootstrap problem, and
it is why the enrollment code carries the authority fingerprint — the peer verifies the
server before sending its token. Every *other* connection in the system is mutual TLS,
and a peer without a certificate from this deployment's authority is refused during the
handshake.

TLS 1.3 only, everywhere. Older versions bring renegotiation and cipher negotiation that
exist for compatibility with software this project does not need to talk to, and both
ends are built from this repository.

### Enrollment, once per peer

```
  admin ──▶ sar-server token -device panel-01
                  │
                  ├── single-use code, valid one hour, carrying the
                  │   authority fingerprint so the peer can verify
                  │   the server before sending anything
                  ▼
            hand it to the endpoint
                  │
                  ▼
  endpoint ──▶ sar-agent enroll -code sar1...
                  │  generates its own key, which never leaves the machine
                  │  sends only a certificate request
                  ▼
            certificate + authority, key sealed with DPAPI on Windows
```

The identity comes from the **token**, never from the certificate request — a request is
written by whoever wants a certificate, so nothing in it is a fact. Re-enrolling replaces
the certificate on file, so the previous one stops working.

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
| `sar-agent` | the protected machine | Runs as a Windows service. Enrolls once, then holds an outbound mTLS session. Local resource allowlist, dials only loopback. Never listens. |
| `sar-server` | a reachable VM you control | Control plane (certificate authority, enrollment, revocation) **and** relay (joins authorized streams). |
| `sarctl` | the operator's laptop | Enrolls once, then opens a local loopback listener and carries it through the relay. |
| `sardiag` | the protected machine | Optional C diagnostics library, dynamically loaded. Not yet written. |

The relay can be entirely self-hosted — a DMZ box, a VPS, your own cloud account. No
third-party service is involved.

## Design

The parts that make this different from a tunnel with a login:

**Outbound-only, both ends.** The agent never calls `listen`. There is no port to scan,
no rule to request, and no exposure added to the protected machine.

**The certificate is the identity.** A peer's identity — including whether it is a device
or an operator — comes from a URI in its certificate, never from what it says about
itself. A claim that disagrees with the certificate ends the connection. Enrollment is
bootstrapped by pinning the authority's fingerprint inside the enrollment code, so a peer
with no trust anchor can still verify the control plane before sending its token. See
[ADR-0010](docs/decisions/0010-certificate-is-the-identity.md).

**Re-enrolling invalidates the old certificate.** The control plane records which
certificate is current for an identity, so rotating after a suspected compromise is a
remedy rather than a ritual.

**The same binary is the service and the debugger.** Started by the Windows service
manager it reports status and answers stop and shutdown; started from a console it runs
directly. One code path, so console mode is a genuine way to debug the service rather
than a second program with its own bugs.

**Windows APIs are called through the standard library.** DPAPI, the service control
manager, and the Event Log are reached with `syscall` rather than a third-party binding —
about fifteen entry points, each visible with its structure layout and error handling.
See [ADR-0012](docs/decisions/0012-win32-through-stdlib.md).

**Loopback-only targets, enforced at startup.** A target must be a literal loopback
address with an explicit port. Hostnames are rejected outright, so **no DNS lookup is ever
performed for a target** — a resource pinned to `127.0.0.1` cannot be moved by a poisoned
answer. A misconfigured allowlist produces a failed startup, never a running agent.

**The relay is untrusted for authorization.** It joins streams and forwards bytes
opaquely, holds no signing key, and makes no access decision. It does check a grant, but
only to fail fast — the endpoint agent verifies the same grant independently, against a
key it obtained at enrollment, before it dials anything. A compromised relay can ask, and
be refused.

**An operator names a resource; the agent resolves it.** The grant carries a resource
identifier, never an address. The agent looks it up in its own local allowlist and refuses
anything not declared there — so an authorization bug cannot become "reach anything you
can name". A resource file with a non-loopback target stops the agent starting.

**Grants expire, and expiry is enforced on running sessions.** A stream is closed when its
grant lapses, not merely refused at the moment it opens. Thirty minutes is the ceiling
regardless of what a policy asks for, checked both when a grant is issued and again when
it is verified — so a compromised issuer cannot mint a year-long one.

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

**Dependencies have to earn their place.** Every one must survive the question *"why not
the standard library?"*, and so far none have: the entire system today is stdlib, and
that includes the Windows DPAPI binding and the multiplexer. Binaries are static, ~4 MB,
`CGO_ENABLED=0`, and cross-compile to Linux, Windows, and ARM from any host.

That count will not stay at zero. A database arrives with the policy engine and audit
trail, because correctness there is hard to write and easy to get subtly wrong — see
[ADR-0011](docs/decisions/0011-sqlite-not-key-value.md). The rule is the property worth
keeping, not the number.

## Status

**This is now a resource proxy.** Every connection is mutual TLS, every peer is an
enrolled identity proved by certificate, and every stream requires a signed, expiring
grant that the endpoint agent verifies for itself before it dials anything.

What is missing is the record: there is no queryable audit trail yet, and grants cannot
be revoked before they expire.

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
| Mutual TLS on every connection | working |
| Enrollment with single-use tokens | working |
| Certificate-bound identity and roles | working |
| Revocation and certificate supersession | working |
| Device key sealed with DPAPI (Windows) | working |
| Named resources declared by the agent | working |
| Policy engine, deny by default | working |
| Ed25519-signed time-bound grants | working |
| Agent verifies grants independently | working |
| Windows Service with restart-on-failure | working |
| Windows Event Log for operational events | working |
| PowerShell installer with ACL-protected state | working |
| End-to-end encryption between operator and agent | not implemented |
| Operator login flow | not implemented |
| Queryable audit trail | not implemented |
| Grant revocation before expiry | not implemented |
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
- **Revocation takes effect on the next connection, not immediately.** A session already
  running continues until it ends. Restarting the relay is currently the way to drop one.
- **Certificates expire after thirty days and are not renewed automatically.**
  Re-enrolling is a manual step.
- **Whoever hands over an enrollment code is trusted.** The code is single-use,
  short-lived, and carries the authority fingerprint so the peer can verify the server it
  enrolls with — but the channel that delivers it is outside the system. That is
  unavoidable at the bottom of a trust chain.

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

Transport security is **TLS 1.3 with mutual TLS**, Ed25519 throughout — the authority,
the certificates, and later the grants use one signature primitive rather than several.
TLS 1.3 only: older versions bring renegotiation and cipher negotiation that exist for
compatibility with software this project does not need to talk to.

Authorization will be **Ed25519-signed grants** with a fixed claim set rather than JWT,
because JWT's `alg` field is a decision a verifier can get wrong —
[ADR-0003](docs/decisions/0003-ed25519-grants-not-jwt.md).

**DPAPI is reached through the standard library**, not a third-party Windows binding.
That keeps the dependency count at zero and rehearses the dynamic-loading technique the
native diagnostics library will use.

## Trying it

Everything on one machine. Nothing listens on a routable interface except the relay.

**1. Say what the endpoint serves.** `resources.json`, read by the agent:

```json
[{ "resource_id": "res_diagnostics", "name": "panel diagnostics",
   "protocol": "tcp", "target": "127.0.0.1:8080",
   "max_bytes": 104857600, "max_duration": "20m" }]
```

A non-loopback target here stops the agent starting. The operator never sees this file;
they name `res_diagnostics` and the agent resolves it.

**2. Say who may reach it.** `policy.json`, in the server's state directory:

```json
[{ "policy_id": "pol_support", "principals": ["maria"],
   "devices": ["panel-lab-01"], "resources": ["res_diagnostics"],
   "max_ttl": "20m", "effect": "allow" }]
```

Allow-only, no wildcards, exact matches. No policy file means nothing is reachable.

**3. Run it.**

```sh
make build

# Mint single-use enrollment codes. The first call creates the authority.
./bin/sar-server token -device panel-lab-01
./bin/sar-server token -operator maria

# Start the control plane and relay.
./bin/sar-server run

# Enroll, once per peer. Each generates its own key locally; only a certificate
# request is ever transmitted.
./bin/sar-agent enroll -code sar1...
./bin/sarctl    enroll -code sar1...

# A local service to expose. Binds strictly to loopback.
go run ./testdata/fixtures/httpfixture.go -addr 127.0.0.1:8080

# The endpoint agent. Dials out; never listens.
./bin/sar-agent run -resources resources.json

# The operator forward. Requests a grant, then carries traffic under it.
./bin/sarctl connect -device panel-lab-01 -resource res_diagnostics -listen 127.0.0.1:18080
```

Then:

```sh
curl http://127.0.0.1:18080/health
```

The request travels `curl -> sarctl -> relay -> agent -> 127.0.0.1:8080` and back, over
mutual TLS between each pair, under a grant the agent verified for itself.

The server log records the decision:

```
"msg":"grant issued"  user_id=maria device_id=panel-lab-01
                      resource_id=res_diagnostics policy_id=pol_support
                      expires_at=2026-08-20T21:01:31Z
```

and the agent records enforcing it:

```
"msg":"stream authorized"  grant_id=grn_1142... resource_id=res_diagnostics
                           target=127.0.0.1:8080 expires_in_s=1199
```

To see the enforcement, ask for something no policy allows:

```sh
./bin/sarctl connect -device panel-lab-01 -resource res_not_allowed -listen 127.0.0.1:18081
# grant refused: policy_denied — no stream is ever opened
```

Or point things where they must not go:

```sh
./bin/sar-agent run -target 192.168.1.10:8080         # refuses to start: must be loopback
./bin/sar-agent run -target localhost:8080            # refuses to start: names are not resolved
./bin/sarctl connect -device x -resource y -listen 0.0.0.0:18080  # refuses: must be loopback
./bin/sar-agent enroll -code <an already used code>   # refused: tokens are single use
```

Revoke an identity and it is refused on its next connection:

```sh
./bin/sar-server revoke -device panel-lab-01
./bin/sar-server list
```

### As a Windows service

On the protected machine, from an elevated prompt:

```powershell
.\installer\install.ps1 -EnrollmentCode sar1... -RelayAddr relay.example:443 -Target 127.0.0.1:8080
```

That copies the agent to Program Files, creates an ACL-protected state directory under
ProgramData that Users cannot read, enrolls the device, and registers the service with
delayed auto-start and restart-on-failure. Removal keeps the enrolled identity unless you
ask for it to be deleted:

```powershell
.\installer\uninstall.ps1              # keeps the key and certificate
.\installer\uninstall.ps1 -RemoveState  # forgets this device entirely
```

The agent can also manage its own registration:

```powershell
sar-agent service install|start|stop|status|uninstall
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
