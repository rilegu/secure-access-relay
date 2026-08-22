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
| `sar-server` | a reachable VM you control | Control plane (certificate authority, enrollment, policy, grants, sessions, audit trail) **and** relay (joins authorized streams). |
| `sarctl` | the operator's laptop | Enrolls once, opens a session, then opens a local loopback listener and carries it through the relay. |
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

**The relay is untrusted, for authorization and for confidentiality both.** It joins
streams and forwards bytes opaquely, holds no signing key, and makes no access decision.
It does check a grant, but only to fail fast — the endpoint agent verifies the same grant
independently, against a key it obtained at enrollment, before it dials anything. A
compromised relay can ask, and be refused.

**Operator and agent run their own encrypted session inside the relayed stream.** A second
mutually authenticated TLS 1.3 session, using the certificates both ends already hold, so
the relay copies records it cannot read. Each end verifies the identity the grant names:
the operator requires the endpoint it was authorized for, and the agent requires the
operator the grant was issued to.

That second check closes a hole that had nothing to do with confidentiality. A grant
travels through the relay, so a compromised relay could previously replay one it observed
and open its own stream with it — the signature verified, the device matched, the user
matched. The agent could prove the *grant* was genuine but not that the peer holding it
was. It now has to prove possession of the operator's private key, which a relay does not
have. See [ADR-0018](docs/decisions/0018-nested-tls-for-end-to-end-encryption.md).

**An operator names a resource; the agent resolves it.** The grant carries a resource
identifier, never an address. The agent looks it up in its own local allowlist and refuses
anything not declared there — so an authorization bug cannot become "reach anything you
can name". A resource file with a non-loopback target stops the agent starting.

**Grants expire, and expiry is enforced on running sessions.** A stream is closed when its
grant lapses, not merely refused at the moment it opens. Thirty minutes is the ceiling
regardless of what a policy asks for, checked both when a grant is issued and again when
it is verified — so a compromised issuer cannot mint a year-long one.

**Revocation reaches sessions already running.** Revoking a grant does not merely refuse
the next stream; it drops the streams that grant already opened, at both ends. Half of a
revocation would leave the agent holding an open connection to the local service, which
is the thing being taken away. Ending an operator's session revokes the grants issued
under it, and revoking an operator ends their sessions — because a revocation that leaves
signed grants valid gives back, for up to half an hour, exactly what it was meant to
remove.

**A session is a revocation handle, not a second factor.** `sarctl login` opens one, and
the certificate is what authenticates it — anyone holding the certificate can open a
session, and no additional secret is required. What it buys is a lever shorter than a
30-day certificate, and attribution: every grant records the session it was issued under,
so an operator's activity during one incident is a single query rather than a
reconstruction from timestamps. It is also the seam an identity provider plugs into later.

**Reconnect backs off, with jitter, and listens for the network coming back.**
A fixed retry interval is fine for one client and pathological for a fleet: a
relay restart is met by every endpoint at the same instant, forever, and the
restart becomes an outage. Delays grow exponentially and are drawn uniformly from
the whole interval — a narrow band around a shared value is still a shared value.
Separately, an address appearing cuts the wait short, because backoff answers
"how hard should I retry" and a network change answers "the reason it was failing
may have just gone away". The two are different questions and both are needed.

**Certificates renew themselves, and a failed renewal cannot brick an endpoint.**
Certificates last thirty days; without renewal a fleet goes dark in the same week
it was enrolled, silently. Renewal is authenticated by the certificate being
replaced, so it needs no token and no human. The subtle part is that a renewed
certificate is recorded as *pending* and only becomes current the first time it
is actually presented — so a crash, a full disk, or a power cut between issuing
and storing it leaves the endpoint still able to authenticate with what it had.
Superseding at issue, the obvious implementation, has a small window with an
unrecoverable consequence, which is the worst combination
([ADR-0016](docs/decisions/0016-renewal-is-pending-until-used.md)).

Certificate lifetime is `sar-server run -cert-ttl` and defaults to thirty days;
peers renew at ten days remaining. Setting it to a couple of minutes is how the
whole cycle is exercised without waiting three weeks.

**Every decision is written to a queryable audit trail.** Who connected, what they were
granted and under which policy, every stream opened and refused with its reason code, and
every finished stream's byte counts and duration. A grant and the record of that grant
commit in one database transaction — access that nothing accounts for is worse than
access refused, so if the record cannot be written the grant is not issued. Payload bytes,
tokens, keys, and grant signatures are never recorded; there is a test that sends a canary
string through a forward and fails if it appears in any column of any row.

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
the standard library?"*. Exactly one has: `modernc.org/sqlite`, which holds control-plane
state and the audit trail. An append-only trail queried across several dimensions is not
something to hand-roll, and the alternative — a key-value store plus a log file — loses on
the data that actually matters and cannot write a decision and its record in one
transaction. See [ADR-0011](docs/decisions/0011-sqlite-not-key-value.md).

It is a pure-Go translation of SQLite rather than a cgo binding, which removes the
memory-safety bug class and keeps `CGO_ENABLED=0`. Be clear about what it costs: one
direct dependency, nine transitive ones, and by a wide margin the largest body of code in
the build — none of which anyone here has read. That is the honest price of not
hand-rolling an audit store.

Everything else, including the multiplexer, the wire protocol, the grant encoding, and
every Windows API binding, is the standard library. Binaries are static and cross-compile
to Linux, Windows, and ARM from any host.

## Status

**This is now a resource proxy.** Every connection is mutual TLS, every peer is an
enrolled identity proved by certificate, and every stream requires a signed, expiring
grant that the endpoint agent verifies for itself before it dials anything.

Every decision is recorded, every grant can be taken back before it expires including from
a session already running, and the relay carries traffic it cannot read. It still sees
metadata — who reached which device and resource, how much, for how long — because that
metadata *is* the audit trail.

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
| Per-session transfer cap (`max_bytes`) | working |
| Operator sessions, bounded and revocable | working |
| Queryable audit trail | working |
| Grant revocation before expiry, including live streams | working |
| Cascading revocation: identity to sessions to grants to streams | working |
| SQLite control-plane state with numbered migrations | working |
| Exponential reconnect backoff with full jitter | working |
| Network-change detection (native on Windows, polled elsewhere) | working |
| Unattended certificate renewal | working |
| Audit retention, explicit and self-recording | working |
| End-to-end encryption between operator and agent | working |
| Operator and agent authenticate each other directly | working |
| Tamper-evident or externally shipped audit | not implemented |
| Single sign-on for operators | not implemented |
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
- **The relay sees connection metadata.** Who connected, to which device and resource,
  how many bytes, for how long, and when. It cannot see payload — that is what the inner
  session prevents — but traffic timing and volume are visible by construction, because a
  relay that could not count bytes could not produce an audit trail. It can also refuse to
  carry traffic at all: end-to-end encryption protects confidentiality and integrity, not
  availability.
- **Scoping is per port, not per operation.** The system controls who reaches which
  resource for how long. What is possible once connected is defined by the service behind
  that port.
- **The audit trail is append-only in the software, not tamper-evident.** Nothing in the
  code updates or deletes a row. Anyone with filesystem access to the database can still
  edit it with a standard tool, and there is no hash chain, no signature, and no shipping
  to an external sink. It is evidence against an operator, not against whoever runs the
  control plane.
- **A session is not a second authentication factor.** The certificate is the only
  credential; a session is a bounded, revocable handle on top of it. It shortens the
  window and groups activity for audit — it does not make a stolen certificate harder to
  use.
- **Revocation reaches live streams only on a relay in the same process as the control
  plane.** That is the shipped topology, and it is what the `sar-server run` command
  starts. A relay running as a separate process learns of a revocation on its next grant
  check, which happens when a stream is opened — so a stream already joined continues
  until it ends or the grant expires. Splitting the two is not supported yet.
- **The control plane is a single node.** SQLite means one writer and one machine. There
  is no replication and no failover; a lost database is a lost deployment unless it was
  backed up.
- **An endpoint offline for most of a month needs re-enrolling by hand.**
  Certificates renew themselves unattended, but renewal is authenticated by
  presenting the certificate being replaced — so one that has already expired
  cannot renew. The window is ten days of a thirty-day life.
- **The audit trail grows until somebody prunes it.** Retention exists but is
  never automatic, because software that silently deletes its own evidence is
  worse than software that fills a disk. `sar-server audit -stats` shows the size.
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

**Go** for the service lifecycle, networking, protocol, policy evaluation, audit, and
CLI. Almost entirely the standard library — `crypto/tls`, `net`, `log/slog`, `database/sql`.
The single external dependency is **`modernc.org/sqlite`**, a pure-Go SQLite used for
control-plane state and the audit trail; every dependency has to survive the question
*"why not the standard library?"*, and that one does
([ADR-0011](docs/decisions/0011-sqlite-not-key-value.md)).

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

**DPAPI is reached through the standard library**, not a third-party Windows binding —
about fifteen entry points called with `syscall`, each visible with its structure layout
and error handling. It also rehearses the dynamic-loading technique the native diagnostics
library will use. The same applies to the service control manager and the Event Log
([ADR-0012](docs/decisions/0012-win32-through-stdlib.md)).

**Reconnection uses full jitter**, not a fixed interval and not a narrow band
around one. A thousand endpoints jittering ten percent around thirty seconds all
arrive inside a six-second window; drawing uniformly from the whole interval is
what actually decorrelates them. On Windows the reconnect loop also waits on
`NotifyAddrChange` and `NotifyRouteChange` through `syscall`, so a returning link
is noticed immediately rather than at the end of a grown delay; elsewhere it
polls the interface list.

**Control-plane state is SQLite**, with numbered migrations and an explicit refusal to
start against a schema newer than the binary understands. Every statement is
parameterised without exception: identifiers reach the control plane from certificates and
request bodies, and string-built SQL is the one failure class this project would otherwise
not have had at all. Key material never goes in the database — the authority key, device
keys, and the grant signing key stay in `internal/keystore`, sealed with DPAPI on Windows,
so a database compromise is not a key compromise.

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

# The endpoint agent. Dials out; never listens. The control-plane address is
# what lets it renew its own certificate before the thirty days are up; without
# it the agent works until the certificate lapses and then goes quiet.
./bin/sar-agent run -resources resources.json -control-addr 127.0.0.1:17071

# Open an operator session. The certificate authenticates it; the session is what
# makes the work that follows revocable as a group and attributable in the audit
# trail. connect opens one automatically if you skip this.
./bin/sarctl login

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

**4. Ask the trail what happened.** Every decision above is a row, queryable by actor,
device, resource, grant, or event:

```sh
./bin/sar-server audit
```

```
TIME                 EVENT           ACTOR  DEVICE        RESOURCE         GRANT              REASON  DETAIL
2026-08-21 20:12:08  stream.closed   maria  panel-lab-01  res_diagnostics  grn_00decae9a1...  ok      85B in / 145B out, 9ms
2026-08-21 20:12:08  stream.opened   maria  panel-lab-01  res_diagnostics  grn_00decae9a1...  -       -
2026-08-21 20:12:08  grant.created   maria  panel-lab-01  res_diagnostics  grn_00decae9a1...  -       policy pol_support
2026-08-21 20:12:06  operator.login  maria  -             -                -                  -       from 127.0.0.1
```

`-denials` narrows it to refusals, which is usually the question worth asking:

```sh
./bin/sar-server audit -denials -since 24h
./bin/sar-server audit -device panel-lab-01 -event stream.closed
./bin/sar-server audit -events            # the closed set of event names
```

Payload bytes never appear here. Neither do tokens, keys, or grant signatures.

**5. Take access back.** Revoking a grant drops the streams it opened, not just the next
one:

```sh
./bin/sar-server grants -active
./bin/sar-server grants -revoke grn_00decae9a1cb604d4a4a828f942b1e79
# the operator's in-flight request is cut; the next is refused with grant_revoked
```

The same at session and identity scope, each cascading down:

```sh
./bin/sar-server sessions -active
./bin/sar-server sessions -revoke ses_7a168801...   # ends the session and its grants
./bin/sar-server revoke -operator maria             # ends their sessions and their grants
./bin/sarctl logout                                 # the operator ending their own
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

Revoke an identity and it is refused on its next connection, and the grants naming it
are revoked immediately:

```sh
./bin/sar-server revoke -device panel-lab-01
./bin/sar-server list
```

### As a Windows service

On the protected machine, from an elevated prompt:

```powershell
.\installer\install.ps1 -EnrollmentCode sar1... -RelayAddr relay.example:443 `
                        -ControlAddr relay.example:17071 -Target 127.0.0.1:8080
```

`-ControlAddr` is what lets the service renew unattended. Leave it out and the
installer warns: the agent will run correctly until its certificate expires and
then stop connecting, which is the failure hardest to attribute after the fact.

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
