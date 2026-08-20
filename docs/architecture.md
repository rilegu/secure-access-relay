# Architecture

## Purpose

Grant a named operator time-limited, audited TCP access to **one explicitly approved
loopback service** on a Windows endpoint, without any inbound network exposure at the
endpoint.

## Components

```
+-------------------------+                      +---------------------------------+
| Operator workstation    |                      | Windows endpoint                |
|                         |                      |                                 |
|  sarctl                 |                      |  sar-agent (Windows Service)    |
|  - OIDC / dev login     |                      |  - device key (DPAPI protected) |
|  - grant request        |                      |  - outbound mTLS, never listens |
|  - local listener       |                      |  - resource allowlist           |
|    127.0.0.1:18080      |                      |  - local grant verification     |
+-----------+-------------+                      |  - audit + Event Log            |
            |                                    |  - WFP leak guard (planned)     |
            | outbound TLS 1.3                   +----------+----------------------+
            |                                               | outbound mTLS
            v                                               v
       +----------------------------------------------------------+
       | sar-server                                                |
       |                                                           |
       |  control plane            |  relay                        |
       |  - identity / orgs        |  - agent session registry     |
       |  - device enrollment      |  - operator session registry  |
       |  - resource registry      |  - authorized stream pairing  |
       |  - policy engine          |  - multiplexing + limits      |
       |  - grant issuance (Ed25519)                               |
       |  - audit sink             |  (no policy decisions here)   |
       +----------------------------------------------------------+
                                   |
                                   v
                            storage (SQLite v1)
```

The endpoint's approved service is reached only as `127.0.0.1:<port>`:

```
sar-agent --dial--> 127.0.0.1:8080   (the one approved resource)
```

## What is built today

The diagram above is the target. The current build implements the data path and none of
the security layers:

| Component | Today |
| --------- | ----- |
| `sar-agent` | outbound session, concurrent streams, one configured loopback target, reconnect on failure. No service packaging, no verified identity, no grant verification. |
| `sar-server` | relay only. One listener for both roles, session registry keyed by device, stream joining. No control plane. |
| `sarctl` | local forwarder. One relay session carrying many streams. No login, no grant request, no audit query. |
| Transport | plain TCP. **No TLS.** |
| Identity | device and user identities are **claims that nothing verifies**. |
| Authorization | none. Any peer reaching the relay may name any device. |

Two controls are fully enforced today:

- **Resource targets are loopback-only.** The agent refuses to start if its target is
  anything else.
- **Flow control is enforced, not advisory.** A peer that sends beyond the window it was
  granted has its session terminated rather than being allowed to grow a buffer.

Everything else in the trust boundary table below describes the design, not the running
code.

## Trust boundaries

| # | Boundary | Crossed by | Authenticated by |
| - | -------- | ---------- | ---------------- |
| 1 | Operator <-> control plane | HTTPS JSON API | operator identity (OIDC device code; dev credentials in `dev` profile) |
| 2 | Operator <-> relay | TLS data-plane connection | short-lived session token bound to a grant |
| 3 | Agent <-> control plane | HTTPS JSON API | mutual TLS, device certificate |
| 4 | Agent <-> relay | TLS data-plane connection | mutual TLS, device certificate |
| 5 | Agent <-> local target | loopback TCP | none — the target is unmodified; the agent is the enforcement point |
| 6 | Unprivileged CLI/UI <-> agent service | named pipe | pipe ACL restricted to Administrators + interactive owner |
| 7 | Agent <-> `sardiag.dll` | `extern "C"` ABI | in-process; DLL path pinned, signature checked before load |

Boundary 5 is the reason resource targets are loopback-only in v1: the agent is the
*only* thing standing between an authorized stream and the service, so the set of
reachable targets must be small, static, and explicitly configured.

## Data flow: an authorized session

```
1. sarctl login                  -> control plane issues an operator session
2. sarctl grants create          -> policy engine evaluates user x device x resource
                                    -> issues Ed25519-signed grant, TTL <= 30m
                                    -> audit: grant.created
3. sarctl connect                -> opens 127.0.0.1:18080 locally
                                 -> connects to relay, presents grant
4. relay                         -> verifies grant signature and expiry
                                 -> locates the agent's live session by device_id
                                 -> sends OPEN_STREAM to the agent, carrying the grant
5. sar-agent                     -> verifies grant signature, expiry, device_id match
                                 -> looks up resource_id in its LOCAL allowlist
                                 -> confirms target is loopback
                                 -> dials 127.0.0.1:8080
                                 -> audit: stream.opened
6. bytes flow                    -> bounded buffers, deadlines, byte accounting
7. close / expiry / revocation   -> audit: stream.closed {bytes, reason}
```

Step 5 is deliberately redundant with step 4. The relay checking the grant is a
convenience that fails fast; the agent checking it is the actual security control. A
compromised relay must not be able to open a stream.

## Why the relay and control plane are separate roles

| Role | Decides access? | Sees payload? | Scaling shape |
| ---- | --------------- | ------------- | ------------- |
| Control plane | yes | never | low volume, database-bound, private/admin-facing |
| Relay | never | ciphertext + metadata only **(target state; it terminates TLS today)** | high bandwidth, horizontally scalable, public-facing |

They ship as one binary in the MVP for operational simplicity, but they are separate
package trees (`internal/control`, `internal/relay`) with no cross-imports, so splitting
them into two deployables is a wiring change and not a refactor.

The relay is the component most exposed to the internet, so it is the component least
trusted with authority.

## Deployment models

| Model | Who runs sar-server | Third-party SaaS | Inbound rules needed |
| ----- | ------------------- | ---------------- | -------------------- |
| Self-hosted (primary) | the resource owner, in their DMZ/VPS/cloud | no | none at either endpoint |
| Hosted | a service operator | yes | none at either endpoint |
| Lab / same LAN | developer, locally | no | none |

Two agents alone cannot work across two organizations' networks: both sit behind NAT,
neither has a stable reachable address, and something must still answer *who is this,
what may they reach, is the grant still valid, and where does the audit go*. That role
is the control plane. It need not be someone else's cloud — but it must exist and be
reachable.

## State on the endpoint

```
%ProgramData%\secure-access-relay\
  device.crt            device certificate
  device.key            private key, DPAPI-protected, service account only
  resources.json        local resource allowlist (loopback targets)
  trust\                pinned control-plane CA
  logs\                 structured JSON logs, rotated
```

Directory ACLs restrict the tree to LocalSystem and Administrators. The unprivileged
CLI reaches this state only through the named-pipe RPC, never by reading files.
