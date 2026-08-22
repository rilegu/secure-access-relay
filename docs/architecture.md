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
                        storage (JSON today, SQLite next)
```

The endpoint's approved service is reached only as `127.0.0.1:<port>`:

```
sar-agent --dial--> 127.0.0.1:8080   (the one approved resource)
```

## What is built today

The diagram above is the target. The current build implements every layer of it except
end-to-end encryption:

| Component | Today |
| --------- | ----- |
| `sar-agent` | runs as a Windows service with delayed auto-start and restart-on-failure. Enrolls, holds an outbound mTLS session, verifies every grant itself, resolves resource identifiers against its own allowlist, enforces expiry and byte budgets on running streams, reconnects on failure. |
| `sar-server` | control plane (authority, enrollment, policy, grants, operator sessions, audit trail in SQLite) **and** relay (one listener for both roles, registry keyed by device, stream joining, revocation enforcement). |
| `sarctl` | enrolls, opens a session, requests grants under it, and carries many streams over one relay session. |
| Transport | **TLS 1.3, mutual, on every data-plane connection.** |
| Identity | **from the certificate.** Enrolled, revocable, role-bound. |
| Authorization | **signed grants.** Policy decides, the agent enforces, the relay fails fast. |
| Accountability | **queryable append-only audit trail**, written in the same transaction as the decision it records. |
| Revocation | **immediate**, including streams already running. Cascades identity to sessions to grants to streams. |

Enforced today:

- **Mutual TLS.** A peer without a certificate from this authority is refused during the
  handshake, before it can send a protocol frame.
- **Identity is certificate-bound.** A handshake claim that disagrees with the
  certificate ends the connection, and the role is part of the certificate.
- **Revocation and supersession** are checked on every connection; re-enrolling
  invalidates the previous certificate.
- **Resource targets are loopback-only.** The agent refuses to start otherwise.
- **Flow control is enforced, not advisory.** A peer exceeding its granted window has its
  session terminated rather than being allowed to grow a buffer.
- **Device keys are sealed with DPAPI on Windows**, and the state directory's ACL is set
  explicitly at install time so Users have no access. Inheritance is broken deliberately:
  the default inherited ACL grants Users read access, which would expose device state.
- **Operational events reach the Windows Event Log** as well as the structured JSON log,
  so an administrator looking in the usual place finds something.

- **Every stream requires a signed grant**, verified independently by the agent against a
  key it obtained at enrollment. The relay checks the same grant, but only to fail fast.
- **Revocation reaches running streams.** The relay registers each joined stream against
  the grant that authorized it and resets both ends when that grant is revoked — see
  [ADR-0015](decisions/0015-revocation-reaches-live-streams.md).
- **Every decision is recorded.** A grant and its audit event commit in one transaction,
  so there is no state where access exists and nothing accounts for it.

The largest remaining gap is **end-to-end encryption**. The relay terminates TLS on both
sides and therefore sees plaintext; it is trusted for confidentiality today, and never for
authorization.

## Trust boundaries

| # | Boundary | Crossed by | Authenticated by |
| - | -------- | ---------- | ---------------- |
| 1 | Operator <-> control plane | HTTPS JSON API | mutual TLS, operator certificate, plus a session token on grant requests |
| 2 | Operator <-> relay | TLS data-plane connection | mutual TLS, operator certificate; each stream carries a signed grant |
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
1. sarctl login                  -> certificate authenticates; control plane opens a
                                    bounded, revocable operator session
                                 -> audit: operator.login
2. sarctl connect requests a grant, presenting the certificate and the session
                                 -> policy engine evaluates user x device x resource
                                    -> issues Ed25519-signed grant, TTL <= 30m
                                    -> grant row and audit: grant.created, one transaction
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

## State on the control plane

```
state/
  ca.crt                the authority certificate
  ca.key                the authority key, sealed through the keystore
  grant-signing.key     the grant signing key, sealed through the keystore
  policy.json           the rule set, read at startup
  control.db            SQLite: identities, enrollment tokens, operator sessions,
                        issued grants, and the audit trail
  control.db-wal        write-ahead log; readers do not block the audit write
```

**No key material is in the database.** The authority key, device keys, and the grant
signing key belong to `internal/keystore`, sealed with DPAPI on Windows. A database
compromise must not be a key compromise, and encrypting the database would not change
that — the key for it would have to live on the same machine.

Nothing usable as a credential is stored in the clear. Enrollment tokens and operator
session tokens are held as SHA-256 hashes, so a reader of this file learns that an
enrollment is pending or a session is open — which is what an audit trail is for — and
cannot use either.

The schema version lives in SQLite's `user_version` pragma. A database written by a newer
build is a startup failure, never a best-effort read: a control plane that half-understands
its own authorization state is worse than one that refuses to start.
