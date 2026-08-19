# End-to-end test plan

The success criterion is not "the tunnel works." It is: **the system permits exactly one
intended connection, explains and logs every decision, recovers correctly, and never
converts a failure into broader access.**

## Test layers

| Layer | Build tag | Runs on | Verifies |
| ----- | --------- | ------- | -------- |
| Unit | none | any OS, every commit | frame codec, grant verification, policy evaluator, limits, backoff, redaction |
| Component | `integration` | Linux + Windows CI | control plane, relay protocol, storage, fake agent |
| Windows integration | `windows_integration` | disposable Windows VM only | SCM lifecycle, named pipes, DPAPI, cert store, WFP, installer |
| System E2E | scripted | isolated VM + control/relay | enrollment through teardown, with audit assertions |
| Chaos / demo | manual | dedicated lab VM | network loss, crash, reboot, upgrade, uninstall |

```sh
go test ./...                            # must stay fast and deterministic
go test -tags=integration ./...
go test -tags=windows_integration ./...  # NEVER on a developer host
```

Windows integration tests install services, alter firewall state, and inject network
failures. Use a snapshot-revertible VM.

## Topology

```
+---------------------+       TLS/mTLS        +---------------------+
| Operator machine    | --------------------- | Control + Relay     |
| sarctl              |                       | docker compose      |
+---------------------+                       +----------+----------+
                                                          | outbound mTLS
                                                          v
                                       +----------------------------------+
                                       | Windows 11 test VM               |
                                       |  sar-agent (Windows Service)     |
                                       |  enrolled device key             |
                                       |  named-pipe local IPC            |
                                       |                                  |
                                       |  test fixture 127.0.0.1:8080     |
                                       +----------------------------------+
```

The fixture binds **strictly to loopback**. That is itself part of the test: it proves
the agent is not merely exposing a LAN-reachable port.

## Golden path

```
1.  compose up control + relay, wait for /readyz
2.  create org, user, group, policy
3.  mint single-use enrollment token
4.  install sar-agent on the Windows VM
5.  agent enrolls: generates key, submits CSR, receives certificate
6.  agent connects outbound, registers res_panel_diagnostics
7.  sarctl login
8.  sarctl devices list                  -> shows win11-lab-01 online
9.  sarctl resources list --device ...   -> shows panel-diagnostics
10. sarctl grants create --ttl 20m       -> grant issued
11. sarctl connect --listen 127.0.0.1:18080
12. curl http://127.0.0.1:18080/health   -> 200 from the fixture
13. sarctl audit                         -> grant.created, stream.opened, stream.closed
```

Step 12 is the minimum end-to-end proof: bytes traverse the whole chain.

## Mandatory deny tests

Each row must fail **closed**, produce the exact reason code, emit an audit event, and
deliver **zero bytes** to the target.

| # | Scenario | Expected reason code |
| - | -------- | -------------------- |
| D1 | Unenrolled agent connects | `auth_failed` |
| D2 | Enrollment token reused for a second device | `auth_failed` |
| D3 | Altered device certificate | `auth_failed` |
| D4 | Revoked device opens a new session | `auth_failed` |
| D5 | Grant with one byte flipped | `grant_invalid_signature` |
| D6 | Grant past `expires_at` | `grant_expired` |
| D7 | Grant with future `issued_at` beyond skew | `grant_not_yet_valid` |
| D8 | Grant for device A presented at device B | `grant_device_mismatch` |
| D9 | Revoked grant | `grant_revoked` |
| D10 | Resource ID absent from the local allowlist | `resource_unknown` |
| D11 | Resource configured with a non-loopback target | agent refuses to start |
| D12 | User with no matching policy requests a grant | `policy_denied` |
| D13 | Correct user, wrong device | `policy_denied` |
| D14 | Correct user and device, wrong resource | `policy_denied` |
| D15 | Frame larger than `MAX_FRAME_PAYLOAD` | `limit_frame_too_large` |
| D16 | More concurrent streams than the cap | `limit_streams_exceeded` |
| D17 | Session exceeds `max_bytes` | `limit_bytes_exceeded` |
| D18 | Unsupported protocol version in HELLO | `protocol_version_unsupported` |
| D19 | Malformed, truncated, or garbage frame | `protocol_malformed_frame` |

D11 deserves emphasis: it is a **startup** failure, not a runtime denial. A misconfigured
allowlist must never produce a running agent.

## Distinguishability tests

| Scenario | Must report | Must NOT report |
| -------- | ----------- | --------------- |
| Fixture stopped, grant valid | `target_connection_refused` | `policy_denied` |
| Fixture hangs, grant valid | `target_timeout` | `policy_denied` |
| Grant invalid, fixture healthy | `policy_denied` / `grant_*` | `target_connection_refused` |

An operator must be able to tell "you may not" from "it is down" without reading logs.

## Data-path tests

- HTTP request/response round trip
- 100 MB transfer, integrity verified by checksum
- Many concurrent streams, interleaved
- Either endpoint closing mid-stream
- Slow reader and slow writer: backpressure holds, memory stays bounded
- Half-close semantics preserved

## Windows-specific tests

**Service lifecycle**

```powershell
sc.exe start   SecureAccessRelay
sc.exe query   SecureAccessRelay
sc.exe stop    SecureAccessRelay
```

- Graceful stop within the SCM timeout; in-flight streams closed with `shutdown`
- Delayed-auto-start survives reboot and reconnects
- SCM recovery restarts the service after a forced kill
- Operational events land in the Windows Event Log

**Privilege separation**

- Named pipe rejects a caller that is neither Administrator nor the interactive owner
- Unprivileged process cannot read `device.key`
- CLI can obtain status without any ability to change policy

**Key protection**

- Copying the state directory to another machine yields an unusable key (DPAPI)
- Key never appears in logs, the support bundle, or process arguments

**WFP**

- Filter blocks the intended demo process or destination
- Agent relay traffic remains allowed
- Filters disappear after stop, crash, reboot, and uninstall
- A bad rule cannot lock the test VM out of all networking

## Failure and resilience tests

| Injection | Expected behavior |
| --------- | ----------------- |
| Kill relay mid-transfer | Streams close with a reason; agent reconnects with backoff and jitter |
| Restart relay | Agent re-registers; stale sessions fenced, not duplicated |
| Disable and re-enable the NIC | Network-change detection triggers reconnect |
| Reboot Windows | Service auto-starts and reconnects without manual action |
| Kill agent process | SCM restarts it; WFP filters released by the OS |
| Revoke grant during an active session | Session terminates promptly, audited |
| Clock skew beyond tolerance | Grants denied, with a skew-specific reason |
| Control plane down, agent already connected | Existing streams survive to expiry; **new streams denied** |
| Fill disk on the endpoint | Logging degrades; access decisions stay correct |

## Cleanup tests

- Uninstall removes the service, state directory, and all WFP filters
- No orphaned firewall rules, registry keys, or Event Log sources
- Reinstall over an existing install preserves or cleanly re-enrolls identity

## Automation

`scripts/e2e.sh` (control side) and `scripts/e2e.ps1` (endpoint side) will together:

1. Start compose services and wait for health
2. Seed a fresh org, user, policy, and enrollment token
3. Install or reset the Windows test agent
4. Run enrollment and resource registration
5. Create an allow grant, confirm HTTP through the tunnel
6. Run every deny case in the matrix above
7. Pull audit logs and assert the expected event sequence
8. Generate the support bundle and assert no secrets are present
9. Tear down and validate service and WFP cleanup

## Published artifacts

- Sanitized sample audit events
- Sanitized sample support bundle
- Demo recording: allowed access, denied access, grant expiry, service restart, audit evidence
- CI badge for unit tests; Windows integration on schedule and manual dispatch
