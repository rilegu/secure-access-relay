# Installer, packaging, and updates

## Install layout

```
%ProgramFiles%\secure-access-relay\
  sar-agent.exe
  sardiag.dll                  optional, Authenticode-signed
  LICENSE  THIRD-PARTY-NOTICES

%ProgramData%\secure-access-relay\
  config.json                  non-secret configuration
  resources.json               local resource allowlist
  device.crt                   device certificate
  device.key                   DPAPI-protected private key
  trust\                       pinned control-plane CA
  logs\                        rotated structured JSON logs
```

Binaries live under `%ProgramFiles%` (writable only by Administrators). Mutable state
lives under `%ProgramData%`. The two are never mixed — a service that can write its own
executable is a privilege-escalation primitive.

## ACLs

| Path | Access |
| ---- | ------ |
| `%ProgramFiles%\secure-access-relay\` | Administrators: full. LocalSystem: read+execute. Users: read+execute. |
| `%ProgramData%\secure-access-relay\` | Administrators: full. LocalSystem: full. Users: **no access**. |
| `device.key` | LocalSystem only. |

Inheritance is broken explicitly on the `%ProgramData%` tree at install time; the
default inherited ACL grants Users read access, which would expose device state.

## Service registration

| Property | Value |
| -------- | ----- |
| Service name | `SecureAccessRelay` |
| Display name | Secure Access Relay Agent |
| Account | `LocalSystem` (a virtual service account is a hardening follow-up) |
| Start type | Automatic (Delayed Start) — **implemented** |
| Recovery | restart after 5 s, 30 s, then 60 s; counter reset daily — **implemented** |
| Dependencies | `Tcpip`, `Dnscache` — not yet set |

The service registers its command line at install time rather than reading configuration
at start time, so `sc.exe qc` shows an administrator exactly how the service runs. The
executable path is quoted unconditionally: an unquoted path containing a space is a
long-standing privilege escalation, because the loader tries each prefix in turn.

Delayed start avoids competing with boot-time networking, which otherwise produces a
guaranteed first connection failure and a misleading error in the log on every boot.

## PowerShell installer

**Implemented.** `installer/install.ps1` and `installer/uninstall.ps1`:

1. Verify Administrator rights; fail clearly if absent.
2. Stop and remove any existing service.
3. Create directories and apply the ACLs above.
4. Copy binaries; register the Event Log source.
5. Register the service with recovery settings.
6. Optionally enroll using a single-use token passed **interactively**, never as a
   command-line argument — arguments are visible to any local process and land in
   transcripts and audit logs.
7. Start the service and wait for a healthy status.

Uninstall reverses all of it, including Event Log source removal, and **keeps state by
default**. Removing an enrolled identity because someone uninstalled a service would turn
a reinstall into a re-enrollment and an upgrade into an outage, so deleting the key and
certificate requires an explicit `-RemoveState`. WFP filter cleanup joins this when there
are filters to clean up.

## MSI packaging (WiX)

The MSI wraps the same steps with proper Windows semantics: upgrade codes, rollback on
failure, per-machine install, and Add/Remove Programs metadata. Custom actions stay
minimal — directory ACLs and service recovery configuration only.

Enrollment is deliberately **not** an MSI property. Passing a token through msiexec puts
it in the MSI log and the command line.

## Code signing

- Authenticode on `sar-agent.exe`, `sardiag.dll`, and the MSI.
- The agent verifies `sardiag.dll` signature and publisher before loading it, and loads
  it by absolute path — never from `%PATH%` or the working directory.
- Development builds are unsigned and must be visibly marked as such at startup.

## Updates

v1 is **manual**: download, verify signature, run the MSI. Automatic update is
deliberately deferred — an auto-updater is a remote code execution channel into a
privileged service, and doing it properly needs update signing, rollback, staged
rollout, and version pinning.

Requirements when it does land:

- Update payloads signed with a key distinct from the grant signing key.
- Downgrade protection with an explicit minimum version.
- Update applied only when no session is active, or after draining.
- Failed update rolls back to the previous version and stays serviceable.

## Upgrade behavior

- Device identity and enrollment survive an upgrade. Re-enrolling on every update would
  make updates operationally expensive and pressure users to skip them.
- `resources.json` schema changes migrate forward with the version recorded in the file.
- An unrecognized config version is a startup failure, not a best-effort parse.

## Uninstall verification

Covered by the cleanup tests in [e2e-test-plan.md](e2e-test-plan.md): no service, no
state directory, no WFP filters, no orphaned firewall rules, registry keys, or Event Log
sources.
