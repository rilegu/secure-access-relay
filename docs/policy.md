# Resource and authorization model

## Objects

| Object | ID prefix | Owner | Notes |
| ------ | --------- | ----- | ----- |
| Organization | `org_` | — | Present in the schema from v1; multi-tenancy untested in v1 |
| User | `usr_` | org | Operator identity from the IdP or dev credential store |
| Group | `grp_` | org | Users may belong to many |
| Device | `dev_` | org | One enrolled agent, one device certificate |
| Resource | `res_` | device | A named loopback target on that device |
| Policy | `pol_` | org | Rule mapping principal to device to resource |
| Grant | `grn_` | — | Signed, short-lived instantiation of a policy decision |
| Session | `ses_` | — | One live relay connection |
| Stream | u32 | session | One proxied TCP connection |

## Resource

A resource is declared **on the agent**, not by the operator, and registered with the
control plane at connect time.

```json
{
  "resource_id":  "res_panel_diagnostics",
  "name":         "panel-diagnostics",
  "protocol":     "tcp",
  "target":       "127.0.0.1:8080",
  "max_bytes":    1073741824,
  "max_duration": "30m"
}
```

Constraints enforced by the agent at load time, refusing to start if violated:

- `protocol` must be `tcp` in v1.
- `target` host must be `127.0.0.1` or `::1`. Hostnames are not accepted, so no DNS is
  consulted and no DNS answer can move a target.
- `target` port must be explicit.
- Duplicate `resource_id` values are a fatal configuration error.

The operator never supplies an address. They name a `resource_id`; the agent resolves it
against its own list. This is what makes the system a resource proxy rather than a
tunnel with authentication.

## Policy

```json
{
  "policy_id":  "pol_support_panel",
  "principals": ["grp_support"],
  "devices":    ["dev_win11_lab_01"],
  "resources":  ["res_panel_diagnostics"],
  "max_ttl":    "30m",
  "effect":     "allow"
}
```

- **Deny by default.** Absence of a matching allow is a denial.
- There are no deny rules in v1. A deny rule that can override an allow makes evaluation
  order a source of bugs; with allow-only, the rule set is a union and order is irrelevant.
- Wildcards are not supported in v1. Explicit lists only.

## Evaluation

Executed at the control plane when a grant is requested:

```
1. Resolve operator identity        -> usr_, group memberships
2. Collect policies matching principal
3. Filter by requested device_id
4. Filter by requested resource_id
5. If no policy survives            -> deny, reason: policy_denied
6. ttl = min(requested, policy.max_ttl, GLOBAL_MAX_TTL = 30m)
7. Issue Ed25519-signed grant
8. Audit: grant.created (or grant.denied) with the reason code
```

The result of evaluation is a signed grant, never a durable permission. The agent
re-verifies it on every stream open.

## Enforcement points

Both of these run, always. This is not redundancy to be optimized away.

| Point | Location | Checks |
| ----- | -------- | ------ |
| Fast-fail | relay | signature, expiry, device has a live session |
| Authoritative | agent | signature, expiry, `device_id` matches self, `resource_id` in local allowlist, target is loopback, byte and duration budgets |

A compromised relay must not be able to open a stream. That property holds only because
the agent's check does not trust anything the relay says.

## Revocation

| Trigger | Effect | Status |
| ------- | ------ | ------ |
| Grant revoked | Relay drops matching live streams; agent drops on next control-plane sync | not implemented |
| Device or operator revoked | Refused at the next connection | **implemented** |
| Device or operator revoked, session already running | Session terminated | **not implemented** |
| Re-enrollment supersedes a certificate | Previous certificate refused | **implemented** |
| User disabled | All that user's grants revoked | not implemented |
| Policy deleted | Existing grants remain valid until expiry, bounded by the 30-minute max TTL | not implemented |

Short TTLs are the primary revocation mechanism. Explicit revocation is the fast path,
not the only path.

**Revocation does not currently reach a live session.** It is checked when a connection is
established, so a peer revoked mid-session keeps that session until it ends; restarting
the relay is the way to drop it. This is a real gap rather than a design choice, and it
matters most for the case revocation exists to handle — a credential believed to be
compromised *right now*.

## Audit events

Emitted **before** the corresponding action completes, so a crash cannot produce an
unlogged action.

```
device.enrolled       device.connected      device.disconnected   device.revoked
resource.registered
grant.created         grant.denied          grant.revoked         grant.expired
stream.opened         stream.denied         stream.closed
policy.created        policy.deleted
admin.login           admin.action
```

Every event carries `timestamp`, `org_id`, actor, subject IDs, and, for any denial, a
reason code from the fixed list in [protocol.md](protocol.md).

`stream.closed` additionally carries `bytes_in`, `bytes_out`, `duration`, and
`close_reason`.

Never present in an audit event: bearer tokens, private keys, grant signatures, target
response bodies, or payload bytes.
