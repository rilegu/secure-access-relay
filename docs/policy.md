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

**Implemented** in `internal/control/policy`. Executed at the control plane when a grant
is requested:

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

Both of these run, always, and both are implemented. This is not redundancy to be
optimized away: the agent's check is what makes a compromised relay survivable, and the
relay's check exists only so an operator learns immediately why a request was refused
rather than after a round trip to a machine that was never going to accept it.

| Point | Location | Checks |
| ----- | -------- | ------ |
| Fast-fail | relay | signature, expiry, device has a live session |
| Authoritative | agent | signature, expiry, `device_id` matches self, `resource_id` in local allowlist, target is loopback, byte and duration budgets |

A compromised relay must not be able to open a stream. That property holds only because
the agent's check does not trust anything the relay says.

## Revocation

| Trigger | Effect | Status |
| ------- | ------ | ------ |
| Grant revoked | Refused at the relay; live streams under it dropped at both ends | **implemented** |
| Operator session ended | The session's grants revoked, their streams dropped | **implemented** |
| Operator revoked | Their sessions ended, their grants revoked, their streams dropped | **implemented** |
| Device revoked | Refused at its next connection; grants naming it revoked | **implemented** |
| Re-enrollment supersedes a certificate | Previous certificate refused | **implemented** |
| Device or operator revoked, data-plane session already running | Session terminated | not implemented |
| Policy deleted | Existing grants remain valid until expiry, bounded by the 30-minute max TTL | not implemented |

Short TTLs remain the mechanism that works when nothing else does — an agent that cannot
reach the control plane still stops honouring an expired grant. Explicit revocation is the
fast path.

### What revocation actually does

Three kinds of state, in this order, because they fail differently:

1. **The database.** The grant row is marked revoked with a reason, and the audit event is
   written in the same transaction. This is the durable record.
2. **New streams.** The relay resolves a grant's state when a stream is opened, so a
   revoked grant is refused with `grant_revoked` before the agent is contacted.
3. **Running streams.** The relay registers every joined stream against the grant that
   authorized it and resets **both ends** when that grant is revoked. Resetting only the
   operator's side would leave the agent holding an open connection to the local service,
   which is the resource being taken away.

Cascades run downward and each step is recorded separately, one audit event per grant
rather than one for the cascade — an administrator asking later why a particular grant
stopped working must find that grant's own record, not a summary naming something else.

**What is still not covered:** revoking an identity does not tear down a *data-plane
session* that is already established. The grants are revoked and the streams are dropped,
so the peer can do nothing with the connection, but the connection itself survives until
it ends or the relay restarts. A relay running in a separate process from the control
plane would also learn of a revocation only at its next grant check, which happens when a
stream opens; the shipped topology runs both in one process, where the drop is immediate.

## Audit events

The trail lives in the control-plane database, append-only: nothing in the software
updates or deletes a row.

A grant and the record of that grant commit in **one transaction**. Access that nothing
accounts for is worse than access refused, so a grant whose record cannot be written is
not issued. The same holds for opening an operator session. Events that merely *report*
something already finished — a stream that closed, an endpoint that disconnected — are
written outside a transaction and a failure is logged rather than propagated, because
failing the operation afterwards would not un-happen it.

The set of names is closed and defined in `internal/control/audit`. Inventing a name at
the call site is how a trail ends up with three spellings of one event and the query that
matters finds two of them.

```
device.enrolled       device.revoked        operator.enrolled     operator.revoked
enroll.denied
device.connected      device.disconnected
operator.login        operator.login_denied operator.logout       operator.session_revoked
grant.created         grant.denied          grant.revoked
stream.opened         stream.denied         stream.closed
admin.action
```

`sar-server audit -events` prints this list.

Every event carries a monotonic sequence number, a timestamp, and whichever of `org_id`,
actor role and identifier, `device_id`, `resource_id`, `grant_id`, and `session_id` apply.
Every denial carries a reason code from the fixed list in [protocol.md](protocol.md).

The sequence number exists because timestamps are stored to the second, and a grant and
the stream it authorized routinely land in the same one. Ordering by time alone would
present them as simultaneous and lose the causal order.

`stream.closed` additionally carries `bytes_in`, `bytes_out`, and `duration_ms`.

**Never present in an audit event:** bearer tokens, private keys, grant signatures, target
response bodies, or payload bytes. An audit trail records that access happened and under
what authority; one that also held the traffic would make reading the evidence a second
disclosure of whatever was being protected. There is an end-to-end test that sends a
canary string through a forward and fails if it appears in any column of any row.

**Not emitted, and why:** `resource.registered` — resources are declared on the agent, not
registered with the control plane. `policy.created` / `policy.deleted` — policy is a file
read at startup. `grant.expired` — expiry is passive; nothing observes the moment a grant
lapses, and a row written by a sweep would claim an event that no component acted on.

### Retention

The trail grows without bound and nothing prunes it automatically. That is
deliberate, and so is the fact that retention exists at all:

```sh
sar-server audit -stats                              # size and how far back it reaches
sar-server audit -prune-older-than 90d               # dry run: reports, removes nothing
sar-server audit -prune-older-than 90d -confirm      # removes, and records that it did
```

A cutoff is mandatory, `-confirm` is mandatory, and the prune writes an
`admin.action` event carrying the cutoff and the number of rows removed — so a
gap in the history is never ambiguous. Nothing selects by actor, device, or
grant: the operation most useful to somebody covering their tracks is the one
that does not exist.

The reason retention exists rather than being refused on principle: a control
plane that cannot write an audit event must refuse the decision it was about to
make, because the grant and its record commit together. A full disk therefore
stops authorization outright, which makes unbounded growth a slow denial of
service rather than a safe default. See
[ADR-0017](decisions/0017-audit-retention-is-the-one-exception.md).

### Querying

```sh
sar-server audit -since 24h
sar-server audit -denials
sar-server audit -device panel-lab-01 -event stream.closed
sar-server audit -actor maria -grant grn_...
```

Filters match exactly. There is no pattern matching, deliberately: a wildcard over an
audit trail is a way to answer a narrower question than the one asked and believe it was
the whole answer. Results are capped, and the cap is reported when it is reached — a
truncated result that looks complete is how somebody concludes an incident was smaller
than it was.
