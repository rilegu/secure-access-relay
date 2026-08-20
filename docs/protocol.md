# Protocol

Two planes, deliberately different technologies.

| Plane | Transport | Encoding | Rationale |
| ----- | --------- | -------- | --------- |
| Control | HTTPS (mTLS for agents) | JSON | Curl-able, self-describing, trivial to document and demo |
| Data | TLS 1.3 over TCP | custom binary frames | Multiplexing, backpressure, and limits are the point |

## Data plane framing

All integers big-endian. One frame:

```
+--------+--------+----------------+------------------+
| ver    | type   | stream_id      | length           |
| u8     | u8     | u32            | u32              |
+--------+--------+----------------+------------------+
| payload (length bytes)                              |
+-----------------------------------------------------+
```

Header is 10 bytes. `length` is validated against `MAX_FRAME_PAYLOAD` **before any
allocation**. `stream_id` is 0 for connection-scoped frames.

### Frame types

| Type | Name | Direction | Payload |
| ---- | ---- | --------- | ------- |
| 0x01 | `HELLO` | initiator to peer | version range, role (agent/operator), nonce |
| 0x02 | `HELLO_ACK` | peer to initiator | negotiated version, server nonce, limits |
| 0x03 | `AUTH` | initiator to relay | device or session credential, signed grant (operator) |
| 0x04 | `AUTH_OK` | relay to initiator | session_id, effective limits |
| 0x10 | `OPEN_STREAM` | relay to agent | stream_id, grant, resource_id |
| 0x11 | `STREAM_OK` | agent to relay | stream_id |
| 0x12 | `STREAM_DATA` | both | opaque bytes |
| 0x13 | `STREAM_WINDOW` | both | stream_id, credit (u32) |
| 0x14 | `CLOSE_STREAM` | both | stream_id, reason code |
| 0x20 | `PING` | both | opaque token |
| 0x21 | `PONG` | both | echoed token |
| 0x7F | `ERROR` | both | reason code, human-readable detail (never secrets) |

### Connection lifecycle

```
initiator                                   relay
    |------------- HELLO ---------------------->|
    |<------------ HELLO_ACK -------------------|   version + limits fixed here
    |------------- AUTH ----------------------->|   mTLS already established
    |<------------ AUTH_OK ---------------------|   session_id assigned
    |                                           |
    |<------------ PING / PONG ---------------->|   keepalive, both directions
```

Version negotiation happens exactly once, in HELLO/HELLO_ACK. An unsupported version
range is an immediate ERROR and close; there is no implicit downgrade.

### Stream lifecycle

```
relay                                       agent
  |---- OPEN_STREAM (grant, resource_id) ---->|
  |                                           | verify grant signature
  |                                           | verify expiry + device_id
  |                                           | resolve resource_id locally
  |                                           | confirm target is loopback
  |                                           | dial 127.0.0.1:port
  |<--------------- STREAM_OK ----------------|   or CLOSE_STREAM(reason)
  |<======= STREAM_DATA (both ways) =========>|
  |<-------- STREAM_WINDOW (credit) --------->|
  |---------- CLOSE_STREAM(reason) ---------->|
```

`stream_id` is allocated by the relay and is unique per connection. IDs are never
reused within a connection.

### Flow control

Credit-based, per stream. A sender may have at most `window` unacknowledged payload
bytes outstanding; the receiver returns credit with `STREAM_WINDOW` as it drains. This
prevents a slow local target from forcing unbounded buffering in the agent, and a slow
operator from doing the same in the relay.

Initial window and maximums are announced in `HELLO_ACK` and are not renegotiable.

### Limits

Every limit is enforced, tested, and has a distinct reason code on violation.

| Limit | v1 default | Enforced at |
| ----- | ---------- | ----------- |
| `MAX_FRAME_PAYLOAD` | 64 KiB | frame decode, before allocation |
| `MAX_STREAMS_PER_CONNECTION` | 16 | relay and agent independently |
| `MAX_STREAMS_PER_DEVICE` | 16 | relay |
| `INITIAL_WINDOW` | 256 KiB | both peers |
| `HANDSHAKE_TIMEOUT` | 10 s | relay |
| `IDLE_TIMEOUT` | 60 s (2 missed pings) | both peers |
| `MAX_SESSION_DURATION` | grant TTL, max 30 min | agent (authoritative) and relay |
| `MAX_SESSION_BYTES` | configurable per resource | agent |

The agent is authoritative for anything that bounds access. The relay's copies of these
limits are an optimization that fails fast, not a control.

## Reason codes

Stable strings. They appear in CLOSE_STREAM, ERROR, audit events, and CLI output, and
they are part of the compatibility surface.

```
ok
grant_invalid_signature
grant_expired
grant_not_yet_valid
grant_device_mismatch
grant_revoked
resource_unknown
resource_target_not_loopback
policy_denied
limit_streams_exceeded
limit_bytes_exceeded
limit_frame_too_large
target_connection_refused
target_timeout
protocol_version_unsupported
protocol_malformed_frame
auth_failed
session_replaced
idle_timeout
shutdown
no_agent
```

`no_agent` reports that no endpoint agent is currently connected to serve the
request. Like `limit_streams_exceeded` it is an **availability** condition, not an
authorization one, and must never be reported as `policy_denied`: the operator may
well be entitled to the resource, and telling them otherwise sends them to argue
about permissions they already have.

`target_connection_refused` must never be reported as a policy denial, and
`policy_denied` must never be reported as a network error. Conflating them destroys the
operator's ability to distinguish "you may not" from "it is down."

## Control-plane API (sketch)

```
POST   /v1/enroll                    single-use token, CSR, returns device certificate
GET    /v1/devices                   operator: list enrolled devices
GET    /v1/devices/{id}/resources    operator: list resources on a device
POST   /v1/grants                    operator: request a grant (policy evaluated here)
DELETE /v1/grants/{id}               operator/admin: revoke
GET    /v1/audit                     operator/admin: query audit events
GET    /healthz  /readyz             liveness and readiness
```

Agent endpoints require mutual TLS with a device certificate. Operator endpoints require
an operator session. No endpoint accepts a target address; the operator names a
`resource_id` and nothing else.

## Grant format

Ed25519 over a canonical encoding of:

```
{
  "v":            1,
  "issuer":       "<control-plane key id>",
  "grant_id":     "grn_...",
  "org_id":       "org_...",
  "user_id":      "usr_...",
  "device_id":    "dev_...",
  "resource_id":  "res_...",
  "issued_at":    "2026-08-19T14:30:00Z",
  "expires_at":   "2026-08-19T15:00:00Z",
  "max_bytes":    1073741824
}
```

Not JWT: the claim set is fixed, the algorithm is fixed, and there is no `alg` field to
confuse. Canonical encoding is defined in `internal/proto` and covered by round-trip and
tamper tests. Verification requires all fields present; unknown fields are rejected
rather than ignored.

## Implementation status

This document specifies the target protocol. The current build implements part of it, and
the gaps are load-bearing enough to state rather than leave a reader to infer.

| Element | Status |
| ------- | ------ |
| Frame header layout, encode/decode, limits | implemented |
| `OPEN_STREAM`, `STREAM_OK`, `STREAM_DATA`, `CLOSE_STREAM`, `ERROR` | implemented |
| Reason codes | implemented |
| `HELLO` / `HELLO_ACK` version negotiation | **not implemented** |
| `AUTH` / `AUTH_OK` | **not implemented** |
| `STREAM_WINDOW` credit-based flow control | **not implemented** |
| `PING` / `PONG` keepalive and idle timeout | **not implemented** |
| Multiple concurrent streams | **not implemented** — one at a time |
| TLS | **not implemented** |
| Grants | **not implemented** |

Two consequences of those gaps are visible in how the current build behaves:

- **The relay separates agents from operators by listening on two ports** rather than by
  a handshake, because peers have no way to say what they are yet. The `HELLO`/`AUTH`
  exchange replaces this, and the second port goes away with it.
- **The version byte is checked but never negotiated.** A peer sending an unrecognised
  version is refused outright, which is the correct failure, but there is no range
  exchange to agree on a common version.

Unimplemented frame types are still defined and still rejected as unknown if they appear,
so a peer that sends one gets a clear protocol error rather than silence.

## Compatibility rules

- Frame header layout is frozen at the first tagged release.
- New frame types may be added; unknown types are a protocol error, not silently skipped.
- Reason codes may be added; existing codes never change meaning.
- Grant `v` increments on any field change; verifiers reject unknown versions.
