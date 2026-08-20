# Protocol

Two planes, deliberately different technologies.

| Plane | Transport | Encoding | Rationale |
| ----- | --------- | -------- | --------- |
| Control | HTTPS | JSON | Curl-able, self-describing, trivial to document and demo |
| Data | TLS 1.3 over TCP | custom binary frames | Multiplexing, backpressure, and limits are the point |

### Client authentication differs between the planes

The data plane requires mutual TLS: a peer without a certificate from this deployment's
authority is refused during the handshake.

The control plane's only endpoint today is enrollment, and it is **server-authenticated
only**. It cannot require a client certificate, because a peer enrolls precisely because
it does not have one. The token authenticates the client; the authority fingerprint
carried in the enrollment code authenticates the server.

Control endpoints added later — listing devices, requesting grants, querying audit — will
require mutual TLS, since their callers are already enrolled by then.

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

### Stream identifiers

IDs are unique per connection and never reused. Each end owns half the identifier
space: **the peer that dialled numbers its streams odd, the peer that accepted numbers
them even.** Both ends can therefore open streams at the same time without ever choosing
the same identifier, and a peer using the wrong parity is a protocol error — it would be
reaching into identifiers its counterpart is about to allocate.

### Closing a stream: half-close versus abort

`CLOSE_STREAM` is a **half-close**, modelled on TCP's FIN. It means "I will send nothing
further on this stream". The peer's reads then return end-of-stream, and the peer may
keep sending in the other direction. A stream is finished when both directions have
closed.

This matters for request/response traffic: a client that finishes its request and
half-closes must still be able to read the response. Collapsing both directions into one
close would discard the response to every completed request.

A `CLOSE_STREAM` carrying a **non-`ok` reason is an abort**. Both directions end
immediately and anything still buffered is discarded, because the reason says the data is
no longer meaningful.

The distinction is load-bearing in the other direction too. When a forwarded connection
breaks rather than ending cleanly, the stream must be aborted rather than half-closed: a
half-close would leave the peer writing into a flow-control window that will never
reopen, blocking forever and holding its own upstream connection open with it. That
presents as a hang rather than an error, which is far harder to diagnose.

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
flow_control_violation
auth_failed
session_replaced
idle_timeout
shutdown
no_agent
```

`flow_control_violation` reports that a peer sent more data than the window it
was granted. It is distinct from `protocol_malformed_frame` on purpose: the frame
was well formed, the peer simply ignored a limit it had been told. It is fatal to
the connection, because the only alternative to disconnecting is buffering
without bound.

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

A grant is signed with Ed25519 over a **binary canonical encoding**, not over JSON. The
wire form is those bytes followed by the 64-byte signature.

```
  u8    version            1
  str   key id             which signing key issued this
  str   grant id           grn_...
  str   org id
  str   user id
  str   device id
  str   resource id
  u64   issued at          unix seconds, big-endian
  u64   expires at         unix seconds, big-endian
  u64   max bytes          0 means the resource's own limit applies

  str = u16 length prefix + UTF-8 bytes
```

Every field is fixed-width or length-prefixed, the order is exactly the order above, and
nothing is optional. Trailing bytes are a malformed grant, not something to ignore.

**Why not JSON.** A signature is over bytes, and JSON has many valid encodings of the same
value — key order, whitespace, unicode escaping, number formatting. A verifier that parses
and re-encodes before checking can produce different bytes from the value it is about to
act on, which is the shape of real signature-bypass bugs. See
[ADR-0013](decisions/0013-canonical-grant-encoding.md).

**Why not JWT.** The claim set is fixed, the algorithm is fixed, and there is no `alg`
field for a verifier to get wrong. See
[ADR-0003](decisions/0003-ed25519-grants-not-jwt.md).

Times are truncated to whole seconds before signing, because the encoding cannot represent
finer precision — signing a value the wire format cannot reproduce would make every grant
fail its own verification.

### Verification order

The signature is checked **first**. Every other field is attacker-controlled until it has
been, so nothing in a grant means anything before then. After that:

1. Lifetime does not exceed the thirty-minute ceiling — checked here as well as at issue,
   so a verifier does not depend on the issuer having behaved.
2. Not before `issued_at`, allowing bounded clock skew.
3. Not after `expires_at`, allowing the same.
4. `device_id` matches the verifying agent's own identity, which is what stops a grant
   captured at one endpoint being replayed at another.

The agent then resolves `resource_id` against its **own** allowlist and confirms the
target is loopback. A correctly signed grant for a resource the agent does not serve is
refused.

### Where a grant travels

The grant is the payload of the `OPEN_STREAM` frame. The operator obtains one from the
control plane, presents it when opening a stream, and the relay forwards the same bytes
unchanged to the agent — it does not re-sign, re-encode, or amend anything, because the
agent must verify exactly what the control plane issued.

## Implementation status

This document specifies the target protocol. The current build implements part of it, and
the gaps are load-bearing enough to state rather than leave a reader to infer.

| Element | Status |
| ------- | ------ |
| Frame header layout, encode/decode, limits | implemented |
| `HELLO` / `HELLO_ACK` version negotiation | implemented |
| `AUTH` / `AUTH_OK` | implemented — identity is verified against the peer certificate |
| `OPEN_STREAM`, `STREAM_OK`, `STREAM_DATA`, `CLOSE_STREAM`, `ERROR` | implemented |
| `STREAM_WINDOW` credit-based flow control | implemented |
| `PING` / `PONG` keepalive and idle timeout | implemented |
| Multiple concurrent streams | implemented |
| Reason codes | implemented |
| TLS | **not implemented** |
| Grants and policy | implemented — see [ADR-0013](decisions/0013-canonical-grant-encoding.md) |

**AUTH does not establish identity; the certificate does.** Every data-plane connection
is mutual TLS, and the relay reads a peer's identity from a URI in its certificate before
reading a single frame. What a peer states in AUTH is checked against that certificate,
and a disagreement ends the connection — see
[ADR-0010](decisions/0010-certificate-is-the-identity.md).

AUTH still carries one thing that is *not* an identity claim: the device an operator
wants to reach. That is a request, and it is answered by the relay rather than believed.

Authorization now exists: a stream carries a signed grant in its `OPEN_STREAM` payload,
and the endpoint agent verifies it before dialing. The grant names a resource, never an
address — the agent resolves the identifier against its own allowlist.

The gap that matters most now is the **record**. Every decision is logged with the
identifiers needed to reconstruct it, but there is no queryable append-only audit trail,
nothing is tamper-evident, and a grant cannot be revoked before it expires.

Because a peer now states its role in `HELLO`, the relay serves both agents and operators
on **one listener**. The separate ports used before this existed are gone.

## Compatibility rules

- Frame header layout is frozen at the first tagged release.
- New frame types may be added; unknown types are a protocol error, not silently skipped.
- Reason codes may be added; existing codes never change meaning.
- Grant `v` increments on any field change; verifiers reject unknown versions.
