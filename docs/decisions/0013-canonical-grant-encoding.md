# ADR-0013: Grants are signed over a hand-written canonical encoding

**Status:** accepted

Extends [ADR-0003](0003-ed25519-grants-not-jwt.md), which chose a fixed-schema Ed25519
grant over JWT. That ADR settled the algorithm and the claim set; this one settles the
bytes.

## Context

A signature is over bytes, not over a value. Anything that signs a structured object has
to define the mapping from that object to those bytes, and a verifier has to reproduce it
exactly. If the mapping is not one-to-one, a signature can be valid over bytes that do
not correspond to the value being acted on.

The obvious choice is JSON: readable, debuggable, already used by the control API.

## Decision

Sign over a hand-written binary encoding, defined in `internal/proto`:

```
u8    version
str   key id          str = u16 length prefix + UTF-8 bytes
str   grant id
str   org id
str   user id
str   device id
str   resource id
u64   issued at       unix seconds
u64   expires at      unix seconds
u64   max bytes
```

Every field is fixed-width or length-prefixed, the order is fixed, and nothing is
optional. The wire form is these bytes followed by the 64-byte signature.

## Rejected: JSON

JSON has many valid encodings of the same value. Key order, insignificant whitespace,
unicode escaping, and number formatting all vary between implementations and between
versions of the same implementation. A verifier that parses and re-encodes before checking
can therefore produce different bytes from the value it is about to act on.

That is not a hypothetical. It is the shape of real signature-bypass bugs, and the usual
mitigations — canonical JSON profiles, sign-the-raw-bytes-as-received — either add a
specification nobody fully implements or make the signed form opaque to the code using it.

The debuggability argument is real but small here: a grant is machine-to-machine, and the
fields that matter appear in the audit record and the operator's output anyway.

## Rejected: signing the transmitted bytes as received

Signing exactly what arrives sidesteps re-encoding entirely and is what several protocols
do. It was rejected because it makes the signed object whatever the sender chose to send,
including fields this version does not understand, and a verifier then has to decide what
to do with bytes it cannot interpret. With a fixed encoding there is nothing to decide:
trailing bytes are a malformed grant.

## Consequences

- **The encoding is frozen.** Any change to the field set or their order changes every
  signature, so it is versioned by the leading byte and a verifier refuses a version it
  does not recognise rather than interpreting unknown fields.
- **Times are truncated to whole seconds before signing**, because the encoding cannot
  represent finer precision. Signing a value the wire format cannot reproduce would make
  every grant fail its own verification — a bug that would only appear once times stopped
  landing on second boundaries.
- **Trailing bytes are a malformed grant, not something to ignore.** Tolerating them would
  mean verifying a signature over bytes that do not correspond to the value being used.
- Coverage is checked by flipping every bit of an encoded grant in turn and requiring each
  mutation to be refused. A field accidentally left out of the canonical bytes would
  otherwise be an unsigned field inside a signed object, which is precisely the bug this
  encoding exists to make impossible.
- The trade is that a grant is not human-readable on the wire. The audit record carries
  the same fields in a readable form, so the loss falls on packet captures rather than on
  operations.
