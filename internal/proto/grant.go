package proto

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// GrantVersion is the current grant schema version.
//
// Carried inside the signed bytes, so a verifier that does not recognise a
// version refuses the grant rather than interpreting unknown fields. Any change
// to the field set increments this.
const GrantVersion uint8 = 1

// MaxGrantTTL is the longest life any grant may have, regardless of what a
// policy or a request asks for.
//
// Short lifetimes are the primary revocation mechanism in this system. Explicit
// revocation is the fast path; expiry is the one that works even when the
// control plane is unreachable, which is why there is a ceiling rather than only
// a per-policy limit.
const MaxGrantTTL = 30 * time.Minute

// ClockSkewTolerance is how far a verifier will stretch to accommodate
// disagreeing clocks.
//
// Bounded and explicit. A generous tolerance quietly extends every grant's real
// lifetime by that amount at both ends, which is why this is small relative to
// MaxGrantTTL rather than "a few minutes to be safe".
const ClockSkewTolerance = 30 * time.Second

// Grant is a signed, short-lived authorization to reach one resource on one
// device.
//
// It is verified offline by the agent. That is the whole point: the agent does
// not ask the control plane whether a stream is allowed, because that would make
// control-plane availability a precondition for access and put a network round
// trip on the hot path. Instead the grant carries its own proof, and its short
// life bounds the damage if it leaks.
type Grant struct {
	// Version is the schema version. Checked before anything else is read.
	Version uint8

	// KeyID identifies which signing key issued this grant, so keys can be
	// rotated without invalidating every grant at once.
	KeyID string

	// GrantID is unique per issued grant. It appears in audit records and is
	// what a revocation names.
	GrantID string

	// OrgID, UserID, DeviceID, ResourceID are the four things a grant is *for*.
	// All are inside the signature, so changing any of them invalidates it.
	OrgID      string
	UserID     string
	DeviceID   string
	ResourceID string

	// IssuedAt and ExpiresAt bound validity, to the second. Sub-second precision
	// would be false accuracy across machines whose clocks already disagree.
	IssuedAt  time.Time
	ExpiresAt time.Time

	// MaxBytes caps how much one stream opened under this grant may carry. Zero
	// means the resource's own limit applies.
	MaxBytes uint64
}

// SignedGrant is a grant together with the signature over its canonical bytes.
type SignedGrant struct {
	Grant
	Signature []byte
}

// Errors from grant handling. Each maps onto a distinct reason code, because an
// operator must be able to tell an expired grant from a forged one from one
// meant for a different machine.
var (
	ErrGrantMalformed      = errors.New("proto: malformed grant")
	ErrGrantVersion        = errors.New("proto: unsupported grant version")
	ErrGrantSignature      = errors.New("proto: grant signature is invalid")
	ErrGrantExpired        = errors.New("proto: grant has expired")
	ErrGrantNotYetValid    = errors.New("proto: grant is not yet valid")
	ErrGrantDeviceMismatch = errors.New("proto: grant is for a different device")
	ErrGrantTTLTooLong     = errors.New("proto: grant lifetime exceeds the maximum")
)

// ReasonForGrant maps a grant error onto the reason code to report.
func ReasonForGrant(err error) Reason {
	switch {
	case err == nil:
		return ReasonOK
	case errors.Is(err, ErrGrantExpired):
		return ReasonGrantExpired
	case errors.Is(err, ErrGrantNotYetValid):
		return ReasonGrantNotYetValid
	case errors.Is(err, ErrGrantDeviceMismatch):
		return ReasonGrantDeviceMismatch
	case errors.Is(err, ErrGrantSignature), errors.Is(err, ErrGrantVersion),
		errors.Is(err, ErrGrantMalformed), errors.Is(err, ErrGrantTTLTooLong):
		// A malformed, wrongly versioned, or over-long grant is reported as a
		// signature failure rather than described precisely. A peer presenting a
		// bad grant does not need to be told which of its fields gave it away.
		return ReasonGrantInvalidSignature
	default:
		return ReasonGrantInvalidSignature
	}
}

// canonical produces the exact bytes that are signed and verified.
//
// # Why a hand-written encoding rather than JSON
//
// A signature is over bytes, so the mapping from a grant to its bytes must be
// one-to-one and stable forever. JSON is not: key order, whitespace, unicode
// escaping, and number formatting all have valid alternatives, and a verifier
// that re-encodes before checking can produce different bytes from the same
// value. That is not a theoretical problem — it is the shape of several real
// signature-bypass bugs.
//
// This encoding has one representation per grant. Every field is fixed-width or
// length-prefixed, the order is the field order below, and nothing is optional.
func (g Grant) canonical() []byte {
	b := make([]byte, 0, 256)
	b = append(b, g.Version)
	b = appendString(b, g.KeyID)
	b = appendString(b, g.GrantID)
	b = appendString(b, g.OrgID)
	b = appendString(b, g.UserID)
	b = appendString(b, g.DeviceID)
	b = appendString(b, g.ResourceID)
	b = binary.BigEndian.AppendUint64(b, uint64(g.IssuedAt.Unix()))
	b = binary.BigEndian.AppendUint64(b, uint64(g.ExpiresAt.Unix()))
	b = binary.BigEndian.AppendUint64(b, g.MaxBytes)
	return b
}

// Sign produces a signed grant.
//
// The TTL ceiling is enforced at issue as well as at verification. Checking in
// both places is deliberate: a verifier that trusted the issuer to have checked
// would accept a grant from a compromised issuer with a lifetime of years.
func (g Grant) Sign(key ed25519.PrivateKey) (*SignedGrant, error) {
	if g.Version == 0 {
		g.Version = GrantVersion
	}
	if g.Version != GrantVersion {
		return nil, fmt.Errorf("%w: %d", ErrGrantVersion, g.Version)
	}
	if ttl := g.ExpiresAt.Sub(g.IssuedAt); ttl > MaxGrantTTL {
		return nil, fmt.Errorf("%w: %s exceeds %s", ErrGrantTTLTooLong, ttl, MaxGrantTTL)
	}
	if g.DeviceID == "" || g.ResourceID == "" || g.GrantID == "" {
		return nil, fmt.Errorf("%w: device, resource, and grant id are all required", ErrGrantMalformed)
	}

	// Times are truncated to the second so that what is signed matches what a
	// decoder will reconstruct. Signing a value the wire format cannot represent
	// would make every grant fail verification.
	g.IssuedAt = g.IssuedAt.Truncate(time.Second)
	g.ExpiresAt = g.ExpiresAt.Truncate(time.Second)

	return &SignedGrant{Grant: g, Signature: ed25519.Sign(key, g.canonical())}, nil
}

// Encode serialises a signed grant for the wire: canonical bytes, then the
// signature.
func (s SignedGrant) Encode() []byte {
	c := s.canonical()
	out := make([]byte, 0, len(c)+ed25519.SignatureSize)
	out = append(out, c...)
	out = append(out, s.Signature...)
	return out
}

// DecodeGrant parses a signed grant. It does not verify anything.
//
// Parsing and verification are separate so that a caller cannot accidentally use
// a decoded grant it never checked: the value returned here is inert until
// Verify has been called on it.
func DecodeGrant(b []byte) (*SignedGrant, error) {
	if len(b) < ed25519.SignatureSize+1 {
		return nil, fmt.Errorf("%w: %d bytes is too short to be a grant", ErrGrantMalformed, len(b))
	}

	body := b[:len(b)-ed25519.SignatureSize]
	sig := b[len(b)-ed25519.SignatureSize:]

	var g Grant
	g.Version = body[0]
	if g.Version != GrantVersion {
		return nil, fmt.Errorf("%w: %d", ErrGrantVersion, g.Version)
	}
	rest := body[1:]

	var err error
	for _, field := range []*string{&g.KeyID, &g.GrantID, &g.OrgID, &g.UserID, &g.DeviceID, &g.ResourceID} {
		if *field, rest, err = takeString(rest); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrGrantMalformed, err)
		}
	}
	if len(rest) != 24 {
		// Trailing or missing bytes mean the sender and this decoder disagree
		// about the schema. Tolerating either would mean verifying a signature
		// over bytes that do not correspond to the value being used.
		return nil, fmt.Errorf("%w: %d trailing bytes after grant fields", ErrGrantMalformed, len(rest))
	}
	g.IssuedAt = time.Unix(int64(binary.BigEndian.Uint64(rest[0:])), 0).UTC()
	g.ExpiresAt = time.Unix(int64(binary.BigEndian.Uint64(rest[8:])), 0).UTC()
	g.MaxBytes = binary.BigEndian.Uint64(rest[16:])

	return &SignedGrant{Grant: g, Signature: append([]byte(nil), sig...)}, nil
}

// Verify checks a grant against a signing key, the current time, and the device
// it was presented to.
//
// The order matters. The signature is checked first, because every other field
// is attacker-controlled until it has been. Nothing about a grant means anything
// before its signature verifies.
func (s SignedGrant) Verify(pub ed25519.PublicKey, now time.Time, deviceID string) error {
	if s.Version != GrantVersion {
		return fmt.Errorf("%w: %d", ErrGrantVersion, s.Version)
	}
	if len(s.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes", ErrGrantSignature, len(s.Signature))
	}
	if !ed25519.Verify(pub, s.canonical(), s.Signature) {
		return ErrGrantSignature
	}

	// Only now is anything in the grant trustworthy.

	if ttl := s.ExpiresAt.Sub(s.IssuedAt); ttl > MaxGrantTTL {
		// A correctly signed grant with an over-long life means the issuer is
		// misconfigured or compromised. The ceiling is enforced here too, so a
		// verifier does not depend on the issuer having behaved.
		return fmt.Errorf("%w: %s exceeds %s", ErrGrantTTLTooLong, ttl, MaxGrantTTL)
	}
	if now.Add(ClockSkewTolerance).Before(s.IssuedAt) {
		return fmt.Errorf("%w: valid from %s", ErrGrantNotYetValid, s.IssuedAt.Format(time.RFC3339))
	}
	if now.Add(-ClockSkewTolerance).After(s.ExpiresAt) {
		return fmt.Errorf("%w: expired at %s", ErrGrantExpired, s.ExpiresAt.Format(time.RFC3339))
	}

	// The device is checked last among the semantic checks, but it is the one
	// that stops a grant captured at one endpoint being replayed at another
	// (threat T6). The identifier is inside the signature, so it cannot be
	// swapped without invalidating it.
	if deviceID != "" && s.DeviceID != deviceID {
		return fmt.Errorf("%w: grant names %q, this device is %q", ErrGrantDeviceMismatch, s.DeviceID, deviceID)
	}
	return nil
}

// Remaining reports how long a grant has left, which the agent uses to bound a
// session's duration.
func (s SignedGrant) Remaining(now time.Time) time.Duration {
	d := s.ExpiresAt.Sub(now)
	if d < 0 {
		return 0
	}
	return d
}
