package enrollment

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// codePrefix versions the enrollment code format.
//
// A version prefix costs four bytes and means a future format change produces a
// clear error rather than a confusing parse failure against the old one.
const codePrefix = "sar1."

// Code is everything a peer needs to enroll, in one string.
//
// # Why the fingerprint is in here
//
// Enrollment has a bootstrap problem: the peer must connect to the control plane
// over TLS, but it has not yet received the certificate authority it would use to
// verify that connection. The options are to skip verification on the first
// connection, to distribute the authority certificate separately, or to carry a
// commitment to it in the credential the peer already has.
//
// This carries the commitment. The code holds the authority's fingerprint, so the
// peer can verify the server it is enrolling with before sending its token. An
// attacker who intercepts the connection cannot present a substitute authority,
// because the fingerprint would not match — and cannot forge a code, because they
// would need the token as well.
//
// The remaining exposure is the channel that carries the code itself: whoever
// hands an operator this string is trusted. That is unavoidable at the bottom of
// any trust chain, and it is at least a single, visible, human-scale step.
type Code struct {
	// Addr is the control-plane address to enroll against.
	Addr string `json:"a"`
	// Token is the single-use enrollment token.
	Token string `json:"t"`
	// CAFingerprint is the SHA-256 of the authority certificate, hex encoded.
	CAFingerprint string `json:"f"`
	// ServerName is the name to verify the relay's certificate against.
	ServerName string `json:"s"`
}

// Fingerprint returns the SHA-256 of a certificate's DER encoding.
//
// Of the whole certificate, not of the public key: two certificates with the same
// key but different validity or constraints must not be interchangeable.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Encode renders a code as the single string an operator copies.
func (c Code) Encode() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encode enrollment code: %w", err)
	}
	return codePrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ErrBadCode means the enrollment code was malformed.
var ErrBadCode = errors.New("enrollment: malformed enrollment code")

// DecodeCode parses an enrollment code.
func DecodeCode(s string) (Code, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, codePrefix) {
		return Code{}, fmt.Errorf("%w: missing %q prefix", ErrBadCode, codePrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, codePrefix))
	if err != nil {
		return Code{}, fmt.Errorf("%w: %v", ErrBadCode, err)
	}

	var c Code
	if err := json.Unmarshal(raw, &c); err != nil {
		return Code{}, fmt.Errorf("%w: %v", ErrBadCode, err)
	}
	// Every field is required. A code missing its fingerprint would enroll
	// without verifying the server, which is the failure this format exists to
	// prevent — so it is refused rather than tolerated.
	switch {
	case c.Addr == "":
		return Code{}, fmt.Errorf("%w: no address", ErrBadCode)
	case c.Token == "":
		return Code{}, fmt.Errorf("%w: no token", ErrBadCode)
	case c.CAFingerprint == "":
		return Code{}, fmt.Errorf("%w: no authority fingerprint", ErrBadCode)
	}
	return c, nil
}

// VerifyFingerprint reports whether a certificate matches the expected
// fingerprint, comparing in constant time.
//
// Constant time is not strictly required for a public value, but comparing
// digests with an early-exit loop is a habit worth not forming.
func VerifyFingerprint(cert *x509.Certificate, expected string) bool {
	got := Fingerprint(cert)
	if len(got) != len(expected) {
		return false
	}
	var diff byte
	for i := range got {
		diff |= got[i] ^ expected[i]
	}
	return diff == 0
}
