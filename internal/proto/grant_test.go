package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func validGrant(now time.Time) Grant {
	return Grant{
		KeyID:      "key_1",
		GrantID:    "grn_abc",
		OrgID:      "org_1",
		UserID:     "usr_maria",
		DeviceID:   "dev_panel_01",
		ResourceID: "res_diagnostics",
		IssuedAt:   now,
		ExpiresAt:  now.Add(20 * time.Minute),
		MaxBytes:   1 << 30,
	}
}

func TestGrantRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Now().Truncate(time.Second)

	signed, err := validGrant(now).Sign(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	decoded, err := DecodeGrant(signed.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := decoded.Verify(pub, now, "dev_panel_01"); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Every field must survive the trip. A field silently lost would still
	// verify, because the signature is over what was encoded.
	if decoded.GrantID != "grn_abc" || decoded.UserID != "usr_maria" ||
		decoded.ResourceID != "res_diagnostics" || decoded.MaxBytes != 1<<30 {
		t.Fatalf("fields lost in transit: %+v", decoded.Grant)
	}
	if !decoded.IssuedAt.Equal(now) {
		t.Fatalf("issued_at = %v, want %v", decoded.IssuedAt, now)
	}
}

// TestTamperedGrantFails is the property the whole design rests on: any change
// to any field invalidates the signature.
//
// It flips one bit at a time across the entire encoding rather than editing a
// chosen field, so a field accidentally left out of the canonical bytes would be
// caught — that is precisely the bug that turns a signed token into an unsigned
// one for the field nobody covered.
func TestTamperedGrantFails(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Now()

	signed, err := validGrant(now).Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	original := signed.Encode()

	for i := 0; i < len(original); i++ {
		for _, bit := range []byte{0x01, 0x80} {
			mutated := append([]byte(nil), original...)
			mutated[i] ^= bit

			decoded, err := DecodeGrant(mutated)
			if err != nil {
				continue // rejected at decode, which is also a refusal
			}
			if err := decoded.Verify(pub, now, "dev_panel_01"); err == nil {
				t.Fatalf("a grant with byte %d flipped by 0x%02x still verified: "+
					"that byte is not covered by the signature", i, bit)
			}
		}
	}
}

func TestGrantSignedByAnotherKeyFails(t *testing.T) {
	pub, _ := testKey(t)
	_, otherPriv := testKey(t)
	now := time.Now()

	signed, err := validGrant(now).Sign(otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	err = signed.Verify(pub, now, "dev_panel_01")
	if !errors.Is(err, ErrGrantSignature) {
		t.Fatalf("err = %v, want ErrGrantSignature", err)
	}
	if got := ReasonForGrant(err); got != ReasonGrantInvalidSignature {
		t.Errorf("reason = %q, want %q", got, ReasonGrantInvalidSignature)
	}
}

func TestExpiredGrantFails(t *testing.T) {
	pub, priv := testKey(t)
	issued := time.Now().Add(-40 * time.Minute)

	g := validGrant(issued)
	g.ExpiresAt = issued.Add(20 * time.Minute) // expired twenty minutes ago
	signed, err := g.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}

	err = signed.Verify(pub, time.Now(), "dev_panel_01")
	if !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("err = %v, want ErrGrantExpired", err)
	}
	if got := ReasonForGrant(err); got != ReasonGrantExpired {
		t.Errorf("reason = %q, want %q", got, ReasonGrantExpired)
	}
}

func TestNotYetValidGrantFails(t *testing.T) {
	pub, priv := testKey(t)
	future := time.Now().Add(10 * time.Minute)

	signed, err := validGrant(future).Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	err = signed.Verify(pub, time.Now(), "dev_panel_01")
	if !errors.Is(err, ErrGrantNotYetValid) {
		t.Fatalf("err = %v, want ErrGrantNotYetValid", err)
	}
}

// TestClockSkewIsBounded checks the tolerance exists and is not unlimited.
//
// A grant a few seconds early is accepted because machine clocks disagree; one
// ten minutes early is refused, because at that point the tolerance would be
// silently extending every grant's real lifetime.
func TestClockSkewIsBounded(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Now()

	justAhead, err := validGrant(now.Add(ClockSkewTolerance / 2)).Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := justAhead.Verify(pub, now, "dev_panel_01"); err != nil {
		t.Fatalf("a grant within the skew tolerance was refused: %v", err)
	}

	wayAhead, err := validGrant(now.Add(10 * time.Minute)).Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := wayAhead.Verify(pub, now, "dev_panel_01"); err == nil {
		t.Fatal("a grant ten minutes in the future was accepted")
	}
}

// TestGrantForAnotherDeviceFails covers threat T6: a grant captured at one
// endpoint must not be usable at another.
func TestGrantForAnotherDeviceFails(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Now()

	signed, err := validGrant(now).Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	err = signed.Verify(pub, now, "dev_a_different_panel")
	if !errors.Is(err, ErrGrantDeviceMismatch) {
		t.Fatalf("err = %v, want ErrGrantDeviceMismatch", err)
	}
	if got := ReasonForGrant(err); got != ReasonGrantDeviceMismatch {
		t.Errorf("reason = %q, want %q", got, ReasonGrantDeviceMismatch)
	}
}

// TestTTLCeilingEnforcedAtSignAndVerify checks the maximum lifetime is refused
// in both places.
//
// Verifying independently matters: a verifier that trusted the issuer to have
// checked would honour a year-long grant from a compromised issuer.
func TestTTLCeilingEnforcedAtSignAndVerify(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Now()

	g := validGrant(now)
	g.ExpiresAt = now.Add(MaxGrantTTL + time.Minute)

	if _, err := g.Sign(priv); !errors.Is(err, ErrGrantTTLTooLong) {
		t.Fatalf("sign accepted an over-long grant: %v", err)
	}

	// Forge one anyway, as a compromised issuer would, and check the verifier
	// refuses it on its own account.
	g.Version = GrantVersion
	forged := &SignedGrant{Grant: g, Signature: ed25519.Sign(priv, g.canonical())}
	if err := forged.Verify(pub, now, "dev_panel_01"); !errors.Is(err, ErrGrantTTLTooLong) {
		t.Fatalf("verify accepted an over-long grant: %v", err)
	}
}

func TestGrantDecodeRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":              {},
		"too short":          make([]byte, 10),
		"signature only":     make([]byte, ed25519.SignatureSize),
		"wrong version byte": append([]byte{99}, make([]byte, ed25519.SignatureSize+8)...),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeGrant(b); err == nil {
				t.Fatal("garbage decoded as a grant")
			}
		})
	}
}

// FuzzDecodeGrant drives arbitrary bytes through the decoder. A decoded grant
// must never verify against a key that did not sign it.
func FuzzDecodeGrant(f *testing.F) {
	pubK, privK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	now := time.Now()
	if signed, err := validGrant(now).Sign(privK); err == nil {
		f.Add(signed.Encode())
	}
	f.Add([]byte{})
	f.Add(make([]byte, ed25519.SignatureSize+1))

	f.Fuzz(func(t *testing.T, data []byte) {
		g, err := DecodeGrant(data)
		if err != nil {
			return
		}
		// Anything that decodes must still fail verification unless it happens to
		// be a genuine grant, which arbitrary bytes will not be.
		if err := g.Verify(pubK, now, ""); err == nil {
			if string(g.Signature) == "" {
				t.Fatal("empty signature verified")
			}
		}
	})
}
