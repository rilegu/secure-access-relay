package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Errors returned by the store. They are distinct because the caller must be
// able to tell them apart when deciding what reason code to return.
var (
	// ErrTokenUnknown means no such enrollment token exists.
	ErrTokenUnknown = errors.New("storage: unknown enrollment token")

	// ErrTokenConsumed means the token was already used. Enrollment tokens are
	// single-use; a second attempt is either a retry after a lost response or an
	// attacker replaying a token they observed (threat T8).
	ErrTokenConsumed = errors.New("storage: enrollment token already used")

	// ErrTokenExpired means the token outlived its validity window.
	ErrTokenExpired = errors.New("storage: enrollment token expired")

	// ErrRevoked means the identity exists but has been revoked.
	ErrRevoked = errors.New("storage: identity revoked")

	// ErrNotEnrolled means no such identity exists.
	ErrNotEnrolled = errors.New("storage: identity not enrolled")
)

// Record is an enrolled identity.
type Record struct {
	ID         string    `json:"id"`
	Role       string    `json:"role"`
	EnrolledAt time.Time `json:"enrolled_at"`

	// SerialHex is the serial of the certificate currently issued to this
	// identity. Re-enrolling replaces it, which is what makes an old certificate
	// stop being accepted without needing a revocation list.
	SerialHex string `json:"serial_hex"`

	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Token is a single-use enrollment token.
//
// The token itself is never stored — only a hash of it. If this file is read by
// someone who should not have it, they learn which identities are pending
// enrollment but cannot enroll as any of them, because the value needed to do
// that was only ever held by whoever the token was issued to.
type Token struct {
	Hash       string     `json:"hash"`
	Role       string     `json:"role"`
	ID         string     `json:"id"`
	IssuedAt   time.Time  `json:"issued_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

type state struct {
	Devices   map[string]Record `json:"devices"`
	Operators map[string]Record `json:"operators"`
	Tokens    map[string]Token  `json:"tokens"`
}

// Store persists enrollment state.
//
// # Why a file rather than a database
//
// The control plane at this stage holds tens of records and needs single-use
// token consumption to be atomic. A file guarded by one mutex, written whole and
// renamed into place, provides exactly that with no dependency. A real database
// arrives with the policy engine and audit trail, where the query patterns
// actually justify one.
//
// The consequence is that every mutation rewrites the file. That is fine at this
// scale and would not be at any other, which is the honest reason this is
// temporary.
type Store struct {
	mu    sync.Mutex
	path  string
	state state
}

// Open loads a store from disk, creating an empty one if the file is absent.
func Open(path string) (*Store, error) {
	s := &Store{
		path: path,
		state: state{
			Devices:   map[string]Record{},
			Operators: map[string]Record{},
			Tokens:    map[string]Token{},
		},
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read store: %w", err)
	}
	if err := json.Unmarshal(b, &s.state); err != nil {
		// A corrupt store is a startup failure, never something to recover from
		// by starting empty: silently discarding enrollment state would let every
		// enrolled device be replaced by whoever asks next.
		return nil, fmt.Errorf("parse store %s: %w", path, err)
	}
	if s.state.Devices == nil {
		s.state.Devices = map[string]Record{}
	}
	if s.state.Operators == nil {
		s.state.Operators = map[string]Record{}
	}
	if s.state.Tokens == nil {
		s.state.Tokens = map[string]Token{}
	}
	return s, nil
}

// HashToken returns the value stored for a token.
//
// SHA-256 with no salt or stretching, deliberately: tokens are high-entropy
// random values with a short lifetime, not user-chosen passwords, so there is
// nothing to brute-force and a slow hash would buy nothing.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// PutToken records a newly issued enrollment token.
func (s *Store) PutToken(t Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Tokens[t.Hash] = t
	return s.persistLocked()
}

// ConsumeToken validates a token and marks it used, all under one lock.
//
// Atomicity is the point of this method existing. If checking and marking were
// separate calls, two enrollment requests arriving together could both observe
// an unused token and both succeed — which is exactly the single-use property
// threat T8 depends on.
func (s *Store) ConsumeToken(token string) (Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.state.Tokens[HashToken(token)]
	if !ok {
		return Token{}, ErrTokenUnknown
	}
	if t.ConsumedAt != nil {
		return Token{}, ErrTokenConsumed
	}
	if time.Now().After(t.ExpiresAt) {
		return Token{}, ErrTokenExpired
	}

	now := time.Now()
	t.ConsumedAt = &now
	s.state.Tokens[t.Hash] = t
	if err := s.persistLocked(); err != nil {
		return Token{}, err
	}
	return t, nil
}

// PutRecord stores or replaces an enrolled identity.
func (s *Store) PutRecord(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordsLocked(r.Role)[r.ID] = r
	return s.persistLocked()
}

// Lookup returns an enrolled identity, refusing revoked ones.
//
// Revocation is checked here rather than by callers, so that every path which
// resolves an identity gets the check without having to remember it.
func (s *Store) Lookup(role, id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.recordsLocked(role)[id]
	if !ok {
		return Record{}, ErrNotEnrolled
	}
	if r.Revoked {
		return Record{}, ErrRevoked
	}
	return r, nil
}

// Revoke marks an identity revoked. Existing sessions are not the store's
// concern; the caller terminates those.
func (s *Store) Revoke(role, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.recordsLocked(role)[id]
	if !ok {
		return ErrNotEnrolled
	}
	now := time.Now()
	r.Revoked, r.RevokedAt = true, &now
	s.recordsLocked(role)[id] = r
	return s.persistLocked()
}

// List returns every record for a role, revoked ones included, for admin output.
func (s *Store) List(role string) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()

	m := s.recordsLocked(role)
	out := make([]Record, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	return out
}

func (s *Store) recordsLocked(role string) map[string]Record {
	if role == "operator" {
		return s.state.Operators
	}
	return s.state.Devices
}

// persistLocked writes the whole store atomically. The caller holds s.mu.
//
// Temporary file plus rename, so a crash mid-write cannot leave a half-written
// store that Open would refuse to parse — which would take the control plane
// down until someone deleted it by hand.
func (s *Store) persistLocked() error {
	b, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode store: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create store directory: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install store: %w", err)
	}
	return nil
}
