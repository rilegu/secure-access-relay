package keystore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Protection describes how a stored key is protected at rest.
type Protection string

const (
	// ProtectionDPAPI means the key is sealed to the current Windows account.
	ProtectionDPAPI Protection = "dpapi"

	// ProtectionFilePermissions means the key is plaintext on disk, readable only
	// by its owner. Weaker: anyone who can read the file, or a backup of it, has
	// the key.
	ProtectionFilePermissions Protection = "file-permissions"
)

// ErrNotFound means no key has been stored yet.
var ErrNotFound = errors.New("keystore: no key stored")

// Save writes key material to path with the strongest protection available,
// reporting which one was used.
//
// The write is atomic: the material goes to a temporary file in the same
// directory and is renamed into place. A partially written key would be worse
// than a missing one, because a process that finds a truncated key on startup
// has no way to tell it from a corrupted one and may re-enroll over a valid
// identity.
func Save(path string, material []byte) (Protection, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create key directory: %w", err)
	}

	sealed, protection, err := seal(material)
	if err != nil {
		return "", err
	}

	tmp := path + ".tmp"
	// 0600 regardless of platform. On Windows the mode is largely advisory and
	// DPAPI is what actually protects the bytes, but setting it costs nothing and
	// keeps one code path.
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return "", fmt.Errorf("write key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("install key: %w", err)
	}
	return protection, nil
}

// Load reads key material previously written by Save.
func Load(path string) ([]byte, Protection, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", ErrNotFound
		}
		return nil, "", fmt.Errorf("read key: %w", err)
	}
	return open(sealed)
}
