//go:build !windows

package keystore

// On platforms without DPAPI the key is stored as written, protected only by
// file permissions.
//
// This is genuinely weaker, and the weakness is reported rather than hidden:
// Save and Load return ProtectionFilePermissions, and callers say so at startup.
// Sealing with a key derived from something on the same disk would look like
// encryption while protecting nothing, which is worse than being plain about it.
//
// A stronger implementation would use the platform keyring or a TPM. That is
// deferred, not overlooked.

func seal(material []byte) ([]byte, Protection, error) {
	return material, ProtectionFilePermissions, nil
}

func open(sealed []byte) ([]byte, Protection, error) {
	return sealed, ProtectionFilePermissions, nil
}
