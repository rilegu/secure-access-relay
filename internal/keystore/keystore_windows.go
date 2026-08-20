//go:build windows

package keystore

import (
	"fmt"
	"syscall"
	"unsafe"
)

// DPAPI, reached through the standard library rather than an external binding.
//
// CryptProtectData seals data so that only the current user account on the
// current machine can unseal it. That is exactly the property threat T9 needs:
// copying the state directory to another host, or reading it as another user,
// yields bytes that cannot be decrypted.
var (
	crypt32           = syscall.NewLazyDLL("crypt32.dll")
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procProtectData   = crypt32.NewProc("CryptProtectData")
	procUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree     = kernel32.NewProc("LocalFree")
)

// dataBlob mirrors the Win32 DATA_BLOB structure: a length and a pointer.
//
// Layout matters here in a way it does not in ordinary Go. The struct is passed
// across an ABI boundary, so the field order and the integer widths must match
// what crypt32 expects exactly. See docs/decisions/0005 for the general rule.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

// bytes copies the blob's contents into Go memory.
//
// A copy, not a reference: the memory belongs to crypt32 and is released by
// LocalFree immediately afterwards. Returning a slice that pointed at it would
// be a use-after-free waiting to happen.
func (b dataBlob) bytes() []byte {
	if b.cbData == 0 || b.pbData == nil {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

// entropy binds the sealed data to this application.
//
// Without it, any process running as the same user could unseal the key by
// calling CryptUnprotectData on the file. With it, a caller must also know this
// value. It is not a secret — it is compiled into the binary — so it raises the
// bar rather than closing the hole: on Windows, code running as the same user is
// outside the threat model either way.
var entropy = []byte("secure-access-relay/device-key/v1")

func seal(material []byte) ([]byte, Protection, error) {
	in := newBlob(material)
	ent := newBlob(entropy)
	var out dataBlob

	r, _, err := procProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // description, unused
		uintptr(unsafe.Pointer(&ent)),
		0, // reserved
		0, // prompt struct, none
		0, // flags
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, "", fmt.Errorf("CryptProtectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))

	return out.bytes(), ProtectionDPAPI, nil
}

func open(sealed []byte) ([]byte, Protection, error) {
	in := newBlob(sealed)
	ent := newBlob(entropy)
	var out dataBlob

	r, _, err := procUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // description out, unused
		uintptr(unsafe.Pointer(&ent)),
		0, // reserved
		0, // prompt struct, none
		0, // flags
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		// The usual cause is that the file came from another machine or another
		// user account, which is the protection working rather than a fault.
		return nil, "", fmt.Errorf("CryptUnprotectData (key may belong to another account or machine): %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))

	return out.bytes(), ProtectionDPAPI, nil
}
