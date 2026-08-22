package diagbridge

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Authenticode verification, threat T17.
//
// Reached through the standard library's syscall package rather than a
// third-party Windows binding, like every other Win32 call in this project
// (ADR-0012). WinVerifyTrust is one entry point and two structures, both laid
// out below with their fields visible.

var (
	wintrust           = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")
)

// WINTRUST_ACTION_GENERIC_VERIFY_V2 selects Authenticode verification: verify
// the signature, build the certificate chain, and check that the signer is
// trusted for code signing.
//
// {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
var actionGenericVerifyV2 = syscall.GUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

// WinVerifyTrust constants. Named rather than inlined, because a bare 2 in a
// security check is a number nobody can review.
const (
	wtdUINone            = 2 // never prompt; this may run as a service with no desktop
	wtdRevokeWholeChain  = 1
	wtdChoiceFile        = 1
	wtdStateActionVerify = 1
	wtdStateActionClose  = 2

	// Cache revocation results but do not require a network round trip on every
	// load. A service starting on a machine with no route out must not hang here.
	wtdCacheOnlyURLRetrieval = 0x00001000

	// Fail rather than prompt if the signature is absent or the publisher is not
	// trusted.
	wtdSafer = 0x00000100
)

// wintrustFileInfo is WINTRUST_FILE_INFO.
type wintrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          syscall.Handle
	pgKnownSubject *syscall.GUID
}

// wintrustData is WINTRUST_DATA.
//
// The field order and sizes are the ABI; changing either silently misreads the
// structure rather than failing to compile, which is the same hazard the sardiag
// header avoids by refusing to pass structs at all. Here there is no choice —
// this is somebody else's API.
type wintrustData struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *wintrustFileInfo
	dwStateAction       uint32
	hWVTStateData       syscall.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

// verifySignature checks a file's Authenticode signature.
//
// # Why this runs before the library is loaded
//
// Loading a DLL executes its entry point. Verifying afterwards would be
// verifying code that had already run, which is not verification.
//
// A failure is always fatal to the load. There is no "warn and continue": the
// entire purpose is to refuse an unexpected file, and a control that can be
// stepped past by ignoring a log line is not one. An administrator who needs to
// run an unsigned library says so explicitly through AllowUnsigned, which is a
// different decision made in a different place.
func verifySignature(path string) error {
	wide, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUntrusted, path, err)
	}

	file := wintrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		pcwszFilePath: wide,
	}
	data := wintrustData{
		cbStruct:            uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeWholeChain,
		dwUnionChoice:       wtdChoiceFile,
		pFile:               &file,
		dwStateAction:       wtdStateActionVerify,
		dwProvFlags:         wtdCacheOnlyURLRetrieval | wtdSafer,
	}

	rc, _, _ := procWinVerifyTrust.Call(
		0, // no window; never interactive
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)

	// The state handle is released whatever the verdict. Skipping it on the
	// failure path is the classic leak in this API, and a service that verifies
	// on every start would accumulate them.
	data.dwStateAction = wtdStateActionClose
	_, _, _ = procWinVerifyTrust.Call(
		0,
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)

	if rc != 0 {
		// The specific reason is reported, because "unsigned", "expired", and
		// "signed by somebody else" call for very different responses from
		// whoever is reading the log.
		return fmt.Errorf("%w: %s: %s", ErrUntrusted, path, trustError(uint32(rc)))
	}
	return nil
}

// trustError names the outcomes worth distinguishing.
func trustError(rc uint32) string {
	switch rc {
	case 0x800B0100:
		return "the file is not signed"
	case 0x800B0101:
		return "the signing certificate has expired"
	case 0x800B0109:
		return "the signing certificate chains to an untrusted root"
	case 0x800B010A:
		return "the signing certificate chain is incomplete"
	case 0x80092003:
		return "the file could not be read"
	case 0x800B0111:
		return "the signer is explicitly distrusted"
	default:
		return fmt.Sprintf("verification failed (0x%08X)", rc)
	}
}
