// Package diagbridge loads the optional sardiag library and calls it.
//
// # Optional means optional
//
// Everything here can fail, and none of it may affect whether authorized access
// works. A missing library, a wrong ABI version, an unsigned file, a call that
// errors — each degrades the support bundle and nothing else. The agent is a
// security control; the diagnostics are a convenience, and a convenience that
// can take the control down is not one.
//
// That is why every entry point returns a result *and* an error rather than
// panicking or caching a failure permanently: a library installed after the
// agent started should work on the next call.
//
// # Why loading is the risky part
//
// Executing code from disk in a process that holds device keys is the most
// dangerous thing this project does. Threat T17 is a hostile DLL substituted
// for the real one, and the controls are all here rather than spread across
// callers:
//
//   - An absolute path inside the ACL-protected install directory. Never a bare
//     name, which would search the working directory and %PATH% and hand the
//     choice to whoever can write to either.
//   - The Authenticode signature is verified before the file is mapped, unless
//     an administrator has explicitly allowed unsigned libraries.
//   - The ABI version is checked before any other function is called.
//
// See ADR-0005 for why this is a dynamically loaded C library rather than cgo.
package diagbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
)

// LibraryName is the file the agent looks for, inside its install directory.
const LibraryName = "sardiag.dll"

// SupportedABI is the sardiag ABI version this build understands.
//
// It must match SARDIAG_ABI_VERSION in native/sardiag/include/sardiag.h. A
// library reporting anything else is refused rather than called: the version
// exists to describe a calling convention, and guessing at an unknown one is how
// a diagnostic call becomes a crash.
const SupportedABI uint32 = 1

// Errors this package reports. Callers distinguish them so that "no library
// installed" reads differently from "a library is installed and was refused" —
// the first is the ordinary state, the second deserves attention.
var (
	// ErrUnavailable means no usable library was found. Expected and benign.
	ErrUnavailable = errors.New("diagbridge: diagnostics library is not available")

	// ErrABIMismatch means a library was found but speaks a version this build
	// does not.
	ErrABIMismatch = errors.New("diagbridge: diagnostics library reports an unsupported ABI version")

	// ErrUntrusted means the file failed signature verification. Distinct from
	// unavailable on purpose: a file that is present and refused is a fact worth
	// surfacing, because the benign explanations and the alarming one look
	// identical from a distance.
	ErrUntrusted = errors.New("diagbridge: diagnostics library failed signature verification")

	// ErrUnsupportedPlatform means this build has no loader.
	ErrUnsupportedPlatform = errors.New("diagbridge: diagnostics library is only available on Windows")
)

// Config controls how the library is located and trusted.
type Config struct {
	// Dir is the directory to load from. Required, and must be absolute: a
	// relative path resolves against a working directory a service does not
	// control, which is the search-order problem this exists to avoid.
	Dir string

	// AllowUnsigned skips Authenticode verification.
	//
	// For development, where the library is built locally and signed by nobody.
	// It is off by default, it is logged every time it is used, and it does not
	// weaken the path pinning — an unsigned library is still only loaded from
	// the ACL-protected directory. The reason it is tolerable at all is that the
	// worst case is a degraded support bundle rather than compromised access.
	AllowUnsigned bool
}

// Snapshot is the decoded network snapshot.
//
// The fields are deliberately a subset of what the library emits. Unknown JSON
// is ignored, which is what lets the library add a field without an ABI bump —
// see the header's note on why the version does not track the schema.
type Snapshot struct {
	ABIVersion uint32     `json:"abi_version"`
	Platform   string     `json:"platform"`
	Adapters   []Adapter  `json:"adapters"`
	Routes     []Route    `json:"routes"`
	Proxy      ProxyState `json:"proxy"`
}

// Adapter is one network interface as the library reports it.
type Adapter struct {
	LUID         uint64   `json:"luid"`
	Index        uint32   `json:"index"`
	Name         string   `json:"name"`
	FriendlyName string   `json:"friendly_name"`
	Description  string   `json:"description"`
	Status       string   `json:"status"`
	MTU          uint32   `json:"mtu"`
	Type         uint32   `json:"type"`
	MAC          string   `json:"mac"`
	Addresses    []string `json:"addresses"`
	DNSServers   []string `json:"dns_servers"`
	Gateways     []string `json:"gateways"`
}

// Route is one entry from the forwarding table.
type Route struct {
	Destination    string `json:"destination"`
	PrefixLength   uint8  `json:"prefix_length"`
	NextHop        string `json:"next_hop"`
	InterfaceIndex uint32 `json:"interface_index"`
	Metric         uint32 `json:"metric"`
	Loopback       bool   `json:"loopback"`
}

// ProxyState is the machine-wide WinHTTP proxy configuration.
type ProxyState struct {
	Available  bool   `json:"available"`
	AccessType uint32 `json:"access_type"`
	Proxy      string `json:"proxy"`
	Bypass     string `json:"bypass"`
}

// Path returns where the library is expected, given a config.
func (c Config) Path() string { return filepath.Join(c.Dir, LibraryName) }

// decodeSnapshot parses what the library produced.
//
// A parse failure is reported as a parse failure rather than as an empty
// snapshot: the library and this package are versioned together, so JSON that
// does not decode means something is wrong that a caller should hear about.
func decodeSnapshot(raw []byte) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("diagbridge: diagnostics library returned unparseable output: %w", err)
	}
	if s.ABIVersion != SupportedABI {
		// The JSON carries the version too, so a library that lied in
		// sardiag_abi_version — or one whose header and source disagree — is
		// still caught before its contents are believed.
		return nil, fmt.Errorf("%w: snapshot reports %d, expected %d",
			ErrABIMismatch, s.ABIVersion, SupportedABI)
	}
	return &s, nil
}
