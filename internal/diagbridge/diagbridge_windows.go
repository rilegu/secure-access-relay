package diagbridge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

// initialBuffer is the first guess at a snapshot's size.
//
// The ABI reports the required size on truncation, so this is a starting point
// rather than a limit. 64 KiB holds an ordinary machine's adapters and routes in
// one call.
const initialBuffer = 64 << 10

// maxBuffer caps the retry.
//
// A snapshot larger than this is not a snapshot, it is a library misbehaving,
// and the agent must not allocate without bound on its say-so. Diagnostics are
// not worth an out-of-memory in a process that is holding authorized sessions
// open.
const maxBuffer = 16 << 20

// Library is a loaded sardiag.
//
// One instance per path. Loading is done once and the handle kept, because a
// DLL that is loaded and unloaded repeatedly re-runs its initialisation each
// time for no benefit.
type Library struct {
	dll *syscall.DLL

	abiVersion   *syscall.Proc
	snapshot     *syscall.Proc
	ifaceMetrics *syscall.Proc
	statusText   *syscall.Proc

	// mu serialises calls. The library is a set of read-only queries and is
	// almost certainly thread-safe, but "almost certainly" about somebody else's
	// C in this process is not a basis for concurrency, and the calls are rare.
	mu sync.Mutex
}

// Open loads the library, verifying it before it is mapped.
//
// The order matters: the path is resolved and the signature checked *before*
// LoadLibrary, because loading a DLL runs its entry point. Verifying after the
// fact would be verifying code that had already executed.
func Open(cfg Config) (*Library, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("%w: no install directory configured", ErrUnavailable)
	}
	if !filepath.IsAbs(cfg.Dir) {
		// A relative path resolves against the working directory, which a
		// service does not control and an attacker may. Refused rather than
		// resolved, because resolving it would produce a path that looks
		// deliberate and is not.
		return nil, fmt.Errorf("%w: install directory %q is not absolute", ErrUnavailable, cfg.Dir)
	}

	path := cfg.Path()
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, path)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%w: %s is a directory", ErrUnavailable, path)
	}

	if !cfg.AllowUnsigned {
		if err := verifySignature(path); err != nil {
			return nil, err
		}
	}

	// LoadDLL with an absolute path. Not syscall.NewLazyDLL with a bare name,
	// which searches the standard order — including, depending on the process's
	// configuration, directories somebody else can write to.
	dll, err := syscall.LoadDLL(path)
	if err != nil {
		return nil, fmt.Errorf("%w: loading %s: %v", ErrUnavailable, path, err)
	}

	lib := &Library{dll: dll}
	for _, entry := range []struct {
		name string
		into **syscall.Proc
	}{
		{"sardiag_abi_version", &lib.abiVersion},
		{"sardiag_network_snapshot", &lib.snapshot},
		{"sardiag_interface_metrics", &lib.ifaceMetrics},
		{"sardiag_status_text", &lib.statusText},
	} {
		proc, perr := dll.FindProc(entry.name)
		if perr != nil {
			_ = dll.Release()
			// A library missing an entry point is not a library this build can
			// use. Reported rather than worked around: calling the subset that
			// happens to be present would be guessing at a contract.
			return nil, fmt.Errorf("%w: %s does not export %s", ErrUnavailable, path, entry.name)
		}
		*entry.into = proc
	}

	// Before anything else is called. A version this build does not know
	// describes a calling convention it does not know.
	got, _, _ := lib.abiVersion.Call()
	if uint32(got) != SupportedABI {
		_ = dll.Release()
		return nil, fmt.Errorf("%w: %s reports version %d, this build supports %d",
			ErrABIMismatch, path, uint32(got), SupportedABI)
	}

	return lib, nil
}

// Close releases the library.
func (l *Library) Close() error {
	if l == nil || l.dll == nil {
		return nil
	}
	return l.dll.Release()
}

// Snapshot collects the machine's network configuration.
func (l *Library) Snapshot() (*Snapshot, error) {
	raw, err := l.collect(func(buf []byte, cap uint32, outLen *uint32) uintptr {
		r, _, _ := l.snapshot.Call(bufPtr(buf), uintptr(cap), uintptr(unsafe.Pointer(outLen)))
		return r
	})
	if err != nil {
		return nil, err
	}
	return decodeSnapshot(raw)
}

// InterfaceMetrics collects one interface by LUID.
func (l *Library) InterfaceMetrics(luid uint64) ([]byte, error) {
	return l.collect(func(buf []byte, cap uint32, outLen *uint32) uintptr {
		r, _, _ := l.ifaceMetrics.Call(uintptr(luid), bufPtr(buf), uintptr(cap),
			uintptr(unsafe.Pointer(outLen)))
		return r
	})
}

// collect runs the ask-then-fill sequence the ABI defines.
//
// The library reports what it needs when given too little, so this asks with a
// reasonable buffer and retries once at the reported size. It does not loop:
// the required size can legitimately change between calls when an adapter
// appears, and a loop against a machine whose configuration is changing
// continuously turns a diagnostic into a hang. One retry covers the ordinary
// case; the second failure is reported.
func (l *Library) collect(call func(buf []byte, cap uint32, outLen *uint32) uintptr) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	size := uint32(initialBuffer)
	for attempt := 0; attempt < 2; attempt++ {
		buf := make([]byte, size)
		var outLen uint32

		switch status := uint32(call(buf, size, &outLen)); status {
		case statusOK:
			if outLen > size {
				// The library claims to have written more than it was given.
				// Refused rather than trusted: acting on it would mean slicing
				// past the end of the buffer on the word of the thing that just
				// reported an impossible number.
				return nil, fmt.Errorf("diagbridge: library reported %d bytes written into a %d byte buffer",
					outLen, size)
			}
			return buf[:outLen], nil

		case statusTruncated:
			if outLen <= size || outLen > maxBuffer {
				return nil, fmt.Errorf("diagbridge: library asked for an unusable buffer size %d", outLen)
			}
			size = outLen

		default:
			return nil, fmt.Errorf("diagbridge: %s", l.statusMessage(status))
		}
	}
	return nil, errors.New("diagbridge: library kept asking for a larger buffer")
}

// Status codes and their text, mirroring sardiag.h.
//
// # Why the text lives here rather than being read from the library
//
// The ABI exports sardiag_status_text, and calling it would let a newer library
// describe a code this build has never heard of. It is deliberately not called.
//
// Doing so means dereferencing a pointer into the DLL's memory from Go, walking
// it byte by byte looking for a NUL. That is the one operation in this package
// that can read out of bounds, and it would exist purely to display an error
// message — the worst possible risk-to-benefit trade in a process holding device
// keys.
//
// The duplication cannot drift within a supported version, because the ABI
// version gates the whole contract: a library that added a status code would
// report a version this build refuses before any of these codes could be
// returned. So the set is fixed for as long as this build will talk to it.
//
// The entry point is still resolved at load, as a completeness check — a library
// missing it is not the library this expects — but its result is never read.
const (
	statusOK          uint32 = 0
	statusTruncated   uint32 = 1
	statusInvalidArg  uint32 = 2
	statusUnsupported uint32 = 3
	statusSystem      uint32 = 4
	statusNotFound    uint32 = 5
)

func (l *Library) statusMessage(status uint32) string {
	switch status {
	case statusOK:
		return "ok"
	case statusTruncated:
		return "output buffer too small"
	case statusInvalidArg:
		return "invalid argument"
	case statusUnsupported:
		return "not supported on this platform"
	case statusSystem:
		return "the operating system refused a query"
	case statusNotFound:
		return "no such interface"
	default:
		// Unreachable while the ABI version check holds, which is why it is
		// worth reporting the raw number: getting here means the version gate
		// did not do its job.
		return fmt.Sprintf("unrecognised library status %d", status)
	}
}

// bufPtr returns a pointer to the first byte, or zero for an empty slice.
//
// &buf[0] panics on an empty slice, and the ABI's size-query form is exactly a
// zero-length buffer — so the case that looks degenerate is one the contract
// explicitly supports.
func bufPtr(buf []byte) uintptr {
	if len(buf) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&buf[0]))
}
