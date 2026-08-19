# ADR-0005: Native diagnostics in C, dynamically loaded, not cgo

**Status:** accepted

## Context

The agent needs a Windows network diagnostics snapshot — adapter state, route table,
DNS configuration, proxy settings, relevant service and driver status — for the support
bundle. This is a legitimate reason to call native Win32 and IP Helper APIs.

## Decision

A small library `native/sardiag` written in **C**, exposing an `extern "C"` ABI of a
handful of functions using caller-allocated buffers:

```c
int sardiag_network_snapshot(uint8_t *out, uint32_t cap, uint32_t *out_len);
int sardiag_interface_metrics(uint64_t luid, uint8_t *out, uint32_t cap, uint32_t *out_len);
```

Go loads it at runtime via `golang.org/x/sys/windows` LazyDLL, from an absolute path
inside the ACL-protected install directory, with the Authenticode signature verified
before load.

## Rejected: C++

C++ has no stable ABI across compilers or even compiler versions, so anything crossing
the boundary would need an `extern "C"` wrapper regardless. Writing the library in C
removes that wrapper entirely rather than hiding it. No class types, exceptions, STL
objects, or DLL-owned buffers cross the boundary under any circumstances.

## Rejected: cgo

cgo forces `CGO_ENABLED=1`, which pulls a C toolchain into every build of the agent,
complicates cross-compilation, and slows builds — all to consume four functions. It also
makes the DLL a hard build dependency rather than an optional runtime component.

## Rejected: an out-of-process helper

Justified when the native code is untrusted or crash-prone. This library only reads
system state; the process boundary would add IPC, lifecycle management, and a second
binary to install for no security gain.

## Consequences

- The agent stays pure Go and `CGO_ENABLED=0` (see [ADR-0006](0006-cgo-disabled-pure-go-sqlite.md)).
- A missing or unloadable DLL degrades the support bundle; it never prevents the agent
  from starting or from serving authorized access.
- The ABI is a compatibility surface: buffer-capacity, truncation, and error-path tests
  are mandatory, and the header is versioned.
- Caller allocates, caller frees. The DLL never returns a pointer it owns.
