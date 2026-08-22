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

## Implementation status

**Implemented.** `native/sardiag` is a C99 library built with
`-Wall -Wextra -Wpedantic -Wconversion -Werror`, and `internal/diagbridge` loads
it. `sar-agent diag` prints the snapshot.

Two details of this record were overtaken by later decisions and are worth
naming rather than leaving to be discovered:

- It says the library is loaded via `golang.org/x/sys/windows`. It is loaded
  through the standard library's `syscall` package instead, following
  [ADR-0012](0012-win32-through-stdlib.md), which was accepted afterwards and
  applies the same rule to DPAPI, the service control manager, and the Event Log.
- The signatures here take `uint8_t *out, uint32_t cap, uint32_t *out_len`, which
  is exactly what shipped. What this record did not settle is what goes *in* the
  buffer: it is UTF-8 JSON, so no struct crosses the boundary and neither
  compiler needs to agree with the other about packing, alignment, or field
  order. That turned out to be the decision that made the ABI boring.

The mandatory tests this record calls for exist: buffer capacity, exact-fit,
one-byte-short, every prefix from zero to the required size, and the error paths.
Each runs with guard bytes on both sides of the output buffer, because a test
that only checked the returned length would not notice a write past the end.

Authenticode verification is implemented through `WinVerifyTrust` and runs
*before* the library is mapped — verifying afterwards would be verifying code
that had already executed. An unsigned library is refused unless an administrator
passes `-allow-unsigned`, which exists because a locally built library is signed
by nobody and the worst case of loading one is a degraded support bundle.

## Consequences

- The agent stays pure Go and `CGO_ENABLED=0` (see [ADR-0006](0006-cgo-disabled-pure-go-sqlite.md)).
- A missing or unloadable DLL degrades the support bundle; it never prevents the agent
  from starting or from serving authorized access.
- The ABI is a compatibility surface: buffer-capacity, truncation, and error-path tests
  are mandatory, and the header is versioned.
- Caller allocates, caller frees. The DLL never returns a pointer it owns.
