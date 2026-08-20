# ADR-0012: Reach Win32 through the standard library

**Status:** accepted

## Context

Three parts of this system need Windows APIs that Go's standard library does not wrap:
DPAPI for sealing a private key, the service control manager for running as a service,
and the Event Log for operational events.

The usual answer is `golang.org/x/sys/windows`. It is maintained by the Go team, is
effectively an extension of the standard library, and wraps all three.

## Decision

Call the Windows APIs directly through the standard library's `syscall` package:
`syscall.NewLazyDLL` to resolve the module, `NewProc` for each entry point, and explicit
structure layouts for anything crossing the boundary.

This applies in `internal/keystore` (DPAPI), `internal/winsvc` (SCM), and
`internal/logging` (Event Log and its registry entries).

## Rejected: golang.org/x/sys/windows

It would be less code and better tested, and for most projects it is the right answer.
Three reasons it is not the answer here.

**It would be the project's first dependency, for convenience rather than for
correctness.** The rule this project applies is that every dependency must survive the
question *"why not the standard library?"* — and here the standard library genuinely
does the job. The surface actually needed is about fifteen entry points, not the
thousands that binding exposes.

**The technique is not incidental to this project.** A later phase adds a C diagnostics
library loaded dynamically at runtime, and that is exactly this: resolve a module,
resolve an entry point, marshal arguments explicitly, own every buffer. Writing the
Win32 calls by hand is a rehearsal of the boundary discipline
[ADR-0005](0005-native-c-dynamically-loaded.md) commits to, in code that has to work
before the harder version is attempted.

**Auditability.** A reviewer can see every Windows call this program makes, with its
structure layout and its error handling, in three files.

## Rejected: cgo for the Windows calls

Would break `CGO_ENABLED=0`, and with it static binaries and cross-compilation from a
non-Windows host. See [ADR-0006](0006-cgo-disabled-pure-go-sqlite.md).

## Consequences

- **Structure layouts are written by hand and must be exactly right.** `SERVICE_STATUS`,
  `SERVICE_FAILURE_ACTIONS`, `DATA_BLOB` and the rest are passed by pointer across an ABI
  boundary. A wrong field order or integer width is not rejected — it is read as
  garbage. Each declaration carries a comment naming the Win32 structure it mirrors.
- **Callbacks must outlive the call.** `syscall.NewCallback` produces a C function
  pointer that Windows holds for the life of the process, so the results are kept in
  package-level variables where the garbage collector cannot move or free them. It also
  means a callback cannot close over state, which is why the service's shared state is
  package-level rather than passed in.
- **Error codes are compared numerically.** `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`
  distinguishes "not running as a service" from a real failure, and
  `ERROR_SERVICE_DOES_NOT_EXIST` from `ERROR_ACCESS_DENIED` decides whether a caller is
  told to install the service or to run as Administrator. Those constants are spelled out
  in the file that uses them rather than imported, so the values the ABI depends on are
  visible.
- **This is more code than the binding, and code nobody else has reviewed.** That is a
  real cost and the honest argument against this decision. It is accepted because the
  surface is small, fixed, and exercised on every run.
- If the needed surface ever grows substantially — a large tranche of new Win32 calls,
  or COM — this should be revisited rather than defended. A future ADR superseding this
  one would be a legitimate response to that, not a reversal of a mistake.
