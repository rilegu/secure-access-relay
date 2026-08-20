# Development guide

How this codebase is built and the rules its code follows. Design rationale lives in
[docs/](docs/) — start with [architecture.md](docs/architecture.md) and
[threat-model.md](docs/threat-model.md).

**This project is not accepting outside contributions.** It is published so the design
and the code can be read, not worked on collectively. Pull requests will not be merged.

## Non-negotiable invariants

Violating any of these is a bug, not a tradeoff. Enforce them in review.

1. **Deny by default.** Every denial carries an explicit machine-readable reason code.
2. **The relay never makes authorization decisions.** It pairs already-authorized
   streams. The agent verifies the signed grant locally before dialing anything.
3. **The control plane never carries payload traffic.**
4. **Resource targets are loopback-only in v1.** No arbitrary LAN proxy, ever, by accident.
5. **Grants are short-lived and signed** (Ed25519) over
   `{issuer, org_id, user_id, device_id, resource_id, issued_at, expires_at, grant_id, key_id}`.
   Max TTL 30 minutes.
6. **On control-plane or authorization failure: deny new streams.** A failure must never
   widen access.
7. **Never log** secrets, bearer tokens, private keys, grant signatures, or payload bytes.
8. **No credentials in** the repository, CLI flags, installer arguments, environment
   dumps, or logs.
9. **`CGO_ENABLED=0` for all Go binaries.** The native library is loaded dynamically at
   runtime, never linked at build time.

## Stable IDs

Fixed up front so that audit, revocation, and multitenancy do not force a redesign:

```
organization_id  user_id  device_id  resource_id  grant_id  session_id  stream_id
```

## Stack decisions

Each of these has an ADR in [docs/decisions/](docs/decisions/) with the alternatives that
were rejected and why.

- **Go for ~95%** of the codebase. Go 1.25 language version.
- **The native library is C, not C++.** C++ has no stable ABI, so it would need an
  `extern "C"` wrapper regardless; plain C removes that layer. If C++ internals are ever
  introduced, only `extern "C"` crosses the boundary — no classes, exceptions, STL types,
  or library-owned buffers.
- **The library is loaded dynamically** via `golang.org/x/sys/windows` LazyDLL, **not
  cgo**. This keeps the agent pure Go, keeps the library optional at runtime, and keeps
  cross-compilation clean.
- **Storage today:** a mutex-guarded JSON file written atomically, in `internal/storage`.
  It holds tens of records and needs single-use token consumption to be atomic, which one
  mutex provides with no dependency. It rewrites the whole file on every mutation, so it
  does not scale and cannot hold an audit trail.
- **Storage next:** `modernc.org/sqlite` — pure Go, never `mattn/go-sqlite3`, which needs
  cgo and would cost static binaries and ARM cross-compilation. It arrives with the policy
  engine and audit trail. See [ADR-0011](docs/decisions/0011-sqlite-not-key-value.md) for
  why a relational database rather than an embedded key-value store, and what that costs.
  When it lands: parameterised statements without exception, and an unrecognised schema
  version is a startup failure rather than a best-effort read.
- **Two planes, two protocols:**
  - Control API: plain JSON over HTTPS. Curl-able and easy to document.
  - Data plane: hand-rolled binary framing in `internal/proto`. Not gRPC, not yamux —
    explicit limits and backpressure are the point, and they must stay auditable.
- **Logging:** stdlib `log/slog` with a JSON handler, plus a Windows Event Log sink in
  `internal/logging`.
- **CLI:** the standard library's `flag`, with hand-written subcommand dispatch. Three
  binaries with a handful of subcommands do not justify a framework; this is the rule
  below applied to a case where it was tempting not to.
- Keep the dependency list short and defensible. Every dependency should survive the
  question "why not the standard library?"

## Layout

```
cmd/{sar-agent,sar-server,sarctl}/   entrypoints only, thin
internal/
  proto/         frames, codec, handshake encoding, limits, reason codes
  mux/           many streams over one connection: flow control, keepalive
  bridge/        bidirectional copy with half-close and abort semantics
  transport/     framed connection, TLS configuration, handshake completion
  ca/            development certificate authority: issues and parses identities
  keystore/      private key at rest; DPAPI on Windows, file permissions elsewhere
  identity/      a peer's own key, certificate, and trust anchor; enrollment client
  agent/         endpoint runtime: session, target validation, stream handling
  operator/      operator-side forwarder: local listener, one session, many streams
  relay/         relay server; sessions/ (registry) authorization/
  control/       enrollment/ httpapi/ ... resources/ policy/ grants/ audit/
  storage/       enrolled identities and enrollment tokens
  config/ logging/
  e2e/           every component wired together in one process
  winsvc/ winpipe/ wincrypt/ wfp/ diagbridge/    all //go:build windows
native/sardiag/  include/ src/ tests/   C diagnostics library
deploy/          docker compose for control plane, relay, and database
installer/       PowerShell installer, then WiX/MSI
scripts/         task.ps1 (Windows task runner)
testdata/        loopback HTTP fixture
docs/            architecture, threat-model, protocol, policy, e2e-test-plan, decisions/
```

`internal/control` and `internal/relay` must not import each other. That boundary is what
makes "a compromised relay cannot authorize access" true; see
[ADR-0007](docs/decisions/0007-one-binary-two-package-trees.md).

Windows-only packages carry `//go:build windows` so `go build ./...` and `go vet ./...`
stay clean on Linux.

## Building and testing

```sh
make lint       # go vet + gofmt check
make test       # fast unit tests
make build      # all three binaries
```

If GNU make is unavailable — common on Windows — `scripts/task.ps1` mirrors every target:

```powershell
.\scripts\task.ps1 all      # vet + gofmt + test + build
.\scripts\task.ps1 test
```

Test layers:

```
go test ./...                              fast, deterministic, any OS
go test -tags=integration ./...            component tests
go test -tags=windows_integration ./...    SCM, pipes, DPAPI, WFP, installer
```

Windows integration tests run on a **disposable VM**, never a development host — they
install services, alter firewall state, and inject network failures. Full matrix in
[docs/e2e-test-plan.md](docs/e2e-test-plan.md).

The success criterion is not "the tunnel works." It is: **the system permits exactly one
intended connection, explains and logs every decision, recovers correctly, and never
converts a failure into broader access.**

## Code conventions

**Comment the reasoning, not the syntax.** This is security-relevant networking code, and
a reader has to be able to follow *why* a check exists, not just that it does. Every file
should be understandable by someone who has read the docs but not the rest of the code.

- Every package has a doc comment stating what it is responsible for and what it must
  never do.
- Every exported type and function has a doc comment.
- Non-obvious decisions get an inline comment giving the reason: why a check happens
  before an allocation, why a lock is held, why a buffer is reused, why an error is
  deliberately not retried.
- Anything that enforces a threat-model control or an invariant says so explicitly, and
  names the threat or invariant it maps to.
- Do not comment what the code plainly says. `i++ // increment i` is noise; the goal is
  to save the reader from reconstructing an argument, not from reading Go.

Other conventions:

- Errors wrap with `%w`, and carry a reason code wherever a policy decision is involved.
- Every network operation takes a `context.Context` with a deadline. No unbounded reads.
- All buffers are bounded. Reject oversized frames rather than allocating for them.
- Every security-relevant decision emits an audit event before the action completes.
- Architectural choices get an ADR in [docs/decisions/](docs/decisions/), recording what
  was rejected and why — not just what was chosen.
- Reason codes are a compatibility surface. New ones may be added; existing ones never
  change meaning.

## On security

This is experimental software and should not be deployed anywhere that matters. It has
not been audited, and the [threat model](docs/threat-model.md) records both the controls
it intends to provide and the ones it does not yet implement.

Read that document before drawing any conclusion about what this software protects.
