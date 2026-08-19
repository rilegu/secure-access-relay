# Development guide

Design rationale lives in [docs/](docs/) — start with
[architecture.md](docs/architecture.md) and [threat-model.md](docs/threat-model.md).
This file covers the rules that code has to follow.

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
- **Storage:** `modernc.org/sqlite` (pure Go) for v1, behind interfaces in
  `internal/storage` so Postgres can replace it later. Not `mattn/go-sqlite3` — it
  requires cgo.
- **Two planes, two protocols:**
  - Control API: plain JSON over HTTPS. Curl-able and easy to document.
  - Data plane: hand-rolled binary framing in `internal/proto`. Not gRPC, not yamux —
    explicit limits and backpressure are the point, and they must stay auditable.
- **Logging:** stdlib `log/slog` with a JSON handler, plus a Windows Event Log sink in
  `internal/logging`.
- **CLI:** `spf13/cobra`.
- Keep the dependency list short and defensible. Every dependency should survive the
  question "why not the standard library?"

## Layout

```
cmd/{sar-agent,sar-server,sarctl}/   entrypoints only, thin
internal/
  agent/         connect loop, resource registry, local dialer
  control/       identity/ enrollment/ resources/ policy/ grants/ audit/
  relay/         sessions/ streams/ authorization/
  proto/         frames, codec, limits, version negotiation
  transport/     mTLS setup, dial/listen, backoff, heartbeats
  storage/       interfaces + sqlite implementation
  config/ logging/
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

- Errors wrap with `%w`, and carry a reason code wherever a policy decision is involved.
- Every network operation takes a `context.Context` with a deadline. No unbounded reads.
- All buffers are bounded. Reject oversized frames rather than allocating for them.
- Every security-relevant decision emits an audit event before the action completes.
- Architectural choices get an ADR in [docs/decisions/](docs/decisions/), recording what
  was rejected and why — not just what was chosen.
- Reason codes are a compatibility surface. New ones may be added; existing ones never
  change meaning.

## Security reporting

This is experimental software and should not be deployed anywhere that matters. If you
find a flaw in the design, open an issue describing the attack path — the
[threat model](docs/threat-model.md) lists what is already known and in scope.
