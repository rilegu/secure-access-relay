GO       ?= go
GOFLAGS  ?=
BIN      := bin
PKGS     := ./...

export CGO_ENABLED := 0

.PHONY: all build test test-race lint vet fmt tidy clean integration win-integration

all: lint test test-race build

build:
	$(GO) build $(GOFLAGS) -o $(BIN)/ ./cmd/...

## fast, deterministic unit tests - must pass on every commit
test:
	$(GO) test -count=1 $(PKGS)

## same tests under the race detector. Needs cgo and a C toolchain, which is why
## it is separate: shipped binaries stay CGO_ENABLED=0, the test harness does not.
test-race:
	CGO_ENABLED=1 $(GO) test -race -count=1 $(PKGS)

## component tests (control plane, relay protocol, storage)
integration:
	$(GO) test -tags=integration -count=1 $(PKGS)

## Windows-only: SCM, named pipes, DPAPI, WFP, installer. Disposable VM only.
win-integration:
	$(GO) test -tags=windows_integration -count=1 $(PKGS)

vet:
	$(GO) vet $(PKGS)

fmt:
	gofmt -l -w .

lint: vet
	@gofmt -l . | grep -v vendor | (! grep .) || (echo "gofmt needed on files above"; exit 1)

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN) coverage.out
