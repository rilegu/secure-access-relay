GO       ?= go
GOFLAGS  ?=
BIN      := bin
PKGS     := ./...

export CGO_ENABLED := 0

.PHONY: all build test lint vet fmt tidy clean integration win-integration

all: lint test build

build:
	$(GO) build $(GOFLAGS) -o $(BIN)/ ./cmd/...

## fast, deterministic unit tests - must pass on every commit
test:
	$(GO) test -race -count=1 $(PKGS)

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
