# byreis Makefile
# Targets: build, test, lint, install

BINARY       := byreis
MODULE       := github.com/ByReisK/byreis
CMD_PKG      := ./cmd/byreis
BIN_DIR      := ./bin

# Inject version from git tag if available (falls back to "dev" if no git).
VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS      := -X $(MODULE)/pkg/byreis.Version=$(VERSION)

GOLANGCI     := golangci-lint
GO_TEST_FLAGS := -race -timeout=120s

.PHONY: build test lint install clean check-allowlist

## build: compile the byreis binary to ./bin/byreis
build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD_PKG)

## test: run all tests with the race detector
test:
	go test $(GO_TEST_FLAGS) ./...

## test-shipgate: run the non-skippable asymmetric-access ship-gate suite
test-shipgate:
	go test $(GO_TEST_FLAGS) -tags shipgate -run TestAsymmetryShipGate ./internal/core/usecase/

## lint: run golangci-lint (enforces Clean Architecture dependency rules)
lint:
	$(GOLANGCI) run ./...

## install: install the byreis binary to $GOPATH/bin (or $HOME/go/bin)
install:
	go install -ldflags "$(LDFLAGS)" $(CMD_PKG)

## check-allowlist: run the closed-world import allowlist gate (Go test is authoritative)
## Targets: internal/core/crypto/encrypt and internal/core/usecase/submit (the Submit compilation unit).
## A non-zero exit is a hard failure; a gate that cannot run fails, never passes.
check-allowlist:
	go test -v -race -run TestAllowlist \
		./internal/core/crypto/encrypt/ \
		./internal/core/usecase/submit/

## clean: remove build artifacts
clean:
	rm -rf $(BIN_DIR)
	go clean ./...

help:
	@grep -E '^## ' Makefile | sed 's/## //'
