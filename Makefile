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

.PHONY: build test test-testhook test-shipgate test-docgate test-composability test-tui-core-ceiling lint install clean check-allowlist check-publish-boundary ci-parity ci-parity-windows-build

## build: compile the byreis binary to ./bin/byreis
build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD_PKG)

## test: run all tests with the race detector
test:
	go test $(GO_TEST_FLAGS) ./...

## test-testhook: run all tests with the testhook build tag (counter-decision negatives)
## This is the ONLY place the testhook tag is compiled; never compiled into shipped binaries.
test-testhook:
	go test $(GO_TEST_FLAGS) -tags testhook ./...

## test-shipgate: run the non-skippable asymmetric-access ship-gate suite.
## Two packages are covered:
##   internal/core/usecase — the §7.1 REQ-B-001 asymmetric-access suite (TestAsymmetryShipGate*)
##   internal/app          — the D-1 positive real-composition suite (TestD1_PositiveComposition)
##                           and the V-3.5 nil-fallback wiring tests (TestV35_*)
test-shipgate:
	go test $(GO_TEST_FLAGS) -tags shipgate -run TestAsymmetryShipGate ./internal/core/usecase/
	go test $(GO_TEST_FLAGS) -tags shipgate -run 'TestD1_PositiveComposition|TestV35_' ./internal/app/

## test-docgate: run the docgate suite (forward-secrecy warning verbatim + release-wiring
## assertion + V5a R4a CLI emission + V6 request-access honesty contract + V6 admin warning
## + V-9 v0.3 positioning-honesty release-notes verbatim ring, REQ-V03-011).
## The docgate tag is a non-default sibling lane to shipgate; it is never compiled into a shipped
## binary (asserted structurally by shipped_surface_test.go and by the CI release-build-clean check).
test-docgate:
	go test $(GO_TEST_FLAGS) -tags docgate -run 'TestForwardSecrecyWarning_VerbatimMatch|TestForwardSecrecyWarning_RunbookPathReferenceIntact|TestReleaseWorkflow_DocgateGateWiringIntact|TestDocGate_ReleaseNotesV03_PositioningHonestyVerbatim|TestDocGate_ReleaseNotesV03_NoGitLabOrMultiProviderLanguage' ./internal/core/usecase/rotate/
	go test $(GO_TEST_FLAGS) -tags docgate -run 'TestV5R4aCLI_RotateRemoveDryRunEmitsVerbatimForwardSecrecyWarning|TestV5R4aCLI_RotateRemoveNonDryRunEmitsVerbatimForwardSecrecyWarning|TestDocGate_RequestAccessHelp_VerbatimHonestyContract|TestDocGate_RequestAccessAdminWarning_VerbatimEmitted|TestR4b_DoctorRotationHistory_VerbatimFixtureMatchesConstant|TestR4b_DoctorRotationHistoryEmitsVerbatimForwardSecrecyWarning|TestR4b_DoctorRotationHistoryNoRemovalsNoWarningExitZero|TestR4b_DoctorRotationHistoryPartialRotationDetected|TestR4b_DoctorRotationHistoryReachableInContributorMode' ./internal/cli/

## test-composability: run the R-005.6 composability scenario (non-release-gating).
## A red R-005.6 is a v0.2.1 fast-follow obligation and MUST NOT block the v0.2.0 tag.
## This target is intentionally DISTINCT from test-shipgate and test-docgate and is
## not included in either of those run sets.
test-composability:
	go test $(GO_TEST_FLAGS) -tags composability -run TestR005_6 ./internal/core/usecase/submit/

## test-tui-core-ceiling: assert that internal/core/** exported symbols and the
## mode-matrix allow set are unchanged from the committed baseline. This gate runs
## on every TUI-related change and at v0.3 close. A new core symbol from TUI work
## fails the gate; escalate to principal-go to extend. The baseline is reseeded
## only when a reviewed, non-TUI change legitimately adds core symbols.
test-tui-core-ceiling:
	go test $(GO_TEST_FLAGS) -tags ceiling -run 'TestTUICeiling' ./internal/tui/

## lint: verify the golangci-lint config schema, then run golangci-lint.
## config verify matches what golangci-lint-action@v7 (CI) runs before lint,
## so a schema error that would fail CI also fails locally.
lint:
	$(GOLANGCI) config verify
	$(GOLANGCI) run ./...

## install: install the byreis binary to $GOPATH/bin (or $HOME/go/bin)
install:
	go install -ldflags "$(LDFLAGS)" $(CMD_PKG)

## check-allowlist: run the closed-world import allowlist gate (Go test is authoritative)
## The tests pin GOOS=linux GOARCH=amd64 on all inner go list -deps calls so the
## evaluated transitive-dep set is identical on every dev host and in CI (linux/amd64).
## The allowlist is the platform-union satisfying linux+windows+darwin.
## A non-zero exit is a hard failure; a gate that cannot run fails, never passes.
check-allowlist:
	go test -v -race -run TestAllowlist \
		./internal/core/crypto/encrypt/ \
		./internal/core/usecase/submit/

## check-publish-boundary: bidirectional publish-boundary audit.
## FAILS if any go list ./... source dir is git-ignored (build-required source excluded from repo).
## FAILS if any intended-private artifact (PLAN*, design/, CLAUDE.md, .claude/, scripts/,
## spike/, *.key, *.age, /identity/, .byreis.local.yaml) is NOT ignored.
## A gate that cannot run (missing go/git) exits non-zero.
check-publish-boundary:
	@echo "--- check-publish-boundary: bidirectional audit ---"
	@FAILED=0; \
	for d in $$(go list -f '{{.Dir}}' ./... | sed "s|$$(pwd)/||"); do \
		if git check-ignore -q "$$d" 2>/dev/null; then \
			echo "FAIL: build-required source dir is git-ignored: $$d"; \
			FAILED=1; \
		fi; \
	done; \
	if [ $$FAILED -eq 0 ]; then \
		echo "PASS: no build-required source dirs are git-ignored"; \
	fi; \
	for p in PLAN.md PLAN.v1.md design/ CLAUDE.md .claude/ scripts/ spike/ somekey.key somekey.age identity/ .byreis.local.yaml; do \
		if ! git check-ignore -q "$$p" 2>/dev/null; then \
			echo "FAIL: intended-private artifact is NOT git-ignored: $$p"; \
			FAILED=1; \
		fi; \
	done; \
	if [ $$FAILED -eq 0 ]; then \
		echo "PASS: all intended-private artifacts are git-ignored"; \
	fi; \
	exit $$FAILED

## ci-parity: clean COMMITTED-HEAD worktree (refuses on dirty tree); GOOS=linux GOARCH=amd64 build-parity + native -race test + GOOS-pinned allowlist + shipgate; true cross-arch test execution is the post-push CI job.
## A gate that cannot run exits non-zero.
##
## Why git worktree into a sibling dir (not mktemp): Go ignores go.mod found under the
## system temp root on macOS (/var/folders/.../T/...), causing "pattern ./...: directory
## prefix . does not contain main module". The worktree lands in a sibling of the repo
## root (outside $TMPDIR, outside the repo itself) where Go respects go.mod normally.
## The sibling path (.byreis-ci-parity.<pid>) is never inside the repo so it cannot trip
## check-publish-boundary or be accidentally committed.
##
## Cross-arch note: a macOS host cannot execute linux/amd64 test binaries (exec format
## error). The split is intentional: GOOS=linux GOARCH=amd64 go build ./... catches
## compile-parity (the class of break that linux CI would catch first); go test -race ./...
## runs on the native host arch for real execution; the allowlist and shipgate tests use
## GOOS=linux GOARCH=amd64 on their inner go list -deps calls (already pinned in the test
## source) so they are platform-deterministic regardless of host arch.
ci-parity:
	@echo "--- ci-parity: clean-worktree CI-platform-matched verification ---"
	@if [ -n "$$(git status --porcelain)" ]; then \
	  echo "ci-parity: REFUSING — working tree is dirty. Stage+commit the exact to-be-pushed tree as one clean commit, THEN run ci-parity (it verifies the committed HEAD that git push will send)."; \
	  exit 1; \
	fi
	@WT="$$(cd .. && pwd)/.byreis-ci-parity.$$$$" && \
	trap 'git worktree remove --force "$$WT" 2>/dev/null || rm -rf "$$WT"' EXIT INT TERM && \
	echo "Creating detached worktree at $$WT ..." && \
	git worktree add --detach "$$WT" HEAD && \
	cd "$$WT" && \
	echo "--- go build ./... (GOOS=linux GOARCH=amd64) ---" && \
	GOOS=linux GOARCH=amd64 go build ./... && \
	echo "--- go test -race -timeout=120s ./... (native host arch) ---" && \
	go test -race -timeout=120s ./... && \
	echo "--- allowlist gate (GOOS-pinned inside tests) ---" && \
	go test -v -race -run TestAllowlist \
		./internal/core/crypto/encrypt/ \
		./internal/core/usecase/submit/ && \
	echo "--- ship-gate suite ---" && \
	go test -race -tags shipgate -run TestAsymmetryShipGate ./internal/core/usecase/ && \
	echo "--- windows/amd64 trust build-parity ---" && \
	GOOS=windows GOARCH=amd64 go build ./internal/core/trust/... && \
	echo "--- ci-parity: ALL CHECKS PASSED ---"

## ci-parity-windows-build: cross-compile internal/core/trust for windows/amd64 (compile-parity check only; no execution)
ci-parity-windows-build:
	@echo "--- ci-parity-windows-build: GOOS=windows GOARCH=amd64 go build ./internal/core/trust/... ---"
	GOOS=windows GOARCH=amd64 go build ./internal/core/trust/...
	@echo "--- ci-parity-windows-build: PASS ---"

## clean: remove build artifacts
clean:
	rm -rf $(BIN_DIR)
	go clean ./...

help:
	@grep -E '^## ' Makefile | sed 's/## //'
