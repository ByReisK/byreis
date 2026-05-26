# Contributing to byreis

Thanks for your interest. byreis is an actively releasing project (v0.5.0 shipped);
stable releases are available and the core workflows are implemented end-to-end.

> **Please open an issue to discuss before sending a pull request.**
> This keeps effort focused and avoids wasted work where an in-progress design
> decision would otherwise conflict with a proposed change.

## Building and testing

Requires the latest stable Go toolchain (see `go.mod` for the pinned version).

```bash
# Build
make build          # produces ./bin/byreis

# Run all tests (race detector is enabled — a merge gate)
make test

# Run tests in a single package
go test ./internal/core/mode/

# Run a single test
go test ./internal/core/mode/ -run TestDetectMode

# Lint (golangci-lint must be installed)
make lint
```

`make test` runs `go test -race -timeout=120s ./...`. The race detector is a hard
merge gate; a test that passes only without `-race` is not acceptable.

Please run `make test` and `make lint` before submitting a pull request.

## Architecture

byreis uses a Clean Architecture layering that the linter mechanically enforces.
The key rules:

- `internal/core/` — all business logic. Zero imports of UI, network, SDK, or
  keychain packages. Interfaces are defined here, by the consumer.
- `internal/adapter/` — outward implementations of core-defined ports (GitHub,
  keychain, filesystem). Adapters depend inward; core never imports adapters.
- `internal/cli/`, `internal/tui/` — UI/orchestration layers. They consume core
  ports; they do not contain business logic.

**The import graph is the security boundary.** The depguard rules in
`.golangci.yml` enforce that the contributor (encrypt) path has no compile-time
route to private-key or decrypt capability. A depguard failure is an architecture
violation, not a style nit.

SDK and transport types are mapped to domain types at the adapter boundary and
never leak into core.

## Writing tests

- Write table-driven tests before (or alongside) implementation.
- Inject all external dependencies: clock, filesystem, network, keychain. No
  real network calls, real clocks, or real keychains in unit tests.
- Use `httptest` for GitHub API interactions.
- Add tests for timeout, retry, and partial-failure paths on I/O-heavy code.

## Pull requests

- One logical change per PR with a clear description.
- Tests and lint must pass; `-race` must be clean.
- Security-relevant changes (crypto paths, trust boundaries, audit) receive
  extra review time — expect this in the timeline.
- By contributing you agree your work is licensed under Apache-2.0.

## Code style

- `context.Context` is the first parameter on all I/O-bound functions.
- Errors wrapped with `%w` and an actionable hint the CLI can surface.
- No global mutable state, no `init()` side effects.
- Comments are professional and self-contained — no internal ticket IDs.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
