# Contributing to byreis

Thanks for your interest! byreis is in **active early development** and the
design direction is still consolidating, so:

> **Please open an issue to discuss before sending a pull request.**
> This avoids wasted work while interfaces and on-disk formats are still moving.

## Development

- Go: the latest stable toolchain (see `go.mod`).
- Build:  `make build`   (or `go build ./cmd/byreis`)
- Test:   `make test`    (race detector enabled)
- Lint:   `make lint`    (golangci-lint; the import/architecture rules are enforced)
- Single package: `go test ./internal/core/mode/`

Please run `make test` and `make lint` before pushing. Keep changes focused;
add table-driven tests for new behavior.

## Pull requests

- Branch from `main`; keep history clean and linear.
- One logical change per PR with a clear, conventional description.
- Tests and lint must pass; security-relevant changes get extra review.
- By contributing you agree your work is licensed under Apache-2.0.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
