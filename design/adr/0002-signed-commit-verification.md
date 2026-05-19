# ADR-0002 — Signed-commit verification: shell to `git verify-commit`

Status: Proposed · Date: 2026-05-19 · Owner: reis-principal-go
Encodes: T8 trust chain (verification leg), REQ-B-003, REQ-B-005.

## Decision

Use `go-git/go-git/v5` for **transport only** (clone/fetch the registry read-only). Perform
**commit signature verification by shelling to the system `git verify-commit` / `git
verify-tag`** (and parsing its exit code + status), against the client-pinned trusted signer
set (DESIGN §4.1). Verification runs in the `internal/adapter/registry` outer layer; core
only sees the domain result (`SourceVerified bool`, signer id) — no go-git or git-process
type crosses into core.

## Alternatives considered

- **go-git native signature verification.** Rejected: go-git's OpenPGP/SSH commit-signature
  support is limited and historically incomplete (PLAN §8/§12 risk row); relying on it for a
  fail-closed security boundary is unacceptable.
- **Pure-Go OpenPGP/SSH-sig verification (ProtonMail/x/crypto).** Rejected for v0.1: re-
  implements key-format/keyring/trust handling that system `git` + the user's existing
  allowed-signers/keyring already do correctly; large surface for a solo maintainer.
- **Skip verification, trust HTTPS only.** Rejected outright — violates T8/REQ-B-003
  (unsigned/invalid HEAD must block ADMIN promotion, fail closed).

## Consequences

- Hard dependency on a system `git` binary for the admin-promotion trust path. `doctor` MUST
  check `git` presence/version and report an actionable fix if absent; missing `git` →
  fail-closed (no admin promotion), contributor read of last-known-good cache may proceed.
- Verification is a subprocess: bounded timeout, context-cancellable, output never logged
  with secrets, exit-code-driven (no stdout scraping for trust decisions beyond documented
  status lines). Pinned-signer set (`trust.yaml`) is the allowed-signers source.
- Cleanly testable: the adapter is behind `RegistryClient`; unit tests inject a fake; an
  integration test exercises real `git verify-commit` against a fixture repo.
- Revisit if a robust audited pure-Go verifier matures (would remove the `git` dependency).
