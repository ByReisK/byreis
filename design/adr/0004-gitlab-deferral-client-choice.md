# ADR-0004 — GitLab deferred to v0.2; client choice when added

Status: Proposed · Date: 2026-05-19 · Owner: reis-principal-go
Encodes: PLAN §8/§9 scope, GitProvider abstraction.

## Decision

v0.1 is **GitHub-only**. `GitProvider` is defined as a provider-agnostic domain interface in
`internal/core/git` (DESIGN §2.2) so a GitLab adapter is additive, not a refactor. When
GitLab is added (v0.2), use **`gitlab.com/gitlab-org/api/client-go`** (the official,
maintained client). `xanzy/go-gitlab` is **forbidden** (unmaintained, PLAN §8).

## Alternatives considered

- **Build GitLab in v0.1.** Rejected: doubles the integration/test surface for the spine
  with no differentiator gain; contradicts the locked minimal scope and solo-maintainer
  burnout risk (PLAN §12, REQUIREMENTS §1).
- **`xanzy/go-gitlab` when GitLab arrives.** Rejected: unmaintained; a security tool must
  prefer maintained/audited dependencies.
- **Generic git+REST hand-rolled, no provider SDK.** Rejected for now: PR creation/merge
  semantics differ enough per provider that a thin official SDK is lower-risk than
  hand-rolling auth + pagination + merge APIs.

## Consequences

- The GitHub adapter must not leak GitHub SDK types into `core/git` — the interface stays
  provider-neutral so the v0.2 GitLab adapter implements the same contract.
- A documented v0.1 limitation (GitHub-only) — acceptable per locked scope.
