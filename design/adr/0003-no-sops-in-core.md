# ADR-0003 — No SOPS dependency in core; `export --sops` is a v0.2 isolated one-way adapter

Status: Proposed · Date: 2026-05-19 · Owner: reis-principal-go
Encodes: C-8, dependency rule.

## Decision

`internal/core/**` has **zero** dependency on `getsops/sops` or any SOPS data-key/MAC code.
byreis's on-disk format is native age (Model B). The optional `byreis export --sops` is a
**v0.2**, admin-only, **one-way** adapter at `internal/adapter/sopsexport`, which depends on
core domain types and (if needed) the sops library, and is **never imported by core** (the
arrow points outward only).

## Alternatives considered

- **SOPS-compatible format (Model A).** Rejected at the SPIKE gate (audited): SOPS's
  symmetric data-key + whole-file MAC make a keyless contributor edit of a *shared* file
  cryptographically impossible — it contradicts the core promise (PLAN §1/§4).
- **Bidirectional sops import+export in core.** Rejected: pulls SOPS's symmetric model and
  its dependency surface into the security-critical core, exactly the contradiction Model B
  removed; bidirectional implies a re-key path that needs a private key.
- **No sops interop at all.** Acceptable for v0.1 (interop is explicitly not a v0.1
  requirement); the one-way export is a v0.2 convenience, not a guarantee.

## Consequences

- Core stays small and free of SOPS's symmetric assumptions; the asymmetric guarantee is not
  diluted.
- byreis files are not stock-`sops`-readable in v0.1 (documented; PLAN §1 repositioning
  "SOPS-inspired, age-native").
- `export --sops` is one-way and admin-only by construction (it decrypts, so it needs a
  private key — it can never be on the contributor path). Its package boundary is enforced by
  the dependency-rule import test.
