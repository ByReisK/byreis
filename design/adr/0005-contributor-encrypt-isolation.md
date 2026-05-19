# ADR-0005 — Contributor-encrypt package isolation (reinforces the asymmetric guarantee)

Status: Proposed · Date: 2026-05-19 · Owner: reis-principal-go
Encodes: REQ-B-001, C (asymmetric guarantee), T4, T6; auditor INFO finding (reflection
guarantee) lifted to an architectural invariant; TM-D5 (closed-world allowlist isolation).

Consistent with DESIGN §1 (closed-world allowlist), §2.0 (`Recipient` no-identity-material
invariant), §4.3 (encrypt/Submit isolation backing T4), §7.2 row M1 (Phase 1/Phase 2
acceptance). Where DESIGN gives wording, this ADR mirrors it; DESIGN is normative.

## Decision

The contributor encrypt path is a dedicated package `internal/core/crypto/encrypt`,
public-key only. Its isolation from identity/private-key material is enforced as a
**CLOSED-WORLD ALLOWLIST**, not a denylist:

1. **Allowlist-subset CI gate (primary control).** The *full transitive* package
   dependency set of `internal/core/crypto/encrypt` **AND** of the
   **`internal/core/usecase/submit` sub-package** (the Submit compilation unit —
   **NOT** the whole `internal/core/usecase` package) (computed via `go list
   -deps`) MUST be a **subset of an explicitly enumerated allowlist**.
   `Decrypt`/`Edit`/`Merge` live in the parent `internal/core/usecase` package,
   **outside** the `submit` sub-package, and are therefore **off the Submit
   allowlist target by construction** — mirroring exactly the `rectypes`
   precedent: isolation is the package boundary, not prose. The package-scoped
   subset test cannot honour a "only the Submit symbols of `usecase`" qualifier,
   so the Submit spine is a dedicated compilation unit
   (`internal/core/usecase/submit`) precisely so the subset assertion enforces
   the rule mechanically. Any dependency present in the transitive set but **not** on the
   allowlist **fails the CI merge gate** and forces architectural review
   (reis-principal-go) before merge — a green test suite does not override this.
   The check is a set-subset assertion (`transitive ⊆ allowlist`), not a
   match against forbidden names. The assertion is **package-scoped**: it computes
   the full transitive set of each admitted package; it cannot honour a "only
   these symbols/value types" qualifier on an allowlist entry. Allowlist entries
   are therefore packages whose *own* transitive closure is itself a subset of
   the allowlist — never a package admitted with prose narrowing the symbols
   used.

2. **Initial allowlist for `internal/core/crypto/encrypt`** (the minimal set this
   package is permitted to reach transitively; derived from DESIGN §1 and §2.0):
   - `internal/core/crypto/manifest` — canonical encoding / `Manifest` domain
     type. Pure: bytes in, bytes out. No age.
   - `internal/core/registry/rectypes` — the **pure value-type sub-package** that
     exports **only** `Recipient` and `Fingerprint` (the public-key-only domain
     value types `crypto/encrypt` is permitted to import, per §2.0). It imports
     no `SignerKey`/`ed25519`/`CounterStore`/identity-bearing type; its **own**
     `transitive ⊆ allowlist` holds **without** `crypto/ed25519`, mirroring the
     existing shared-fingerprint-package precedent. Admission of `rectypes`
     remains conditional on the §2.0 / §7.2-M1 `Recipient` no-identity-material
     reflection invariant holding (see point 4); if `rectypes` ever acquires a
     transitive identity-bearing dependency, that propagates here and the gate
     fails by construction.

     The parent package `internal/core/registry` is **explicitly NOT on this
     allowlist.** It defines `SignerKey = ed25519.PublicKey`, `CounterStore`,
     and other identity/counter types, so the *whole* `registry` package
     transitively imports `crypto/ed25519` (and the identity-bearing graph) —
     which point 2's stdlib rule below explicitly does **not** admit. Admitting
     `registry` would pull `crypto/ed25519` into `crypto/encrypt`'s transitive
     graph and admit the private-key constructor, defeating the wedge. The prior
     "package `internal/core/registry` … **value types only**" allowlist entry is
     therefore **removed**: that "value types only" qualifier was
     judgement-dependent prose the package-scoped `transitive ⊆ allowlist` test
     **cannot mechanically enforce**, and it was internally contradictory with
     the `crypto/ed25519` exclusion below (the same allowlist forbids the very
     dependency the `registry`-as-a-whole entry transitively required). The
     value types are relocated into `rectypes` precisely so the subset test
     enforces the rule mechanically with zero prose.
   - `filippo.io/age` — **recipient-only surface**. The package may construct/use
     age *recipients* and `age.Encrypt`; it MUST NOT reach `age.Identity`,
     `age.X25519Identity`, or any age type that carries/returns private-key
     material. (This is enforced as a subset property: `internal/core/crypto/identity`
     and `internal/core/crypto/decrypt` are **not** on the allowlist, so any path
     that pulls age-identity material in via those packages fails the gate; the
     reflection test in point 4 is the defense-in-depth backstop for an age API
     that returns identity material under a differently-named type.)
   - A standard-library subset only: the packages required for public-key
     encryption and encoding — e.g. `io`, `bytes`, `errors`, `fmt`, `crypto/sha256`
     (shared fingerprint concept), and their unavoidable stdlib transitive closure.
     `crypto/ed25519`, `crypto/ecdh`/X25519 private-key constructors, and any
     stdlib path that yields private-key material are **not** admitted.
   - The **shared fingerprint package** (the pure package where `Fingerprint`
     derivation lives) — it holds **no private material** (see Consequences).

3. **Allowlist for the `internal/core/usecase/submit` sub-package.** This
   sub-package (NOT the parent `usecase`) depends on the above ports ONLY
   (DESIGN §1: `usecase/` "Depend on the above ports ONLY. No SDK imports"). Its
   permitted transitive set is the union of: the `crypto/encrypt` allowlist above
   (including `internal/core/registry/rectypes`, **not** the parent
   `internal/core/registry`), plus the consumer-defined port interfaces it
   orchestrates (`internal/core/git`, `internal/core/audit`,
   `internal/core/config` domain + port types — interface/domain types only, no
   adapter impls), plus the stdlib subset those require. `internal/core/crypto/identity`
   and `internal/core/crypto/decrypt` are **explicitly not on the `Submit` allowlist**;
   so `Submit` cannot, by construction, reach decrypt or identity material.

4. **`Recipient` carries no identity material — tested reflection invariant
   (Phase 1), not prose.** Mirroring DESIGN §2.0 / §7.2-M1: no field (exported or
   unexported) and no method reachable from a `rectypes.Recipient` value is
   assignable to or yields `age.Identity`, `age.X25519Identity`, an X25519/Ed25519
   *private* key, or a byte buffer typed/named as private-key material. This is a
   Phase 1 reflection-test invariant, **re-asserted on any change to `Recipient`**,
   kept as **defense-in-depth** alongside the allowlist gate (it checks reachable
   shape, not the transitive graph; the allowlist checks the graph, not in-type
   shape — neither subsumes the other).

5. **Authoritative gate is the Go test; the bash script is RETIRED.** The
   allowlist-subset assertion is implemented as a Go test
   (`TestAllowlist`, using `go list -deps` from within the test) and is the
   **single authoritative gate**. The prior bash script is **retired** (not kept
   as a parallel control — two gates that can disagree is itself a defect).
   `make check-allowlist` and the CI `allowlist` job MUST run exactly:
   `go test -run TestAllowlist ./internal/core/crypto/encrypt/
   ./internal/core/usecase/submit/`
   (note: the Submit target is the `internal/core/usecase/submit` **sub-package**,
   not the whole `internal/core/usecase`). **A gate that cannot run MUST FAIL
   loudly** — a missing/uncompilable test, a `go list` error, a skipped or
   absent job is a **FAIL**, never an `exit 0` / green / "no-op pass". A RED
   `allowlist` job is CHANGES REQUIRED and overrides an otherwise-green suite
   (`reis-principal-go` enforces).

This turns "a contributor process cannot decrypt and cannot write the live file"
from a runtime hope into a compile-time + import-graph property with a typed-shape
backstop.

Acceptance is pinned in DESIGN §7.2 row M1: the allowlist-subset Go test
(`TestAllowlist`) is a Phase 1 obligation for `crypto/encrypt` and a Phase 2
obligation for the `internal/core/usecase/submit` **sub-package** (NOT the whole
`internal/core/usecase`; `Decrypt`/`Edit`/`Merge` are off-target by construction);
the `Recipient` reflection invariant is a Phase 1 obligation re-run on `Recipient`
change. An injected unknown/identity-bearing dependency MUST fail the test; a gate
that cannot run is a FAIL, never a silent pass.

## Alternatives considered

- **Denylist of known identity package/type names** (the prior framing of this
  ADR: "forbidden from importing `crypto/identity`, `crypto/decrypt`,
  `age.Identity`/`age.X25519Identity`"). **Rejected as a DEFECT.** A denylist is
  bypassable by (a) any *new* identity-bearing package added later that nobody
  thought to add to the denylist, and (b) an age (or stdlib) API that returns
  identity / private-key material under a *different* type or name than the
  enumerated ones — the file would silently pass the gate while leaking identity
  reachability. A closed-world allowlist fails *closed* on the unknown: anything
  not explicitly admitted blocks the merge and forces review. (DESIGN §7.2-M1: "a
  denylist that would silently pass is itself a defect".)
- **Admit the whole `registry` package "for value types only" (prose-narrowed
  allowlist entry).** **Rejected (this revision).** The `transitive ⊆ allowlist`
  test is package-scoped and computes the *full* transitive closure of any
  admitted package; it cannot enforce a "only `Recipient`/`Fingerprint`"
  qualifier. Because `registry` defines `SignerKey = ed25519.PublicKey` /
  `CounterStore`, admitting it transitively admits `crypto/ed25519` — directly
  contradicting the stdlib-exclusion in point 2 and giving a BUILD engineer a
  footgun: making the gate green by adding `crypto/ed25519` to the allowlist
  would admit the private-key constructor into `crypto/encrypt`'s transitive
  graph and defeat the wedge. The value types are instead relocated into the
  pure sub-package `internal/core/registry/rectypes`, whose own transitive set
  excludes `crypto/ed25519` by construction, so the subset assertion enforces
  the rule mechanically with zero judgement-dependent prose.
- **Single `crypto` package, discipline-only.** Rejected: REQ-B-001 is a
  ship-blocking gate; a private key reachable in the same package is one
  accidental call from defeating the wedge. Discipline is not a control.
- **Runtime reflection check only (spike approach).** Kept as **defense in depth**
  (point 4), but insufficient alone: it checks reachable type shape from a
  `Recipient` value, not the whole transitive package reachability of
  `crypto/encrypt` / `Submit`. The closed-world allowlist-subset test is the
  primary control.
- **Interface-only separation without package separation.** Rejected: an
  interface in the same package still allows the concrete identity type to be
  imported and misused.

## Consequences

- `Submit` cannot, by construction, decrypt or touch identity material — the
  allowlist gate proves the transitive graph excludes `crypto/decrypt` /
  `crypto/identity`, directly supporting the REQ-B-001 machine-checkable proof and
  T4/T6.
- The public-key value types `Recipient`/`Fingerprint` live in
  `internal/core/registry/rectypes`; identity/counter types (`SignerKey =
  ed25519.PublicKey`, `CounterStore`, `AdminSet`, etc.) stay in the parent
  `internal/core/registry`. `crypto/encrypt` and the
  `internal/core/usecase/submit` sub-package import `rectypes` only; `internal/core/registry` (which transitively reaches
  `crypto/ed25519`) is off both allowlists. The split is structural, not prose:
  the package-scoped subset test now mechanically enforces the rule.
- Adds an architectural constraint the reviewer (reis-principal-go) enforces: any
  PR whose change makes the `crypto/encrypt` or the
  `internal/core/usecase/submit` sub-package transitive set include a
  package **not on the allowlist** is **CHANGES REQUIRED**, overriding a green
  suite. Admitting a new package to the allowlist is itself an explicit,
  reviewed architectural decision (amend this ADR), not an incidental import. In
  particular, "add `crypto/ed25519` (or `internal/core/registry`) to the
  allowlist to make the gate green" is a wedge-defeating change and is
  CHANGES REQUIRED on sight.
- **Allowlist admission rule (no judgement-dependent membership):** a package
  may be added to the allowlist only if it is (a) a pure/domain or port-interface
  package whose **own full transitive closure has no reach to private-key /
  identity material** (verified by the same package-scoped subset test applied to
  *it*), and (b) necessary for public-key encryption or submission orchestration.
  A package is admitted **as a whole package**; "admit package X but only its
  value types" is not a valid entry (the test cannot enforce it) — split the
  pure value types into their own sub-package instead, as done for `rectypes`.
  Convenience, logging-with-secrets risk, or "it's probably fine" are not
  admission grounds. When in doubt, the dependency is **not** admitted (fail
  closed).
- The mechanism is `go list -deps` driven from the **Go test `TestAllowlist`**
  (the single authoritative gate; the bash script is retired), used as an
  **allowlist-subset assertion** (`transitive ⊆ allowlist`) rather than a
  denylist name match. The test runs over `./internal/core/crypto/encrypt/` and
  the `./internal/core/usecase/submit/` **sub-package**. An un-runnable gate
  FAILS loudly (never exit 0).
- The reflection test is retained as **defense-in-depth** for the `Recipient`
  no-identity-material invariant and is re-asserted on any `Recipient` change
  (DESIGN §2.0, §7.2-M1).
- Minor cost: recipient/identity share a fingerprint concept — fingerprint
  derivation lives in a pure shared package (on the allowlist) that both can
  import and that holds **no private material**; the same precedent motivates the
  pure `rectypes` sub-package for the recipient/fingerprint value types.
