# byreis — DESIGN (Phase D gate artifact)

Status: **PROPOSED — auditor FIX-BEFORE-BUILD closed (H-1, H-2, M-1, M-2, M-3); post-DESIGN assurance hardening applied (TM-D1/D3/D4/D5, QA-B1/C3/B2/D1/M6 + folded MEDIUM/LOW); pending focused re-review by `reis-threat-modeler` (TM-*) and `reis-qa-lead` (QA-*)** · Phase: DESIGN · Date: 2026-05-19
Owner: `reis-principal-go` (architecture / interface contracts / standards enforcer)
Upstream gates signed off: SPIKE ✅ (Model B native-age, audited) · ANALYSIS ✅ (15 reqs locked)
Downstream gate: BUILD may not start until this design is APPROVED **and** `reis-crypto-auditor`
confirms C-1…C-8 are encoded (PLAN §10 Phase D gate) **and** the post-DESIGN assurance
items (TM-* / QA-*) are confirmed closed by their respective reviewers.

Revision log (this iteration — only these sections changed; all others verbatim):
- **H-1** counter reconciliation re-specified: §2.1 (sentinels), §2.3 (store methods),
  §3.4 step 4, §4.2 steps 4a–6, + ADR-0006 rewritten.
- **H-2** AEAD-freshness binding clause: new §3.0, §4.2 step 3, + ADR-0001.
- **M-1** expected-recipient sourcing bound for ALL verify entry points: §2.1, §3.4, §4.3.
- **M-2** `format_version` charset constraint: §3.2 field 1, + ADR-0001.
- **M-3** `trust.yaml` perms hard error: §4.1.
- **L-1 / L-2** folded as carried BUILD test obligations: §7 (non-blocking).

Post-DESIGN assurance hardening (this iteration — threat-modeler + qa-lead FIX BEFORE BUILD;
NO crypto re-decision, both reviewers confirmed):
- **TM-D1** counter-authority sourcing as a binding type-shape constraint (mirrors M-1):
  §2.0, §2.1, §3.4 step 4, §4.2 step 4, §7.
- **TM-D3** artifact SHA preimage = exact untransformed bytes, zero normalization;
  unsigned→signed file-of-record SHA relationship: new §3.5, referenced from §2.2 /
  §3.4 step 4 / §4.4, + ADR-0006 step 4a/4b.
- **TM-D4** parent dir `~/.config/byreis/` promoted to HARD ERROR; TOCTOU-safe
  `O_NOFOLLOW`+`fstat`-on-fd trust-anchor read: §4.1, §7.
- **TM-D5** contributor-encrypt isolation reworded as a CLOSED-WORLD ALLOWLIST;
  `Recipient`-carries-no-identity-material as a tested invariant: §1, §4.3, ADR-0005, §7.
- **QA-B1** REQ-B-001 behavioral ship-gate suite designed as an enumerated, operationally
  red-blocks-ship §7 obligation: new §7.1.
- **QA-C3 / QA-B2 / QA-D1 / QA-M6** + folded MEDIUM/LOW (B3, C1, A3, L3, L4, A1, A2,
  M1, L2-adequacy) pinned as named §7 rows: new §7.2 row table.

Authoritative inputs: `PLAN.md` v2 (§4 crypto + C-1…C-8, §6 T1–T9, §9 scope, §10 roadmap,
§11 negative vectors), `design/REQUIREMENTS.md` (locked reqs + acceptance),
`design/FINDINGS.md` (Model B proof). The spike code is **reference only**; nothing is lifted
verbatim. The canonical-encoding *logic* is re-specified normatively in §3 below and
re-implemented fresh under TDD.

This document is **normative**. A TDD engineer must be able to implement against it without
making any further crypto decision. Where a number/order/separator is given, it is binding.

---

## 1. Package layout (Clean Architecture dependency rule — binding)

Dependencies point **inward only**. `internal/core/**` imports zero UI (cobra/bubbletea/lipgloss/
huh), zero SDK/transport (go-git, go-keyring, net/http client, GitHub API), zero `os`-side I/O for
network/clock/fs in unit-testable units. Interfaces are **defined by the consumer** (the inner
core package that needs the capability) and implemented by outer adapters. SDK/transport types
never cross into core — adapters map them to domain types at the boundary.

```
cmd/byreis/                         entry point only: wire cobra root, build adapters, inject
                                    into core, set exit code. ZERO business logic.

internal/cli/                       cobra commands. Thin: parse flags, call core use-cases,
                                    render via internal/cli/render. NO crypto, NO git, NO policy
                                    logic. Imports core + adapters constructors only.
internal/cli/render/                TTY/JSON/pipe output, masking, exit-code map (REQ-A-006).
internal/tui/                       (v0.2) bubbletea screens. Not in v0.1. UI only.

internal/core/                      ALL business logic. No UI/SDK/network imports anywhere below.

  internal/core/mode/               REQ-M-001 mode detection + command×mode policy matrix.
                                    Defines consumer interfaces: KeyProbe, RegistryTrust,
                                    Clock. NO age, NO ed25519 import here — it asks the
                                    encryption port "CanDecryptAny" via an injected interface.

  internal/core/crypto/encrypt/     CONTRIBUTOR ENCRYPT PATH. Public-key only.
                                    *** This package MUST NOT import internal/core/crypto/identity
                                        nor filippo.io/age Identity types, nor the parent
                                        internal/core/registry package (it transitively reaches
                                        crypto/ed25519 via SignerKey/CounterStore). It depends
                                        only on internal/core/registry/rectypes — the pure
                                        value-type sub-package (Recipient/Fingerprint, NO private
                                        material). Enforced by ADR-0005 CLOSED-WORLD ALLOWLIST + a
                                        reflection/import test (C, T4, auditor INFO; TM-D5). ***
  internal/core/crypto/identity/    Admin identity (age X25519 private key) + Ed25519 signer.
                                    Imported by decrypt/sign packages ONLY, never by encrypt.
  internal/core/crypto/manifest/    Canonical encoding (§3), Manifest domain type. No age.
                                    Pure: bytes in, bytes out. Imported by encrypt/verify/sign.
  internal/core/crypto/verify/      VerifyOfRecord / VerifySubmission (§2.1). Imports manifest,
                                    identity (for ed25519 PublicKey type only), age (decrypt
                                    round-trip is in decrypt, not here).
  internal/core/crypto/decrypt/     Admin decrypt + post-merge round-trip check. Imports
                                    identity + age. NEVER imported by encrypt or by cli's
                                    submit command path.
  internal/core/crypto/artifact/    On-disk artifact domain type + YAML (de)serialization.
                                    Serialization order is NOT the signing order (§3).

  internal/core/registry/           RegistryClient interface (consumer-defined here) + domain
                                    types: AdminSet, SignerKey (= ed25519.PublicKey), Project,
                                    Policy, CounterStore. Carries identity/counter types, so its
                                    OWN transitive set includes crypto/ed25519 — it is therefore
                                    OFF the crypto/encrypt + Submit ADR-0005 allowlist. NO go-git,
                                    NO http. Fetch/verify/cache impl lives in an adapter
                                    (internal/adapter/registry). Does NOT import
                                    crypto/verify (gap-4a removed: CounterAuthority/PendingBump
                                    moved to registry/countertypes; the old
                                    registry → crypto/verify edge no longer exists).
  internal/core/registry/rectypes/  PURE value-type sub-package: exports ONLY Recipient and
                                    Fingerprint (public-key-only, NO identity material). Imports
                                    no SignerKey/ed25519/CounterStore/identity-bearing type; its
                                    OWN transitive set is a subset of the allowlist WITHOUT
                                    crypto/ed25519 (mirrors the shared-fingerprint-package
                                    precedent). THIS is the only registry-side package on the
                                    crypto/encrypt + Submit allowlist (ADR-0005; TM-D5).
  internal/core/registry/countertypes/  PURE isolated sub-package: exports ONLY the opaque
                                    CounterAuthority + PendingBump value types and the
                                    ErrReplay / ErrCounterReconcile sentinels. Constructor is
                                    PACKAGE-PRIVATE (newCounterAuthority) — reachable ONLY by
                                    the registry adapter that produces the value from the
                                    signature-verified counter store; the SOLE producer is the
                                    registry port (TM-D1). `crypto/verify` may import this
                                    sub-package to READ fields / call Valid() but CANNOT
                                    construct a valid value (no exported constructor / no
                                    settable trust-bearing field — the §2.0 type-shape
                                    constraint, enforced at compile time, NOT prose).
                                    Imports no SignerKey/ed25519/identity-bearing type. This
                                    placement REMOVES the internal/core/registry →
                                    internal/core/crypto/verify import (gap 4a).
  internal/core/git/                GitProvider interface (consumer-defined) + domain types:
                                    PullRequest, Submission, ArtifactRef. NO GitHub SDK.
  internal/core/audit/              Append-only audit log port + domain events. No fs (port).
  internal/core/config/             Project/global config domain + load/validate (pure;
                                    fs behind a Filesystem port).
  internal/core/validator/          Value validation patterns (REQ-A-003 pre-commit check).
  internal/core/usecase/            Orchestration use-cases. Depend on the above ports
                                    ONLY. This is where the spine lives. No SDK imports.
                                    Decrypt/Edit/Merge/Get/Init/Doctor/Review live HERE,
                                    NOT in the submit sub-package below — so they are off
                                    the ADR-0005 Submit allowlist BY CONSTRUCTION (same
                                    rectypes-style structural wedge: identity-reaching
                                    use-cases are a different compilation unit).
  internal/core/usecase/submit/     THE Submit compilation unit (public-key-only spine).
                                    *** This sub-package — NOT the parent
                                        internal/core/usecase — is the ADR-0005 closed-world
                                        allowlist target for "Submit". Its full transitive
                                        dep set MUST be a subset of the ADR-0005 allowlist.
                                        Decrypt/Edit/Merge are NOT in this sub-package, so
                                        they cannot pull crypto/decrypt | crypto/identity
                                        into the Submit transitive graph (mirrors the
                                        rectypes precedent: isolation is the package
                                        boundary, not prose). Depends only on crypto/encrypt
                                        + the pure registry/rectypes + git/audit/config
                                        port + domain types. Enforced by the ADR-0005
                                        allowlist test + §7.2 M1 (TM-D5; REQ-B-001). ***

internal/adapter/                   OUTER layer. Implements core ports using real SDKs.
  internal/adapter/git/github/      GitProvider impl (go-github / REST). Maps SDK→domain.
  internal/adapter/registry/        RegistryClient impl: go-git transport + git verify-commit
                                    shell (ADR-0002) + offline cache + counter store.
  internal/adapter/keychain/        OAuth token store (go-keyring). Behind core/auth port.
  internal/adapter/fs/              Real filesystem + clock + randomness adapters.
  internal/adapter/sopsexport/      (v0.2) one-way export --sops. Isolated; NOT imported by
                                    core. See ADR-0003.

internal/auth/                      core port for OS keychain + OAuth (interface in core;
                                    impl in internal/adapter/keychain).

pkg/byreis/                         public API for external integrations. Re-exports stable
                                    domain types + a façade over usecase. NO `any` in
                                    signatures without written reason. Stable surface only.
```

**Why `crypto/encrypt` is isolated (C, T4, auditor INFO; TM-D5 — CLOSED-WORLD ALLOWLIST).**
The asymmetric guarantee (REQ-B-001) is only credible if the contributor encrypt path is
*structurally* incapable of touching a private key. We enforce this with the dependency
graph as a **closed-world allowlist**, not a denylist and not discipline:

- The full **transitive** dependency set of `internal/core/crypto/encrypt` AND of
  the `internal/core/usecase/submit` **sub-package** (the Submit compilation unit —
  NOT the whole `internal/core/usecase` package; `Decrypt`/`Edit`/`Merge` live in
  the parent `usecase` package and are therefore off this target by construction,
  mirroring the `rectypes` precedent) MUST be a
  **subset of an explicit allowlist** committed in `ADR-0005` and enforced by an
  automated test (`go list -deps`). The allowlist enumerates exactly the permitted
  packages (stdlib subset, `filippo.io/age` *recipient/encrypt* surface only,
  `crypto/manifest`, the pure `internal/core/registry/rectypes` value-type
  sub-package — **NOT** the parent `internal/core/registry`, which transitively
  reaches `crypto/ed25519` via `SignerKey`/`CounterStore` — `git` domain types).
  Allowlist entries are whole packages whose *own* transitive closure is itself a
  subset of the allowlist; a package is never admitted "for value types only"
  (the package-scoped subset test cannot enforce a symbol qualifier — that prose
  was removed, see ADR-0005 point 2). **Any package not on the allowlist —
  including a newly added dependency — fails the test and forces an explicit
  ADR-0005 amendment + re-review.** This is a closed world: the test
  does NOT enumerate forbidden identity package/type names (a denylist would silently
  pass a new identity-bearing import); it asserts membership in the allowlist and
  fails on anything unknown.
- `crypto/encrypt` depends on `crypto/manifest` (pure) and the pure
  `internal/core/registry/rectypes` sub-package, which exports only the `Recipient`
  / `Fingerprint` value types that carry **no identity material**. The parent
  `internal/core/registry` (with `SignerKey = ed25519.PublicKey` / `CounterStore`,
  hence transitively `crypto/ed25519`) is **not** on the allowlist, so the value
  types are placed in `rectypes` precisely so the package-scoped
  `transitive ⊆ allowlist` test enforces the rule mechanically. The no-identity
  property is additionally a **tested invariant** (TM-D5), not prose: a reflection
  test asserts that no field (exported or unexported) and no method reachable from
  `rectypes.Recipient` is assignable to / yields an `age.Identity`,
  `age.X25519Identity`, an Ed25519/X25519 private key, or any byte buffer typed as
  private key material. The invariant is re-asserted whenever `Recipient` changes
  (it is part of the Phase 1 `crypto/encrypt` acceptance, §7.2 M1).
- The `Submit` use-case composes `crypto/encrypt` + `registry` (recipients) + `git`.
  Its transitive import set is governed by the same allowlist; it does **not**
  import `crypto/decrypt` or `crypto/identity`, and the allowlist test (not a
  name-denylist) is what proves it.

This makes "a contributor process cannot decrypt" a compile-time + closed-world
import-graph property, re-inforcing the spike's reflection guarantee at the
architecture level.

**Dependency rule check (must hold at review; violation = CHANGES REQUIRED):**

- `go list -deps ./internal/core/...` contains no `spf13/cobra`, `charmbracelet/*`,
  `go-git`, `go-keyring`, `net/http` client, GitHub SDK.
- `go list -deps ./internal/core/crypto/encrypt` and `go list -deps
  ./internal/core/usecase/submit` (the Submit sub-package — NOT the whole
  `internal/core/usecase`) are each a **subset of the ADR-0005 allowlist** (closed-world;
  any unknown package = test failure = CHANGES REQUIRED), which in particular
  excludes `internal/core/crypto/identity`, `internal/core/crypto/decrypt`,
  `age.Identity`/`age.X25519Identity`, **`crypto/ed25519`, and the parent
  `internal/core/registry`** (the recipient/fingerprint value types are imported
  from `internal/core/registry/rectypes` only). Adding `crypto/ed25519` or
  `internal/core/registry` to the allowlist to turn the gate green is a
  wedge-defeating change = CHANGES REQUIRED on sight (ADR-0005).
- `internal/adapter/**` may import SDKs and core ports; core never imports `internal/adapter`.

---

## 2. Interface contracts

Conventions binding on every signature below:
- `context.Context` is the **first parameter** of every method that does I/O, crypto over
  large input, or could be cancelled. Cancellation/deadline honored.
- Errors are wrapped with `%w` and carry an **actionable hint** at the boundary. Core returns
  **sentinel/typed** errors; the CLI maps them to exit codes + fix text (REQ-A-006).
- No `any`/`interface{}` in these signatures.
- Interfaces are **small and role-based**, defined in the consuming core package.
- No panics in library code. Security paths **fail closed**.

### 2.0 Shared domain types (illustrative — exact fields finalized in BUILD)

```go
// package rectypes  (import path: internal/core/registry/rectypes)
// PURE value-type sub-package. Exports ONLY Recipient + Fingerprint.
// Imports NO SignerKey/ed25519/CounterStore/identity-bearing type, so its
// OWN transitive ⊆ allowlist holds WITHOUT crypto/ed25519. This is the only
// registry-side package on the crypto/encrypt + Submit ADR-0005 allowlist.
type Recipient struct {
    Label       string // diagnostics only, not security-relevant
    AgePubKey   string // "age1..." opaque to core
    Fingerprint Fingerprint // sha256(AgePubKey), full 32 bytes — C-7
}
type Fingerprint [32]byte             // C-7: full digest, never truncated

// package registry  (import path: internal/core/registry)
// Carries identity/counter types → its OWN transitive set includes
// crypto/ed25519 → it is OFF the crypto/encrypt + Submit allowlist.
// Does NOT import internal/core/crypto/verify (gap 4a removed): the opaque
// CounterAuthority/PendingBump live in internal/core/registry/countertypes.
import "internal/core/registry/rectypes"
import "internal/core/registry/countertypes" // opaque CounterAuthority (pkg-private ctor)
type SignerKey = ed25519.PublicKey    // registry commit-signer / manifest-signer pubkey
type AdminSet struct {
    ProjectID    string
    Recipients   []rectypes.Recipient // age recipients — encryption targets (C-4 source)
    SignerKeys   map[string]SignerKey // admin id -> Ed25519 manifest-signing pubkey
    SourceVerified bool        // true ONLY if commit-signature verified against pinned anchor
    FetchedAt    time.Time
    HeadCommit   string
}
```

`Fingerprint` is `[32]byte` (C-7). The spike's truncated `[:16]` is **forbidden**.

**`rectypes.Recipient` carries no identity material — tested invariant (TM-D5).**
`Recipient` is a public-key-only value type living in the **pure
`internal/core/registry/rectypes` sub-package** (the only registry-side package on the
ADR-0005 `crypto/encrypt` + `Submit` allowlist; the parent `internal/core/registry`,
which carries `SignerKey = ed25519.PublicKey` / `CounterStore` and therefore
transitively `crypto/ed25519`, is **off** that allowlist). The earlier "package
`registry` value types only" allowlist admission is removed — the package-scoped
`transitive ⊆ allowlist` test cannot enforce a "value types only" symbol qualifier and
that prose was internally contradictory with the `crypto/ed25519` exclusion; the value
types are relocated into `rectypes` so the subset assertion enforces the rule
mechanically (ADR-0005 point 2). No field (exported or unexported) and no method
reachable from a `Recipient` value is assignable to or yields `age.Identity`,
`age.X25519Identity`, an X25519/Ed25519 *private* key, or a byte buffer typed/named as
private-key material. This is a Phase 1 reflection-test invariant (§7.2 M1), re-asserted
on any change to `Recipient`, kept as defense-in-depth alongside the allowlist gate
(neither subsumes the other), not prose.

**Expected-recipient sourcing — single binding rule (C-4, M-1).** Every value of type
`[]rectypes.Recipient` (defined in the pure `internal/core/registry/rectypes`
sub-package — ADR-0005 point 2) that is used as an `Expected*Recipients` input to **any**
verify entry point (`VerifyOfRecord` *and* `VerifySubmission`) MUST originate from
an `AdminSet` returned by `FetchAdminSet` with `SourceVerified == true` (commit
signature verified against the client-pinned anchor) and within freshness policy.
The artifact's own `recipients:` block is **display-only** and is **explicitly
forbidden** as a source for `ExpectedRecipients` for *both* entry points — there is
no API path that takes recipients from the artifact and feeds them back as the
expected set. This is restated normatively at §3.4 and §4.3 and is a required
negative-test obligation (§7).

**Counter-authority sourcing — single binding rule (C-3, M-1-symmetric, TM-D1).**
Symmetric to the recipient rule above: every `CounterAuthority` value (and its
embedded `*PendingBump`) that is fed to `VerifyOfRecord` step 4 MUST originate from
a `RegistryClient.CounterAuthority` / store fetch whose backing `AdminSet`-equivalent
fetch is `SourceVerified == true` (the **same client-pinned anchor** as
`ExpectedRecipients`) and within freshness policy. This is a **type-shape
constraint, not prose**, mirroring exactly how M-1 closed recipient sourcing:

- `CounterAuthority` and `PendingBump` are **opaque value types defined in the
  pure isolated sub-package `internal/core/registry/countertypes`** (the established
  `rectypes`-style isolation). Their **only constructor is package-private**
  (`countertypes.newCounterAuthority`), reachable **only by the registry adapter**
  that produces the value from the signature-verified counter store + anti-rollback
  cache mirror. The SOLE producer is therefore the `registry` port's
  `CounterAuthority(ctx, project, file)` method (§2.3) — this is a **compile-time
  type-shape constraint, not prose** (the exact TM-D1 §2.0 wedge form).
- `internal/core/crypto/verify` **imports `countertypes` and CONSUMES the opaque
  value** (reads fields / calls `Valid()`); it **cannot construct a valid one** —
  there is no exported constructor and no settable trust-bearing field. The prior
  exported `verify.NewCounterAuthority` is **removed**. (This also removes the
  `internal/core/registry → internal/core/crypto/verify` import — gap 4a.)
- There is **no exported constructor, struct-literal entry point, or API path** by
  which `mode`, `verify`, a use-case, the project repo, the artifact, or an
  unverified/stale cache can synthesize a `CounterAuthority`/`PendingBump` and feed
  it to `VerifyOfRecord`. The value is carried opaque from the registry port to
  step 4.
- Disallowed-by-construction (compile/API-shape, not a runtime string check) and a
  required §7 negative test (§7.2 D1): a `CounterAuthority` constructed from the
  artifact's claimed counter, from the project repo, or from an unverified/stale
  cache cannot satisfy the `VerifyOfRecord` signature flow — it is uncompilable,
  because no caller outside the registry adapter can reach the constructor.

### 2.1 Encryptor — split, NO nil-key downgrade (C-1)

Defined in `internal/core/crypto/verify` (the consumer of verification) and
`internal/core/crypto/encrypt` (the consumer of encryption). They are deliberately **separate
interfaces** so the submit path can depend on `Encryptor` without ever seeing a verify/identity
type.

```go
// package encrypt  — PUBLIC-KEY ONLY. No identity import allowed (ADR-0005 allowlist).
// Imports internal/core/registry/rectypes (pure value types), NOT the parent
// internal/core/registry (which transitively reaches crypto/ed25519).

// Encryptor builds an UNSIGNED contributor artifact from plaintext values using
// only recipient public keys. It can never sign and never decrypt.
type Encryptor interface {
    // Encrypt produces an unsigned artifact: each value is an independent
    // multi-recipient age ciphertext to ALL recipients from a FRESH age.Encrypt
    // (AEAD-freshness, §3.0), plus the digest-committed manifest WITHOUT a
    // signature. counter is the value the caller intends to claim; authority
    // over acceptance is the registry (C-3) — this method does not validate it.
    //
    // recipients MUST be non-empty (encrypting to nobody is a hard error,
    // hint: "registry returned zero admin recipients") and MUST be C-4-sourced
    // (SourceVerified registry; never artifact/repo/stale).
    // Returns ErrNoRecipients, or a wrapped age error with a hint.
    Encrypt(ctx context.Context, in EncryptInput) (artifact.Unsigned, error)
}
type EncryptInput struct {
    ProjectID       string                 // C-2 bound into manifest
    LogicalFileName string                 // C-2 bound into manifest
    Counter         uint64                 // claimed; registry decides (C-3)
    Recipients      []rectypes.Recipient   // C-4 source = verified registry only; pure registry/rectypes (ADR-0005)
    Values          map[string]string      // key name -> plaintext
}
```

```go
// package verify — VERIFICATION. Two entry points; NO nil-key path (C-1).
// Imports internal/core/registry/countertypes to CONSUME the opaque
// CounterAuthority (read fields / call Valid()); it CANNOT construct one
// (no exported ctor — verify.NewCounterAuthority was removed). It does NOT
// import the parent internal/core/registry.

// VerifierOfRecord checks a SIGNED file-of-record for any live read / CI
// decrypt / deploy. Signature is MANDATORY. The trusted Ed25519 key MUST be
// present; if it cannot be acquired (offline, cache miss, parse error) this is
// a HARD ERROR — never a downgrade to unsigned (T9, C-1).
type VerifierOfRecord interface {
    VerifyOfRecord(ctx context.Context, in OfRecordInput) error
}
type OfRecordInput struct {
    Artifact            artifact.Signed
    ExpectedProjectID   string                 // C-2 — caller's identity for this file
    ExpectedFileName    string                 // C-2
    ExpectedRecipients  []rectypes.Recipient   // C-4/M-1 — SourceVerified registry ONLY; pure registry/rectypes
    TrustedSigners      map[string]ed25519.PublicKey // C-1 — required, non-empty
    Counter             countertypes.CounterAuthority // C-3/TM-D1 — opaque; sole producer = registry port; verify cannot construct
}
// package countertypes  (import path: internal/core/registry/countertypes)
// PURE ISOLATED sub-package — the established rectypes-style wedge for the counter
// authority. CounterAuthority/PendingBump are the two-record view from the
// signature-verified registry counter store (ADR-0006). The ONLY constructor is
// PACKAGE-PRIVATE (newCounterAuthority) and is reachable ONLY by the registry
// adapter; the sole producer is the registry port (TM-D1). verify imports this
// sub-package, reads fields / calls Valid(), and CANNOT construct a valid value
// — there is no exported constructor and no settable trust-bearing field. This
// is a compile-time type-shape constraint, NOT prose. (Removing the type from
// verify also removes the registry → crypto/verify import — gap 4a.)
type CounterAuthority struct {
    lastAccepted uint64        // unexported: set only by newCounterAuthority
    pending      *PendingBump  // unexported: nil if no merge in flight
}
// Valid reports whether this value was produced by the registry adapter via the
// package-private constructor (a zero-value / struct-literal CounterAuthority is
// NOT Valid). VerifyOfRecord step 4 hard-errors on a non-Valid value.
func (c CounterAuthority) Valid() bool          // { ... }
func (c CounterAuthority) LastAccepted() uint64 // { ... }  read-only accessor
func (c CounterAuthority) Pending() *PendingBump // { ... } read-only accessor
type PendingBump struct {
    PendingCounter    uint64
    TargetArtifactSHA string // full content SHA the admin recorded write-ahead (§3.5)
    TargetPR          string
}
// newCounterAuthority is PACKAGE-PRIVATE: only internal/adapter/registry (the
// counter-store reader) can call it, after signature-verified store + anti-rollback
// cache checks. There is deliberately NO exported constructor (the removed
// verify.NewCounterAuthority). This is the TM-D1 §2.0 type-shape wedge.
//   func newCounterAuthority(lastAccepted uint64, pending *PendingBump) CounterAuthority

// VerifierOfSubmission performs a STRUCTURAL-ONLY check of an UNSIGNED
// contributor submission. It returns an explicit Unverified result. Its output
// MAY NEVER gate a prod decrypt/deploy. There is no key parameter and no
// "treat as trusted" branch.
type VerifierOfSubmission interface {
    VerifySubmission(ctx context.Context, in SubmissionInput) (SubmissionResult, error)
}
type SubmissionInput struct {
    Artifact           artifact.Unsigned
    ExpectedProjectID  string
    ExpectedFileName   string
    // ExpectedRecipients is structural-equality only, but is STILL bound by the
    // C-4/M-1 sourcing rule: it MUST come from a SourceVerified registry fetch.
    // Feeding artifact-self-declared recipients here is disallowed by
    // construction (§2.0, §4.3) and is a required negative test (§7).
    ExpectedRecipients []rectypes.Recipient
}
type SubmissionResult struct {
    State      VerificationState // always Unverified for submissions
    KeyNames   []string          // key names present (NOT secret) — for ADD/REPLACE
    Reason     string
}
type VerificationState int
const (
    StateUnverified VerificationState = iota // structural-only; never trust-equivalent
    StateOfRecord                              // signed + fully verified
)
```

**Hard rules encoded here (C-1, T9, M-1, TM-D1):**
- `VerifyOfRecord` has **no** parameter that, when nil/empty, skips the signature. If
  `TrustedSigners` is empty → `ErrNoTrustedSigner` (hard error). If `Artifact` is unsigned →
  `ErrUnsigned` (hard error). If signature invalid → `ErrSignatureInvalid`.
- `VerifyOfRecord`'s `Counter` (`countertypes.CounterAuthority`) parameter has **no
  nil/zero-value path that skips step 4 or fabricates authority**: it is an opaque
  type whose only constructor is package-private to `countertypes` and reachable
  only by the registry adapter (§2.0 TM-D1, §2.3) from a `SourceVerified` fetch. A
  zero-value / struct-literal value is **not `Valid()`** and step 4 hard-errors on
  it. A caller cannot satisfy the flow with an artifact/repo/stale-cache-derived
  counter authority — there is no exported constructor to even compile one.
- `VerifySubmission` **cannot** return `StateOfRecord`. There is no code path from a submission
  to a "trusted" result. A required negative test (§7/C-6) characterizes exactly what it does
  NOT catch (it does not, and cannot, prove authenticity — only structure & recipient-set
  shape).
- For **both** entry points, `ExpectedRecipients` MUST be C-4/M-1-sourced
  (`SourceVerified` registry). Artifact-sourced recipients fed to either entry
  point is disallowed by construction and is a required negative test (§7).
- The single `VerifyArtifact(verifyKey)` with a `nil`-means-skip branch from the spike is
  **explicitly forbidden** in `internal/`.

**Sentinel ownership rule (binding — no junk-drawer errors package; no
cross-package aliasing).** Each shared sentinel is defined **exactly once, in its
semantic owner package**; other packages **import and reference the canonical
symbol** — `Err = otherpkg.Err` re-alias vars are **forbidden** (a junk-drawer
`errors` package is **explicitly rejected**). Specifically:

- `ErrReplay`, `ErrCounterReconcile` → defined in
  `internal/core/registry/countertypes` (the counter authority is their semantic
  owner; they travel with the opaque `CounterAuthority` type). `verify` and
  `registry` reference `countertypes.ErrReplay` / `countertypes.ErrCounterReconcile`
  directly — no local alias.
- `ErrNoTrustedSigner` → defined in `internal/core/crypto/verify` (its semantic
  owner: trusted-signer resolution at verify). The registry boundary (L-1) returns
  `verify.ErrNoTrustedSigner` by reference — no `registry.ErrNoTrustedSigner` alias.
- The remaining `verify`/`encrypt` sentinels below stay in their consuming package.

```go
// package countertypes (internal/core/registry/countertypes) — counter authority owner
var (
    ErrReplay            = errors.New("artifact counter is not strictly greater than last accepted (replayed/old file)") // C-3
    ErrCounterReconcile  = errors.New("counter authority requires manual reconciliation (no matching write-ahead/committed bump)") // C-3/H-1 — terminal, NOT auto-heal
)

// package verify / package encrypt — wrappable with %w
var (
    ErrNoRecipients      = errors.New("refusing to encrypt to zero recipients")           // package encrypt
    ErrFormatVersion     = errors.New("unsupported or malformed artifact format version") // M-2
    ErrManifestMismatch  = errors.New("manifest does not match artifact contents")
    ErrIdentityMismatch  = errors.New("artifact project/file identity does not match expected") // C-2
    ErrRecipientMismatch = errors.New("artifact recipient set does not match the verified registry") // C-4
    ErrUnsigned          = errors.New("file-of-record is unsigned") // C-1
    ErrNoTrustedSigner   = errors.New("no trusted manifest signer key available") // C-1/T9/L-1 — verify owns; registry references by import (no alias)
    ErrSignatureInvalid  = errors.New("manifest signature verification failed")
    ErrDecrypt           = errors.New("no available identity could decrypt the value")
)
// verify references countertypes.ErrReplay / countertypes.ErrCounterReconcile
// (the §3.4 step-4 decision returns the countertypes-owned sentinels directly).
```

`ErrReplay` and `ErrCounterReconcile` are **mutually exclusive and both fail
closed**. `ErrReplay` = the signed counter is `<` committed authority (an old /
replayed file). `ErrCounterReconcile` = the counter authority's own integrity is in
question (signed counter claims `last+1` with **no matching write-ahead intent and
no committed bump**, or skips ahead of authority, or a different artifact than the
recorded intent claims the pending slot). The exhaustive decision table is in
ADR-0006 and is restated at §3.4 step 4. `ErrCounterReconcile` is **terminal and
manual** — there is no automatic heal; the tool refuses to serve/deploy the file
and prints the reconciliation runbook hint.

### 2.2 GitProvider — GitHub-only v0.1 (consumer-defined in `internal/core/git`)

```go
// package git — domain interface. NO GitHub SDK type appears here.

type GitProvider interface {
    // OpenSubmissionPR creates branch + commit of the unsigned artifact and
    // opens a PR. Returns the PR and the FULL artifact content SHA actually
    // pushed (ArtifactSHA, §3.5 preimage) — the pin anchor for review/merge
    // (T1/T2).
    OpenSubmissionPR(ctx context.Context, in OpenPRInput) (PullRequest, error)

    // GetSubmission fetches the artifact bytes + PR metadata for review. It
    // returns the artifact content SHA (§3.5: sha256 over the EXACT untransformed
    // fetched bytes, zero normalization) so review can pin EXACTLY these bytes.
    GetSubmission(ctx context.Context, ref PRRef) (Submission, error)

    // MergeSubmission writes the SIGNED file-of-record to the protected
    // secrets path and merges, ONLY if the live artifact SHA still equals
    // expectSHA (T2). Fails closed with ErrArtifactMoved otherwise.
    MergeSubmission(ctx context.Context, in MergeInput) (MergeResult, error)

    CommentPR(ctx context.Context, ref PRRef, body string) error
}

type PRRef          struct { Project string; Number int }
type ArtifactSHA    string // §3.5: sha256 over exactly the artifact file bytes, no normalization
type PullRequest    struct { Ref PRRef; URL string; Branch string; ArtifactSHA ArtifactSHA }
type Submission     struct {
    Ref          PRRef
    Author       string
    Justification string
    ArtifactBytes []byte
    ArtifactSHA  ArtifactSHA
    BaseFileBytes []byte // current live file (may be empty for first add)
}
type OpenPRInput struct {
    Project       string
    Branch        string // byreis/<add|replace>-<key>-<ts>
    Action        SubmitAction // Add | Replace (REQ-C-003 — labels branch/PR)
    Key           string
    ArtifactBytes []byte
    TitleTemplate string
    Justification string
}
type MergeInput struct {
    Ref           PRRef
    ExpectSHA     ArtifactSHA // T2 — fail closed if moved
    SignedBytes   []byte      // the file-of-record (signed manifest) to commit
    CommitMessage string
}
type MergeResult struct { MergedCommit string; LiveFileSHA string }
```

`ErrArtifactMoved` (sentinel) is returned by `MergeSubmission` when the on-PR artifact SHA no
longer equals `ExpectSHA` (T1/T2). All `ArtifactSHA` values follow the §3.5 preimage rule.
GitLab is out of scope (ADR-0004).

### 2.3 RegistryClient — fetch + signed-commit verify + offline cache + counter authority

```go
// package registry — consumer-defined. NO go-git / net/http here.

type RegistryClient interface {
    // FetchAdminSet returns the admin recipient + signer set for a project.
    // It MUST verify the registry HEAD commit signature against the
    // client-pinned trusted signer set (§4 / ADR-0002) before returning data
    // with SourceVerified=true. On signature failure it returns
    // ErrUnsignedRegistry (hard error for admin promotion; contributor read of
    // last-known-good cache may still proceed per REQ-B-003).
    // On network failure it falls back to cache and sets Stale + StaleReason
    // (REQ-C-004), NEVER silently granting admin from an expired cache.
    //
    // L-1: every Ed25519 key parsed into SignerKeys / TrustedSigners is
    // length-validated to exactly 32 bytes AT THIS BOUNDARY. A wrong-length
    // entry yields ErrNoTrustedSigner (the signer is unusable / absent), NOT a
    // confusing ErrSignatureInvalid raised later at verify time.
    FetchAdminSet(ctx context.Context, projectID string) (AdminSet, error)

    // VerifyRegistryFreshness enforces anti-rollback (REQ-B-004, C-3): the
    // fetched HEAD must be a fast-forward of the last-observed HEAD. A
    // regressed/non-ancestor HEAD returns ErrRegistryRollback.
    VerifyRegistryFreshness(ctx context.Context, projectID string) error

    // CounterAuthority returns the per-(project,file) two-record anti-replay
    // view {last_accepted_counter, pending} from the registry/audit store —
    // the SOLE authority (C-3, TM-D1, ADR-0006). The returned value is the opaque
    // countertypes.CounterAuthority constructed via the PACKAGE-PRIVATE
    // countertypes.newCounterAuthority — callable ONLY by the registry adapter
    // implementing this port. It is bound to the SAME client-pinned anchor as
    // FetchAdminSet (signature-verified store + anti-rollback cache mirror) and is
    // monotonic + integrity-checked in cache (anti-rollback offline). It is the
    // ONLY producer of countertypes.CounterAuthority/PendingBump values fed to
    // VerifyOfRecord step 4; verify can read but NOT construct one — no exported
    // constructor exists (TM-D1; the removed verify.NewCounterAuthority). pending
    // is nil if no merge is in flight.
    CounterAuthority(ctx context.Context, projectID, fileName string) (countertypes.CounterAuthority, error)

    // RecordPendingBump WRITE-AHEAD records merge intent (pending_counter +
    // target_artifact_sha + target_pr) as a SIGNED commit in the admin registry
    // repo BEFORE the secrets-repo merge (ADR-0006 step 2). target_artifact_sha
    // follows the §3.5 preimage rule (exact signed file-of-record bytes the admin
    // is about to push). It is idempotent: a re-call with the SAME
    // pending_counter AND SAME target_artifact_sha is a safe resume; any other
    // mismatch against an existing pending returns ErrCounterReconcile
    // (terminal, manual).
    RecordPendingBump(ctx context.Context, in PendingBumpInput) error

    // CommitBump finalizes: sets last_accepted_counter = pending_counter and
    // CLEARS pending in a SINGLE signed registry commit, AFTER the secrets
    // merge has landed (ADR-0006 step 5). It MUST be atomic (advance+clear
    // together). pendingCounter MUST equal the open pending's pending_counter
    // or it returns ErrCounterReconcile and the caller does NOT proceed.
    CommitBump(ctx context.Context, in CommitBumpInput) error
}

type PendingBumpInput struct {
    ProjectID         string
    FileName          string
    PendingCounter    uint64 // == last_accepted_counter + 1
    TargetArtifactSHA string // §3.5: full content SHA of the exact signed bytes
    TargetPR          string
}
type CommitBumpInput struct {
    ProjectID      string
    FileName       string
    PendingCounter uint64 // must match the open pending
    PRRef          string // audit linkage
}
```

Sentinel errors: `ErrUnsignedRegistry`, `ErrRegistryRollback`, `ErrRegistryOffline`
(carries cache age), `ErrCacheTampered` are **owned by `registry`**. The registry
boundary additionally returns, **by reference to the canonical owner (no local
alias var)**: `countertypes.ErrCounterReconcile` (terminal/manual, ADR-0006 — owned
by `internal/core/registry/countertypes`) and `verify.ErrNoTrustedSigner` (owned by
`internal/core/crypto/verify`; raised here at the L-1 boundary for a wrong-length
signer key). All wrap with `%w` + hint. (No junk-drawer errors package; no
`registry.ErrCounterReconcile = countertypes.ErrCounterReconcile` re-alias.)

`AdminSet.SourceVerified` is the ONLY thing `mode` and `merge` may trust for promotion / for
`expectedRecipients` (C-4/M-1) **and** the same anchor that binds `CounterAuthority` (TM-D1).
A cache-only `AdminSet` has `Stale=true`; mode policy refuses ADMIN promotion off a stale set
(REQ-C-004 / conflict C4) — it does not silently downgrade trust.

---

## 3. Normative spec — signed manifest canonical encoding

This is the **single source of truth** for the bytes Ed25519 signs. It re-specifies the spike
logic normatively with the C-2/C-3/C-7 additions. The on-disk YAML serialization order is
**irrelevant** to and **independent of** this encoding: map iteration order MUST NEVER reach
the signer (the encoder sorts internally).

### 3.0 AEAD freshness — binding clause (auditor H-2)

This clause is binding on the encrypt path, the C-4 re-encrypt-at-merge path, and
the signing model:

1. Each secret value is an **independent multi-recipient `age` ciphertext** from a
   **fresh `age.Encrypt`** to the verified recipient set. No shared data key, no
   whole-file MAC (PLAN §4, Model B).
2. **Re-encryption at merge (the C-4 stale-recipient path, §4.2 step 3) MUST
   regenerate EVERY value's ciphertext** from plaintext to the *current
   signature-verified recipient set* via fresh `age.Encrypt`. It MUST NOT splice,
   re-wrap, copy, or carry forward any prior ciphertext blob — not even for values
   whose recipient set appears unchanged. Re-encrypt is whole-file or not at all.
3. **Ciphertext reuse across counter generations is forbidden.** A new
   file-of-record (new `counter`) is signed only over ciphertext freshly produced
   for that generation. Carrying a prior generation's ciphertext under a new
   counter is a defect (the per-key digest binds `name‖ct` but not freshness, so a
   stale or attacker-influenced blob would still verify structurally and ride the
   fresh admin signature).

This is restated at §4.2 step 3 and is a required **negative**-test obligation in
§7 (a re-encrypt that reuses any prior ciphertext byte, and a re-sign that reuses a
prior generation's ciphertext under a bumped counter, must both be caught).

### 3.1 Separators

- `RS = 0x1e` (record separator) — between elements of a list / between sub-fields of a record.
- `US = 0x1f` (unit separator) — between top-level fields.

These bytes are control characters and cannot occur in age-armored ciphertext, hex digests,
fingerprints, format-version, project/file ids (all are restricted to printable ASCII; the
encoder MUST reject any key name / id / format_version containing `0x1e` or `0x1f` — ids and
key names with `ErrManifestMismatch`, a malformed `format_version` with `ErrFormatVersion`,
see §3.2 field 1).

### 3.2 Field order (fixed, signature excluded)

The canonical byte stream is the concatenation, in **exactly** this order:

```
1.  format_version            (UTF-8 string, CONSTRAINED — see below)  US
2.  registry_project_id       (UTF-8 string)            ── C-2        US
3.  logical_file_name         (UTF-8 string)            ── C-2        US
4.  counter                   (8 bytes, big-endian uint64) ── C-3     US
5.  for each key in SORTED(key_names):                   ── sorted
        key_name              (UTF-8)                                 RS
        per_key_digest_hex    (lowercase hex of sha256(  RS
                               key_name_bytes ‖ 0x00 ‖ ciphertext ))
        (after the last key) ......................................   US
6.  for each fp in SORTED(recipient_fingerprints):       ── sorted
        fingerprint_hex       (64 lowercase hex chars =  RS
                               full 32-byte sha256(age_pubkey)) ── C-7
        (after the last fp) — no trailing US (end of stream)
```

Binding details:

- **Field 1 `format_version` charset (auditor M-2)**: `format_version` MUST match
  the fixed regex `^byreis\.native\.v[0-9]+$` (e.g. `byreis.native.v1`). It is
  **not** free-form. It is routed through the **same `0x1e`/`0x1f` control-char
  rejection** as ids and key names *before* it reaches the encoder. A
  `format_version` that fails the regex or contains a separator byte is rejected
  with `ErrFormatVersion` **before any byte is emitted**, so the separator-injection
  safety claim holds for *every* signed field, including the first. (Without this,
  an unconstrained first field could embed a `US` byte and shift the framing of
  every subsequent signed field.)
- **Sort order**: `sort.Strings` byte-wise ascending on the UTF-8 key name (field 5) and on the
  lowercase-hex fingerprint string (field 6). Sorting is performed by the encoder over a copy;
  the input map's iteration order is never observed by the signer (defeats reorder, T7).
- **Counter** (field 4) is the monotonic anti-replay value. Its *authority* is the registry/
  audit store two-record view (`last_accepted` + `pending`, C-3, §4.2, ADR-0006) — the encoder
  merely binds whatever counter the signed file claims so a replayed old file is detected
  against the registry authority (the §3.4 step-4 decision table).
- **C-2 binding**: `registry_project_id` and `logical_file_name` are fields 2 and 3, signed.
  An artifact signed for `(projX, prod)` presented as `(projY, prod)` or `(projX, staging)`
  fails `ErrIdentityMismatch` *before* signature check (verify compares the caller's expected
  identity to the signed fields). **Required negative vector**: artifact signed for file X
  rejected as file Y, and project X rejected as project Y.
- **C-7 fingerprint**: `fingerprint = sha256(age_recipient_pubkey_string_bytes)`, the **full
  32 bytes**, lower-hex (64 chars). The spike's `[:16]` truncation is forbidden.
- **Per-key digest binds ciphertext to key NAME** (defeats ciphertext-swap): the digest is
  `sha256( key_name_bytes ‖ 0x00 ‖ ciphertext_bytes )`, not `sha256(ciphertext)` alone. The
  `0x00` domain separator prevents `name‖ct` ambiguity. Swapping two values' ciphertexts
  changes both digests → `ErrManifestMismatch`. (Note: the digest binds ciphertext to name,
  NOT freshness — freshness is enforced separately by §3.0.)
- **Signature excluded**: the Ed25519 signature is computed over the byte stream above and is
  NOT part of it. Verification recomputes the stream from the artifact and checks
  `ed25519.Verify(signerPub, stream, sig)`.

### 3.3 Who signs, when, over what

- A **contributor submission is unsigned** (no private key — inherent). It carries the full
  manifest (all digests, recipient set, counter, C-2 ids) but `manifest_sig` is absent.
  `VerifySubmission` validates structure only (`StateUnverified`).
- The **admin signs at merge** (`byreis merge`), over **the exact reviewed bytes**: `review`
  emits the pinned artifact SHA; `merge --expect <sha>` refuses if the on-PR artifact moved
  (T1/T2). The admin recomputes the canonical stream from the pinned artifact (after any C-4
  re-encryption to the current verified recipient set — a FRESH whole-file re-encrypt per
  §3.0), signs with the admin's registry-attested Ed25519 key, and that signed manifest is the
  **file-of-record**. The signed file-of-record's content SHA (§3.5) is the SHA the next
  reader pins; §3.5 defines how `pending.target_artifact_sha` is recomputed/recorded at sign
  so that reader pin still holds.
- Signature algorithm: **Ed25519** (`crypto/ed25519`, stdlib). Public key is the admin's
  `ed25519_signer` from the signature-verified registry (`admins.yaml`), length-validated to
  32 bytes at the registry boundary (L-1). `manifest_sig.signer` is the admin id;
  `VerifyOfRecord` looks the id up in `TrustedSigners` (sourced from verified registry) and
  verifies against that key — never a key embedded in the artifact.

### 3.4 Verification order (fail-closed, every step hard error)

`VerifyOfRecord` MUST execute and short-circuit in this exact order:

```
1. format_version matches ^byreis\.native\.v[0-9]+$ and is
   supported, and contains no 0x1e/0x1f               else ErrFormatVersion (M-2)
2. manifest.format_version == artifact.format_version, counters agree
                                                  else ErrManifestMismatch
3. project_id == expected AND file == expected (C-2)
                                                  else ErrIdentityMismatch
4. counter decision vs registry CounterAuthority (C-3, TM-D1, ADR-0006 table):
     PRECONDITION (TM-D1): the countertypes.CounterAuthority value used here
     MUST have been produced by RegistryClient.CounterAuthority (via the
     package-private countertypes.newCounterAuthority — no exported ctor; verify
     cannot construct one) from a SourceVerified store
     fetch (same anchor as ExpectedRecipients) — there is NO API path feeding a
     project-repo / artifact / unverified-or-stale-cache-derived authority into
     this step (enforced by §2.0/§2.3 type-shape, required §7.2 D1 negative test).
     let sc = signed counter, la = LastAccepted, P = Pending (nil-able)
     - sc <  la                                   → ErrReplay
     - sc == la  (steady-state live read of the committed file) → continue
     - sc == la+1 AND P!=nil AND P.PendingCounter==sc
         AND P.TargetArtifactSHA == content_sha(artifact)   [content_sha per §3.5]
                                                  → continue (legit in-flight;
            caller (merge resume / first read) MUST drive CommitBump, §4.2 step 5)
     - sc == la+1 AND P!=nil AND P.PendingCounter==sc
         AND P.TargetArtifactSHA != content_sha(artifact)   [content_sha per §3.5]
                                                  → ErrCounterReconcile
     - sc == la+1 AND (P==nil OR P.PendingCounter!=sc)
                                                  → ErrCounterReconcile
            (the previously-undetectable "merged-but-unbumped / forged-advance,
             intent lost" state — terminal, manual, NOT auto-heal)
     - sc >  la+1                                  → ErrCounterReconcile (gap)
5. artifact key-set == manifest sorted_keys       else ErrManifestMismatch
6. each per-key digest recomputed == manifest     else ErrManifestMismatch
7. artifact/manifest recipient fp set == ExpectedRecipients, where
   ExpectedRecipients is C-4/M-1-sourced (SourceVerified registry ONLY,
   never the artifact/repo/stale cache)           else ErrRecipientMismatch
8. manifest is signed                             else ErrUnsigned   (C-1)
9. signer id resolvable in TrustedSigners (each entry length-validated
   to 32 bytes at the registry boundary, L-1)     else ErrNoTrustedSigner (C-1/T9/L-1)
10. Ed25519 verify over canonical stream          else ErrSignatureInvalid
```

`content_sha(artifact)` at step 4 is the §3.5 preimage (sha256 over the exact
untransformed artifact file bytes, zero normalization). `VerifySubmission` runs
steps 1–3, 5–7 only, returns `StateUnverified`, and **never** runs 4 and 8–10 and
**never** returns a trusted state. Step 4 (counter) is informational for a
submission (the registry decides at merge), not a gate. **Step 7 binds for
`VerifySubmission` too**: its `ExpectedRecipients` MUST be C-4/M-1-sourced
(SourceVerified registry); feeding artifact-self-declared recipients into
`VerifySubmission` is disallowed by construction (§2.0, §2.1, §4.3) — required
negative test (§7).

There is no step that, on a nil/empty input, *skips* 8–10. Missing trusted signer at step 9 is
terminal (T9/C-1). The step-4 `ErrReplay` vs `ErrCounterReconcile` outcomes are distinguishable
and both fail closed; `ErrCounterReconcile` is never auto-healed (ADR-0006). The step-4
`CounterAuthority` cannot originate from the artifact/repo/unverified-stale cache (TM-D1).

### 3.5 Artifact content SHA — preimage definition (TM-D3)

This clause is normative and is referenced by §2.2 (`ArtifactSHA`), §3.4 step 4
(`content_sha(artifact)`), §4.2 step 4a/4b, §4.4, and ADR-0006 step 4a/4b.

1. **`ArtifactSHA` / `content_sha(x)` = `sha256` over the EXACT, UNTRANSFORMED byte
   sequence of the artifact file** as it was fetched from / will be pushed to git.
   **ZERO normalization**: no YAML re-parse or re-serialize, no key reordering, no
   CRLF↔LF translation, no leading/trailing whitespace trimming, no Unicode
   normalization, no re-indentation. The hash input is the literal file bytes. Two
   files that "mean the same YAML" but differ by one byte have different SHAs by
   design (this is what makes the T1/T2 pin meaningful).
2. **The SHA is computed once over the raw byte buffer at the boundary** (git fetch,
   git push, on-disk read) and carried as an opaque `ArtifactSHA`. Core never
   recomputes it from a re-marshalled domain object — only from the original byte
   slice it was given. Adapters MUST NOT canonicalize before hashing.
3. **Unsigned → signed file-of-record SHA relationship (binding).** Signing changes
   the file bytes: the unsigned contributor artifact (SHA = `S_unsigned`, what the
   contributor pushed and the reviewer pins via `--expect`) becomes the signed
   file-of-record (SHA = `S_signed`) once the admin's Ed25519 `manifest_sig` is
   serialized into it (and after any C-4 fresh whole-file re-encrypt, §3.0/§4.2
   step 3, which itself changes the bytes). These are **two distinct SHAs over two
   distinct byte sequences**:
   - `review`/`--expect` pins `S_unsigned` (T2: the reviewed contributor bytes).
   - At sign time, the admin produces the signed bytes and computes `S_signed`
     over those exact bytes (§3.5.1). **`pending.target_artifact_sha` is
     `S_signed`** — the SHA of the bytes that will actually be committed as the
     file-of-record and that the *next reader* pins at §3.4 step 4. It is recorded
     write-ahead in §4.2 step 4a / ADR-0006 step 4a so the post-merge reader's
     `content_sha(file) == pending.target_artifact_sha` check holds against the
     committed signed file (not the pre-sign unsigned bytes).
   - Therefore §4.2 step 4a records the **post-sign** `S_signed`, and step 4b
     re-records it if a C-4 re-encrypt occurred after the initial write-ahead (the
     recorded intent always equals the bytes that get signed and committed). This
     resolves the apparent paradox "signing changes the bytes the next reader
     pins": the reader pins `S_signed`, which is exactly what is recorded.
4. **Required negative-test obligations (§7.2 D3):** (i) a one-byte change
   (whitespace / CRLF / key reorder via re-serialize) to an otherwise-equivalent
   artifact yields a *different* `ArtifactSHA` and is rejected by `--expect`/step 4;
   (ii) a reader pinning `S_unsigned` against the committed `S_signed`
   file-of-record does NOT spuriously pass — it is the recorded `S_signed` that
   step 4 matches; (iii) any adapter path that re-marshals before hashing is a
   defect (asserted by hashing-the-raw-buffer test).

---

## 4. Trust & authority design

### 4.1 The pinned trust anchor (T8 — registry cannot vouch for itself)

The set of trusted **registry commit-signer** keys is pinned **outside the registry**, in
client bootstrap config (`~/.config/byreis/trust.yaml`). Resolution chain (PLAN §2):

```
client-pinned signer set ──verifies──▶ registry HEAD commit signature
registry admins.yaml     ──attests──▶ admin → {age recipient pubkey, Ed25519 signer pubkey}
admin Ed25519 signer key ──verifies──▶ file-of-record manifest signature
```

Every "is X trusted?" terminates at the **client-pinned** anchor, never at the registry.

**`trust.yaml` AND its parent dir permissions are a HARD ERROR if too permissive
(auditor M-3; TM-D4 — parent dir promoted from SHOULD to HARD ERROR).** The pinned
trust anchor file is exactly as security-critical as the admin private key, so it
mirrors the PLAN §3 / §5.3 `identity/admin.key` 0600 rule, and its containing
directory is treated identically:

- **File `trust.yaml`**: required regular file, owned by the invoking user, mode
  **`0600`** (`0400` also acceptable — read-only is stricter, still allowed), not a
  symlink. Any bit in `0077` set, or a symlink, or wrong owner → byreis **refuses
  to run** any command that consults trust (every command except `version`) with a
  hard error printing the **exact fix**, e.g.:
  `trust anchor ~/.config/byreis/trust.yaml has insecure permissions 0644; run: chmod 600 ~/.config/byreis/trust.yaml`
  (the printed mode/path are the actual observed values).
- **Parent directory `~/.config/byreis/` (TM-D4 — HARD ERROR, was "SHOULD 0700"):**
  required to be a real directory (not a symlink), owned by the invoking user, mode
  **`0700`** (no bit in `0077` set). If it is group/world-accessible, a symlink, or
  not owned by the invoking user, byreis **refuses to run** (same fail-closed
  treatment as the file and the admin key) with the exact fix, e.g.:
  `byreis config dir ~/.config/byreis has insecure permissions 0755; run: chmod 700 ~/.config/byreis`
  (printed mode/path are the actual observed values). The prior "SHOULD be `0700`"
  language and the §7 *WARN* line for parent-dir perms are **superseded and
  removed**; it is a **FAIL**.
- **TOCTOU-safe read (TM-D4):** the trust anchor (and the parent-dir check) MUST be
  performed on a file descriptor, never via stat-path-then-open-path:
  1. `open(parent_dir, O_NOFOLLOW|O_DIRECTORY)`; `fstat` that fd; enforce
     owner+mode (`0700`, no `0077`) **on the fd**; use `openat` relative to that
     dir fd for the file.
  2. `open(trust.yaml, O_NOFOLLOW)`; `fstat` the returned fd; enforce owner+mode
     (`0600`/`0400`, no `0077`, regular file) **on that same fd**; then read **the
     same fd**. Never `os.Stat(path)` then `os.Open(path)` (a symlink/file swap
     between the two calls would defeat the check). `O_NOFOLLOW` rejects a symlink
     at the final component; the fstat-on-fd binds the security decision to the
     exact object subsequently read.
- **`doctor` check obligation**: `byreis doctor` MUST explicitly report the
  `trust.yaml` ownership + mode **and the parent-dir ownership + mode** and surface
  the same chmod hint as a **FAIL line** (not a warning) when either is too
  permissive — mirroring the existing admin-key-perms doctor check (REQ-A-002).
  Negative-test obligations in §7 (§7.2 D4): symlink-swap-after-check (file and
  dir), and dir-writable-then-replace, both must be caught fail-closed.

This is fail-closed: an unreadable-because-too-strict file is allowed; a
too-permissive file *or directory* is never silently tolerated.

**Bootstrap (REQ-B-005, no silent TOFU):** on first `init` against an unknown registry, byreis
displays the commit-signer key fingerprint and **requires explicit operator confirmation**
(typed fingerprint match or `--accept-signer <fp>`), then pins it to `trust.yaml` written with
mode `0600` (and the parent dir created `0700` if absent). An existing pin is never silently
replaced; a different signer is `ErrSignerChanged` (hard, manual re-pin).
`--non-interactive` requires `--accept-signer <fp>` or fails closed (REQ-A-001/B-005).

### 4.2 Counter authority & write-ahead transactional bump (C-3, T3, auditor H-1)

- `last_accepted_counter` is stored **per-(project, file)** in the **registry/audit store** —
  NOT in the project repo. Project-repo-sourced counters are forbidden as an authority (they
  are display-only copies; verify compares them but never trusts the repo's value). The
  `countertypes.CounterAuthority` value handed to `VerifyOfRecord` step 4 is produced
  **only** by the registry port via the package-private
  `countertypes.newCounterAuthority` from a `SourceVerified` fetch (TM-D1,
  §2.0/§2.3) — no exported constructor exists, so no other producer can compile.
- Store shape (ADR-0006, revised): the signed/append-only
  `counters/<project>/<file>.json` committed in the **admin registry repo** holds
  **two** records — `last_accepted_counter` (the committed authority) **and** a
  nullable `pending` write-ahead intent `{pending_counter, target_artifact_sha,
  target_pr, intent_at}`. Both inherit the registry's signed-commit integrity and
  the pinned-anchor trust chain. The cache mirror is monotonic + integrity-checked:
  a cached `last_accepted_counter` that regresses vs the last observed is
  `ErrCacheTampered` (anti-rollback offline, C-3/REQ-B-004). `pending` is **never**
  authority for acceptance — only `last_accepted_counter` is.
- **Write-ahead transactional bump at merge** — `Merge` use-case sequence is strictly
  ordered; each step is a hard gate (this corrects the prior non-implementable
  "detect-on-next-verify-as-ErrReplay" claim, auditor H-1):

  1. `review` pinned SHA confirmed (`--expect`, T2; `S_unsigned` per §3.5) — else
     abort, live file untouched.
  2. Fresh signature-verified registry fetch; recompute `expectedRecipients`
     (C-4/M-1, SourceVerified only).
  3. If submission's recipient set ≠ current verified set → **re-encrypt at merge**
     to the current set: a **FRESH whole-file `age.Encrypt`** of every value from
     plaintext (§3.0 — no ciphertext spliced or carried forward); submission
     against a stale admin set is re-encrypted, not accepted. The re-encrypt
     produces a new deterministic-shape artifact whose content SHA the admin
     re-pins and re-confirms (§4.4 — never signs blindly).
  4. `auth := CounterAuthority(project,file)` — produced ONLY by the registry port
     from a `SourceVerified` fetch (TM-D1; never repo/artifact/stale);
     `next := auth.LastAccepted + 1`.
  4a. **WRITE-AHEAD (registry-side signed commit, BEFORE the secrets merge):**
     the admin first produces the signed file-of-record bytes (Ed25519 sign, step
     4b conceptually, over the pinned post-step-3 artifact) and computes
     `S_signed = content_sha(signed bytes)` per §3.5; then
     `RecordPendingBump{pending_counter=next, target_artifact_sha=S_signed,
     target_pr}`. `target_artifact_sha` is the **post-sign** SHA (§3.5.3) — exactly
     the bytes the next reader pins at §3.4 step 4. Must be durable before 5.
     If an existing `pending` matches (same counter + same `S_signed`) → resume;
     any other mismatch → `ErrCounterReconcile` (terminal, manual, abort —
     live file untouched).
  4b. The canonical-bytes build + Ed25519-sign producing those signed bytes is the
     operation whose output `S_signed` was recorded in 4a. (If step 3's C-4
     re-encrypt changed the artifact after an earlier write-ahead, 4a is
     re-recorded with the new `S_signed` before merge so recorded intent always
     equals the signed bytes — §3.5.3.)
  5. `MergeSubmission(--expect sha, SignedBytes)` → writes protected `secrets/**`
     + merges (fails closed `ErrArtifactMoved` if SHA moved, T2). On failure the
     write-ahead `pending` is **left in place** (matching pending makes a retry a
     safe resume, not a reconcile).
  6. **COMMIT-BUMP (registry-side signed commit, only AFTER the merge lands):**
     `CommitBump{pending_counter=next}` — sets `last_accepted_counter = next` AND
     **clears `pending` in the SAME atomic registry commit**. If `CommitBump`
     cannot be durably committed, the merge is **not final**: re-running `merge`
     resumes from the matching `pending` and completes the bump; it never re-signs
     a new counter while a matching `pending` is open. The "merged-but-unbumped"
     window is now **detected and distinguished** at verify §3.4 step 4: a file
     whose SHA matches the still-present `pending.target_artifact_sha` (=`S_signed`,
     §3.5) verifies OK (and the caller drives `CommitBump`); a `last+1` file with
     **no matching pending/committed bump** is `ErrCounterReconcile` (terminal,
     manual) — it is **never** silently accepted and **never** auto-healed. A
     **read-only `VerifyOfRecord` caller in this `sc==la+1` crash window MUST NOT
     write `CommitBump` and MUST NOT synthesize a pending** (L3, §7.2): only the
     `merge` resume path (or an explicit admin action) drives `CommitBump`, and
     only against a pre-existing matching signed `pending`.
  7. Post-merge mandatory integrity check: live file MUST `VerifyOfRecord` and
     round-trip decrypt for **every** current recipient; failure surfaces loudly
     with a reconciliation hint (the live file is committed by now — this is an
     **alarm**, not a silent pass) (REQ-B-002 / REQ-C-001). This is the
     **post-merge** failure window (QA-B2 row (b)); it is distinct from the
     **pre-merge** structural-invalid abort (step 1 / REQ-B-002 / REQ-C-001),
     which leaves the live file UNTOUCHED (QA-B2 row (a)).

### 4.3 expectedRecipients sourcing — bound for ALL verify entry points (C-4, T4, M-1)

`ExpectedRecipients` is sourced **only** from a `FetchAdminSet` result with
`SourceVerified == true` and within freshness policy. This binds **every verify
entry point** — `VerifyOfRecord` *and* `VerifySubmission` (auditor M-1) — and the
encrypt path's `Recipients`. **Never**:
- from the artifact's own `recipients:` block (that block is **display-only** and
  is **explicitly forbidden** as a source for `VerifySubmission` as well as
  `VerifyOfRecord` — there is no API path that takes recipients from the artifact
  and feeds them back as the expected set),
- from the project repo,
- from a stale/expired cache that could retain a revoked admin or drop an active one.

The symmetric counter-authority sourcing rule (TM-D1, §2.0) binds the **same
client-pinned anchor** for `CounterAuthority` as for `ExpectedRecipients`: both come
only from a `SourceVerified` registry fetch; neither has an artifact/repo/stale-cache
API path.

The contributor-encrypt isolation that backs T4 is enforced as a **closed-world
allowlist** (TM-D5, §1, ADR-0005): the transitive package set of `crypto/encrypt`
and of the `Submit` use-case is a subset of an explicit allowlist (any new dep =
review), NOT a denylist of identity names. The recipient/fingerprint value types
are imported from the pure `internal/core/registry/rectypes` sub-package only; the
parent `internal/core/registry` (transitively `crypto/ed25519` via
`SignerKey`/`CounterStore`) is **off** the allowlist, so the package-scoped subset
test enforces the rule mechanically with no "value types only" prose. The
`rectypes.Recipient` value carrying no identity material is a **tested reflection
invariant** (§2.0, §7.2 M1), kept as defense-in-depth.

A submission whose recipient set differs from the current verified set is **re-encrypted at
merge** (§4.2 step 3, a fresh whole-file re-encrypt per §3.0), never accepted as-is. A
contributor adding an attacker pubkey (T4) is caught: the artifact's recipient set ≠ verified
registry set → `ErrRecipientMismatch`, and the re-encrypt step would in any case re-target
only the verified set. **Required negative test (§7): `VerifySubmission` fed artifact-sourced
recipients is disallowed by construction** (no caller can satisfy the type/flow that takes the
artifact's `recipients:` and passes it as `ExpectedRecipients`), and symmetrically a
`VerifyOfRecord` fed an artifact/repo-sourced `CounterAuthority` is disallowed by construction
(TM-D1, §7.2 D1).

### 4.4 Review → merge pinned artifact (T1/T2)

- `byreis review --pr N`: ADMIN-only (mode-gated). Decrypts submitted value(s), renders
  plaintext + key + env + author + justification + ADD/REPLACE + validation. Emits a **pinned
  full-artifact SHA** = `content_sha` (§3.5) of exactly the bytes shown (`S_unsigned`).
- `byreis merge --pr N --expect <sha>`: `MergeSubmission` fails closed with `ErrArtifactMoved`
  if the on-PR artifact SHA ≠ `<sha>` (branch re-push between review and sign — T2). The admin
  signs only the pinned bytes (post C-4 fresh re-encryption, §3.0, which produces a new
  artifact whose SHA the admin re-pins and re-confirms — never signs blindly). The signed
  file-of-record's SHA is `S_signed` (§3.5); it is what is recorded write-ahead in §4.2 step
  4a and what the next reader pins at §3.4 step 4 (§3.5.3).
- The admin **never** approves from the PR diff/description (T1) — `review` always decrypts
  from the artifact bytes and shows plaintext; merge always operates on the pinned SHA.

### 4.5 Registry cache anti-rollback (REQ-B-004)

Cache stores `{HEAD, last_observed_HEAD, fetched_at, cached_last_accepted, cached_pending}`
with an integrity tag. `VerifyRegistryFreshness`: a fetched HEAD that is not a fast-forward
descendant of `last_observed_HEAD` → `ErrRegistryRollback` (refuse for admin promotion, warn).
Tampering the local cache to fake freshness must not grant admin: the cache integrity tag + the
monotonic `last_accepted_counter` mirror make a rollback detectable; expired/cannot-verify →
contributor (REQ-C-004), never silent admin. A regressed cached `last_accepted_counter` →
`ErrCacheTampered`. The cached counter mirror, like the live store, is a `SourceVerified`-bound
producer of `CounterAuthority` (TM-D1) and is anti-rollback integrity-checked; a stale cache
withholds ADMIN promotion (REQ-B-003) but its integrity-checked counter mirror may still serve
a contributor read.

---

## 5. ADRs

Full text in `design/adr/`. Summary:

- **ADR-0001** — Manifest canonical encoding & Ed25519 signing model (this §3, normative);
  now also carries the AEAD-freshness clause (H-2) and the `format_version` charset
  constraint (M-2).
- **ADR-0002** — Signed-commit verification: shell to `git verify-commit` (go-git for
  transport only). Decision/alternatives/consequences.
- **ADR-0003** — No SOPS dependency in core (C-8); `export --sops` is a v0.2 isolated one-way
  adapter (`internal/adapter/sopsexport`), never imported by core.
- **ADR-0004** — GitLab deferral; when added use `gitlab.com/gitlab-org/api/client-go`, not
  unmaintained `xanzy/go-gitlab`.
- **ADR-0005** — Contributor-encrypt package isolation: **CLOSED-WORLD ALLOWLIST**
  (transitive dep set of `crypto/encrypt` and of the **`internal/core/usecase/submit`
  sub-package** — NOT the whole `usecase` package — ⊆ explicit allowlist; any new
  dep forces review) + the `Recipient`-carries-no-identity-material tested
  reflection invariant (TM-D5; reinforces C/T4/REQ-B-001). The authoritative gate is
  the **Go allowlist test** (`go test -run TestAllowlist`); the bash script is
  retired; a gate that cannot run FAILS loudly (never exit 0).
- **ADR-0006** — Counter/audit store shape (two-record signed file in the admin registry
  repo: `last_accepted_counter` + write-ahead `pending`) + **write-ahead transactional
  bump-at-merge** with a distinct terminal `ErrCounterReconcile` (C-3/T3, rewritten to
  close auditor H-1); `target_artifact_sha` is the §3.5 `S_signed` preimage (TM-D3).
  Also: `CounterAuthority`/`PendingBump` + `ErrReplay`/`ErrCounterReconcile` live in
  the pure isolated `internal/core/registry/countertypes` with a **package-private
  constructor** (sole producer = registry adapter; `verify` consumes opaque, cannot
  construct — removes the `registry → crypto/verify` import, gap 4a). This is a
  **TM-D1 security-relevant change requiring `reis-crypto-auditor` sign-off before
  B0 closes — NOT self-certified.**

---

## 6. Traceability matrix (C-1…C-8, T1–T9) — auditor re-review target

| ID | Requirement / constraint | Where encoded in this DESIGN |
|----|--------------------------|------------------------------|
| **C-1** | Two verify entry points; no nil-key downgrade; file-of-record always admin-signed; offline-without-trusted-key = hard error | §2.1 (`VerifyOfRecord` mandatory sig, `TrustedSigners` required; `VerifySubmission` cannot return trusted; spike single-verify forbidden); §3.4 steps 8–10 + "no skip" rule; `ErrUnsigned`/`ErrNoTrustedSigner` |
| **C-2** | Bind project_id + logical_file_name into signed bytes; X-as-Y rejected | §3.2 fields 2 & 3; §3.4 step 3 `ErrIdentityMismatch`; required negative vector in §3.2 / §7 |
| **C-3** | Anti-replay counter authority in registry/audit, per-(project,file), **write-ahead** transactional bump, distinct terminal `ErrCounterReconcile` vs `ErrReplay`, cache monotonic+integrity, no repo-sourced authority, **authority value sourced ONLY from SourceVerified registry port; opaque type in `registry/countertypes` with package-private ctor — `verify` consumes, cannot construct (TM-D1)** | §2.0 (TM-D1 counter-authority sourcing type-shape rule → `countertypes` pkg-private ctor); §2.1 (`countertypes.CounterAuthority`/`PendingBump`, `Valid()`, no nil-skip; `ErrReplay`/`ErrCounterReconcile` owned by `countertypes`); §2.3 (`CounterAuthority` returns `countertypes.CounterAuthority`/`RecordPendingBump`/`CommitBump`); §3.2 field 4; §3.4 step 4 decision table + TM-D1 precondition; §4.2 (two-record store + write-ahead sequence 4a–6); §4.5; **ADR-0006 (rewritten — H-1; + countertypes ctor/sentinel ownership, pending `reis-crypto-auditor`)** |
| **C-4** | expectedRecipients only from signature-verified registry, for ALL verify entry points; stale submission re-encrypted (fresh whole-file) at merge | §2.0 single sourcing rule; §2.1 (`SourceVerified`, both entry points bound); §4.3 (M-1, VerifySubmission forbidden artifact-sourced); §4.2 step 3 (fresh re-encrypt, §3.0); §3.4 step 7 `ErrRecipientMismatch` |
| **C-5** | Threat model rewritten incl. pending-submission tamper + git-history rollback + honest caveat | Encoded against PLAN §6 (kept intact); T-row mapping below; honest git-history caveat carried (PLAN §6 "does NOT protect") — DESIGN adds no claim beyond it |
| **C-6** | Full negative-vector set incl. explicit "what VerifySubmission does NOT catch" | §7 test obligations enumerate every PLAN §11 vector and bind them to delegated units; §7.2 named-row table; §2.1 mandates the VerifySubmission-negative characterization test |
| **C-7** | Full 32-byte recipient fingerprint (not truncated 16) | §2.0 `Fingerprint [32]byte`; §3.2 field 6 (64 hex chars, full sha256); spike `[:16]` explicitly forbidden |
| **C-8** | No SOPS in core; optional admin-only one-way export | §1 (`internal/adapter/sopsexport` isolated, not imported by core); ADR-0003 |
| **H-2 (AEAD freshness)** | Every value a fresh independent ciphertext; re-encrypt regenerates all; no ciphertext reuse across counter generations | **§3.0** (binding clause); §2.1 `Encrypt` doc; §3.3 / §4.2 step 3 (fresh whole-file re-encrypt); §4.4; ADR-0001; §7 negative tests |
| **TM-D3 (artifact SHA preimage)** | `ArtifactSHA`/`content_sha` = sha256 over exact untransformed bytes, zero normalization; unsigned→signed `S_signed` recorded so reader pin holds | **§3.5** (normative); §2.2 (`ArtifactSHA` doc); §3.4 step 4 (`content_sha` per §3.5); §4.2 step 4a/4b (records `S_signed`); §4.4; ADR-0006 step 4a/4b; §7.2 D3 |
| **TM-D5 (encrypt isolation = allowlist)** | Closed-world allowlist for `crypto/encrypt` + the `internal/core/usecase/submit` **sub-package** (NOT whole `usecase`) transitive deps; `Recipient` no-identity-material tested invariant; Go test is the authoritative gate | §1 (allowlist, not denylist; Submit target = `usecase/submit` sub-package; `Decrypt`/`Edit`/`Merge` off-target by construction; recipient value types via pure `registry/rectypes`, parent `registry` off allowlist); §2.0 (`rectypes.Recipient` invariant + type placement); §4.3; ADR-0005 point 2/3 (no "value types only" prose; submit sub-package target; Go-test gate, bash retired); §7.2 M1 |
| **T1** | Author-spoof / opaque-diff merge | §4.4 (review decrypts from artifact bytes, never PR diff/description); §2.2 `GetSubmission` returns artifact bytes |
| **T2** | TOCTOU branch re-push between review and sign | §2.2 `MergeSubmission` `ExpectSHA` + `ErrArtifactMoved`; §3.5 (SHA preimage); §4.4; §3.3 + §4.2 4a/4b (sign only pinned bytes; recorded intent == signed bytes `S_signed`) |
| **T3** | Rollback/resurrection | §4.2 write-ahead counter authority + §3.4 step-4 decision table (distinct `ErrCounterReconcile`); §2.0/§2.3 TM-D1 sourcing; §4.5 registry anti-rollback; ADR-0006 |
| **T4** | Recipient-set injection (contributor adds attacker pubkey) | §4.3 (M-1, both entry points); §3.4 step 7; §4.2 step 3 fresh re-encrypt to verified set only; §1 closed-world allowlist via pure `registry/rectypes`, Submit target = `usecase/submit` sub-package (TM-D5) |
| **T6** | Sabotage/DoS overwrite/delete live file | §1 (contributor path never writes live file — `crypto/encrypt` allowlist isolation via pure `registry/rectypes` + the `internal/core/usecase/submit` sub-package import set; `Decrypt`/`Edit`/`Merge` are a different compilation unit, off the Submit allowlist by construction; parent `registry`/`crypto/ed25519` off allowlist); §4.2 step 5 (write only via admin-merged commit); branch-protection documented prereq (PLAN §6) + `doctor` check (§7); §7.2 C3 (no contributor command writes/truncates live secrets file) |
| **T7** | Structural tamper of signed file (reorder/delete/swap/strip) | §3.2 sorted keys + per-key-name-bound digest + recipient-set field; §3.2 field-1 charset (M-2 — every signed field separator-safe); §3.4 steps 5–7 |
| **T8** | Trust-root circularity | §4.1 pinned anchor outside registry; §4.1 `trust.yaml` + parent-dir perms hard error (M-3/TM-D4) + TOCTOU-safe fd read + doctor FAIL; §4.1 bootstrap no silent TOFU |
| **T9** | nil-verify-key downgrade | §2.1 (no nil branch, no nil-counter-authority skip); §3.4 "no skip" rule; `ErrNoTrustedSigner`; ADR-0001 |
| **L-1** | Trusted-signer entries length-validated to 32 bytes at the registry boundary → `ErrNoTrustedSigner` (not `ErrSignatureInvalid`) | §2.3 `FetchAdminSet` L-1 note; §3.3; §3.4 step 9; §7 carried test obligation |
| **L-2** | Identity-key zeroization | §7.2 L2 carried BUILD test obligation (GC/escape-analysis-resistant pass criterion) |
| **REQ-M-001** | Crypto-derived mode | §1 `internal/core/mode`; promotion needs `SourceVerified` + fresh/within-TTL (§2.3, §4.5); §7.2 M6 (command×mode matrix + bypass list) |
| **REQ-B-001** | Provable asymmetric guarantee (ship gate) | §1 encrypt-path closed-world allowlist (recipient value types via pure `registry/rectypes`; parent `registry`/`crypto/ed25519` off allowlist) + the `internal/core/usecase/submit` sub-package import-set Go test (NOT whole `usecase`; bash retired; un-runnable gate FAILS loud) (TM-D5); **§7.1 enumerated behavioral ship-gate suite (QA-B1, red-blocks-ship)** |
| **REQ-B-003/4** | Registry client fetch/verify/cache/rollback | §2.3, §4.5; §7.2 B3 (asymmetric branch: unsigned HEAD blocks ADMIN, contributor cache read proceeds) |
| **REQ-C-001** | Concurrent-submission safety | §2.2 (per-branch PR), §4.2 steps 4a–7 (write-ahead resume vs reconcile; post-merge integrity alarm); §7.2 C1 (two concurrent submissions never overwrite; conflict refuses) |
| **REQ-C-003** | Add-vs-replace explicit, non-clobbering | §2.2 `SubmitAction` labels branch/PR; `VerifySubmission` returns `KeyNames` (no plaintext) for ADD/REPLACE detection; §7.2 C3 (REPLACE-detection reaches no decrypt/identity code; no contributor write/truncate of live file) |

---

## 7. Sequenced work breakdown (PLAN §10) + delegation

Priority path = the **submit → review → merge vertical slice** (PLAN §9). Build it before
breadth. Every unit's tests tie to REQ acceptance criteria + PLAN §11 negative vectors.
`-race` clean is a merge gate; no real net/clock/fs/keychain in unit tests (injected).

**Build/CI allowlist-gate obligation (binding — ADR-0005).** The authoritative
ADR-0005 closed-world allowlist gate is the **Go test**, not a bash script. The bash
script is **retired**. `make check-allowlist` and the CI `allowlist` job MUST run:

```
go test -run TestAllowlist ./internal/core/crypto/encrypt/ ./internal/core/usecase/submit/
```

(note the target is the `internal/core/usecase/submit` **sub-package**, not the
whole `internal/core/usecase`). The gate **fails loudly** if it cannot run — a
missing/uncompilable test, a `go list` error, or a skipped job is a **FAIL**, never
an `exit 0` / green. A RED allowlist job is CHANGES REQUIRED and overrides a green
unit suite (`reis-principal-go` enforces).

| Phase | Unit | Owner | Implements | Test obligations (REQ + §11) |
|------|------|-------|------------|------------------------------|
| 0 | Skeleton: go.mod, Makefile (build/test/lint/install), golangci-lint, CI, `byreis version` | reis-backend | — | CI green; lint config enforces the dependency-rule import bans; **ADR-0005 closed-world allowlist GO TEST wired into CI as `make check-allowlist` + CI `allowlist` job = `go test -run TestAllowlist ./internal/core/crypto/encrypt/ ./internal/core/usecase/submit/`; bash script retired; un-runnable gate FAILS (never exit 0) (TM-D5)** |
| 0 | `internal/core/mode` detector + policy matrix | reis-go-tdd | mode + `KeyProbe`/`RegistryTrust`/`Clock` ports | REQ-M-001 all bullets; **the §7.2 M6 (command×mode) named fixture incl. denied rows + the full bypass list (`--mode admin`, `BYREIS_MODE`, `mode:` config key, tampered cached AdminSet w/ forged `SourceVerified`) must-not-grant-admin**; 0600 hard-error; fail-closed-to-contributor |
| 1 | `crypto/manifest` canonical encoding (§3) | reis-go-tdd | manifest encoder | Determinism (map order never reaches signer); reject `0x1e/0x1f` in ids/key names; **`format_version` rejected unless `^byreis\.native\.v[0-9]+$` and separator-free → `ErrFormatVersion` (M-2)**; C-2/C-7 field presence; **§3.5 SHA preimage: hash the raw byte buffer, zero normalization; one-byte/CRLF/reorder change ⇒ different SHA (TM-D3 / §7.2 D3)** |
| 1 | `crypto/encrypt` (public-key only) | reis-go-tdd | `Encryptor` | `ErrNoRecipients`; round-trip; **each value a FRESH independent `age.Encrypt` ciphertext; no shared blob (H-2)**; **ADR-0005 CLOSED-WORLD ALLOWLIST Go test `TestAllowlist` (transitive set ⊆ allowlist; unknown dep fails; bash retired) + the `Recipient` no-identity-material reflection invariant (TM-D5 / §7.2 M1)**; REQ-B-001 contributor-keyless |
| 1 | `crypto/verify` `VerifyOfRecord`/`VerifySubmission` | reis-go-tdd | `VerifierOfRecord`/`VerifierOfSubmission` | Full §11 negatives: single-byte tamper, wrong-recipient, recipient-strip, ciphertext-swap, key reorder/delete, **cross-file/cross-project transplant (C-2)**, unsigned-to-VerifyOfRecord rejected, forged-key, **explicit "what VerifySubmission does NOT catch" (C-6)**; **§3.4 step-4 counter decision table fully table-tested incl. the 3 `ErrCounterReconcile` rows + the OK-resume row + the old "merged-but-unbumped, intent lost" ⇒ `ErrCounterReconcile` NOT OK/NOT `ErrReplay` (H-1)**; **`VerifySubmission` fed artifact-sourced `ExpectedRecipients` disallowed by construction (M-1)**; **`VerifyOfRecord` fed artifact/repo/stale-cache-sourced `countertypes.CounterAuthority` disallowed by construction — compile/API-shape test (no exported ctor; pkg-private `countertypes.newCounterAuthority`; `verify` imports `countertypes` to read/`Valid()` only; a zero-value/struct-literal is `!Valid()` -> hard error), not a runtime string check (TM-D1 / §7.2 D1)**; **`registry` does NOT import `crypto/verify` — gap 4a closed (assert no such import edge)**; **`content_sha` matched at step 4 is the §3.5 raw-byte preimage; `S_unsigned` vs committed `S_signed` does not spuriously pass (TM-D3 / §7.2 D3)**; **read-only verify caller in the `sc==la+1` window writes no `CommitBump` and synthesizes no pending (§7.2 L3)** |
| 1 | `crypto/decrypt` admin decrypt + round-trip-all | reis-go-tdd | decrypt port | admin×value cross-product; removed-admin `ErrDecrypt`; post-merge round-trip-all; **L-2: identity private-key material zeroized after use — explicit BUILD test whose pass criterion is resistant to GC/escape-analysis defeating a naive zero-check (§7.2 L2; carried, non-blocking)** |
| 2 | `git` domain + `internal/adapter/git/github` | reis-backend | `GitProvider` | `OpenSubmissionPR` returns ArtifactSHA (§3.5 raw-byte preimage; adapter MUST NOT canonicalize before hashing — §7.2 D3); `MergeSubmission` `ErrArtifactMoved` on moved SHA (T2); httptest, no real network |
| 2 | `usecase/submit` sub-package (keyless spine) | reis-go-tdd | Submit | REQ-A-003/C-002, REQ-C-003 add/replace label, REQ-C-005 resumable (encrypted-at-rest only), **`internal/core/usecase/submit` sub-package transitive import set ⊆ ADR-0005 allowlist (Go test `TestAllowlist`; NOT whole `usecase`; `Decrypt`/`Edit`/`Merge` off-target by construction) (closed-world, TM-D5 / REQ-B-001)**; **§7.2 C1 (two concurrent submissions never overwrite each other's branch; conflict refuses, never silently drops a secret — distinct from write-ahead resume/reconcile)**; **§7.2 C3 (no contributor command writes/truncates the live secrets file for an existing key; REPLACE detection reaches no decrypt/identity code — ties to ADR-0005 allowlist & T6)**; **§7.2 A3 (double-entry TTY vs single-entry pipe; irreversibility ack; validation refuses BEFORE any commit)** |
| 2 | `usecase/Review` + `usecase/Merge` | reis-go-tdd | Review/Merge | T1 (decrypt from artifact not diff), T2 `--expect` mismatch, **§4.2 write-ahead sequence: RecordPendingBump (records post-sign `S_signed`, §3.5) BEFORE merge; CommitBump (advance+clear) only after; crash-after-write-ahead resumes on matching pending; lost-intent → `ErrCounterReconcile` terminal, never auto-heal (H-1)**; **C-4 re-encrypt at merge is a FRESH whole-file `age.Encrypt`, reuses zero prior ciphertext bytes; re-sign under bumped counter never reuses prior generation's ciphertext (H-2 negative tests)**; **§7.2 B2: PRE-merge structural-invalid ⇒ abort, live file UNTOUCHED (REQ-B-002/C-001) as a row DISTINCT from POST-merge integrity failure ⇒ terminal alarm, file already committed (ADR-0006 step 6)** |
| 2 | `usecase/Init` + `usecase/Doctor` + CLI scaffold | reis-backend | Init/Doctor | **REQ-A-001 reframed (QA-D1): NOT a wall-clock assertion — documented `<120s` budget measured in a perf job, PLUS deterministic sub-assertions: no key step in the init call graph; bounded #network round-trips under an injected clock**; **§7.2 A1 (sig-verify fail ⇒ does NOT write project config — no-side-effect negative)**; **§7.2 A2 (`doctor`: offline = cache age NOT error; exit≠0 iff ≥1 PROBLEM)**; REQ-A-002 (mode reason, perms chmod hint, branch-protection check for T6); **`trust.yaml` AND parent-dir perms: too-permissive/symlink/wrong-owner = HARD ERROR refuse-to-run with exact chmod hint; TOCTOU-safe `O_NOFOLLOW`+`fstat`-on-fd read; `doctor` FAIL line (parent-dir is FAIL, the old WARN is removed) mirroring admin-key check (M-3/TM-D4); §7.2 D4 symlink-swap-after-check (file+dir) & dir-writable-replace negatives**; REQ-A-006 error UX |
| 3 | `internal/adapter/registry` fetch+verify+cache+counter | reis-backend | `RegistryClient` | REQ-B-003 (unsigned blocks promotion), **§7.2 B3 (asymmetric branch: unsigned HEAD blocks ADMIN promotion BUT contributor last-known-good cache read proceeds; cache>TTL withholds promotion with explicit reason)**, REQ-B-004 `ErrRegistryRollback`, **C-3 two-record store + `RecordPendingBump`/`CommitBump` (write-ahead + atomic advance-and-clear), `ErrCounterReconcile` on mismatched/absent pending (H-1)**, **registry adapter is the SOLE producer of the step-4 authority value via the package-private `countertypes.newCounterAuthority`, bound to the same `SourceVerified` anchor — no exported ctor, no repo/artifact/stale construction path (TM-D1); `ErrReplay`/`ErrCounterReconcile` referenced from canonical `countertypes` owner (no `registry` alias var); `ErrNoTrustedSigner` referenced from `verify` owner (no alias) — junk-drawer errors pkg rejected**, `ErrCacheTampered` on regressed cached `last_accepted`, **L-1: signer key length-validated to 32 bytes at this boundary → `ErrNoTrustedSigner` (not `ErrSignatureInvalid`) — carried test obligation**, REQ-B-005 bootstrap no-silent-TOFU |
| 4 | `usecase/Get/Decrypt/Edit` + CI decrypt | reis-go-tdd / reis-backend | admin read | REQ-B-006 (masking/TTY/json, edit abort-on-fail no clobber), CI uses `VerifyOfRecord` (C-1/T9), all four denied in CONTRIBUTOR by mode policy — **denied, not attempted-then-failed (§7.1)** (REQ-B-001) |
| 4 | Error UX polish + `--json` schema | reis-backend | render | REQ-A-006 distinct exit codes (incl. distinct `ErrReplay` vs `ErrCounterReconcile` with reconcile runbook hint), no secret/key in errors |
| 5 | QUALITY/SECURITY gate | reis-qa-lead + reis-crypto-auditor + reis-threat-modeler | — | **§7.1 REQ-B-001 behavioral ship-gate suite green (red blocks ship — QA-B1)**; full §11 set present (missing any = HIGH); H-1/H-2/M-1/M-2/M-3 + TM-D1/D3/D4/D5 + the §7.2 named rows present; L-1/L-2 carried tests present |

Security-relevant units (`crypto/*`, `mode`, `registry` trust, counter authority) are
**not self-certified** — routed to `reis-crypto-auditor` after Phase 1/3 (PLAN §10).
The TM-* items additionally route to `reis-threat-modeler`; the QA-* items to
`reis-qa-lead` for the ship-gate sign-off (§7.1).

**Carried (non-blocking) BUILD test obligations folded earlier iterations:**
- **L-1**: registry-boundary length validation of every Ed25519 signer key to
  exactly 32 bytes; wrong length → `ErrNoTrustedSigner` (NOT `ErrSignatureInvalid`).
  Asserted in the Phase 3 registry adapter tests and the Phase 1 verify tests
  (signer-resolution path).

### 7.1 REQ-B-001 asymmetric-guarantee behavioral ship-gate suite (QA-B1 — BLOCKER)

This is a **named, enumerated ship-gate suite**, designed test-first by the BUILD
engineer. It is in addition to the structural ADR-0005 closed-world allowlist /
reflection invariant (§1, TM-D5) — those prove the *code shape*; this proves the
*observable behavior* against a REAL encrypted project file.

- **Test package**: `internal/core/usecase/asymmetry_shipgate_test.go` (build tag
  `shipgate`), driving the public `pkg/byreis` façade + the CLI render layer
  through the in-process command runner (no real net/fs/keychain — injected; the
  encrypted project file fixture is real age ciphertext to a known test recipient
  set whose private key is **never** provided to the test process).
- **CI job**: dedicated `shipgate` CI job (separate from unit/`-race`), required,
  non-skippable. **Gate mechanism: a RED `shipgate` job hard-fails the release
  pipeline** — the `release` workflow has `needs: [shipgate]` and there is no
  manual override path. Phase 5 (`reis-qa-lead`) verdict is contingent on this job
  green; red = "does not ship", overrides an otherwise-green unit suite.
- **Matrix (full cross-product, enumerated, not a sample):**
  - **Commands × flags**: every contributor-runnable v0.1 command and every flag
    incl. `--json`: `version`, `init`, `doctor`, `submit` (`--add`/`--replace`,
    `--key`, `--value`/stdin, `--justification`, `--non-interactive`, `--json`),
    plus the *attempted* `get` / `decrypt` / `edit` (see denied assertion below).
  - **Keyless states (each individually AND all simultaneously)**: (a) no admin key
    file on disk; (b) `BYREIS_KEY` unset; (c) `BYREIS_KEY_FILE` unset; (d) empty /
    no keychain entry; (e) all of (a)–(d) at once.
  - **Output channels observed (every one, per command×state)**: stdout, stderr,
    any generated or temp file the command writes (submission artifact, branch
    working tree, cache, audit entry), the structured log sink, the `--json`
    payload, the error value's full `%v`/`%+v` text, and any exit-data/diagnostic
    blob.
- **Assertions:**
  1. **No-plaintext invariant**: given the REAL encrypted project file, NO secret
     plaintext value (from the known fixture's cleartext set) appears verbatim,
     base64'd, or hex'd in ANY observed channel for ANY command×state cell. (The
     test holds the cleartext only to assert absence; the process under test never
     receives a decrypting identity.)
  2. **Denied-by-policy, not attempted-then-failed**: `get`, `decrypt`, `edit` in
     the keyless/contributor state are rejected by `internal/core/mode` policy
     **before** any decrypt/identity code is reached. The suite asserts the denial
     error is the mode-policy sentinel (a permission denial), and asserts — via the
     ADR-0005 allowlist/import-set hook + a call-graph spy — that no
     `crypto/decrypt` / `crypto/identity` function was entered. "Attempted decrypt
     that then errored" is a FAIL of this gate even if no plaintext leaked.
- **Implementable test-first**: the fixture (real age file + known cleartext +
  withheld identity), the channel-capture harness, and the mode-policy/​call-graph
  spy are all specified above; a BUILD engineer can write the table before the
  use-cases exist.

### 7.2 Pinned named §7 rows (QA-C3/B2/M6 + folded MEDIUM/LOW)

Each row below is a **named, individually-failing** test obligation bound to the
owning Phase unit above. "Floating prose" is not acceptable — these are rows.

| Row | Binding obligation | Owning unit |
|----|--------------------|-------------|
| **M6** | Named Phase-0 fixture/acceptance: full (command×mode) matrix — commands {`version`,`init`,`doctor`,`submit`,`review`,`merge`,`get`,`decrypt`,`edit`} × modes {C,A,S} with explicit expected allow/deny per cell, PLUS the bypass list each asserted must-not-grant-admin: `--mode admin` flag, `BYREIS_MODE` env, a `mode:` config key, and a tampered cached `AdminSet` with forged `SourceVerified`. A partial table does NOT satisfy this row. | Phase 0 `internal/core/mode` |
| **D1 (TM)** | `VerifyOfRecord` fed a `countertypes.CounterAuthority`/`PendingBump` constructed from the artifact, the project repo, or an unverified/stale cache is **disallowed by construction**: the opaque type lives in `internal/core/registry/countertypes` with a **package-private constructor** (`newCounterAuthority`) callable only by the registry adapter; `verify` imports `countertypes` to read fields / call `Valid()` and CANNOT construct one; the exported `verify.NewCounterAuthority` is removed; `registry` no longer imports `crypto/verify` (gap 4a). Compile/API-shape test (no exported ctor / no struct-literal / no settable trust-bearing field; zero-value is `!Valid()` -> step-4 hard error), NOT a runtime string match. **SECURITY-RELEVANT (TM-D1) — pending `reis-crypto-auditor` sign-off before B0 closes; NOT self-certified.** | Phase 1 `crypto/verify` + Phase 3 `registry` (`countertypes` sub-package) |
| **D3 (TM)** | (i) one-byte / CRLF / key-reorder-via-reserialize change ⇒ different `ArtifactSHA`, rejected by `--expect`/step 4; (ii) reader pinning `S_unsigned` vs the committed `S_signed` does NOT spuriously pass — step 4 matches the recorded `S_signed`; (iii) hashing is over the raw fetched/pushed buffer — any adapter that re-marshals before hashing is a defect. | Phase 1 `crypto/manifest` + Phase 2 `git` adapter |
| **D4 (TM)** | `trust.yaml` AND parent dir `~/.config/byreis/`: symlink-swap-after-check (file and dir) and dir-writable-then-replace are caught fail-closed; read is `O_NOFOLLOW`+`fstat`-on-fd (never stat-path-then-open-path); parent-dir too-permissive is a **FAIL** (the prior WARN is removed). `doctor` emits the FAIL line for both. | Phase 2 `usecase/Doctor` + Init/CLI |
| **M1 (TM-D5)** | ADR-0005 **closed-world allowlist**, enforced by the authoritative **Go test** `go test -run TestAllowlist ./internal/core/crypto/encrypt/ ./internal/core/usecase/submit/` (bash script retired; an un-runnable gate FAILS loudly, never exit 0): transitive dep set of `crypto/encrypt` AND of the `internal/core/usecase/submit` **sub-package** (NOT the whole `internal/core/usecase`; `Decrypt`/`Edit`/`Merge` live in the parent package and are off-target by construction, mirroring `rectypes`) ⊆ explicit allowlist; an injected unknown/identity-bearing dependency FAILS the test (a denylist that would silently pass is itself a defect). The only registry-side allowlist entries are the pure `internal/core/registry/rectypes` AND `internal/core/registry/countertypes` sub-packages; the parent `internal/core/registry` and `crypto/ed25519` are NOT on the allowlist and MUST fail if reached (no "value types only" prose — the subset test is package-scoped). PLUS `rectypes.Recipient` no-identity-material reflection invariant (no field/method reachable from a `Recipient` value assignable to age identity / private key material), re-asserted on `Recipient` change. Also assert `rectypes`'s OWN transitive set excludes `crypto/ed25519`. | Phase 1 `crypto/encrypt` + Phase 2 `internal/core/usecase/submit` sub-package |
| **C3 (QA)** | (i) REPLACE-detection path provably reaches NO decrypt/identity code (tie to the M1 allowlist/import-set + a call-graph assertion); (ii) NO contributor command writes or truncates the live secrets file for an existing key (named negative row, distinct from the ADD/REPLACE label test; ties to T6). | Phase 2 `usecase/Submit` |
| **B2 (QA)** | Two distinct rows, separately failing: (a) PRE-merge structural-invalid ⇒ abort, live file UNTOUCHED (REQ-B-002/REQ-C-001) — explicitly the pre-merge row; (b) POST-merge integrity failure ⇒ terminal alarm, file already committed (ADR-0006 step 6). REQ-B-002's "leaves the live file untouched" is row (a), separate from the row (b) alarm. | Phase 2 `usecase/Merge` |
| **B3 (QA)** | REQ-B-003 asymmetric branch: unsigned registry HEAD BLOCKS ADMIN promotion BUT a contributor last-known-good cache read still proceeds; cache age > TTL withholds promotion with an explicit machine-readable reason (not a generic failure). | Phase 3 `registry` |
| **C1 (QA)** | Two concurrent submissions never overwrite each other's branch; a branch/PR conflict REFUSES and never silently drops a secret. This is distinct from the write-ahead resume/reconcile (§4.2) — it is a submission-side concurrency row. | Phase 2 `usecase/Submit` |
| **A3 (QA)** | `submit` value entry: double-entry-confirm on a TTY vs single-entry when piped; explicit irreversibility acknowledgement; value validation (REQ-A-003) refuses BEFORE any branch/commit is created. | Phase 2 `usecase/Submit` |
| **L3 (QA)** | A read-only `VerifyOfRecord` caller hitting the `sc == la+1` crash window does NOT write `CommitBump` and never synthesizes a `pending`; only the `merge` resume (or explicit admin action) drives `CommitBump`, and only against a pre-existing matching signed `pending`. | Phase 1 `crypto/verify` + Phase 2 `Merge` |
| **A1 (QA)** | Registry signature-verify failure during `init` ⇒ byreis does NOT write project config (`.byreis.yaml`) or any pin — explicit no-side-effect negative. | Phase 2 `usecase/Init` |
| **A2 (QA)** | `doctor`: offline / cache present ⇒ cache age is reported, NOT an error; `doctor` exit code ≠ 0 **iff** ≥1 check is a PROBLEM (a stale-but-usable cache alone is not exit≠0). | Phase 2 `usecase/Doctor` |
| **L2 (QA)** | Identity private-key zeroization test pass criterion is **resistant to GC/escape-analysis defeating a naive zero-check**: assert via a stable referenced backing buffer (e.g. an explicitly-managed `[]byte` whose address is pinned for the assertion, checked after explicit wipe + before drop), NOT by reading a value the compiler may have optimized away. Carried, non-blocking. | Phase 1 `crypto/decrypt`/`identity` |

(The former parent-dir-perms **WARN** obligation (old L4) is **superseded by
TM-D4 / row D4** and is now a **FAIL**; the WARN line is removed — see §4.1.)

---

## 8. Standards compliance self-check (binding — `reis-principal-go` enforces)

- Dependency rule: core has zero UI/SDK/network imports; `crypto/encrypt` + `Submit`
  transitive set ⊆ ADR-0005 **closed-world allowlist** (CHANGES REQUIRED if any unknown
  dep appears; a denylist would be a defect — TM-D5).
- Interfaces consumer-defined, small, role-based; accept interfaces / return structs; ctor
  injection; no globals/singletons/`init()` side effects; packages by domain not layer-type.
- `context.Context` first param on all I/O; `%w` + actionable hints; sentinel/typed errors;
  no panics; fail-closed on security paths.
- Determinism: clock/fs/net/keychain/randomness injected; `go test -race ./...` merge gate;
  REQ-A-001 timing is a perf-job budget + deterministic sub-assertions, NOT a wall-clock
  unit assertion (QA-D1).
- No `any` in domain signatures.

---

## 9. Gate status

This design is **PROPOSED, not self-certified**. Per PLAN §10/§12 and the project guardrail
("Security-relevant code is never self-certified"):

- The crypto/trust items H-1, H-2, M-1, M-2, M-3 + carried L-1/L-2 remain encoded and were
  previously routed to `reis-crypto-auditor`.
- This iteration applies the post-DESIGN assurance hardening with **NO crypto re-decision**
  (both reviewers confirmed Model B is unaffected). It is **ready for focused re-review**:
  - `reis-threat-modeler` — **TM-D1** (§2.0 + §2.1 + §2.3 + §3.4 step 4 + §4.2 step 4 +
    §7.2 D1), **TM-D3** (§3.5, referenced from §2.2/§3.4 step 4/§4.2 4a-4b/§4.4 + ADR-0006
    step 4a/4b + §7.2 D3), **TM-D4** (§4.1 parent-dir HARD ERROR + TOCTOU fd read + §7.2 D4),
    **TM-D5** (§1 closed-world allowlist with the recipient/fingerprint value types in the
    pure `internal/core/registry/rectypes` sub-package and the parent `internal/core/registry`
    /`crypto/ed25519` explicitly OFF the allowlist + §2.0 `rectypes.Recipient` invariant and
    type placement + §4.3 + ADR-0005 point 2 with no judgement-dependent "value types only"
    prose + §7.2 M1). This closes the single carried LOW/INFO from the threat-modeler's
    attack-surface re-check (the prose-narrowed `registry` allowlist footgun).
  - **B0-gate adjudication landed (this iteration — 4 decisions, normative):**
    (1) Submit allowlist target = the `internal/core/usecase/submit` **sub-package**
    (NOT whole `usecase`); `Decrypt`/`Edit`/`Merge` off-target by construction
    (§1, §6 TM-D5/T4/T6/REQ-B-001, §7 Phase-2, §7.2 M1, ADR-0005). (2)
    `CounterAuthority`/`PendingBump` moved to the pure isolated
    `internal/core/registry/countertypes` with a **package-private constructor**
    (sole producer = registry adapter; `verify` consumes opaque, cannot construct;
    `verify.NewCounterAuthority` removed; `registry → crypto/verify` import removed
    = gap 4a) (§1, §2.0, §2.1, §2.3, §3.4 step 4, §4.2, §6 C-3, §7.2 D1, ADR-0006).
    (3) Shared sentinels defined once in their semantic owner — `ErrReplay`/
    `ErrCounterReconcile` in `countertypes`, `ErrNoTrustedSigner` in `verify`;
    no cross-package alias vars; junk-drawer errors package explicitly rejected
    (§2.1, §2.3, ADR-0006). (4) Authoritative allowlist gate is the **Go test**
    (`go test -run TestAllowlist ./internal/core/crypto/encrypt/
    ./internal/core/usecase/submit/`); bash script retired; an un-runnable gate
    FAILS loudly, never exit 0 (§5, §7 build/CI obligation, §7.2 M1, ADR-0005).
  - **Decision (2) is a TM-D1 SECURITY-RELEVANT change — the `countertypes`
    construction/trust model is NOT self-certified.** It requires
    `reis-crypto-auditor` sign-off (and `reis-threat-modeler` TM-D1 confirmation)
    **before B0 closes**. Until then the `countertypes` contract is **PENDING
    crypto-auditor**.
  - `reis-qa-lead` — **QA-B1** (§7.1 enumerated behavioral ship-gate suite + CI gate
    mechanism), **QA-C3/B2/D1/M6** and the folded set (B3/C1/A3/L3/L4-reconciled/A1/A2/M1/
    L2-adequacy) as named §7.2 rows; §6 traceability + this §9 focus list updated.

BUILD must not start until: the auditor confirms C-1…C-8 + H/M/L closed
**AND `reis-crypto-auditor` signs off the `countertypes` construction/trust model
(B0 decision #2, TM-D1 — NOT self-certified)** AND `reis-threat-modeler` confirms
TM-D1/D3/D4/D5 closed AND `reis-qa-lead` confirms QA-B1 (+ the rows) closed AND the
design is APPROVED. The four B0-gate adjudications are now landed normatively; the
only open contract item is the `countertypes` model pending `reis-crypto-auditor`.

Focused re-review targets (this iteration):
- TM-D1 (**security-relevant — pending `reis-crypto-auditor`; the `countertypes`
  construction/trust model is NOT self-certified**): §1 (`registry/countertypes`
  sub-package, pkg-private ctor, gap-4a removal) · §2.0 (counter-authority
  sourcing type-shape → `countertypes` pkg-private ctor) · §2.1
  (`countertypes.CounterAuthority`/`Valid()`, no nil-counter skip, sentinel
  ownership) · §2.3 (`CounterAuthority` returns `countertypes.CounterAuthority`,
  sole producer) · §3.4 step 4 precondition · §4.2 step 4 · §5 ADR-0006 ·
  §7.2 D1 · ADR-0006 (countertypes ctor + sentinel ownership).
- TM-D3: §3.5 (preimage, normative) · §2.2 · §3.4 step 4 · §4.2 step 4a/4b · §4.4 ·
  ADR-0006 step 4a/4b · §7.2 D3.
- TM-D4: §4.1 (parent-dir HARD ERROR, TOCTOU `O_NOFOLLOW`+fstat-fd, doctor FAIL) · §7.2 D4.
- TM-D5: §1 (closed-world allowlist; Submit target = `internal/core/usecase/submit` sub-package) · §2.0 (`Recipient` invariant) · §4.3 · §5/ADR-0005 (Go-test gate, bash retired) · §7 build/CI obligation · §7.2 M1.
- QA-B1: §7.1 (suite + CI gate) · §7 Phase 4/5 rows.
- QA-C3/B2/D1/M6 + folded: §7.2 rows · §4.1 (D4/L4 reconcile) · §4.2 step 7 (B2) ·
  §7 Phase 2 Init/Doctor row (D1) · §6 traceability.

### 9.1 B0 closure status & recorded pre-Phase-3 obligation

**B0 gate: CLOSED.** All four B0 CHANGES-REQUIRED items are landed normatively
and the security-relevant item (#2, `countertypes`/TM-D1) has cleared the
not-self-certified loop: `reis-crypto-auditor` ("TM-D1 type-shape invariant
SATISFIED AT B0 — crypto half clears") and `reis-threat-modeler` ("TM-D1 HELD —
concur CLOSED FOR B0"; the Go `internal/` boundary it required is implemented
and compile-fail-proven) have both signed and converged. The `countertypes`
construction/trust model is no longer "PENDING crypto-auditor": it is CLEARED
for B0 by aggregating both reviewers' verdicts.

**Recorded pre-Phase-3 obligation (gates Phase 3, NOT B0).** The
`capmint.Mint -> countertypes.newCounterAuthority` bridge is deferred to Phase 3.
At B0 `capmint.Mint` and the registry adapter stub panic; the TM-D1 type-shape
constraint (package-private ctor, no exported `Valid()`-producing symbol, Go
`internal/` boundary on `capmint`, zero-value `!Valid()`) is fully operative and
compile-fail-proven (§7.2-D1). Before Phase 3 closes, the bridge MUST keep the
invariant **"only code rooted at `internal/adapter/registry` can construct a
`Valid()==true` CounterAuthority"** enforced by a **mechanical in-CI fail-closed
gate (compile error or build-breaking test — never grep/review)**. The §7.2-D1
compile-fail test MUST keep passing unchanged; a positive test MUST prove the
bridge produces a `Valid()` value through `capmint.Mint` only.

- Owner: **`reis-backend`**.
- Gating authority: **`reis-principal-go` Phase-3 design gate**.
- Security re-sign: **MANDATORY** — `reis-crypto-auditor` + `reis-threat-modeler`
  re-sign the realised bridge (TM-D1) before Phase 3 ships; not self-certified.
- Bridge mechanism = a **recorded Phase-3 design-gate decision (not decided
  now)**. Option A (preferred): restricted-by-name exported ctor consumed only
  by `capmint`, with a §7.2-D1 source/dep-scan belt-and-suspenders on top of the
  `internal/` rule. Option B (constrained): registration var — no `init()`, no
  open exported mutable var, `sync.Once` single-writer if used, still gated by
  the `capmint` `internal/` boundary. Option C: another mechanism that does NOT
  break the dependency rule (no `core -> adapter`, gap 4a stays closed) or the
  ADR-0005 allowlist, still terminating in a mechanical fail-closed gate.
- See ADR-0006 §"Pre-Phase-3 obligation" (Consequences) for the full constraint
  text and acceptance criteria.
