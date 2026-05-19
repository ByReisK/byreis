# byreis — Technical Plan (v2)

> **byreis** — Friendly GitOps secrets management with asymmetric access.
> *"Send secrets. Not see them."*
>
> CLI + (later) TUI, written in Go. Default-contributor, central admin registry.

> **v2 status.** This plan is the synthesis of a completed `/reis` pipeline run:
> SPIKE (crypto model chosen + audited) → ANALYSIS (scope locked) → this rewrite.
> v1 is preserved at `PLAN.v1.md`. The gate artifacts this plan integrates:
> - `design/FINDINGS.md` — Model B selected, proven with `go test -race` (6 attack tests fail-closed).
> - `design/REQUIREMENTS.md` — locked requirements (15 reqs, v0.1 scope, PM⇄BA debate recorded).
> - `reis-crypto-auditor` verdict — *FIX BEFORE MERGE*: 8 constraints (C-1…C-8 below) the real impl must encode.
> - `reis-threat-modeler` delta — Model B threats T1–T9, §6 rewritten accordingly.
>
> **The single most important change vs v1:** v1's "SOPS-compatible format" is **dropped**. SOPS's symmetric data-key + whole-file MAC make a keyless contributor edit of a *shared* file cryptographically impossible — this directly contradicted v1's own Workflow B. byreis is now **SOPS-inspired, age-native** (Model B), with an optional admin-only one-way `export --sops`.

---

## 0. Brand & Identity

| Element | Value |
|---|---|
| Project / binary | `byreis` |
| GitHub org / module | `github.com/ByReisK/byreis` |
| Config / cache dir | `~/.config/byreis/` · `~/.cache/byreis/` |
| Env prefix | `BYREIS_*` |
| License | Apache 2.0 |

**Tagline:** *"Send secrets. Not see them."* · Voice: friendly but technical (Charm/Linear style), confident, acknowledges prior art (SOPS, age) as the foundation it evolves.

---

## 1. Vision & Core Concept

### Problem (validated, 2026 market)

GitOps secrets force a bad trade:
- **SOPS + age:** zero-infra and git-native, but **symmetric** — anyone with a key reads *everything*, and public-key contribution only works for *whole files you create*, **never for editing a shared environment file** (data-key + whole-file MAC require a private key). Arcane CLI.
- **Infisical:** polished, MIT, self-hostable — but **server-based**, not plain git.
- **Doppler / 1Password:** SaaS, vendor-coupled.
- **Vault:** heavy infra. **sealed-secrets:** Kubernetes-only. **agenix/sops-nix:** Nix-bound, painful manual rekey. **git-crypt:** unmaintained, whole-file only.

### byreis's defensible wedge

> *The only zero-infra, plain-git tool where people who must never **read** secrets can still safely **add/update** them — with friendly errors and CI-native flows.*

This wedge is exactly the gap SOPS structurally cannot fill. **If the asymmetric guarantee is not provable, byreis is just a worse SOPS** — which is why the guarantee (REQ-B-001) is a machine-checkable ship gate, not a marketing claim.

### Principles

1. **Default = contributor.** `byreis init` works with only a registry URL + a git login. No key handling.
2. **Access = cryptographic reality.** Mode is derived, never granted by config/flags. Registry is governance/identity only — *not* an access-control boundary.
3. **Contributor path is keyless and provably write-only.** No private key anywhere in submit, including CI.
4. **Zero infra.** Pure CLI + git. No server, no vendor backend.
5. **Friendly is the product.** In v0.1, friendliness ships as best-in-class CLI error UX (TUI is v0.2).

---

## 2. Architecture Overview

### Two-repo model (unchanged from v1 — still correct)

1. **Admin registry repo** (e.g. `myorg/byreis-admins`) — source of truth for admin identity: `admins.yaml` (each admin's age **recipient** pubkey **and** Ed25519 **manifest-signing** pubkey), `projects/*.yaml`, `policy.yaml`. Fetched read-only, signature-verified, cached aggressively, **anti-rollback** (REQ-B-004). byreis writes to it only via the explicit admin add/remove flow (v0.2).
2. **Project repos** (e.g. `myorg/my-app-secrets`) — `.byreis.yaml` (points at the registry) + native-encrypted `secrets/*.enc.yaml`. **Branch protection on `secrets/**` is a documented hard prerequisite** — the live file is only writable via an admin-merged commit (mitigates T6).

### Trust anchor (mitigates T8 — was unaddressed in v1)

The registry cannot vouch for *who may sign the registry*. The set of trusted registry **commit-signer keys** is **pinned in client bootstrap config outside the registry** (org-distributed, or TOFU-with-explicit-fingerprint-confirmation on `init`, never silent TOFU). The chain is:

```
client-pinned signer set ──verifies──▶ registry commits
registry (admins.yaml) ──attests──▶ admin → { age recipient pubkey, Ed25519 signing pubkey }
Ed25519 signing pubkey ──verifies──▶ file-of-record manifest signature
```

Every "is X a trusted admin/signer?" question terminates at the client-pinned anchor, never at the registry itself.

### Component layering (binding — see CLAUDE.md "Engineering standards")

`cmd/byreis` → `internal/cli` (cobra, thin) / `internal/tui` (v0.2) → `internal/core` (**zero UI/SDK imports**) → backends behind interfaces (`Encryptor`, `GitProvider`, `RegistryClient`). Dependencies point inward only.

---

## 3. Mode System (REQ-M-001 — crypto-derived, fail-closed)

Mode is determined by cryptographic reality, never config. Resolution order (each step fail-closed):

```
private key file present?            ──No──▶ CONTRIBUTOR
  │Yes
perms exactly 0600?                  ──No──▶ HARD ERROR, refuse to run (print exact chmod). NEVER downgrade-to-admin.
  │Yes
key decrypts some project file?      ──No──▶ CONTRIBUTOR
  │Yes
pubkey in signature-verified registry? ─No─▶ CONTRIBUTOR + explicit "key unregistered" warning
  │Yes
ADMIN  (promotion written to audit log)
```

Any ambiguity/error → CONTRIBUTOR (or hard error for the perms case), **never ADMIN**. Command×mode permission is enforced centrally in `internal/core/mode/policy.go` and tested for **every (command × mode) pair including denied + flag/env/config bypass attempts**. Admin promotion additionally requires a fresh signature-verified registry fetch *or* a within-TTL cache (REQ-B-003/B-004/C-004) — a stale/rolled-back registry never grants admin.

---

## 4. Crypto Model — Model B (native, age, no data key)

**Decision (SPIKE gate, audited).** Each secret value is an **independent multi-recipient `age` ciphertext**, encrypted to *every current admin recipient pubkey*. There is **no shared data key and no whole-file MAC**. Therefore a contributor holding only public keys can add/replace a single value and the file stays valid — the property SOPS cannot provide. Proven in `spike/` with `go test -race` green and six structural attacks failing closed.

### 4.1 File-of-record integrity: signed manifest

AEAD only protects each ciphertext blob. Structural integrity (reorder / delete / swap / strip-recipient / rollback) is protected by a **manifest** whose canonical bytes are **Ed25519-signed by an admin at review/merge**. The signed canonical encoding covers, in fixed order, with fixed separators, signature excluded:

```
format_version
registry_project_id          ← C-2: project/file identity binding (NEW vs spike)
logical_file_name            ← C-2
counter                      ← monotonic; authority is registry/audit, NOT the repo (C-3)
sorted_key_names
per-key ciphertext digest (bound to key name)
recipient_fingerprint_set    ← full 32-byte digest (C-7), source = verified registry only (C-4)
```

### 4.2 Two verification entry points (C-1 — no `nil`-key downgrade)

The spike's single `VerifyArtifact(verifyKey)` with a `nil`-means-skip-signature branch is a **fail-open footgun** and is **forbidden** in `internal/`. The real API is split:

- **`VerifyOfRecord`** — used for any live read / CI decrypt / deploy. Signature is **mandatory**; the registry-trusted Ed25519 key is required; key-acquisition failure (offline, cache miss, parse error) is a **hard error**, never a downgrade to unsigned.
- **`VerifySubmission`** — structural-only check of an *unsigned contributor submission*; returns an explicit `Unverified` state and **may never gate a prod decrypt/deploy**.

A contributor has no private key and **cannot sign** — inherent. Submissions are unsigned-but-digest-committed; the **admin signs the manifest at merge**, over the *exact bytes reviewed* (see §7 review flow), producing the signed file-of-record.

### 4.3 The 8 binding constraints (from `reis-crypto-auditor`) — DESIGN must encode all

| # | Constraint |
|---|---|
| **C-1** | Two verify entry points; no `nil`-key downgrade; file-of-record always admin-signed; offline-without-trusted-key = hard error. |
| **C-2** | Bind `project_id` + `logical_file_name` into the signed canonical bytes (anti cross-file/cross-project transplant). Required test: artifact signed for file X rejected as file Y. |
| **C-3** | Anti-replay `lastAccepted` counter authority lives in the **registry/audit store**, per-(project,file), updated transactionally at merge, fetched+verified before trust. Project-repo-sourced counters are forbidden. Registry cache is itself monotonic + integrity-checked (anti-rollback offline). |
| **C-4** | `expectedRecipients` comes **only** from the signature-verified registry — never the artifact, never the project repo, never a stale cache that could retain a revoked or drop an active admin. Submission against a now-stale admin set is re-encrypted at merge, not accepted. |
| **C-5** | §6 threat model rewritten (done below) — explicit rows for pending-submission tamper & git-history rollback; keep the honest git-history caveat. |
| **C-6** | Full required negative test-vector set (see §11) — missing any is a HIGH at the QA gate. Includes an explicit test characterizing what `VerifySubmission` does **not** catch. |
| **C-7** | Use the full 32-byte recipient digest (not spike's truncated 16). |
| **C-8** | Drop "SOPS-compatible" headline (done — §1); offer optional admin-only one-way `export --sops`. |

Nothing from `spike/` is lifted verbatim — it is re-implemented fresh under TDD in `internal/core/encryption/` with its own test vectors. The hand-rolled canonical encoding *logic* (fixed field order, `0x1e`/`0x1f` separators, sorted keys/fingerprints, signature excluded, map order never reaching the signer) is re-specified normatively and re-tested.

---

## 5. File Formats & Configuration

### 5.1 Native encrypted file (`secrets/<env>.enc.yaml`)

```yaml
# each value: an independent multi-recipient age ciphertext (armored)
DB_PASSWORD: ENC[age,recipients=4,...]
STRIPE_KEY:  ENC[age,recipients=4,...]
byreis:
  format_version: 1
  project_id: "registry-canonical-id"     # C-2 (bound into signature)
  file: "prod"                            # C-2
  counter: 7                              # display copy; AUTHORITY is registry/audit (C-3)
  recipients:                             # display copy; AUTHORITY is registry (C-4)
    - fp: "<sha256 of age recipient pubkey, 32 bytes hex>"
  manifest_sig:                           # Ed25519 over canonical bytes; admin-applied at merge
    signer: "<admin id>"
    sig: "<base64>"
```

A contributor submission has the same shape **without `manifest_sig`** (unsigned; `VerifySubmission` only).

### 5.2 Registry repo

`admins.yaml` (per admin: `age_recipient`, `ed25519_signer`, role, scope), `projects/*.yaml`, `policy.yaml`, plus the **counter/audit store** holding per-(project,file) `last_accepted_counter` (C-3). Commits signed; trusted-signer set pinned client-side (§2 trust anchor).

### 5.3 Local state & env

`~/.config/byreis/` (config, `identity/admin.key` 0600 — admins only, `auth/` keychain-wrapped token) · `~/.cache/byreis/registry/...` (HEAD + last-observed HEAD + timestamp + cached counter, integrity-checked). Env: `BYREIS_KEY`, `BYREIS_KEY_FILE`, `BYREIS_REGISTRY`, `BYREIS_CONFIG`, `BYREIS_NON_INTERACTIVE`, `BYREIS_LOG_LEVEL`, `BYREIS_NO_TELEMETRY`.

---

## 6. Security Model & Threat Model (v2 — rewritten per T1–T9)

### What byreis protects (and how)

| Threat | Reachable by | Mitigation | Status in v0.1 |
|---|---|---|---|
| **Contributor reads prod secrets** | contributor | No private key; provably write-only (REQ-B-001 ship gate) | Core guarantee |
| **T7 Structural tamper of signed file** (reorder/delete/swap/strip) | repo-write actor | Ed25519-signed manifest over keynames+digests+recipients (§4) | **Solid** (spike-proven) |
| **T1 Author-spoof / opaque-diff merge** | contributor / repo-write | `review` decrypts and shows plaintext from the *exact artifact bytes that get signed*; admin never approves from PR diff/description | DESIGN-mandated (§7) |
| **T2 TOCTOU: branch re-push between review and sign** | branch owner | `review` emits a pinned full-artifact SHA; `merge --expect <sha>` fails closed if the artifact moved; sign only pinned bytes | DESIGN-mandated (§7) |
| **T3 Rollback/resurrection** (replay old signed artifact, re-enable revoked admin) | repo-write actor; revoked admin | Monotonic counter; **authority in registry/audit, not the repo** (C-3); cache anti-rollback | DESIGN-mandated |
| **T4 Recipient-set injection** (contributor adds attacker pubkey → attacker decrypts) | contributor | `expectedRecipients` only from signature-verified registry; artifact set verified equal; mismatch rejected (C-4) | DESIGN-mandated — *confidentiality-critical* |
| **T6 Sabotage/DoS: overwrite/delete live file** | repo-write actor | Branch protection on `secrets/**` (documented hard prereq); contributor path never writes the live file; live read fails closed via `VerifyOfRecord` | Process + C-1 |
| **T8 Trust-root circularity** | registry-write actor | Trusted signer set pinned **outside** the registry (§2) | DESIGN-mandated |
| **T9 nil-verify-key downgrade** | consumer misconfig/offline | API split; live path has no nil branch; offline-without-trusted-key = hard error (C-1) | C-1 |
| Tampered registry / MITM | network | Signed commits + HTTPS + rollback check (REQ-B-004) | Core |
| Modified byreis binary | attacker host | Signed releases (cosign/sigstore) | Release eng |

### What byreis does NOT protect against (honest — keep stated, never remove)

- A compromised machine that **already holds** an admin private key.
- A modified byreis binary on an attacker's own machine.
- **Git history**: an admin removed today can still decrypt *old* ciphertext versions retained in git history. Resurrecting them as the *live* file is blocked (T3 counter), but the historical blobs remain readable by old recipients. Documented limitation.
- Side channels (timing, power).
- Single-admin key loss = **unrecoverable data loss** (REQ-C-006) — stated, no false escrow promise (an escrow would violate the access invariant).

---

## 7. Core Workflows

### A. Contributor onboarding (`byreis init`) — keyless, <120 s

Registry URL → read-only fetch → **verify commit signatures against client-pinned signer set** (fail closed, no silent TOFU; first-time anchor confirmed by explicit fingerprint) → pick project → write project config → "you are CONTRIBUTOR". No key step.

### B. Contributor submit (`byreis submit`) — keyless, write-only, the spine

1. Resolve mode; collect value: **interactive TTY → double-entry + explicit irreversibility ack**; piped/`--value`/CI → single entry, no echo, never logged (C1/C2 conflict resolution).
2. Detect **ADD vs REPLACE without decrypting** (key names are not secret); REPLACE forces an explicit acknowledgement and is labelled on branch/PR (REQ-C-003, mitigates accidental/ malicious clobber).
3. Encrypt the value to the **current registry recipient set** (no private key). Persist the **encrypted** submission locally *first* (resumable; plaintext never at rest) — then auth/push (C3 conflict resolution).
4. Branch `byreis/<add|replace>-<key>-<ts>`, commit the unsigned submission artifact, open GitHub PR with policy title + justification. Print PR URL + "you cannot view this value again."
5. Never writes the live `secrets/**` file; one artifact per submission branch (T5).

### C. Admin review & merge (`byreis review` / `merge`) — the authenticity binding

1. ADMIN only (mode-gated). `byreis review --pr N`: fetch the submission, **decrypt the submitted value(s)**, render plaintext + key + env + author + justification + **ADD/REPLACE classification** + format validation. Emit a **pinned full-artifact SHA** of exactly what was shown (T1, T2).
2. `byreis merge --pr N --expect <sha>`: **fail closed if the artifact moved** since review (T2). Re-validate recipient set against a **fresh signature-verified registry fetch** (C-4); re-encrypt to current admins if the set drifted. Increment the counter from the **registry/audit authority** (C-3), build canonical manifest bytes incl. `project_id`+`file` (C-2), **Ed25519-sign**, write the file-of-record, transactionally bump `last_accepted_counter` in the registry/audit store.
3. Post-merge **integrity check mandatory**: the live file must `VerifyOfRecord` and round-trip-decrypt for every current recipient; failure aborts the merge leaving the live file untouched (REQ-B-002, REQ-C-001).

### D. Admin read (`get`/`decrypt`/`edit`) & E. CI decrypt

`get` masked-in-TTY/plain-piped/`--json`; `decrypt` whole-file (env/yaml/json) for CI; `edit` via `$EDITOR`, re-encrypt to all current recipients, abort-on-failure (no clobber). CI deploy path uses **`VerifyOfRecord`** with `BYREIS_KEY` — signature mandatory, offline-without-trusted-key is a hard error (C-1/T9). All four denied in CONTRIBUTOR mode (REQ-B-001).

---

## 8. Tech Stack

Go 1.22+ (dev/CI on 1.24.x). Core deps: `filippo.io/age` (encryption + recipients), Go stdlib `crypto/ed25519` (manifest signing), `github.com/spf13/cobra` (CLI), `github.com/go-git/go-git/v5` (registry fetch). TUI (v0.2): `charmbracelet/bubbletea`+`lipgloss`+`huh`. Keychain: `github.com/zalando/go-keyring`. Logging: `github.com/rs/zerolog`. Test: `stretchr/testify`, `net/http/httptest`.

**ADRs `reis-principal-go` must produce before BUILD:**
- **Signed-commit verification**: go-git's signature support is limited — decide go-git vs shelling to `git verify-commit` (lean: shell to `git` for verification, go-git for transport). Pin the trusted-signer anchor mechanism (§2).
- **No SOPS dependency in core** (C-8). `export --sops` (v0.2) is an isolated one-way adapter.
- **GitLab** deferred (v0.2); when added, `gitlab.com/gitlab-org/api/client-go` (not the unmaintained `xanzy/go-gitlab`).
- Counter/audit store shape in the registry (C-3) and its transactional update at merge.

---

## 9. Locked v0.1 Scope (from `design/REQUIREMENTS.md` — PM⇄BA signed off)

**The one critical thing:** the asymmetric **submit → review → merge** spine, keyless and provably write-only. Everything else is scaffolding.

| Tier | Items |
|---|---|
| **v0.1 MUST (P0)** | REQ-M-001 mode detection · REQ-B-001 asymmetric-guarantee ship gate · REQ-A-001 `init` · REQ-A-002 `doctor` · REQ-A-003/C-002 `submit` · REQ-C-003 add-vs-replace · REQ-B-002 `review`/`merge` · REQ-B-006 admin `get`/`decrypt`/`edit` · REQ-B-003 registry client · REQ-A-006 error UX · REQ-C-001 concurrent-submission safety |
| **v0.1 SHOULD (P1)** | REQ-A-004 CI submit · REQ-B-004 registry rollback protection · REQ-B-005 audited bootstrap · REQ-C-004 offline-safe · REQ-C-005 resumable submit · REQ-C-006 key-recovery docs |
| **v0.2 NEXT** | TUI · `rotate`/`share`/`revoke` · `request-access` · GitLab · bulk submit · self-service `admin add/remove` · audit-log sync · `export --sops` |
| **REJECTED** | anomaly/ML detection · leaked-secret DB · web dashboard · KMS/YubiKey/HSM (v0.1) · multi-registry (v0.1) · per-env distinct keys (v0.1) |

≤~8 commands, GitHub-only, no TUI in v0.1. Constraint: every requirement traces to the spine or a P0 must-item; no feature whose correctness needs ML or a hosted service.

---

## 10. Implementation Roadmap (vertical-slice first)

The format gate is **resolved** (Model B), so DESIGN is unblocked *provided C-1…C-8 are designed in*.

- **Phase D — DESIGN** (`reis-principal-go`): interface contracts (`Encryptor`/`GitProvider`/`RegistryClient`), the ADRs in §8, and a normative spec of the manifest canonical encoding + the two verify entry points (C-1) + counter authority (C-3). **Gate:** design APPROVED + `reis-crypto-auditor` re-review confirming C-1…C-8 are encoded.
- **Phase 0 — Skeleton:** `go.mod`, Makefile (`build`/`test`/`lint`/`install`), golangci-lint, CI, `byreis version`, mode detector (REQ-M-001) TDD.
- **Phase 1 — Crypto core (TDD, `reis-go-tdd`):** native multi-recipient encrypt, manifest canonical bytes + Ed25519 sign/verify, `VerifyOfRecord`/`VerifySubmission`. Full negative vectors (§11). → `reis-crypto-auditor`.
- **Phase 2 — Spine vertical slice:** `submit` (keyless) → `review`/`merge` (decrypt+pin+sign) end-to-end on GitHub, with `init`/`doctor`. This is the earliest point the differentiator is demonstrable — prioritize it over breadth.
- **Phase 3 — Registry hardening (`reis-backend`):** fetch+signature verify+offline cache (REQ-B-003), rollback protection + counter/audit authority (REQ-B-004, C-3), bootstrap (REQ-B-005).
- **Phase 4 — Admin read path + CI** (REQ-B-006, REQ-A-004) + error UX polish (REQ-A-006).
- **Phase 5 — QUALITY/SECURITY gate:** `/reis-qa` + `reis-crypto-auditor` + `reis-threat-modeler`; REQ-B-001 ship gate must be green.
- **v0.2:** TUI, rotate/share/revoke, GitLab, `export --sops`.

---

## 11. Testing Strategy

Pyramid ~60/30/10. Target >80% coverage on `core` (reject coverage theater — a covered line with no security assertion is a gap).

**REQ-B-001 is a v0.1 ship-blocking gate:** a CONTRIBUTOR-mode process with no private key by *any* means, given a real encrypted file, must be unable to emit a plaintext value via any command/flag/`--json`/pipe/env/error — proven by an automated suite. Red here blocks ship regardless of other green tests.

**Required negative vectors (C-6 — missing any = HIGH at QA gate):** round-trip · single-byte tamper (AEAD) · wrong-recipient · rollback (resurrect old counter) · recipient-strip · ciphertext-swap · key reorder/delete · **cross-file/cross-project transplant** (C-2) · unsigned-artifact-presented-to-`VerifyOfRecord` (rejected) · signed-artifact-with-forged-key · **an explicit test characterizing what `VerifySubmission` does NOT catch** · every (command × mode) incl. denied + config/env/flag bypass · merge `--expect` mismatch (T2) · post-merge integrity-abort leaves live file untouched. Determinism: no real network/clock/fs/keychain in unit tests; `go test -race ./...` is a merge gate.

---

## 12. Risks & Mitigations

| Risk | L | I | Mitigation |
|---|:--:|:--:|---|
| C-1…C-8 not fully encoded before BUILD | Med | Crit | DESIGN gate requires `reis-crypto-auditor` re-review; BUILD blocked otherwise |
| Asymmetric guarantee not machine-provable | Low | Crit | REQ-B-001 ship gate; spike already demonstrated feasibility |
| Branch protection on `secrets/**` not enforced by adopters | Med | High | Documented hard prerequisite + `doctor` checks it; T6 mitigation depends on it |
| Solo-maintainer burnout | High | High | Scope deliberately minimal (§9); any creep back to v1's full §8 re-introduces this |
| go-git can't verify signed commits robustly | Med | Med | ADR: shell to `git verify-commit`; fail closed |
| Losing the "friendly" claim without a TUI | Med | Med | REQ-A-006 error UX elevated to P0 |

---

## 13. Open Questions — status

- **Format (Model A/B)** — **RESOLVED: Model B**, audited.
- **First-admin bootstrap** — explicit audited command + manual fingerprint confirmation, no silent TOFU (REQ-B-005).
- **Counter authority** — **RESOLVED: registry/audit store, per-(project,file)** (C-3).
- **Multi-registry / per-env keys / KMS** — deferred to v0.2+ (rejected for v0.1).
- **Audit-log destination** — local append-only in v0.1; repo/SIEM sync v0.2.

---

## 14. Operating Model

This repo runs as a `reis-*` agent team via the `/reis` orchestrator through `SPIKE → ANALYSIS → DESIGN → BUILD → QUALITY/SECURITY → DONE`, each phase gated. See `CLAUDE.md` for the team directory and the binding engineering standards (Clean Architecture dependency rule, SOLID, system-design robustness) that `reis-principal-go` enforces at review. Security-relevant code is never self-certified (`reis-crypto-auditor` + `reis-threat-modeler`); nothing ships without `reis-qa-lead`'s verdict.

**Current state:** SPIKE ✅ (Model B, audited) · ANALYSIS ✅ (scope locked) · **next gate: DESIGN** — `reis-principal-go` produces contracts/ADRs encoding C-1…C-8, then `reis-crypto-auditor` re-review before BUILD.

---

## 15. Quick Start for the Next Phase

```
Run /reis. SPIKE and ANALYSIS gates are signed off (Model B chosen + audited;
design/REQUIREMENTS.md locked). Proceed to DESIGN: dispatch reis-principal-go to
produce interface contracts + the §8 ADRs + a normative spec of the manifest
canonical encoding, the two verify entry points (C-1), project/file identity
binding (C-2), and the registry-side counter authority (C-3). DESIGN gate =
design APPROVED AND reis-crypto-auditor confirms constraints C-1…C-8 are
encoded. Do not start BUILD until that gate passes.
```

---

*v2 — synthesized from the SPIKE + ANALYSIS gate artifacts. v1 preserved at `PLAN.v1.md`. The asymmetric guarantee is the product; everything else serves it.*
