# byreis — Locked Requirements Spec (ANALYSIS gate artifact)

Status: **LOCKED** · Phase: ANALYSIS · Date: 2026-05-19 · Owner: reis-ba (Principal BA)
Consumed by: `reis-principal-go` (DESIGN), `reis-qa-lead` (test basis), feeds the PLAN.md rewrite.
Procedure: `/reis-requirements` — PM frame → 3-lens BA pod (Contributor/DX, Admin/Security, Ops/Edge/Market) → synthesis → BA⇄PM scope debate → lock.

> Execution note: the Agent tool was unavailable in this run, so the Principal BA executed all three analyst lenses, the PM scope frame, and the PM debate in-process rather than via spawned sub-agents. The lens structure, conflict surfacing, and debate record are preserved exactly as the procedure requires. Findings are evidence-backed (PLAN.md citations + 2026 market research).

---

## 0. Frame & central finding

**Target:** full rewrite of `PLAN.md` so byreis is the best, *friendliest* Go secrets encode/decode tool that covers real 2026 market needs — without violating its core promise (contributors write secrets, never read them) and without sinking a solo maintainer.

**Open questions carried in:** encrypted-file format (Model A SOPS-compat vs Model B native asymmetric); how a keyless contributor can edit a *shared* file at all; registry trust bootstrap; CI consumer ergonomics; scope vs burnout.

### 0.1 The central finding (drives the whole spec)

The "known critical flaw" is **confirmed and is the spec's pivot**:

- SOPS encrypts every value in a file with one **data key**, wrapped once per recipient public key. Changing/adding any value requires the **data key**, obtained only by **decrypting a wrapped slot with a private key**. SOPS additionally computes a **MAC over all values**; editing requires decrypting existing values to recompute it. (Confirmed: getsops docs / encryption-protocol — see Sources.)
- **Consequence:** in stock SOPS a contributor holding only public keys **cannot add or modify a key in an existing `prod.enc.yaml`**. They can only emit a brand-new file where they supply *every* value — which is not byreis's "add one secret to an existing environment" job.
- Therefore PLAN.md §4 ("use SOPS-compatible format") **directly contradicts** PLAN.md Workflow B (contributor adds `STRIPE_API_KEY` to an existing environment). They cannot both be true. This is the single most important thing the rewrite must resolve.

**Implication for the spec:** the *contributor write path* is not a UX detail — it is a cryptographic format decision. Every requirement whose correctness depends on how a keyless contributor's value lands in the repo is marked **GATED-ON-SPIKE** and offers an explicit Model A vs Model B branch. We assume no format.

The two candidate models the spike must rule on:

- **Model A — SOPS-compatible.** Keep `.enc.yaml` readable by stock `sops`. Forces contributor submissions to be **out-of-band**: contributor encrypts their *single* value to admin pubkeys as a standalone artifact (separate file / PR payload), and an **admin (or trusted CI with a key) merges it into the live SOPS file** at review time. Contributor never edits the live file. Wins ecosystem interop; the asymmetric merge is a real engineering cost and the contributor PR is not itself a valid SOPS file.
- **Model B — native asymmetric.** byreis-native per-key envelope format (each key independently encrypted to recipient pubkeys, no shared data key, no whole-file MAC). A keyless contributor *can* add/replace a single key directly and the file stays valid. Loses drop-in `sops` CLI interop (needs `byreis decrypt`); a `sops`-importer/exporter can bridge.

This decision is owned by `/reis-crypto-spike` and is a **hard blocker on DESIGN**.

### 0.2 Invariants every requirement is held to

1. Access boundary = **private-key possession**. Registry is governance/identity only, never access control.
2. Contributor-runnable flows must be **implementable with public keys only** (no private key anywhere in the contributor path, incl. CI submit).
3. A contributor-runnable requirement must be **provably incapable of revealing any plaintext value** and **must not directly write/clobber the live secrets file**.
4. Mode is derived from **cryptographic reality**, never config/flags. Default = contributor; promotion explicit + audited.
5. Format-dependent requirements are **GATED-ON-SPIKE** — never assume Model A or B.

---

## 1. PM scope frame (guardrails the pod analyzed within)

Produced as the first step so the pod analyzed inside real boundaries.

**The single "if only one thing ships" feature:** the **asymmetric submit → review → merge spine** — a keyless contributor turns a plaintext value into a reviewable PR an admin can decrypt, validate, and merge. Everything else (init, registry, TUI, rotate) is scaffolding around this. If the spine is not smooth and provably write-only, byreis has no reason to exist over `sops`+`age`.

**Tiered scope:**

| Tier | Items |
|---|---|
| **v0.1 — MUST** | Mode detection (crypto-derived); `init`; `doctor`; `submit` (keyless, write-only, GitHub PR); `review` (admin decrypt+validate+approve); admin read path (`get`/`decrypt`/`edit`); CI decrypt consumer; registry client (fetch+cache+signature verify, offline-first); structured/actionable errors + `--json` + exit codes. |
| **v0.2 — NEXT** | TUI (admin); `rotate`; `share`/`revoke`; `request-access`; GitLab provider; bulk submit; `admin add/remove` self-service; audit log sync to repo. |
| **Not now — REJECTED** | Anomaly/ML detection (PLAN §5/§8 — unmaintainable solo, low v0.1 value); web dashboard (scope explosion); KMS/YubiKey/HSM backends (v0.2+, age covers v0.1); multi-registry (single registry v0.1, PLAN §12); leaked-secret DB lookup (external dep, privacy surface); per-environment distinct encryption keys (start per-file, PLAN §12). |

**Burnout/time constraints the pod must respect:** ≤8 commands in v0.1; GitHub-only; no TUI in v0.1; every requirement must trace to the spine or to a v0.1 must-item; prefer one correct path over many options; no feature whose correctness needs ML or a hosted service.

**PM positioning statement (honest, 2026):** Infisical (MIT, self-hostable, polished UI) and Doppler/1Password own centralized + great UX; SOPS+age owns zero-infra GitOps but is symmetric (everyone with a key reads everything) and arcane; agenix/sops-nix carry painful manual rekeying and are Nix-bound; git-crypt is unmaintained and whole-file-only. **byreis's only defensible wedge: zero-infra GitOps + provably asymmetric write-only contribution + friendly UX.** Not "another secrets manager" — "the safe way to let people *add* secrets they must never *read*, in plain git." Lose the asymmetric guarantee and byreis is a worse SOPS.

---

## 2. Lens findings (condensed)

### Lens A — Contributor & DX (jobs: onboard fast, submit safely, never get blocked)

- Time-to-first-value is the make-or-break metric. PLAN §11 targets <2 min to first PR. The biggest threat is auth + registry setup friction before any value is delivered.
- `submit` must be runnable by someone who has *nothing but the registry URL* and a GitHub login. No key generation, no admin contact.
- Strong DX need: contributor must be told, unambiguously and before confirming, "you will not be able to see this value again." Irreversibility must be explicit, not surprising.
- Interrupted submit (network drop mid-push) must be resumable, not "start over and re-type the secret."
- Error UX is a primary differentiator vs SOPS's arcane errors: every failure must say what failed and the exact next action.
- Non-interactive/CI submit (`--value`, stdin) needed for automation, still keyless.
- Pointer to Lens B: contributor must never be able to overwrite an existing key's value silently (sabotage / accidental clobber) — surfaced as a conflict below.

### Lens B — Admin & security governance (jobs: trust the registry, review fast, keep the asymmetric guarantee true)

- Mode detection is the security spine; PLAN §3 order is sound but must **fail closed**: missing/0600-violating/corrupt key → refuse or downgrade, never silently admin.
- The asymmetric guarantee must be **provable in tests**, not asserted: a contributor-mode process with no private key, given a real encrypted file, must be unable to emit plaintext through *any* command, flag, or env var.
- Registry trust is circular (registry says who's admin; admins control the registry). Bootstrap (first admin) needs an explicit, audited, manually-verified path — never an implicit trust-on-first-use that an attacker can seed.
- Signature verification on registry fetch is mandatory and must fail closed; an unsigned/invalid-signature registry HEAD must block admin promotion, not just warn.
- Review must show the **decrypted submitted value + format validation + structural diff** (what key, what env, add vs replace) so an admin can approve in seconds (PLAN §11 <30s) without being tricked into clobbering prod.
- Threat gaps to encode: (a) contributor replaces an existing prod key's value (sabotage) — review must flag add-vs-replace explicitly; (b) git history retains old ciphertext after revoke (document, not solve in v0.1); (c) registry rollback to an older signed HEAD re-enabling a removed admin — needs monotonic/commit-recency check; (d) structural integrity: a malformed submission must never corrupt the live file on merge.
- Pointer to Lens A: double-entry confirmation on submit is a security ask that fights DX's "fewer prompts" — conflict below.

### Lens C — Ops, edge cases & market (jobs: scale, survive offline/conflicts, beat competitors on friendliness)

- Concurrent submissions to the same environment file → PR/branch and (under Model A) merge conflicts. Must be deterministic and non-destructive; never "last writer silently wins on a secret."
- Offline-first: registry network failure must fall back to cache and *work*, with a visible staleness warning; stale cache must not silently grant or revoke admin in a way that surprises.
- Scale across many projects: registry is shared; per-project config must not require copying admin lists (PLAN §2 already argues this — keep).
- Key recovery: lost admin private key → documented recovery via other admins re-encrypting; if only one admin exists, that is an accepted, documented data-loss risk for v0.1 (not solved).
- **Market reality (2026, cited):** SOPS+age public-key encryption *does* let contributors encrypt without decrypting — **but only for files they create whole**; editing a shared file needs the private key (data-key + MAC). So byreis's wedge is specifically *editing a shared environment file write-only*, which stock SOPS cannot do — this is real and defensible. Infisical/Doppler are server-based; byreis's zero-infra GitOps + asymmetric is genuinely unoccupied. git-crypt unmaintained; agenix/sops-nix rekey pain is a friendliness opening (`rotate` must not be 20 password prompts).
- Scope-cut candidates agreeing with PM: anomaly detection, leaked-secret DB, web dashboard, KMS in v0.1.

---

## 3. Synthesized cross-lens conflicts (explicit — not papered over)

| # | Conflict | Lens A position | Lens B position | Resolution (locked) |
|---|---|---|---|---|
| C1 | Double-entry secret confirmation on submit | Fewer prompts; re-typing a long secret is hostile, esp. paste | Double-entry prevents silent typo committed forever (irreversible) | **Compromise:** double-entry **only in interactive TTY**; **single entry** for piped/`--value`/CI (the operator already controls the source). Plus a mandatory explicit irreversibility acknowledgement (one keystroke, not re-type). Encoded in REQ-C-002. |
| C2 | Contributor replacing an existing key's value | Contributors legitimately *update* secrets (rotated API key) — must be allowed | Silent replace of a prod value by a non-admin is a sabotage/clobber vector | **Resolution:** replace is **allowed but never silent**. Submit must detect add-vs-replace and force an explicit "this REPLACES an existing value" acknowledgement; review **must render add-vs-replace prominently**. Contributor still cannot see old or new plaintext. REQ-C-003 / REQ-B-002. |
| C3 | Auth before value (time-to-first-value) | Don't block first submit on OAuth dance | Submitting via PR requires authenticated git write | **Resolution:** `submit` collects + encrypts the value and **persists the encrypted submission locally first**, then does auth/push; if auth fails the encrypted artifact is queued and resumable — value never re-typed, never stored in plaintext. REQ-A-003 / REQ-C-005. |
| C4 | Offline cache vs correct admin set | Ops wants it to "just work" offline | Security: stale cache must not wrongly grant/revoke admin | **Resolution:** offline uses cache and works, but **admin promotion** specifically requires either a fresh signature-verified fetch or a cache within policy TTL **and** prints a staleness warning; expired cache → downgrade to contributor with explicit reason, never silent admin. REQ-B-004 / REQ-C-004. |
| C5 | SOPS-compat (market/interop) vs the asymmetric write path (the differentiator) | Market wants `sops` interop | The differentiator requires keyless edit of a shared file, which SOPS-compat forbids | **Unresolved by design — GATED-ON-SPIKE.** This is the Model A/B decision. The spec specifies behavior for *both* branches and forbids assuming either. This is the top gating risk. |

---

## 4. PM ⇄ BA scope debate (mandatory; recorded)

| Topic | BA asked for | PM pushback | Converged outcome |
|---|---|---|---|
| `share`/`revoke`/`rotate` in v0.1 | Admin lifecycle is core to "asymmetric" being real | Recipient management is heavy and not the spine; SOPS users live without friendly rotate today | **Moved to v0.2.** v0.1 ships the spine + admin *read/review*. Rotate/share documented as known v0.1 gap. BA conceded — time/burnout case stronger. |
| TUI in v0.1 | Friendliness is the wedge; TUI is the "wow" | TUI is weeks of work, not the differentiator; a smooth CLI submit *is* the friendliness | **TUI v0.2.** v0.1 must instead over-invest in CLI error UX + prompts. BA conceded; added REQ-A-006 (error UX) as a hard v0.1 must to keep "friendly". |
| `request-access` in v0.1 | Closes the contributor→admin loop | Manual pubkey hand-off is fine for v0.1; self-service is polish | **v0.2.** Documented manual bootstrap path stays (REQ-B-005). BA conceded. |
| Asymmetric guarantee test as a v0.1 gate | Must be provable, not asserted | Agreed — this is non-negotiable for the wedge | **Kept, elevated:** REQ-B-001 is a v0.1 ship-blocking acceptance gate. PM conceded scope cost here. |
| Concurrent-submission correctness | Must be deterministic/non-destructive | Edge case, could defer | **Kept in v0.1 (must not be destructive); "friendly auto-resolve" deferred to v0.2.** v0.1 must at minimum *fail safe and tell the user*, never silently lose a secret. Split into REQ-C-001 (v0.1 safety) / future (v0.2 ergonomics). |
| Model A/B | Need it to write any format-dependent req | Cannot lock a format that isn't validated | **Both agree:** all format-dependent reqs GATED-ON-SPIKE; DESIGN blocked until spike verdict. |

Net scope change from PLAN.md: contributor/admin spine + safety hardened; rotate/share/TUI/request-access/GitLab/bulk explicitly deferred; anomaly/leaked-DB/dashboard/KMS rejected.

---

## 5. Locked requirements

Priority: **P0** = v0.1 ship-blocking · **P1** = v0.1 should · **P2** = v0.2.
Mode: C=contributor, A=admin, S=super-admin.

### Mode & security core

**REQ-M-001 — Crypto-derived mode detection**
*User story:* As any user, I want my access level decided by what I can cryptographically do, so config or flags can never grant me admin.
*Mode:* C/A/S · *Priority:* P0
*Acceptance:*
- Given no private key file present, When byreis resolves mode, Then mode = CONTRIBUTOR and no admin command is permitted.
- Given a private key file with permissions looser than 0600, When byreis runs, Then it refuses with a non-zero exit and an actionable fix hint (chmod), and does **not** fall back to admin.
- Given a private key present and 0600 but it cannot decrypt any project file, When mode resolves, Then mode = CONTRIBUTOR.
- Given a key that can decrypt a project file but whose public key is absent from a signature-verified registry, When mode resolves, Then mode = CONTRIBUTOR **with an explicit warning** stating the key is unregistered.
- Given a 0600 key that decrypts a project file and whose public key is present in a signature-verified registry, When mode resolves, Then mode = ADMIN and the promotion is written to the audit log.
- Given any ambiguity/error in the chain, Then resolution fails closed to CONTRIBUTOR (or hard error for the perms case), never ADMIN.
*Security:* Invariant 4. Test every (command × mode) incl. flag/config/env bypass attempts.
*Deps:* none (format-independent).

**REQ-B-001 — Provable asymmetric guarantee (ship-blocking gate)**
*User story:* As a security owner, I need a machine-checkable proof that a keyless contributor can never reveal a plaintext value, so the wedge is real.
*Mode:* C · *Priority:* P0
*Acceptance:*
- Given a process in CONTRIBUTOR mode with no private key available by any means (no file, no `BYREIS_KEY`, no `BYREIS_KEY_FILE`, no keychain), And a real encrypted project file, When any contributor-permitted command, flag combination, `--json`, or env var is exercised, Then no plaintext secret value is ever emitted to stdout/stderr/files/logs/exit data.
- Given the same, When `get`/`decrypt`/`edit` are attempted, Then they are denied by the mode policy with a non-zero exit and a clear reason — not attempted-and-failed.
- Given the same, When a contributor command writes output, Then no path writes to or truncates the live `secrets/*.enc.yaml` of an existing key (see REQ-C-003 add-vs-replace, REQ-C-001 conflict safety).
- This test suite is a **v0.1 release gate**: red here blocks ship regardless of other green tests.
*Security:* Invariants 2 & 3. Hand directly to `reis-qa-lead` as the canonical asymmetric-guarantee suite; reviewed by `reis-crypto-auditor` + `reis-threat-modeler`.
*Deps:* none for the *guarantee*; the *mechanism that satisfies it on submit* is GATED-ON-SPIKE (see REQ-C-003).

### Contributor / DX

**REQ-A-001 — `byreis init` (keyless onboarding)**
*User story:* As a new contributor with only a registry URL and a git login, I want setup in well under 2 minutes with zero key handling.
*Mode:* C/A/S · *Priority:* P0
*Acceptance:*
- Given a registry URL, When I run `byreis init`, Then byreis fetches the registry read-only, verifies commit signatures, lists projects, and lets me pick one, with no private-key step required for contributor onboarding.
- Given signature verification fails, Then init stops with a clear, actionable error and does **not** write project config.
- Given success, Then it writes project config, reports mode = CONTRIBUTOR, and prints the next commands; total interactive time budget < 120 s on a normal connection.
- Given `--non-interactive` with required flags, Then init completes with no prompts and machine-readable output.
*Security:* No key material handled in contributor onboarding (Invariant 2).
*Deps:* registry client (REQ-B-003). Format-independent.

**REQ-A-002 — `byreis doctor`**
*User story:* As any user, I want one command that tells me exactly what's wrong and how to fix it.
*Mode:* C/A/S · *Priority:* P0
*Acceptance:*
- Given any environment, When I run `byreis doctor`, Then it reports: detected mode + the reason, registry reachability + signature status + cache staleness, key file presence/perms, git auth status — each with an explicit OK/PROBLEM and a fix hint for every PROBLEM.
- Given a key with bad perms, Then doctor reports the exact chmod to run.
- Given offline, Then doctor reports cache age and that it is operating from cache, not an error.
- Exit code non-zero iff at least one PROBLEM.
*Security:* Must not print any plaintext secret or private key material.
*Deps:* none. Format-independent.

**REQ-A-003 / REQ-C-002 — `byreis submit` (keyless, write-only) — GATED-ON-SPIKE**
*User story:* As a contributor, I want to add or update a secret for an environment so an admin can review and merge it, without ever being able to read existing or my own submitted secrets afterward.
*Mode:* C/A/S · *Priority:* **P0 (the spine)**
*Acceptance (format-independent):*
- Given CONTRIBUTOR mode with only registry public keys, When I run `byreis submit` for an environment+key, Then the value is encrypted to the current admin recipient set with **no private key required at any point**.
- Given an interactive TTY, Then the value is entered with double-entry confirmation **and** an explicit irreversibility acknowledgement before anything is sent.
- Given piped input / `--value` / stdin / `--non-interactive`, Then single entry, no re-prompt, still keyless; secret is read without echo and never written to logs or shell history by byreis.
- Given success, Then byreis creates a branch (`byreis/<add|replace>-<key>-<timestamp>`), commits the encrypted submission, opens a GitHub PR with the policy title/justification, prints the PR URL, and tells the contributor the value cannot be viewed again.
- Given any failure after the value was captured, Then the encrypted submission is persisted locally and resumable; the plaintext is never persisted and never re-requested.
- Given a value failing a configured validation pattern, Then submit refuses **before** any commit, with the rule that failed and an example.
*Acceptance (GATED-ON-SPIKE — both branches specified, choose at DESIGN per spike):*
- **If Model A (SOPS-compat):** the contributor PR payload is a standalone encrypted artifact (not an in-place edit of the live SOPS file); merge into the live file is performed by an admin/trusted-key step during `review` (REQ-B-002). Acceptance: stock `sops` can still decrypt the post-merge file; the contributor branch never contains a re-keyed live file; no private key used by the contributor.
- **If Model B (native):** the contributor directly produces a valid post-add/replace native file because each key is independently envelope-encrypted; no shared data key, no whole-file MAC. Acceptance: `byreis decrypt` round-trips the file after a keyless contributor add; the contributor still cannot decrypt any value.
*Security:* Invariants 1–3. Conflicts C1, C3 resolved here. The *mechanism* is format-dependent → **GATED-ON-SPIKE**; the *guarantee* (REQ-B-001) is not.
*Deps:* `/reis-crypto-spike` (BLOCKING), registry client, git provider.

**REQ-C-003 — Add-vs-replace must be explicit and non-clobbering — GATED-ON-SPIKE**
*User story:* As a contributor I may legitimately update a secret, but I must never silently overwrite a production value (mine or anyone's).
*Mode:* C · *Priority:* P0
*Acceptance:*
- Given the target key does not exist in the environment, When I submit, Then the action is labeled ADD.
- Given the target key already exists, When I submit, Then byreis detects it as REPLACE **without decrypting the old value**, requires an explicit "this replaces an existing value" acknowledgement, and labels the PR/branch REPLACE.
- Given CONTRIBUTOR mode, Then no submit path truncates or in-place rewrites the live secrets file for an existing key outside the reviewed PR mechanism (Model A: never touches live file; Model B: produces a reviewable diff, never a force-clobber on the contributor branch's base).
*Security:* Conflict C2 resolution. Detection of key existence must be doable without plaintext (key names are not secret values; confirm this holds under the chosen format — GATED-ON-SPIKE).
*Deps:* spike (existence detection depends on format layout).

**REQ-A-006 — Friendly, actionable error UX (TUI replacement for v0.1 friendliness)**
*User story:* As any user, every failure should tell me what went wrong and exactly what to do next — this is byreis's friendliness in v0.1.
*Mode:* C/A/S · *Priority:* P0
*Acceptance:*
- Given any non-zero exit, Then stderr contains: a one-line what-failed, the most likely cause, and a concrete next action (command/flag/path).
- Given a TTY, Then output is colorized and secrets are masked; given a pipe, Then plain output; `--json` yields a stable machine schema with an `error` object.
- No error message ever contains a plaintext secret or private key.
- Exit codes are documented and distinct per failure class.
*Security:* No secret/keys in errors/logs (binding standards).
*Deps:* none. Format-independent.

**REQ-A-004 — CI/CD contributor submit (keyless automation)**
*User story:* As a pipeline, I want to submit a secret non-interactively without any private key.
*Mode:* C · *Priority:* P1
*Acceptance:*
- Given `BYREIS_NON_INTERACTIVE=1`, a registry URL, a value via stdin/`--value`, and a git token, When CI runs `byreis submit`, Then it produces a PR with no prompts, no private key, and machine-readable output (PR URL in `--json`).
- Given no git token, Then it fails closed with an actionable error and does not block on a prompt.
*Security:* Invariant 2.
*Deps:* git provider; submit (REQ-A-003) → inherits GATED-ON-SPIKE.

### Admin / governance

**REQ-B-002 — `byreis review` (decrypt submitted value + validate + safe merge) — GATED-ON-SPIKE**
*User story:* As an admin, I want to see the actual submitted value, its validation, and exactly what it changes, then approve in seconds without risk of clobbering prod.
*Mode:* A/S · *Priority:* P0
*Acceptance (format-independent):*
- Given ADMIN mode and a pending submission PR, When I run `byreis review --pr N`, Then byreis decrypts and displays the submitted value, the author, environment, justification, the ADD/REPLACE classification, and validation results.
- Given REPLACE, Then the old-vs-new distinction is rendered prominently and approval requires explicit confirmation.
- Given CONTRIBUTOR mode, Then `review` is denied by mode policy.
- Given approval, Then the live secrets file ends in a valid, decryptable state for all current recipients (post-merge integrity check is mandatory; a structurally invalid result aborts the merge and leaves the live file untouched).
*Acceptance (GATED-ON-SPIKE):*
- **Model A:** the admin/trusted-key merge step re-keys the standalone submission into the live SOPS file; post-merge file must validate with stock `sops`.
- **Model B:** merge is the native file with the new/updated envelope; `byreis decrypt` must round-trip for every current recipient.
*Security:* Structural-integrity threat (Lens B): malformed submission must never corrupt the live file. Invariant 1.
*Deps:* spike (BLOCKING), git provider, encryption core.

**REQ-B-006 — Admin read path: `get` / `decrypt` / `edit`**
*User story:* As an admin, I need to read, fully decrypt, and edit secrets, with masking by default.
*Mode:* A/S · *Priority:* P0
*Acceptance:*
- Given ADMIN mode, When `byreis get KEY`, Then the value is shown masked in a TTY, plain when piped, `--json` structured.
- Given ADMIN mode, When `byreis decrypt FILE`, Then the full file decrypts; output format selectable (env/yaml/json) for CI.
- Given ADMIN mode, When `byreis edit FILE`, Then it opens in `$EDITOR` and re-encrypts to all current recipients on save; a failed re-encrypt aborts without clobbering.
- Given CONTRIBUTOR mode, Then all three are denied by mode policy (ties to REQ-B-001).
*Security:* Invariant 1; masking/TTY rules; no plaintext to logs.
*Deps:* encryption core. Decrypt output format is format-independent; underlying decode is **GATED-ON-SPIKE** (Model A uses sops/age, Model B native).

**REQ-B-003 — Registry client: fetch + signature verify + offline cache**
*User story:* As any user, I need the admin registry fetched read-only, integrity-verified, and usable offline from cache.
*Mode:* C/A/S · *Priority:* P0
*Acceptance:*
- Given a reachable registry, When fetched, Then commit signatures are verified; an unsigned or invalid-signature HEAD is rejected and **must block ADMIN promotion** (not merely warn) while still allowing contributor read of last-known-good cache.
- Given network failure, Then byreis uses the cache and operates, printing a staleness warning with cache age.
- Given cache older than policy TTL, Then admin promotion is withheld with an explicit reason (downgrade to contributor), but contributor flows still work.
- byreis never writes to the registry except via the explicit admin add/remove flow (v0.2).
*Security:* Trust-root: fail closed on signature; conflict C4 resolution.
*Deps:* none cryptographically tied to secret format. Format-independent.

**REQ-B-004 — Registry rollback / freshness protection**
*User story:* As a security owner, I need protection against an attacker presenting an older but validly signed registry state that re-enables a removed admin.
*Mode:* C/A/S · *Priority:* P1
*Acceptance:*
- Given a previously observed registry HEAD, When a fetched HEAD is older than the last-observed (non-ancestor / regressed), Then byreis refuses to use it for admin promotion and warns explicitly.
- Given a legitimate fast-forward, Then it updates normally.
- Cache stores last-observed HEAD + timestamp; tampering with the local cache to fake freshness must not grant admin (perms/integrity on cache).
*Security:* Replay/rollback threat (Lens B).
*Deps:* registry client. Format-independent.

**REQ-B-005 — Documented, audited bootstrap for the first admin**
*User story:* As the first super-admin, I need an explicit, verifiable way to establish trust without an attacker being able to seed it.
*Mode:* S · *Priority:* P1
*Acceptance:*
- Given an empty/new registry, When bootstrapping, Then the first admin is established only via an explicit command with manual verification (e.g., displayed key fingerprint the operator must confirm), and the action is audit-logged.
- Given an existing registry, Then bootstrap refuses (no silent re-bootstrap / no trust-on-first-use that auto-accepts an unknown signer).
*Security:* Trust-root circularity (Lens B). No implicit TOFU promotion.
*Deps:* registry client. Format-independent.

### Ops / edge

**REQ-C-001 — Concurrent submissions must be safe (never lose a secret)**
*User story:* As an ops owner, two contributors submitting to the same environment must never result in a silently lost or clobbered secret.
*Mode:* C/A/S · *Priority:* P0 (safety only; friendly auto-resolve is v0.2)
*Acceptance:*
- Given two submissions targeting the same environment, Then each lands on its own branch/PR; neither overwrites the other's branch.
- Given a merge conflict at review/merge time, Then byreis detects it and refuses to merge with an explicit, actionable message; it must **never** auto-resolve by dropping a secret.
- Given a stale base (live file moved since submission), Then review surfaces this and requires re-validation before merge; the live file is never left invalid.
*Security:* Structural integrity; no silent clobber (Invariant 3, conflict C2).
*Deps:* spike (conflict shape differs Model A vs B) → **GATED-ON-SPIKE** for the *resolution mechanics*; the *safety guarantee* is not.

**REQ-C-005 — Resumable / crash-safe submission**
*User story:* As a contributor on a flaky network, an interrupted submit must not force me to re-type the secret.
*Mode:* C · *Priority:* P1
*Acceptance:*
- Given a submit interrupted after value capture but before PR creation, When I re-run, Then byreis offers to resume from the locally persisted **encrypted** submission; plaintext is never persisted.
- Given resume, Then it completes the branch/commit/PR without re-prompting for the value.
- Given the user declines resume, Then the pending encrypted artifact is safely discardable.
*Security:* No plaintext at rest (binding standards); conflict C3.
*Deps:* submit → GATED-ON-SPIKE.

**REQ-C-004 — Offline-first behavior is explicit and safe**
*User story:* As a user with no network, byreis should still work for everything that doesn't require fresh trust, and be honest about staleness.
*Mode:* C/A/S · *Priority:* P1
*Acceptance:*
- Given offline + valid cache within TTL, Then contributor flows work and a staleness banner is shown.
- Given offline + admin, Then admin read works if the key + cache satisfy policy; admin *promotion* of a newly-added admin requires a fresh verified fetch.
- No offline path silently grants admin that an online fetch would deny.
*Security:* Conflict C4 resolution.
*Deps:* registry client. Format-independent.

**REQ-C-006 — Key recovery is documented (accepted-risk for solo-admin)**
*User story:* As an org, I need a defined path when an admin private key is lost.
*Mode:* A/S · *Priority:* P1 (documentation + re-encrypt support; full recovery automation v0.2)
*Acceptance:*
- Given ≥2 admins and one lost key, Then docs define the procedure: a remaining admin re-encrypts to a new recipient set (depends on `rotate`/`share`, v0.2 — v0.1 documents the manual `edit`-based path).
- Given exactly one admin and a lost key, Then this is documented as an **accepted, unrecoverable data-loss risk** for v0.1 (no false promise).
*Security:* No silent backdoor / escrow (would violate Invariant 1).
*Deps:* re-encrypt path → GATED-ON-SPIKE for mechanics; the documented risk statement is not.

---

## 6. De-scoped (with PM rationale)

| Item | Rationale |
|---|---|
| TUI | Weeks of work, not the differentiator; v0.1 friendliness delivered via CLI error UX (REQ-A-006). → v0.2. |
| `rotate`, `share`, `revoke` | Heavy, not the spine; SOPS users tolerate worse today. v0.1 documents the manual `edit` path. → v0.2. |
| `request-access`, self-service `admin add/remove` | Manual signed-pubkey hand-off acceptable for v0.1 (REQ-B-005). → v0.2. |
| GitLab provider, bulk submit | GitHub-only keeps surface small; bulk is an optimization of a working single path. → v0.2. |
| Anomaly / ML detection, leaked-secret DB | Unmaintainable solo; external dep + privacy surface; low v0.1 value. **Rejected.** |
| Web dashboard | Scope explosion, contradicts zero-infra positioning. **Rejected.** |
| KMS / YubiKey / HSM backends | age covers v0.1; SOPS-KMS can't do asymmetric anyway. → v0.2+. |
| Multi-registry | Single registry sufficient for v0.1 (PLAN §12). → v0.2. |
| Per-environment distinct keys | Start per-file (PLAN §12). → later. |

---

## 7. Gating risks

1. **TOP — Model A/B format decision (BLOCKING DESIGN).** Owned by `/reis-crypto-spike`. REQ-A-003, REQ-C-003, REQ-B-002, REQ-C-001 (mechanics), REQ-C-005, REQ-B-006 (decode), REQ-C-006 (mechanics) are **GATED-ON-SPIKE**. DESIGN must not start until the spike delivers an audited verdict. If the spike finds **neither** model satisfies a *smooth* keyless edit of a shared file, byreis's differentiator is in question and PM must re-frame scope — this is a project-level risk, not just a requirement risk.
2. **Asymmetric-guarantee proof (REQ-B-001) is a hard ship gate.** If it cannot be made machine-checkable under the chosen format, the wedge is unproven and v0.1 should not ship.
3. **Registry trust-root circularity / rollback** (REQ-B-004/B-005) — must fail closed; an unsigned/rolled-back registry granting admin is a critical defect.
4. **Solo-maintainer burnout** — scope is deliberately minimal; any scope creep back toward PLAN.md's full §8 roadmap re-introduces this risk.

---

## 8. Competitive positioning summary (2026, evidence-backed)

- **SOPS + age:** zero-infra GitOps, but **symmetric** (any key-holder reads everything) and public-key contribution only works for *whole files you create*, not editing a shared environment file (data-key + whole-file MAC require a private key). Arcane CLI. → byreis's wedge is exactly the gap SOPS cannot fill.
- **Infisical:** MIT, polished, self-hostable — but **server-based**, not plain-git GitOps. ~$18/user/mo cloud.
- **Doppler / 1Password:** SaaS, great UX, no real self-host (Doppler) / human-sharing focus (1Password). Vendor-coupled.
- **Vault:** powerful, heavy infra — opposite of byreis's zero-infra promise.
- **sealed-secrets:** Kubernetes-only controller.
- **agenix / sops-nix:** Nix-bound; painful manual rekeying (e.g., re-enter passphrase per secret) — a concrete friendliness opening for byreis's future `rotate`.
- **git-crypt:** unmaintained, whole-file only, no field-level/format awareness.

**byreis's defensible position:** *the only zero-infra, plain-git tool where people who must never read secrets can still safely add/update them, with friendly errors and CI-native flows.* Win condition = the submit→review→merge spine being genuinely smooth and the asymmetric guarantee being provable. Lose the asymmetric guarantee → byreis is a worse SOPS; that is why REQ-B-001 is the ship gate.

---

## Sources

- [getsops/sops — docs & encryption protocol](https://getsops.io/docs/)
- [SOPS encryption protocol (data key, per-value AEAD, MAC)](https://autrilla.gitbooks.io/sops/content/encryption-protocol.html)
- [getsops/sops GitHub (updatekeys, rekey requires old private key)](https://github.com/getsops/sops)
- [Secret Management with SOPS and age — public-key contributor encryption](https://gist.github.com/patlegu/4494c8af543444289e50c4a9d5f6eae7)
- [Using SOPS + age to Encrypt Files (2026)](https://blog.heylinux.com/en/2026/02/using-sops-age-to-encrypt-files/)
- [The Best Secrets Management Tools in 2026 — Infisical](https://infisical.com/blog/best-secret-management-tools)
- [Infisical Review 2026 vs Doppler/Vault](https://cybersecurityo.com/secrets-management/infisical-review/)
- [Secrets management pricing breakdown 2026](https://www.cybersectool.com/blog/secrets-management-pricing-breakdown-2026)
- [Handling Secrets in NixOS: git-crypt, agenix, sops-nix overview](https://discourse.nixos.org/t/handling-secrets-in-nixos-an-overview-git-crypt-agenix-sops-nix-and-when-to-use-them/35462)
- [agenix — age-encrypted secrets (rekey pain)](https://github.com/ryantm/agenix)
- [2026 Secrets Management Guide — secrets sprawl context](https://dev.to/linou518/is-your-api-key-still-running-naked-the-complete-2026-secrets-management-guide-4m7n)
