# byreis v0.4 release notes

v0.4 is the **reviewer-loop release**. It closes the two halves of the admin
review flow that v0.3 only half-showed: a real, browsable submission-PR queue in
the TUI and a first-class `reject` verb (CLI and in-TUI). Alongside the loop, the
successful-merge audit record now lands durably in the registry's signed file
instead of only on the merging admin's local machine.

The asymmetric-access guarantee is unchanged. Contributors still encrypt and
submit write-only; they cannot decrypt, and no v0.4 surface gives a non-key-holder
a route to a plaintext value. Access level remains derived from cryptographic
reality, never from a flag, an environment variable, or a config file.

## What's new

### A browsable submission-PR queue in `byreis review`

`byreis review`, run on an interactive terminal as an admin, now opens a **list of
pending submission PRs** (the `byreis/add-*`, `byreis/replace-*`, and
`byreis/bulk-*` branches) with PR number, key/action, author, and age. Select a row
and press Enter to open the existing no-plaintext detail/approve flow — no manual PR
reference, no dropping to the CLI or the web UI.

The list view never decrypts. It calls only the bounded read port; the only path
that decrypts is the explicit approve-detail flow you opt into per item, which is
the same already-audited v0.3 decryption path. The list itself never constructs key
material and never binds a plaintext value.

The queue is **bounded**: at most 5 pages / 200 results, with a visible truncation
signal, a loading indicator on a slow fetch, and context-cancellation honored.

### `byreis admin request reject`

A single verb closes a request or submission PR with a structured reason, from
within byreis rather than out-of-band `gh pr close`:

```
byreis admin request reject --pr <owner/repo#N> --reason "<text>"
```

The PR is closed, the reason is posted as a PR comment (so the contributor gets
structured feedback), and a reject event is recorded in the audit log. `--json`
emits `{pr, status, reason, url}`. The verb is **ADMIN/SUPER only**; a contributor
invocation is denied at the permission matrix before any network contact.

`reject` is **PR-close-only**. It never loads a private key, never decrypts, never
advances a counter, and never writes to `admins.yaml`, `projects/*`, `policy.yaml`,
or the counter store. It validates the PR type before acting: pointed at a PR whose
type does not match (its source repo and branch prefix must agree), it refuses and
closes nothing. An already-merged PR is refused with a typed error (a merged
submission is never silently closed); an already-closed PR is an idempotent no-op
with no duplicate comment.

The reason is sanitized for terminal safety (control bytes and Unicode
bidirectional/format overrides — the Trojan-source class — are stripped) before it
reaches the PR comment or the audit log, and it is length-capped. The free-text
reason is **never stored in the audit event** — only its byte length is recorded —
so audit search and diff cannot leak it.

### In-TUI reject

The submission detail screen in `byreis review` gains a reject action. It is a thin
caller: it collects a reason, shows a confirm step, and calls the **same** reject
use-case as the CLI verb. It never constructs key material and never reads a
plaintext value; aborting the confirm makes no call and returns to the detail view.

### Durable merge audit in the signed registry file

A successful `byreis merge` now appends a signed merge event to the registry's
`audit/<project>.jsonl`, fetchable read-only, so post-incident review no longer
depends on a specific admin's local machine. The merge audit record **rides the same
signed registry commit as the counter advance**: it is written if and only if the
counter `CommitBump` lands. There is never an orphan audit entry on a non-advanced
counter, and never an orphan unsigned line. The audit counter is strictly monotonic
and subordinate to the counter advance; concurrent merges are serialized by a
compare-and-swap push so exactly one wins. The audit file auto-initializes on the
first merge.

The merge-audit posture is **fail-closed**: a signed registry commit cannot be
retried offline, and an unattended audit gap is worse than a failed command. If the
registry write cannot complete (offline at merge), the command fails with a clear
retry hint and a result describing what landed, rather than dropping the record.

#### Scope of merge-audit tamper-evidence (read this)

The merge-audit channel is protected by the **HEAD commit signature** verified
against the pinned trust anchor, plus the **monotonic counter** and the
**compare-and-swap (CAS)** push. Together these detect an unsigned or forged
registry HEAD and provide anti-rollback.

It is **not** per-line tamper-detection. byreis does **not** today re-verify the
per-line integrity of `audit/<project>.jsonl` on read: the per-entry hash is
write-side provenance only, with no read path recomputing it. A key-less repository
writer who edits, reorders, or deletes JSONL lines underneath a validly-signed HEAD
is therefore **not** detected by byreis. This is a **pre-existing, system-wide
property of the audit channel** (it has applied to the rotation audit since v0.2),
not something specific to merge-audit. Per-line read-side integrity binding across
the whole audit system (rotation and merge) is a tracked follow-up for a release
after v0.4.

## Behavior and configuration change: the two-variable project contract

v0.4 splits the project identity into two variables with distinct meanings:

- **`BYREIS_PROJECT`** is now the **slash-free logical project id** (for example
  `myapp`). It is used for registry paths — admin set, policy, counters, and the
  `audit/<project>.jsonl` file.
- **`BYREIS_PROJECT_REPO`** is the **`owner/repo` slug** of the project secrets
  repository (for example `myorg/myapp`). The GitHub git provider derives the repo
  location from it.

`byreis doctor` warns if `BYREIS_PROJECT` contains a slash, because that almost
always means an `owner/repo` value was left in the wrong variable.

### Migration note

If you previously set `BYREIS_PROJECT=owner/repo` (the v0.3.x single-variable form),
split it: put the `owner/repo` slug in **`BYREIS_PROJECT_REPO`** and put the
slash-free logical id in **`BYREIS_PROJECT`**. Pass `--project` to override per
invocation. A `BYREIS_PROJECT` that still contains a slash is flagged by
`byreis doctor`.

## Positioning and honesty disclosures

These statements bound what byreis does, deliberately:

- **The review TUI opens the submission-PR queue by default; press `a` to toggle to
  access-request triage.** The submission queue is the new default screen; the v0.3
  access-request-triage path is preserved, not removed — it is one keystroke away.
- **`reject` is PR-close-only and never touches key material.** It closes a PR and
  posts a comment; it never loads a key, decrypts, advances a counter, or writes any
  trust state.
- **Merge-audit is HEAD-signature, monotonic-counter, and CAS protected — not
  per-line tamper-detection.** A key-less repo writer editing JSONL lines under a
  validly-signed HEAD is not detected today; per-line read-side integrity is a
  tracked follow-up.
- **byreis is GitHub-only.** There is no GitLab provider and no other forge backend.
- **There is no `export --sops` and no SOPS-symmetric interoperation.** The format
  is native-`age` Model B; a key-less contributor can encrypt to admins but cannot
  decrypt, and there is no shared data key to export.

## Upgrading

Drop-in replacement for v0.3.1 with one configuration change: split the project
identity into `BYREIS_PROJECT` (slash-free logical id) and `BYREIS_PROJECT_REPO`
(`owner/repo` slug) per the migration note above. No secrets-format change. Existing
encrypted files, registries, and signed commits are unaffected.
