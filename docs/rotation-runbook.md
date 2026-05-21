# Rotation runbook: recovering a partial rotation and using `admin rotation reconcile`

This runbook is the operator-facing procedure for recovering from a failed or
interrupted `byreis rotate` invocation. The error message emitted by a
rotation that lands in a partial state points here for the recovery steps;
this file is the single canonical reference.

Read this end-to-end **before** running `byreis admin rotation reconcile`
against a project you suspect is in a partial-rotation state. The
classification step is read-only and safe to run at any time, but the
recovery actions described below are admin-only and write to the registry;
treat them as production change events.

For the related question of **forward secrecy over git history** — what
`byreis rotate --remove` does and does not guarantee about pre-rotation
ciphertext — see `docs/forward-secrecy.md`. The two runbooks are
complementary: this one is about recovering a partial transaction; the
forward-secrecy runbook is about what remains decryptable to a removed
recipient who retains their key material and a clone of the history.

## TL;DR

- A `byreis rotate` invocation that fails after Phase 1 (branch + per-file
  pending bumps written) but before Phase 2 (registry `CommitRotation`
  landed) leaves the system in a recoverable partial state. Running
  `byreis admin rotation reconcile` classifies the state and, when the
  classification permits, reverts the Phase-1 side effects in a single
  signed registry commit.
- The reconcile verb is **admin-only**. A contributor invocation is
  denied at policy gate before any registry fetch, with exit code
  `permission-denied`.
- The reconcile verb is **classify-first**: a partial state that cannot
  be safely auto-reverted (the Phase-2 mid-flight case) surfaces a
  terminal error pointing back to this runbook and requires manual
  admin coordination. There is no auto-rollback for Phase-2 mid-flight,
  by design.
- Reconcile does **not** affect the forward-secrecy property of any
  ciphertext. It reverts the in-flight recipient-set change attempt; it
  does not change what a retained-key party can decrypt from history.

## When to invoke `byreis admin rotation reconcile`

Invoke this verb in one of two situations:

1. **After a `byreis rotate` failure.** When a `rotate` invocation
   returns an error that mentions "rotation is in a partial state",
   "see rotation runbook", or a non-zero exit class of `counter-reconcile`
   or `trust-error` from a rotation path, the system may have committed
   Phase-1 side effects (a rotation branch on the project repo, per-file
   pending bumps in the registry counter store) without landing the
   atomic Phase-2 `CommitRotation` that finalises the rotation. Run
   `byreis admin rotation reconcile --project <id>` to classify and, where
   safe, revert.

2. **Proactively on a suspected partial state.** If `byreis doctor`
   reports a per-file pending counter ahead of the per-file committed
   counter for a project, or if a rotation branch named
   `byreis/rotate-<epoch>-*` is present on the project repo with no
   matching `CommitRotation` audit row in the registry log, the project
   may be in a Phase-1-only partial state. The classify step is read-only
   and safe to run at any time; it will report `NoPartial` if nothing
   needs reversing.

## What `byreis admin rotation reconcile` does

The verb proceeds in two stages:

### Stage 1 — Classify (read-only)

The reconciler fetches a signature-verified, non-stale view of the
registry (it never reads from a stale cache for this decision) and
fetches the current state of the project repo's rotation branch (if
one exists). It then assigns the partial state to one of four classes:

- **`NoPartial`** — no rotation in flight; nothing to do. Exit code
  `ok`. The verb returns immediately with a success message.
- **`Phase1Only`** — Phase-1 side effects are present (rotation branch
  written, pending counters bumped) but no `CommitRotation` has landed
  in the registry log. This is safely reversible: the rotation never
  reached its commit point, so no published recipient-set change has
  taken effect.
- **`Phase2Midflight`** — partial Phase-2 evidence is present: some
  project-side files appear committed to the project repo's main
  branch (the rotation branch was merged), but the atomic
  `CommitRotation` row that finalises the per-file counters in the
  registry has not landed; **or** the project rotation branch has been
  merged but the registry counter-store + audit advance did not land
  in the same signed commit it was supposed to. This class is **not**
  auto-revertable.
- **`InconsistentPartial`** — the observed state does not fit any of
  the three classes above (e.g. a rotation branch is present but the
  per-file pendings on the registry are absent, or vice versa). Treated
  the same as `Phase2Midflight` from the recovery standpoint: terminal,
  no auto-revert, manual coordination required.

Stage 1 never writes. It is composed against a read-only registry view
and a read-only project-repo probe. The classify step does not load
write credentials and does not require the running admin to hold any
write capability beyond the read capability already implied by ADMIN
mode.

### Stage 2 — Revert (only on `Phase1Only`)

When the classification is `Phase1Only`, the reconciler:

1. Builds a reversal audit event recording the rotation epoch, the
   recipient-set delta that was attempted, the rotation branch ref, and
   the reason for reversal.
2. Issues a single signed registry commit that **atomically**:
   - clears every per-file pending counter that was bumped by Phase 1
     back to its pre-rotation value, and
   - appends the reversal audit row to the registry's audit log.

   The cleared-pendings state and the reversal audit row land together
   in one signed commit. An operator reading the registry log can rely
   on the join: you will never observe a phantom reversal audit row
   without its accompanying counter reset, or a counter reset without
   its audit row.

3. Attempts to delete the rotation branch from the project repo via
   `git push origin --delete <branch-ref>`, retrying under a bounded
   compare-and-swap budget.

After step 2 succeeds the registry is in a consistent, pre-rotation
state. Step 3 is cosmetic cleanup of the project repo: if it fails after
the registry commit has landed, the registry state is **already**
consistent and the only outstanding work is removing the stale branch
from the project repo. The verb surfaces this case explicitly (see
"Branch-delete budget exhausted" below).

When the classification is `Phase2Midflight` or `InconsistentPartial`,
the reconciler does **not** attempt a revert. It returns a terminal
error pointing back to this runbook and surfaces the `counter-reconcile`
exit class. No further automatic action is taken, and no further
automatic action will be attempted on re-invocation: the verb is
idempotent on terminal classifications.

## Exit codes

The verb's exit codes correspond to the project's standard exit classes:

- **`ok`** — `NoPartial` (nothing to do) or a successful `Phase1Only`
  reversal. The verb completed cleanly.
- **`permission-denied`** — the caller is not in ADMIN mode. The verb
  is denied at policy gate before any registry fetch.
- **`counter-reconcile`** — the classification was `Phase2Midflight`
  or `InconsistentPartial`. A terminal error was returned; see
  "Phase-2 mid-flight recovery" below.
- **`trust-error`** — the registry CAS was rejected after the bounded
  retry budget was exhausted (registry contention), or the project
  rotation-branch probe surfaced a missing branch ref where one was
  required.
- **`auth-error`** — the running admin's mode could not be derived
  (e.g. the key is unavailable, file permissions are not `0600`, or
  the registry trust-path is unverified).

## Phase-2 mid-flight recovery (terminal class — manual procedure)

When `byreis admin rotation reconcile` classifies the state as
`Phase2Midflight` (or `InconsistentPartial`), automatic recovery stops.
There is **no auto-rollback** for this class, and that is a deliberate
design decision, not a missing feature.

### Why there is no auto-rollback

A Phase-2 mid-flight state means some portion of the rotation's
project-side merge has taken effect (the rotation branch was merged to
the project main, so the new ciphertext is visible to readers), while
the registry-side `CommitRotation` that finalises the per-file counter
advance + audit log entry has not landed atomically. An automated
recovery from this point would itself have to be a trust-path write
under uncertain pre-conditions: it would need to either (a) push the
missing `CommitRotation` forward to match the project-side merge, or
(b) revert the project-side merge to match the missing registry commit.
Both options require the recovery code to make a unilateral decision
about the operator's intent, against an inconsistent observed state,
while holding write capability on a trust-path resource. The project's
position is that **fail-closed beats fail-clever** for a primitive
this load-bearing: the safer behaviour is to halt the automatic path
and surface the situation to a human, even at the cost of a manual
recovery step.

### Manual recovery procedure

When you observe a `Phase2Midflight` or `InconsistentPartial` exit
from `byreis admin rotation reconcile`:

1. **Stop and coordinate.** Do not re-run `rotate` or `reconcile`
   against this project until the manual procedure is complete. Open
   an incident channel with at least one other administrator who is in
   the **pre-rotation** recipient set (so they can read the affected
   files independently of the rotation that just failed).

2. **Establish ground truth.** Inspect both sides of the partial
   commit:
   - On the project repo, identify the merged rotation branch ref and
     confirm which `secrets/*.enc.yaml` files have post-rotation
     ciphertext at the current main `HEAD`.
   - On the registry repo, inspect the audit log and counter store.
     Confirm which (if any) per-file pending counters were bumped, and
     whether a partial `CommitRotation` row exists. Cross-check the
     rotation epoch on both sides.

3. **Decide on the corrective direction.** Either:
   - **Roll forward**: manually re-derive the missing `CommitRotation`
     (rotation epoch, per-file committed counters, audit row) for the
     project-side merge that already took effect, and push that signed
     commit to the registry. Verify the new registry state by running
     `byreis doctor` against the project and confirming the per-file
     committed counters match the project-repo `HEAD` ciphertext.
   - **Roll back**: revert the project-side merge on the project repo
     (a `git revert` of the rotation merge commit, pushed as a new
     commit on main), and **independently** restore the registry
     counter store to its pre-rotation values via a signed registry
     commit that includes the appropriate audit row.

   The choice between roll-forward and roll-back depends on whether
   the rotation's recipient-set change is still desired. Roll-forward
   is appropriate when the rotation's intent is still valid and the
   only remaining work is to land the registry side of an already
   merged project change. Roll-back is appropriate when the rotation
   itself should be undone (e.g. the operator now believes the
   recipient delta was wrong, or the rotation is part of an aborted
   incident response).

4. **Surface the recovery to the audit log.** Whichever direction is
   chosen, the registry commit that lands the recovery must carry an
   audit row identifying the recovery as a manual reconciliation, the
   rotation epoch involved, and the administrator who performed it.
   Do not perform the recovery as a "silent" registry write.

5. **Warn explicitly.** An incorrect manual recovery — for example,
   re-deriving the wrong rotation epoch, or skipping the per-file
   counter advance on a roll-forward — can break the asymmetric-access
   invariant the project depends on (the contributor-can-write-but-not-
   read property), because it would leave the project repo's ciphertext
   addressed to a recipient set the registry does not agree exists. Two
   administrators must independently verify the recovery commit before
   it is pushed.

## Branch-delete budget exhausted

When a `Phase1Only` reversal lands the registry-side reversal commit
cleanly but the subsequent project-repo branch delete fails after the
bounded retry budget, the verb surfaces an error of the shape:

    branch-delete CAS rejected after N retries; manual cleanup required
    via git push origin --delete <ref>

This error is **cosmetic cleanup**, not a transactional failure. The
registry is **already** in a consistent, pre-rotation state — the
pending counters were cleared and the reversal audit row was appended
in the same signed registry commit, and that commit landed before the
branch-delete was attempted. The only outstanding work is removing the
stale rotation branch from the project repo.

To complete the cleanup, run the exact command the verb surfaced, for
example:

    git push origin --delete byreis/rotate-7-20260521t1200z

If the branch delete continues to fail (typically because of project
branch-protection rules or a concurrent reviewer who is mid-look at the
rotation branch), coordinate with the project repo's reviewers and
delete the branch through the project's standard ref-deletion path.
You do **not** need to re-run `byreis admin rotation reconcile`
afterwards; the registry side is settled.

## Large-N rotation considerations

A project with a very large number of secrets files (substantially
more than the day-to-day case) can in principle produce a partial
state with a long list of per-file pendings to revert. To date,
project fixtures and integration test fixtures have not surfaced any
large-N regression — no observed runs have exceeded the practical
single-commit revert budget — but the operational guidance is:

- If `byreis admin rotation reconcile` reports a `Phase1Only`
  classification with a very large number of files to revert, allow the
  verb to run to completion. The reversal is one signed registry commit
  regardless of file count; it does not fan out into per-file commits.
- If a `Phase2Midflight` classification surfaces against a project with
  a very large number of files, the manual recovery procedure described
  above applies, but operator coordination becomes proportionally more
  important: two administrators reviewing the recovery commit is not a
  nice-to-have at that scale, it is a precondition.
- Future hardening to batch the reversal commit (or to add a
  per-file-count guardrail before reconcile proceeds) is tracked as a
  hardening item in the project's reserved work; nothing about the
  current verb's behaviour changes until that hardening lands.

## Same-commit atomicity contract

The reconcile verb's central transactional contract on a `Phase1Only`
reversal is that the cleared-pendings state and the reversal audit row
land **together** in a single signed registry commit. This contract is
load-bearing:

- An operator reading the registry log can rely on the join. You will
  not observe a phantom reversal audit row without its effect (the
  counters reset), and you will not observe a counter reset without
  its audit row.
- A reader reproducing the registry log offline (e.g. when verifying
  the audit history as part of a security review) sees the reversal
  as a single atomic event, not a two-step that could be torn across
  intermediate states.
- The bounded CAS retry budget on the registry commit defends the
  contract against concurrent registry writes: a CAS rejection causes
  the verb to retry the same composed commit, never to split the
  reversal into a counter reset on one commit and an audit row on a
  later commit.

The branch-delete step on the project repo is intentionally **outside**
this atomicity envelope. It is cosmetic post-cleanup; failing it does
not corrupt the registry state.

## Forward-secrecy reminder

Even after a clean `Phase1Only` reversal, the underlying secret values
that were ever encrypted under the **pre-rotation** recipient set remain
decryptable by anyone who holds:

- a private key that was a member of that pre-rotation recipient set,
  and
- any retained clone, fork, mirror, or backup of the project repo's git
  history.

The reversal undoes the *recipient-set change attempt* that was in
flight. It does **not** change the forward-secrecy property of past
ciphertext, because no rotation can: pre-rotation ciphertext is
permanently retained by every party with read access to the project
repo, and a retained private key remains a valid decryption capability
indefinitely. See `docs/forward-secrecy.md` for the full operator
procedure when a recipient is suspected compromised; running this
reconcile verb is not, on its own, an incident-response action.

## Frequently asked

**"My `rotate` failed mid-flight and I think I'm in `Phase1Only` — can I
just re-run `rotate`?"** No. Re-running `rotate` against a project with
non-cleared per-file pendings will fail closed, because the rotation
spine refuses to begin a new rotation against a project that has a
prior rotation in flight. Run `byreis admin rotation reconcile` first
to clear the partial state; only then re-run `rotate`.

**"The reconcile verb says `NoPartial` but `byreis doctor` reports a
counter mismatch — what now?"** That combination indicates the
project-repo `HEAD` and the registry are in steady state from the
rotation perspective (no rotation is in flight) but some other counter
drift is present. Use `byreis doctor` for the diagnostic, not the
rotation runbook; the rotation reconcile path is specifically for
partial-rotation recovery.

**"Why does the verb require an ADMIN identity for the read-only
classify step?"** Because the classify step needs a signature-verified,
non-stale view of the registry, and that capability is gated to ADMIN
in the project's mode model. The classify step itself never loads write
credentials; the policy gate is the cheapest possible denial point and
runs before any registry fetch.

**"Can I run `byreis admin rotation reconcile` against an arbitrary
project I do not administer?"** No. The verb is gated to projects the
running admin is a registered admin of, and the registry trust path
verifies that membership before the classify stage proceeds. A
non-admin invocation is denied at policy gate; an admin invocation
against an unrelated project is denied at registry trust.

## Related reading

- `docs/forward-secrecy.md` — what `byreis rotate --remove` does and
  does not guarantee about pre-rotation ciphertext, and the
  out-of-band remediation procedure when a recipient is compromised.
- `byreis doctor` — general diagnostic verb; surfaces counter drift,
  unverified registry trust, and key/permission issues independently of
  the rotation lifecycle.
- The audit log on the admin registry repo — the canonical record of
  rotation, reversal, and recovery events; any manual recovery
  performed under the procedure above MUST be reflected in the audit
  log.
