# byreis v0.2 release notes

## Correction (added 2026-05-23)

The v0.2.0 binary did not wire the `submit` and `review` use-cases into its
production composition root. The code for both — including the headlined
`submit --file` bulk flow — shipped in the binary and passed its tests, but the
runtime wiring that connects those use-cases to their adapters was missing.
As a result, `byreis submit` (single-key and `--file`) and `byreis review`
returned an "adapters not configured" error at runtime in v0.2.0. The
encryption and review logic itself was unchanged and correct; only the
production wiring was absent. This is fixed in v0.3.x, where `submit` and
`review` are wired into the production composition root and work end to end.
The original v0.2 notes are preserved below as published.

## What's new in v0.2

v0.2 lands the admin key-rotation lifecycle and contributor onboarding flow on
top of the v0.1 submit/review/merge spine. The asymmetric-access guarantee is
unchanged: contributors still encrypt-to-admins and can never read a value.

### Key rotation

- `byreis rotate` — admin-only rotation of a project's recipient set. Rotation
  re-encrypts every current secrets file to the new recipient set in a
  two-phase commit so a project is never left half-rotated; an interrupted run
  is safe to re-run. Removing a recipient prints a forward-secrecy warning:
  rotation re-encrypts current files but cannot retroactively scrub a removed
  recipient's access to ciphertext already in git history, so values that a
  compromised recipient could have read must be rotated out-of-band. See
  `docs/forward-secrecy.md` for the incident runbook.
- `--dry-run` previews exactly which files and recipients a rotation would
  change without writing anything.
- Destructive rotations require typing the new recipient-set fingerprint to
  confirm, so a fat-fingered rotation cannot proceed unattended.
- `byreis admin rotation reconcile` detects and repairs a project left in a
  partially rotated state (for example, after an interrupted earlier run) by
  bringing every secrets file back to a single consistent recipient set.

### Contributor onboarding

- `byreis request-access` — a contributor opens a pull request asking to be
  added as a recipient. The contributor never needs admin credentials; the
  request travels as a normal reviewable PR.
- `byreis rotate --add --from-request <PR>` — an admin lifts an access request
  into a rotation that adds the requester, verifying that the recipient key
  being added belongs to the PR's author before granting access. This closes
  the loop from "contributor asks" to "admin grants" without manual key
  copy-paste.
- `byreis admin request list` — an admin lists the open access-request PRs
  awaiting triage.

### Audit and diagnostics

- `byreis doctor --rotation-history` — reports a project's rotation history and
  flags a partially rotated project, so an operator can confirm rotation state
  at a glance.
- `byreis admin audit show` — a read-only view of the signed registry audit
  log for rotation events.

### Bulk submission

- `byreis submit --file <.env>` — submit many key/value pairs from a single
  `.env` file in one flow, with a per-key review step before anything is
  encrypted and committed. Single-key submission is unchanged; the encryption
  path is identical to v0.1.

## Known limitations / deferred to v0.3

- `byreis admin request list` enumerates all open access-request pull requests
  and is not yet result-capped. On a very large registry the listing may page
  slowly.
- The signed registry audit log records a removed recipient by their
  (non-secret) public key. `byreis admin audit show` reports removed-recipient
  counts only, not a per-recipient breakdown.
- Audit-log read and the signed registry audit file cover the rotation event
  class in v0.2. Merge events are recorded host-local only and are not yet
  appended to the signed registry audit file; that is deferred to v0.3.
- The per-key value validation surfaced in the `submit --file` review step is a
  placeholder and is not yet wired to a production validator. Treat its output
  as advisory in v0.2.

## Migration: counter-store format change

byreis v0.2 extends the registry-side counter store JSON with a new
field that records each file's rotation epoch. Once an admin running
v0.2 lands the first rotation in a project, the counter store for that
project includes this field, and a v0.1 binary will not be able to
read it (the v0.1 decoder uses a strict-unknown-field rejection
posture). All admin operators must upgrade to v0.2 before the first
rotation commit lands; there is no rollback path from a registry that
has seen any rotation. Pre-rotation counter stores are forward-
compatible (v0.2 reads v0.1 fine).
