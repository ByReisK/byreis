# byreis v0.3 release notes

## What's new in v0.3

v0.3 makes the contributor and admin day-to-day flows real end to end and adds
an interactive terminal experience on top of them. The asymmetric-access
guarantee is unchanged: contributors still encrypt-to-admins and can never read
a value.

### Production-wired submit and review

- `byreis submit` and `byreis review` are now fully production-wired and work
  end to end, including bulk `submit --file`. This closes the v0.2.0 gap where
  both verbs returned an "adapters not configured" error at runtime because the
  use-cases were never connected to their adapters in the production
  composition root (see the Correction in `docs/release-notes-v0.2.md`). The
  encryption and review logic was already correct in v0.2; v0.3 wires it into
  the production composition root so it runs.

### Interactive TUI for submit and review

- On an interactive terminal, `byreis submit` now launches a masked-entry
  submit form. The form keeps the write-only affordance front and centre: a
  contributor types a value, the value is masked, and it is encrypted-to-admins
  and submitted as a pull request without ever being displayed back as
  plaintext.
- On an interactive terminal, `byreis review` now launches an admin review
  flow. The review flow is (a) an access-request triage queue that lists the
  open access-request pull requests awaiting a decision, and (b) a single-PR
  submission detail view addressed by reference.

### Other v0.3 hardening

- The contributor `request-access` GitHub calls now go through a clean adapter
  port, keeping the contributor write path's network access behind a single
  boundary.
- The admin `request list` enumeration is now bounded, so a large registry no
  longer pages without limit.

## Honesty and scope

byreis ships with a deliberately narrow, machine-checkable set of guarantees,
and the release notes state the limits as plainly as the features.

- **The TUI covers `submit` and `review` only.** Rotation, decryption, key
  management, and audit remain CLI-only commands. There is no TUI for those
  flows in v0.3, by design — the plaintext decrypt path in particular stays on
  the CLI and is never rendered through the TUI.
- **The CLI remains the source of truth and the CI-native interface.** Every
  flow is fully available on the CLI; the TUI is a convenience layer over the
  `submit` and `review` use-cases and never the only way to do anything. Any
  automated, headless, or CI usage targets the CLI.
- **TUI review is access-request triage plus single-PR detail, not a browsable
  submission-PR queue.** The review flow lists open access-request pull
  requests and shows a single submission PR by reference; it does not yet
  enumerate or browse the full set of open submission pull requests. A
  browsable submission-PR queue needs new core surface and is deferred to v0.4.
- **Behavioral delta from v0.2.** In v0.2 these verbs always ran the CLI path.
  In v0.3, on an interactive terminal, `byreis submit` and `byreis review`
  launch the TUI by default. This is a deliberate behavior change.
- **Headless and non-interactive usage is unchanged.** With `--json`, with
  `BYREIS_NON_INTERACTIVE` set, with `TERM=dumb`, or on any non-TTY pipe, the
  TUI never launches and the existing CLI path runs exactly as before. The
  headless output is byte-identical to v0.2's CLI output for these verbs.
- **Windows is the CLI path only.** The interactive TUI targets linux and
  darwin; on Windows byreis is buildable and the full CLI works, but the TUI is
  not a Windows target. Windows users get the CLI experience.

## Changes

- The unimplemented top-level `byreis merge` command is removed; use `byreis admin merge`.

## Known limitations / deferred to v0.4

- A browsable submission-PR queue in the TUI (enumerate and select across all
  open submission pull requests) is deferred to v0.4; it requires new core
  surface that v0.3 intentionally does not add.
- The signed registry merge-audit append (a registry write-side feature with
  its own crypto and threat review) remains deferred to v0.4, as disclosed in
  the v0.2 notes.
