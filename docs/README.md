# byreis documentation

User-facing documentation for byreis. All documents here are written for people
who use byreis; internal engineering and design notes are kept out of the public
repository.

## Start here

- **[User guide](guide.md)** — complete feature and usage reference: the
  asymmetric model, install, contributor workflow, admin workflow, interactive
  TUI, CI usage, audit verification, and security boundaries.

## Runbooks

- **[Request-access runbook](request-access-runbook.md)** — opening, reviewing,
  and absorbing access-request PRs (`request-access` + `rotate --from-request`).
- **[Rotation runbook](rotation-runbook.md)** — recovering from a partial
  rotation via `admin rotation reconcile`.
- **[Forward secrecy](forward-secrecy.md)** — what `rotate --remove` does and
  does not guarantee about pre-rotation ciphertext; the incident runbook when a
  recipient is suspected compromised.

## Release notes

- [v0.5](release-notes-v0.5.md) — audit-binding release (`admin audit show --verify`)
- [v0.4](release-notes-v0.4.md) — reviewer-loop release (submission-PR queue TUI, `admin request reject`, durable merge audit)
- [v0.3.1](release-notes-v0.3.1.md) — patch: graceful fallback on malformed `BYREIS_PROJECT`
- [v0.3](release-notes-v0.3.md) — production-wired submit/review, interactive TUI
- [v0.2](release-notes-v0.2.md) — key rotation, contributor onboarding, bulk submit
