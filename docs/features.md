# Features

byreis is organised around its defining constraint: **access level is derived
from cryptographic reality**. A contributor (no private key) can write but never
read; an admin (holds a registered private key) can read, edit, rotate, and
consume. The capabilities below are grouped the same way.

## Contributor — write-only, no private key

| Capability | Command |
| --- | --- |
| Submit a single secret (encrypted to admin public keys, opens a PR) | `byreis submit --key NAME` |
| Bulk submit every pair from a `.env` file | `byreis submit --file .env` |
| Verify the audit trail — key-less, read-only, zero-decrypt | `byreis audit verify` |
| Request access (in-band, audited) | `byreis request-access` |
| Initialize a project / diagnose configuration | `byreis init`, `byreis doctor` |

- **Submitting never decrypts.** The contributor encrypts to the admins'
  recipients and can add or replace a key directly — but cannot read any value,
  not even one they just submitted.
- **`audit verify`** runs the full per-line audit-trail verification with no
  private key and no decryption. With `--json` it emits a machine-readable
  result and a **non-zero exit code on tamper**, so it drops straight into a CI
  pipeline as a tripwire.

## Admin — holds a registered private key

| Capability | Command |
| --- | --- |
| Read a value / all values | `byreis get`, `byreis decrypt` |
| Edit a secret in place | `byreis edit` |
| Export to an `env` / `dotenv` stream | `byreis export --format env\|dotenv` |
| Run a child process with secrets injected into its environment | `byreis run -- <cmd>` |
| Review and merge a submission | `byreis review`, `byreis admin merge` |
| Reject a submission or access request | `byreis admin request reject` |
| List open access requests | `byreis admin request list` |
| Inspect & verify the audit trail with per-line binding | `byreis admin audit show --verify` |
| Rotate the recipient set | `byreis rotate`, `byreis rotation-reconcile` |

### Consuming secrets safely

byreis gives an admin two complementary ways to *use* a decrypted secret:

- **`byreis export --format env|dotenv`** — emit shell-sourceable `export KEY="..."`
  lines or a dotenv file. Values are always quoted and escaped (including `$` and
  backtick) so a hostile value cannot inject a command when sourced. Plaintext is
  refused to an interactive terminal by default to avoid an accidental scrollback
  dump.
- **`byreis run -- <cmd>`** — launch a single child process with every value in
  its environment, so the secrets **never touch disk or terminal scrollback**.
  byreis execs the command after `--` directly (no shell, no `$VAR` expansion),
  keeps secrets out of the child's argv, forwards `SIGINT`/`SIGTERM`, and exits
  with the child's exit code.

`--sops` export is deliberately unsupported — see the
[security model](security-model.md) for why a shared symmetric data key would
break the asymmetric guarantee.

## Across both roles

- **Trustworthy audit trail.** Every audit-channel line is bound to the
  anchor-verified commit that introduced it; the verifier detects edits, deletes,
  reorders, forged inserts, cross-file splices, and counter regressions, and
  fails closed on tamper. Actor attribution is anchor-attested, not copied from
  the log line.
- **Interactive TUI.** A bubbletea terminal UI for the submit form and the review
  queue (submission PRs + access requests), with an in-TUI approve / reject — and
  a hard guarantee that the review UI never binds a decrypted plaintext value.
- **Offline-first registry.** Network failure falls back to the cache; a stale
  cache warns but still works. Registry integrity is verified through signed
  commits.
- **Honest, machine-friendly CLI.** Secrets are masked in a terminal and printed
  plainly when piped; `--json` for machine output; meaningful exit codes; error
  messages carry actionable fix hints.
- **Cross-platform.** Linux and macOS, amd64 and arm64, shipped as static
  binaries each release.

## What is intentionally *not* in byreis

These are deliberate scope decisions, not gaps:

- **No `--sops` interoperability** — it would reintroduce a shared symmetric data
  key and defeat asymmetric access.
- **No shell interpretation in `run`** — `byreis run` execs your command
  directly; spawn a shell yourself (`byreis run -- sh -c '...'`) if you want one.
- **No server or vendor backend** — byreis is plain git and public-key crypto.

See the [release notes](release-notes-v0.8.md) for the per-release history.
