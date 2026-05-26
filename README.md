<div align="center">

# byreis

**Send secrets. Not see them.**

Friendly GitOps secrets management with asymmetric access control — written in Go.

</div>

---

## What is byreis?

byreis lets a team manage secrets in plain git, with one defining twist:

> **Contributors can submit secrets, but only admins can read them.**

A contributor encrypts a value to the team's admin public keys and opens a pull
request. They never hold a private key, so they can add or update a secret but
can never decrypt one — not even the value they just submitted. An admin reviews
the decrypted value and merges.

```bash
# Contributor — write-only, no private key required
byreis submit --key STRIPE_API_KEY

# Admin — review the real value, then merge
byreis review --pr myorg/my-app-secrets#42
byreis admin merge --pr myorg/my-app-secrets#42 --expect <pin> \
  --project myapp --file secrets/production.enc.yaml
```

No server. No vendor backend. Just git and modern public-key encryption.

Access level is derived from cryptographic reality, never from a config flag or
environment variable. If you can decrypt a project file and your public key is in
the verified admin registry, you are an admin. Otherwise you are a contributor.

## Why?

Existing tooling forces a trade:

- **SOPS + age** — zero-infra and git-native, but symmetric: anyone with a key
  reads everything, and a keyless contributor cannot edit a shared environment
  file at all.
- **Server-based managers** — good UX, but require infrastructure or a vendor.
- **Kubernetes-only controllers** — not usable for plain local or CI workflows.

byreis fills the gap: the only zero-infra, plain-git tool where people who must
never _read_ secrets can still safely _add and update_ them.

## Status

Stable releases shipped through **v0.5.0**. See the [Releases](https://github.com/ByReisK/byreis/releases) page.

## Install

### Pre-built binaries (recommended)

Download the binary for your platform from the [Releases](https://github.com/ByReisK/byreis/releases) page.
Supported platforms: **linux/amd64**, **linux/arm64**, **darwin/amd64**, **darwin/arm64**.

Windows is build-safe but is not a release binary target; Windows users must build from source.

```bash
# Example: Linux amd64
curl -L https://github.com/ByReisK/byreis/releases/download/v0.5.0/byreis-linux-amd64 \
  -o /usr/local/bin/byreis
chmod +x /usr/local/bin/byreis
```

### From source

Requires Go 1.26 or later.

```bash
git clone https://github.com/ByReisK/byreis.git
cd byreis
make build        # produces ./bin/byreis
```

Or install directly with:

```bash
go install github.com/ByReisK/byreis/cmd/byreis@latest
```

## 2-minute quickstart

### Contributor: submit a secret

```bash
# 1. Initialize the project (first time only — pins the registry trust anchor)
byreis init --project myapp --registry myorg/byreis-admins

# 2. Submit a secret — value is collected interactively (masked entry)
byreis submit --key DATABASE_URL

# byreis opens a PR against the project secrets repo.
# You never see the value again; it was encrypted to admin public keys only.
```

### Admin: review and merge

```bash
# 1. Review the submission — decrypts and shows the value
byreis review --pr myorg/my-app-secrets#42

# The output includes a PinnedSHA. Pass it to merge to guard against branch re-push.

# 2. Merge the reviewed submission
byreis admin merge --pr myorg/my-app-secrets#42 \
  --expect <PinnedSHA> \
  --project myapp \
  --file secrets/production.enc.yaml
```

On an interactive terminal, `submit` and `review` open an interactive TUI.
Set `BYREIS_NON_INTERACTIVE=1` or pipe stdout to suppress the TUI and use the
plain CLI path (for CI).

## Commands

| Command | Mode | Description |
|---|---|---|
| `init` | any | Initialize a project and pin the registry trust anchor |
| `doctor` | any | Health check: mode, trust anchor, registry status |
| `submit` | any | Encrypt and submit a secret (single key or `--file .env` bulk) |
| `review` | admin | Review a pending submission PR |
| `admin merge` | admin | Merge a reviewed submission into the live secrets file |
| `get` | admin | Decrypt and print a single secret value |
| `decrypt` | admin | Decrypt and print all values in a secrets file |
| `edit` | admin | Edit a secret value in-place (decrypt → `$EDITOR` → re-encrypt) |
| `rotate` | admin | Rotate the recipient set and re-encrypt all secrets files |
| `admin rotation reconcile` | admin | Recover a partially rotated project |
| `request-access` | contributor | Open a PR requesting to be added as a recipient |
| `admin request list` | admin | List open request-access PRs |
| `admin request reject` | admin | Close a request or submission PR with a reason |
| `admin audit show` | admin | Display (and optionally verify) the registry audit log |
| `version` | any | Print the version |

For flags and full usage: `byreis <command> --help`.

See the **[full user guide](docs/guide.md)** for detailed workflows, configuration
reference, CI integration, and the security model.

## Admin registry requirements

The admin registry repository (pointed to by `.byreis.yaml` in each project repo)
**must** have the following branch-protection rules on `main` before any
`byreis admin merge` or counter-write operation is attempted:

- **Signed commits required (byreis-aware status check)** — the registry must
  run a byreis verifier as a CI gate on `main` that validates the
  `byreis-signer:` / `byreis-sig:` footer in each counter commit against the
  registry's signer roster. GitHub's native "Require signed commits"
  branch-protection rule is **not** the enforcement point and must not be
  relied on, because byreis embeds its Ed25519 signature in the commit
  message body rather than in the commit object's `gpgsig` header.
- **Linear history** — no merge commits; rebase-only. Ensures counter
  monotonicity.
- **No force-push** — ordinary `git push --force` is rejected. byreis uses
  `--force-with-lease` (CAS) to detect concurrent writes; if the remote accepts
  force-pushes, the concurrent-write guard loses its effectiveness.
- **No branch deletion** — protects the history that signed-commit verification
  and anti-rollback checks rely on.

Counter writes validate these requirements at push time and surface
`ErrRegistryWriteRejected` if the remote refuses the push. If you see that error,
verify the branch-protection configuration above.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
