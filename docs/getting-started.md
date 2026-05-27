# Getting started

This page takes you from zero to a working byreis flow: install the binary,
point at a registry, submit a secret as a contributor, and read it back as an
admin. For the complete reference, see the **[user guide](guide.md)**.

## Install

=== "Pre-built binary"

    Download the binary for your platform from the
    [Releases](https://github.com/ByReisK/byreis/releases) page (Linux and macOS,
    amd64 and arm64), then put it on your `PATH`:

    ```bash
    # Example: Linux amd64
    curl -fsSL -o byreis \
      https://github.com/ByReisK/byreis/releases/latest/download/byreis-linux-amd64
    chmod +x byreis && sudo mv byreis /usr/local/bin/
    byreis version
    ```

=== "From source"

    Requires Go 1.26+.

    ```bash
    go install github.com/ByReisK/byreis/cmd/byreis@latest
    byreis version
    ```

`byreis version`, `byreis --help`, and the first-run commands all work with zero
configuration — you only need a key and a registry once you start submitting or
reading real secrets.

## The two repositories

byreis separates *who is trusted* from *what is encrypted*:

- **Admin registry repo** (e.g. `myorg/byreis-admins`) — the source of truth for
  who is an admin, their public keys, per-project config, and policy. Fetched
  read-only, cached, and integrity-verified through signed commits.
- **Project secrets repo** (e.g. `myorg/my-app-secrets`) — holds `.byreis.yaml`
  (which points at the registry) and the encrypted `secrets/*.enc.yaml` files.

Point byreis at your registry once, typically through environment variables:

```bash
export BYREIS_REGISTRY=myorg/byreis-admins
export BYREIS_PROJECT=myapp                       # slash-free logical project id
export BYREIS_PROJECT_REPO=myorg/my-app-secrets   # the GitHub owner/repo slug
```

## Initialize a project

From inside a project secrets repo, scaffold the `.byreis.yaml` that links it to
the registry:

```bash
byreis init
byreis doctor    # confirm your resolved mode + configuration
```

`byreis doctor` is your friend: it reports whether byreis sees you as a
**contributor** or an **admin**, and *why* — including a warning if a private key
is present but does not grant admin (wrong file permissions, or your public key
is not yet registered).

## Contributor workflow — submit a secret

A contributor needs **no private key**. Submitting encrypts the value to the
admins' public keys and opens a pull request.

```bash
# Single key — the value is collected interactively (masked, double-entry)
byreis submit --key STRIPE_API_KEY

# Bulk — read every KEY=VALUE pair from a .env file
byreis submit --file .env

# With a justification recorded in the PR
byreis submit --key STRIPE_API_KEY --reason "rotating the live key"
```

You can verify the integrity of the audit trail at any time — no key required:

```bash
byreis audit verify --json    # non-zero exit on tamper makes a clean CI tripwire
```

## Admin workflow — review, merge, and consume

An admin holds a private key whose public half is in the verified registry.

```bash
# Review the real, decrypted value behind a submission PR
byreis review --pr myorg/my-app-secrets#42

# Merge it, pinning the expected content so nothing can change underneath you
byreis admin merge --pr myorg/my-app-secrets#42 --expect <pin> \
  --project myapp --file secrets/production.enc.yaml
```

Once a secret is merged, you can read or consume it:

```bash
# Read a value
byreis get --project myapp --file secrets/production.enc.yaml --key STRIPE_API_KEY

# Export to a shell-sourceable / dotenv stream
byreis export --project myapp --file secrets/production.enc.yaml --format env

# Run a process with every secret injected into its environment —
# never touching disk or terminal scrollback (exec, not a shell)
byreis run --project myapp --file secrets/production.enc.yaml -- ./server --port 8080
```

## Next steps

- See every command, flag, and configuration value in the **[user guide](guide.md)**.
- Understand the guarantees in the **[security model](security-model.md)**.
- Operating at scale? Read the **[rotation](rotation-runbook.md)** and
  **[access-request](request-access-runbook.md)** runbooks.
