---
hide:
  - navigation
---

# byreis

> **Send secrets. Not see them.**

Friendly GitOps secrets management with **asymmetric access control** — written in Go.

byreis lets a team manage secrets in plain git, with one defining twist:

!!! quote ""
    **Contributors can submit secrets, but only admins can read them.**

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

# Admin — consume the secrets without ever writing them to disk
byreis run --project myapp --file secrets/production.enc.yaml -- ./server
```

No server. No vendor backend. Just git and modern public-key encryption.

Access level is **derived from cryptographic reality**, never from a config flag
or environment variable. If you can decrypt a project file and your public key is
in the verified admin registry, you are an admin. Otherwise you are a contributor.

<div class="grid cards" markdown>

-   :material-rocket-launch: **[Getting started](getting-started.md)**

    Install byreis, initialize a project, submit your first secret, and read it
    back as an admin.

-   :material-feature-search: **[Features](features.md)**

    The full capability set, organised by role: what a contributor can do, what
    an admin can do, and the guarantees that hold across both.

-   :material-shield-key: **[Security model](security-model.md)**

    How asymmetric access works: native `age` encryption, the two-repo trust
    model, fail-closed mode detection, and the trustworthy audit trail.

-   :material-book-open-variant: **[User guide](guide.md)**

    The complete reference for every workflow, command, configuration value, and
    environment variable.

</div>

## Why byreis?

Existing tooling forces a trade-off:

- **SOPS + age** — zero-infra and git-native, but *symmetric*: anyone with a key
  reads everything, and a keyless contributor cannot edit a shared environment
  file at all.
- **Server-based managers** — good UX, but require infrastructure or a vendor.
- **Kubernetes-only controllers** — not usable for plain local or CI workflows.

byreis fills the gap: the only zero-infra, plain-git tool where people who must
never *read* secrets can still safely *add and update* them.

## Where to next

- New here? Start with **[Getting started](getting-started.md)**.
- Evaluating? Read the **[Security model](security-model.md)** and **[Features](features.md)**.
- Operating byreis? See the **[runbooks](rotation-runbook.md)** and the
  **[user guide](guide.md)**.
- Latest changes are in the **[release notes](release-notes-v0.8.md)**.
