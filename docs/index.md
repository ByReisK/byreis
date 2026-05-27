---
template: home.html
title: byreis — send secrets, not see them
hide:
  - navigation
  - toc
---

## See it in action

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

Access level is **derived from cryptographic reality**, never from a config flag
or environment variable. If you can decrypt a project file and your public key is
in the verified admin registry, you are an admin. Otherwise you are a contributor.

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } **Getting started**

    ---

    Install byreis, initialize a project, submit your first secret, and read it
    back as an admin.

    [:octicons-arrow-right-24: Get started](getting-started.md)

-   :material-feature-search:{ .lg .middle } **Features**

    ---

    The full capability set by role: what a contributor can do, what an admin can
    do, and the guarantees that hold across both.

    [:octicons-arrow-right-24: Browse features](features.md)

-   :material-shield-key:{ .lg .middle } **Security model**

    ---

    How asymmetric access works: native `age` encryption, the two-repo trust
    model, fail-closed mode detection, and the trustworthy audit trail.

    [:octicons-arrow-right-24: Read the model](security-model.md)

-   :material-book-open-variant:{ .lg .middle } **User guide**

    ---

    The complete reference for every workflow, command, configuration value, and
    environment variable.

    [:octicons-arrow-right-24: Open the guide](guide.md)

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
