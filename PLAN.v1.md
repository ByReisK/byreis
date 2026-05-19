# byreis — Technical Plan

> **byreis** — Friendly GitOps secrets management with asymmetric access.
> *"Send secrets. Not see them."*
>
> CLI + TUI, written in Go. Default-contributor mode, central admin registry.
> A first project under the `byreis` brand.

---

## 0. Brand & Identity

### Naming

| Element | Value |
|---------|-------|
| **Project name** | `byreis` |
| **Binary / command** | `byreis` |
| **Personal brand** | byreis (umbrella for future projects) |
| **GitHub org** | `github.com/byreis` |
| **Primary repo** | `github.com/byreis/byreis` |
| **Module path** | `github.com/byreis/byreis` |
| **Domain** | `byreis.dev` (primary), `byreis.io` (backup) |
| **Config dir** | `~/.config/byreis/` |
| **Cache dir** | `~/.cache/byreis/` |
| **Env prefix** | `BYREIS_*` (e.g., `BYREIS_KEY`, `BYREIS_REGISTRY`) |

### Tagline

**Primary:** *"Send secrets. Not see them."*

**Variants for different contexts:**
- Marketing: "Friendly GitOps secrets that respect your team's roles."
- Technical: "Asymmetric encryption for git-based secrets management."
- Punchy: "Drop secrets in. Get answers out."

### Voice & Tone

- Friendly but technical (Vercel, Linear, Charm style)
- Confident, not apologetic
- First-person OK in marketing ("I built byreis because...")
- Acknowledge prior art (SOPS, sealed-secrets) respectfully — position as evolution

### Visual Direction

- **Logo concept**: stylized envelope with red wax seal
- **Colors**: warm trust palette (deep blue `#1a2b4a` + cream `#f5f1e8` + accent gold `#d4a017`)
- **Typography**: monospace for code, clean sans-serif (Inter / Geist) for marketing

---

## 1. Vision & Core Concept

### Problem Statement

GitOps secrets today have 2 extremes:
- **SOPS-style**: everyone needs private key → hard to share, hard to rotate, everyone can read everything
- **Sealed Secrets / Vault**: server-based, complex setup, not truly GitOps

Unsolved pain points:
- Devs need to add secrets but shouldn't view prod secrets
- Onboarding new contributors is painful (share key, re-encrypt all files)
- Reviewing PR shows ciphertext, can't tell what changed
- No proper audit trail
- Rough UX (SOPS commands are arcane, no TUI)

### Our Solution

**Asymmetric access model:**
- **Contributor (default)**: only has admin public keys → can encrypt, cannot decrypt
- **Admin**: has private key → full access (encrypt/decrypt/edit/rotate)
- Contributor workflow: input plaintext → tool encrypts → auto-creates PR → admin reviews

**Key principles:**

1. **Default = contributor** — `byreis init` works for anyone without complex setup
2. **Admin registry = separate repo** — central source of truth, versioned, auditable
3. **Friendly UX** — TUI for admins, simple CLI for contributors, hide git complexity
4. **CI/CD friendly** — same binary has CLI mode for automation
5. **No server required** — pure CLI + git, no vendor lock-in

### Why This Wins

vs **SOPS**: better UX, asymmetric access model, hides complexity behind workflows
vs **sealed-secrets**: works outside Kubernetes, no controller, no infra
vs **Doppler/Infisical**: 100% self-hosted, no proprietary backend, no monthly fee
vs **Vault**: zero infrastructure, just git

---

## 2. Architecture Overview

### Two-Repo Model

```
┌─────────────────────────────────────────────────────────────┐
│                   ADMIN REGISTRY REPO                        │
│              (e.g., github.com/myorg/byreis-admins)          │
│                                                              │
│   ├── admins.yaml          # Source of truth: who is admin   │
│   ├── recipients/          # Public keys                     │
│   │   ├── alice.pub                                          │
│   │   └── bob.pub                                            │
│   ├── projects/            # Registered projects             │
│   │   ├── project-a.yaml                                     │
│   │   └── project-b.yaml                                     │
│   └── policy.yaml          # Global policy                   │
│                                                              │
│   Protection: signed commits, branch protection, CODEOWNERS │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ fetched by tool (read-only)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROJECT REPOS                             │
│         (e.g., github.com/myorg/my-app-secrets)              │
│                                                              │
│   ├── .byreis.yaml         # Reference to admin registry     │
│   ├── secrets/                                               │
│   │   ├── dev.enc.yaml                                       │
│   │   ├── staging.enc.yaml                                   │
│   │   └── prod.enc.yaml                                      │
│   └── .github/                                               │
│       └── workflows/                                         │
│           └── secret-review.yml                              │
└─────────────────────────────────────────────────────────────┘
```

### Why separate admin registry?

**Pros:**
- ✓ Central management — change admin list once, applies everywhere
- ✓ Easier auditing — one repo to monitor
- ✓ Reduces permission sprawl — admin of registry repo = effective tool admin
- ✓ Scales across many projects — no copying admin lists
- ✓ Decoupled lifecycle — onboard/offboard without touching project repos

**Cons (mitigated):**
- Network dependency — cache aggressively, work offline with cached registry
- Bootstrap problem — registry itself needs bootstrapping (mitigated: GPG signed commits + branch protection)

### Component Diagram

```
┌──────────────────────────────────────────────────────┐
│                      byreis CLI                       │
├──────────────────────────────────────────────────────┤
│                                                       │
│  ┌─────────────────┐         ┌────────────────────┐  │
│  │   CLI Layer     │         │    TUI Layer       │  │
│  │  (cobra cmds)   │         │   (bubbletea)      │  │
│  └────────┬────────┘         └─────────┬──────────┘  │
│           │                            │              │
│           └────────────┬───────────────┘              │
│                        ▼                              │
│              ┌─────────────────────┐                  │
│              │   Core (business)   │                  │
│              ├─────────────────────┤                  │
│              │ - Mode detection    │                  │
│              │ - Encryption engine │                  │
│              │ - Policy engine     │                  │
│              │ - Audit logger      │                  │
│              └──────────┬──────────┘                  │
│                         │                             │
│         ┌───────────────┼───────────────┐             │
│         ▼               ▼               ▼             │
│   ┌──────────┐   ┌────────────┐   ┌──────────┐       │
│   │ Crypto   │   │   Git      │   │ Registry │       │
│   │ Backend  │   │  Backend   │   │ Backend  │       │
│   ├──────────┤   ├────────────┤   ├──────────┤       │
│   │ age      │   │ go-git     │   │ HTTP     │       │
│   │ sops     │   │ GitHub API │   │ Cache    │       │
│   │ kms (v2) │   │ GitLab API │   │          │       │
│   └──────────┘   └────────────┘   └──────────┘       │
└──────────────────────────────────────────────────────┘
```

---

## 3. Mode System (Critical Design)

### Mode Detection Logic

**Mode is determined by cryptographic reality, NOT config files.**

```
START
  │
  ▼
Has private key file? ──No──> CONTRIBUTOR mode
  │
  Yes
  ▼
Key file permissions OK (0600)? ──No──> ERROR (refuse to run)
  │
  Yes
  ▼
Can decrypt any file in project? ──No──> CONTRIBUTOR mode
  │
  Yes
  ▼
Public key in admin registry? ──No──> CONTRIBUTOR mode + warning
  │
  Yes
  ▼
ADMIN mode
```

### Why default = contributor?

**Adoption flow:**
1. Dev installs `byreis` → automatically contributor
2. Setup takes 30 seconds: just point at admin registry URL
3. Can submit secrets immediately → low friction
4. If needs admin → request access, get approved → auto-promote

**Security benefit:**
- Principle of least privilege by default
- No accidental admin access
- Mode upgrade is explicit, audited

### Command Matrix

| Command | Contributor | Admin | Description |
|---------|:-----------:|:-----:|-------------|
| `byreis init` | ✓ | ✓ | Setup project |
| `byreis list` | ✓ (keys only) | ✓ (full) | List secrets |
| `byreis submit` | ✓ | ✓ | Submit new/updated secret via PR |
| `byreis request-access` | ✓ | — | Request admin access |
| `byreis doctor` | ✓ | ✓ | Diagnose setup |
| `byreis auth login` | ✓ | ✓ | Login to Git provider |
| `byreis get` | ✗ | ✓ | View secret value |
| `byreis edit` | ✗ | ✓ | Edit secret directly |
| `byreis decrypt` | ✗ | ✓ | Decrypt file |
| `byreis tui` | ✓ (read-only) | ✓ (full) | Interactive UI |
| `byreis rotate` | ✗ | ✓ | Rotate secret |
| `byreis review` | ✗ | ✓ | Review pending PR |
| `byreis share` | ✗ | ✓ | Add recipient |
| `byreis revoke` | ✗ | ✓ | Remove recipient |
| `byreis admin add` | ✗ | ✓ (super) | Add new admin |
| `byreis admin remove` | ✗ | ✓ (super) | Remove admin |

---

## 4. File Formats & Configuration

### Admin Registry Repo Structure

**`admins.yaml`** (source of truth):
```yaml
version: 1
schema_version: "1.0"

organization:
  name: "My Organization"
  contact: "security@myorg.com"

admins:
  - id: alice
    github: alice-gh
    email: alice@myorg.com
    public_key: "age1abc...xyz"
    role: super-admin
    added_at: "2025-01-01T00:00:00Z"
    added_by: alice  # bootstrap
    
  - id: bob
    github: bob-gh
    email: bob@myorg.com
    public_key: "age1def...uvw"
    role: admin
    added_at: "2025-01-15T00:00:00Z"
    added_by: alice
    scope:
      projects: ["my-app", "another-app"]   # null = all projects
      environments: ["dev", "staging"]      # null = all envs

  - id: carol
    github: carol-gh
    email: carol@myorg.com
    public_key: "age1ghi...rst"
    role: env-admin
    added_at: "2025-02-01T00:00:00Z"
    added_by: alice
    scope:
      projects: ["my-app"]
      environments: ["dev"]
```

**`projects/my-app.yaml`** (project registration):
```yaml
version: 1
project:
  name: my-app
  repo: github.com/myorg/my-app-secrets
  description: "Main application secrets"
  
environments:
  - name: dev
    admins: [alice, bob, carol]
  - name: staging
    admins: [alice, bob]
  - name: prod
    admins: [alice]   # super-admin only

contribution:
  enabled: true
  allowed_for:
    - github_team: "developers"
    - github_team: "qa"
  default_pr_reviewers: ["@admins"]
  
validation:
  STRIPE_*:
    pattern: "^sk_(test|live)_[a-zA-Z0-9]{20,}$"
  AWS_ACCESS_KEY_ID:
    pattern: "^AKIA[0-9A-Z]{16}$"
```

**`policy.yaml`** (global policy):
```yaml
version: 1

security:
  require_signed_commits: true
  require_2fa_for_admins: true
  admin_key_rotation_days: 365
  
contribution:
  default_branch_prefix: "byreis/"
  pr_title_template: "[byreis] {action} {key} in {env}"
  require_justification: true
  min_justification_length: 20

audit:
  log_all_admin_actions: true
  audit_log_repo: "github.com/myorg/byreis-audit"   # optional
```

### Project Repo Structure

**`.byreis.yaml`** (project config):
```yaml
version: 1

# Reference to central admin registry
admin_registry:
  url: "github.com/myorg/byreis-admins"
  branch: main
  cache_ttl: 3600   # seconds
  signature_required: true

# Project metadata (must match registry)
project:
  name: my-app

# Encryption backend
encryption:
  backend: age
  
# Environments
environments:
  - name: dev
    file: secrets/dev.enc.yaml
  - name: staging
    file: secrets/staging.enc.yaml
  - name: prod
    file: secrets/prod.enc.yaml
```

### Encrypted Secret File Format

Use SOPS-compatible format for ecosystem interop:

```yaml
# secrets/prod.enc.yaml
DB_PASSWORD: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
STRIPE_KEY: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
sops:
  age:
    - recipient: age1abc...xyz   # alice
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
        ...
        -----END AGE ENCRYPTED FILE-----
    - recipient: age1def...uvw   # bob
      enc: |
        -----BEGIN AGE ENCRYPTED FILE-----
        ...
        -----END AGE ENCRYPTED FILE-----
  lastmodified: "2025-01-15T10:00:00Z"
  mac: ENC[...]
  version: 3.8.0
```

### Local State (per user)

```
~/.config/byreis/
├── config.yaml              # User preferences
├── identity/
│   ├── admin.key            # Private key (admins only, 0600)
│   └── admin.key.pub        # Public key
└── auth/
    └── github-token.enc     # Encrypted with OS keychain

~/.cache/byreis/
├── registry/
│   └── github.com/myorg/byreis-admins/
│       ├── HEAD             # Cached commit SHA
│       ├── admins.yaml
│       └── policy.yaml
└── submissions/
    └── pending/             # Resilient to crash
```

### Environment Variables

| Variable | Purpose | Used in |
|----------|---------|---------|
| `BYREIS_KEY` | Inline age private key | CI/CD |
| `BYREIS_KEY_FILE` | Path to private key | CI/CD, override default |
| `BYREIS_REGISTRY` | Admin registry URL | Override config |
| `BYREIS_CONFIG` | Override config file path | Testing, multi-config |
| `BYREIS_NO_TELEMETRY` | Disable any telemetry | Privacy |
| `BYREIS_LOG_LEVEL` | Logging verbosity | Debugging |
| `BYREIS_NON_INTERACTIVE` | Force non-interactive mode | CI/CD |

---

## 5. Core Workflows

### Workflow A: First-time Contributor Setup

```
$ byreis init
👋 Welcome to byreis!

? What's the admin registry URL? github.com/myorg/byreis-admins
⚙ Fetching registry...
✓ Found 3 admins, 5 projects

? Which project? 
  > my-app
    another-app
    ...

✓ Cloned project repo
✓ Verified admin signatures
✓ You are in CONTRIBUTOR mode

Try:
  byreis submit
  byreis list
```

### Workflow B: Contributor Submits Secret

```
$ byreis submit
? Environment: dev
? Secret name: STRIPE_API_KEY
? Value: ••••••••••• (masked)
? Confirm: •••••••••••
? Justification: "Need for payment feature PROJ-1234"

⚙ Validating format... ✓
⚙ Checking policy... ✓
⚙ Encrypting with admin public keys (3 recipients)... ✓
⚙ Creating branch 'byreis/add-stripe-key-1699...'  
⚙ Committing... ✓
⚙ Pushing... ✓
⚙ Creating PR... ✓

✓ PR #1234 created!
  URL: https://github.com/myorg/my-app-secrets/pull/1234
  Reviewers: @admins
  
ℹ Value encrypted. You cannot view it again.
```

### Workflow C: Admin Reviews PR

```
$ byreis review --pr 1234
┌─ PR #1234 ─────────────────────────────────────────────┐
│ Author:    @alice-dev (contributor)                     │
│ Action:    ADD STRIPE_API_KEY → dev                     │
│ Justification: "Need for payment feature PROJ-1234"     │
├────────────────────────────────────────────────────────┤
│ DECRYPTED VALUE:                                       │
│   <example-key-redacted>                     │
│                                                         │
│ VALIDATION:                                            │
│   ✓ Matches Stripe test key pattern                    │
│   ✓ Entropy: high                                      │
│   ✓ Not in known leaks database                        │
│                                                         │
│ ANOMALY CHECK:                                         │
│   ✓ Author has submitted 3 secrets before              │
│   ⚠ First STRIPE_* submission from this user           │
├────────────────────────────────────────────────────────┤
│ [a] approve  [c] comment  [r] request changes  [d] deny│
└────────────────────────────────────────────────────────┘
```

### Workflow D: Admin Setup

```
# Admin (Alice) needs to be added to registry first by another admin
# This is bootstrap: super-admin manually adds first admin

$ byreis admin generate-key
✓ Generated keypair
  Public:  age1abc...xyz
  Private: ~/.config/byreis/identity/admin.key
  
Send public key to existing admin to add you.

# Later, when added:
$ byreis doctor
✓ Your public key found in admin registry
✓ You are now ADMIN mode
```

### Workflow E: CI/CD Decrypt

```yaml
# .github/workflows/deploy.yml
- name: Decrypt secrets for deployment
  env:
    BYREIS_KEY: ${{ secrets.AGE_KEY }}
    BYREIS_REGISTRY: github.com/myorg/byreis-admins
  run: |
    byreis decrypt secrets/prod.enc.yaml \
      --output env \
      --format github-env >> $GITHUB_ENV
```

---

## 6. Security Model

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Malicious contributor reads prod secrets | Crypto: no private key, cannot decrypt |
| Contributor submits malicious value | Validation rules + admin review |
| Compromised admin laptop | Audit log + key rotation procedures |
| Tampered admin registry | Signed commits + branch protection |
| Man-in-the-middle on git fetch | HTTPS + commit signature verification |
| Replay attack | Commit timestamps + uniqueness check |
| Lost admin key | Recovery procedure: other admins re-encrypt |
| Modified tool binary | Sign releases with cosign/sigstore |

### Cryptographic Choices

- **Primary backend**: `age` (modern, audited, simple)
- **Compat layer**: SOPS format (for ecosystem interop)
- **Key types supported**: age X25519, SSH ed25519
- **Future**: AWS KMS, GCP KMS, YubiKey, HSM

### What we DON'T protect against

Document clearly:
- Compromised user machine with private key
- Modified byreis binary on attacker's machine
- Git history (old encrypted versions remain if admin removed)
- Side channels (timing, power analysis)

---

## 7. Tech Stack

### Language: Go

**Why Go:**
- Single binary distribution (no runtime deps)
- Cross-platform (macOS, Linux, Windows, ARM)
- Strong ecosystem for CLI/crypto/git
- Fast startup (good UX)
- Memory-safe vs C/C++

### Key Dependencies

```go
// CLI framework
github.com/spf13/cobra v1.8+
github.com/spf13/viper v1.18+   // config

// TUI framework
github.com/charmbracelet/bubbletea v0.25+
github.com/charmbracelet/lipgloss v0.9+
github.com/charmbracelet/bubbles v0.17+
github.com/charmbracelet/huh v0.3+    // forms

// Crypto
filippo.io/age v1.1+
github.com/getsops/sops/v3 v3.8+   // SOPS compat

// Git
github.com/go-git/go-git/v5 v5.11+

// Git providers
github.com/google/go-github/v58
github.com/xanzy/go-gitlab

// Utilities
github.com/sahilm/fuzzy v0.1+      // fuzzy search
github.com/zalando/go-keyring v0.2+ // OS keychain
github.com/rs/zerolog v1.31+        // structured logging
github.com/stretchr/testify v1.8+   // testing
```

### Project Structure

```
byreis/
├── cmd/
│   └── byreis/
│       └── main.go              # Entry point
├── internal/
│   ├── cli/                     # CLI commands (cobra)
│   │   ├── init.go
│   │   ├── submit.go
│   │   ├── get.go
│   │   ├── tui.go
│   │   └── ...
│   ├── tui/                     # TUI screens (bubbletea)
│   │   ├── app.go
│   │   ├── secrets_view.go
│   │   ├── submit_form.go
│   │   └── ...
│   ├── core/                    # Business logic (no UI deps)
│   │   ├── mode/
│   │   │   ├── detector.go      # Mode detection
│   │   │   └── policy.go        # Command permissions
│   │   ├── encryption/
│   │   │   ├── age.go
│   │   │   ├── sops.go
│   │   │   └── interface.go
│   │   ├── registry/
│   │   │   ├── client.go        # Admin registry client
│   │   │   ├── cache.go
│   │   │   └── verifier.go      # Signature verification
│   │   ├── git/
│   │   │   ├── provider.go      # Interface
│   │   │   ├── github.go
│   │   │   └── gitlab.go
│   │   ├── config/
│   │   │   ├── project.go
│   │   │   └── user.go
│   │   ├── audit/
│   │   │   └── logger.go
│   │   └── validator/
│   │       └── rules.go
│   └── auth/
│       ├── keychain.go
│       └── oauth.go
├── pkg/                         # Public API (for integrations)
│   └── byreis/
│       └── client.go
├── docs/
│   ├── threat-model.md
│   ├── architecture.md
│   ├── user-guide.md
│   ├── admin-guide.md
│   └── ci-integration.md
├── examples/
│   ├── admin-registry/          # Example registry repo
│   └── project/                 # Example project setup
├── scripts/
│   ├── install.sh
│   └── release.sh
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── go.mod                       # module github.com/byreis/byreis
├── go.sum
├── Makefile
├── README.md
└── LICENSE                      # Apache 2.0
```

### `go.mod` starter

```go
module github.com/byreis/byreis

go 1.22

require (
    github.com/spf13/cobra v1.8.0
    github.com/charmbracelet/bubbletea v0.25.0
    github.com/charmbracelet/lipgloss v0.9.1
    github.com/charmbracelet/huh v0.3.0
    filippo.io/age v1.1.1
    github.com/go-git/go-git/v5 v5.11.0
    github.com/google/go-github/v58 v58.0.0
    github.com/stretchr/testify v1.8.4
    github.com/zalando/go-keyring v0.2.3
)
```

---

## 8. Implementation Roadmap

### Phase 0: Foundation (Week 1)

**Goal:** Project skeleton + core abstractions

- [ ] `go mod init github.com/byreis/byreis`
- [ ] Setup linting (golangci-lint), CI (GitHub Actions)
- [ ] Define core interfaces:
    - [ ] `Encryptor` interface (Encrypt/Decrypt/CanDecrypt)
    - [ ] `GitProvider` interface (CreatePR/GetPR/CommentPR)
    - [ ] `RegistryClient` interface (FetchAdmins/VerifySignature)
- [ ] Mode detection logic with unit tests
- [ ] Config file parsing (project + user configs)
- [ ] Setup test infrastructure (table-driven tests, mocks)
- [ ] Stub `byreis version` command
- [ ] `Makefile` with `build`, `test`, `lint`, `install` targets

**Deliverable:** `byreis version` works, core packages compile, CI green.

### Phase 1: Encryption Core (Week 2)

**Goal:** Encrypt/decrypt works for both contributor and admin

- [ ] Implement `age` encryption backend
- [ ] Implement SOPS-compatible format reader/writer
- [ ] Key management:
    - [ ] Load private key from file (`~/.config/byreis/identity/admin.key`)
    - [ ] Load from env var (`BYREIS_KEY`, `BYREIS_KEY_FILE`)
    - [ ] Verify permissions (0600 check)
    - [ ] Optional passphrase decryption
- [ ] Recipient management:
    - [ ] Multi-recipient encryption
    - [ ] Re-encryption on recipient change
- [ ] Unit tests with test vectors
- [ ] Fuzz tests for parser

**Deliverable:** Can encrypt/decrypt YAML files with age. Tests pass.

### Phase 2: CLI Commands (Week 3-4)

**Goal:** Basic CLI working for both modes

**Contributor commands:**
- [ ] `byreis init` — interactive setup
- [ ] `byreis list` — show keys (no values)
- [ ] `byreis doctor` — diagnose setup
- [ ] `byreis auth login` — Git provider auth

**Admin commands:**
- [ ] `byreis get` — view value (with masking)
- [ ] `byreis edit` — open in $EDITOR
- [ ] `byreis decrypt` — full file decrypt
- [ ] `byreis set` — direct edit (admin only)

**Shared:**
- [ ] Smart TTY detection (mask in terminal, plain in pipe)
- [ ] Color output with auto-disable
- [ ] Error messages with fix hints
- [ ] `--json` flag for machine output
- [ ] Meaningful exit codes

**Deliverable:** Daily use works for admins. Contributors can inspect.

### Phase 3: Admin Registry (Week 5)

**Goal:** Central registry fetching, caching, verification

- [ ] Registry HTTP client (use go-git for fetch)
- [ ] Local caching with TTL
- [ ] Signature verification:
    - [ ] GPG signed commits
    - [ ] SSH signed commits (newer)
- [ ] Parse `admins.yaml`, `projects/*.yaml`, `policy.yaml`
- [ ] Offline mode (use cache)
- [ ] Registry health check in `byreis doctor`

**Deliverable:** Tool fetches admin list from separate repo, verifies integrity.

### Phase 4: Submit Workflow (Week 6-7)

**Goal:** Contributor can submit secrets via PR

- [ ] GitHub provider implementation:
    - [ ] OAuth flow
    - [ ] Token storage in OS keychain
    - [ ] Branch creation
    - [ ] PR creation
    - [ ] PR comment posting
- [ ] Submit workflow:
    - [ ] Interactive prompt (huh forms)
    - [ ] Double-entry verification
    - [ ] Format validation (regex rules)
    - [ ] Encryption with admin pubkeys
    - [ ] Branch naming convention (`byreis/add-<key>-<timestamp>`)
    - [ ] Commit message template
- [ ] Resume capability (if interrupted)

**Deliverable:** `byreis submit` creates valid PR end-to-end.

### Phase 5: TUI (Week 8-9)

**Goal:** Interactive UI for admin

- [ ] Main app shell (bubbletea + lipgloss)
- [ ] Layout: sidebar (envs) + main (secrets list) + status bar
- [ ] Navigation (j/k, tab, /)
- [ ] Reveal value with timeout
- [ ] Inline edit
- [ ] Submit form (for contributors)
- [ ] Search/filter (fuzzy)
- [ ] Auto-lock after idle

**Deliverable:** `byreis tui` provides rich admin experience.

### Phase 6: Review & Audit (Week 10)

**Goal:** Admin can efficiently review PRs

- [ ] `byreis review` command:
    - [ ] Fetch PR details
    - [ ] Decrypt new value
    - [ ] Show validation results
    - [ ] Anomaly detection (basic)
    - [ ] Approve/deny from CLI
- [ ] Audit log:
    - [ ] Local audit log (append-only)
    - [ ] Optional remote (sync to repo)
- [ ] PR comment bot mode (for CI)

**Deliverable:** Review workflow polished, audit trail complete.

### Phase 7: Polish & Release v0.1 (Week 11-12)

- [ ] Documentation:
    - [ ] User guide (`docs/user-guide.md`)
    - [ ] Admin guide (`docs/admin-guide.md`)
    - [ ] CI integration guide
    - [ ] Threat model doc
- [ ] Examples:
    - [ ] Example admin registry repo
    - [ ] Example project setup
- [ ] Distribution:
    - [ ] GitHub releases with signed binaries (goreleaser + cosign)
    - [ ] Homebrew formula
    - [ ] Docker image (`ghcr.io/byreis/byreis`)
    - [ ] Install script (`curl -sSL byreis.dev/install.sh | bash`)
- [ ] Pre-commit hook
- [ ] Shell completions (bash/zsh/fish)
- [ ] Launch page: `byreis.dev`
- [ ] v0.1.0 release announcement (HN, Reddit, Twitter)

### Future (v0.2+)

- GitLab support
- Bulk submit
- Policy engine (advanced)
- Auto-rotation
- KMS backends (AWS/GCP/Azure)
- YubiKey support
- Web dashboard (optional)
- Approval workflows (multi-signer)
- Anomaly detection (ML-based)

---

## 9. Testing Strategy

### Test Pyramid

```
        /\
       /  \      E2E (10%)
      /────\     - Full workflow with real git repo
     /      \
    /────────\   Integration (30%)
   /          \  - CLI commands with fake registry
  /────────────\ - Crypto roundtrip
 /              \
/────────────────\ Unit (60%)
                   - Mode detection
                   - Encryption logic
                   - Validation rules
                   - Config parsing
```

### Critical Test Cases

1. **Mode detection edge cases:**
    - No key → contributor
    - Key with wrong perms → error
    - Key not in registry → contributor + warning
    - Valid admin → admin
    - Corrupted key → error

2. **Encryption correctness:**
    - Roundtrip: encrypt → decrypt → match
    - Multi-recipient: each recipient can decrypt
    - Tampered ciphertext → decrypt fails
    - SOPS compat: tool reads SOPS-encrypted, SOPS reads tool-encrypted

3. **Permission enforcement:**
    - Every (command × mode) combo
    - Bypass attempts (config tampering)

4. **Registry trust:**
    - Unsigned commits → refuse
    - Modified registry → detect
    - Network failure → use cache
    - Stale cache → warn

5. **PR creation:**
    - Successful flow
    - Network failure mid-push → resumable
    - Conflict (branch exists) → handle
    - Auth failure → clear error

### Test Tools

- `testify` for assertions
- `httptest` for fake Git APIs
- `testcontainers-go` for integration with real git
- `bubbletea/test` for TUI testing
- Fuzz tests for parser/validator

---

## 10. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|:----------:|:------:|------------|
| Crypto vulnerability | Low | Critical | Use audited libs (age), external audit pre-1.0 |
| Adoption fails (no users) | Medium | High | Target DevOps teams first, dogfood internally |
| SOPS does what we do better | Medium | Medium | Differentiate on UX + asymmetric model |
| Bigger player ships similar | Low | Medium | Move fast, build community moat |
| Maintainer burnout (solo project) | High | High | Modular architecture, good tests, accept PRs |
| Breaking change in `age` | Low | Medium | Pin version, compat tests |
| Personal brand pressure | Medium | Low | Build sustainably, no overpromise |

---

## 11. Success Metrics (v0.1)

**MVP success criteria:**
- [ ] Tool works end-to-end on macOS + Linux
- [ ] Contributor flow: < 2 minutes to first submitted PR
- [ ] Admin flow: < 30 seconds to review and merge
- [ ] CI integration: works on GitHub Actions
- [ ] Documentation: full user + admin guide
- [ ] Test coverage: > 80% on core packages

**Community signals (3 months post-release):**
- 100+ GitHub stars
- 10+ external contributors filing issues
- 3+ blog posts written by users
- Used in production by 1+ company outside builder

---

## 12. Open Questions

1. **Bootstrap for first admin?**
    - Recommendation: `byreis admin bootstrap` command with explicit verification UX

2. **Multi-admin registry support?**
    - v0.1: single registry. v0.2: multi.

3. **Per-environment encryption?**
    - Recommendation: start simple (per-file), evolve later

4. **Audit log destination?**
    - Recommendation: all 3 options (local, git, SIEM), configurable

5. **License choice?**
    - Recommendation: **Apache 2.0** for trust + adoption + patent protection

---

## 13. Pre-Implementation Checklist

Before opening Claude Code:

- [ ] Reserve `github.com/byreis` org
- [ ] Reserve `byreis.dev` domain (or `byreis.io`)
- [ ] Create empty repo `github.com/byreis/byreis`
- [ ] Decide license: Apache 2.0 (recommended)
- [ ] Set up local dev environment:
    - [ ] Go 1.22+
    - [ ] golangci-lint
    - [ ] make
- [ ] Optional but useful:
    - [ ] `@byreis` social handles
    - [ ] Logo concept sketches

---

## 14. Quick Start for Claude Code

When you load this in Claude Code, suggested order:

1. **Start with `internal/core/mode/detector.go`** — most critical logic, foundational
2. **Then `internal/core/encryption/age.go`** — core crypto operations
3. **Then `cmd/byreis/main.go` + `internal/cli/`** — CLI scaffold with cobra
4. **Add `byreis init` + `byreis doctor` commands** — first thing users run
5. **Then registry client** — needed for everything else
6. **Then `byreis submit` command** — main contributor flow
7. **Then admin commands** — `get`, `edit`, etc.
8. **TUI last** — polish on top of working CLI

Each module should have:
- Clear interface definition
- Unit tests written BEFORE implementation (TDD)
- Doc comments explaining "why" not just "what"
- Error messages that are actionable

### Suggested first prompt for Claude Code

```
Read PLAN.md. We're building byreis — start with Phase 0.

Initialize the Go module github.com/byreis/byreis, set up the project 
structure per section 7, and implement internal/core/mode/detector.go 
with TDD. Write tests first (table-driven), then implementation.

The mode detector must determine ContributorMode vs AdminMode based on 
cryptographic reality (private key existence + decrypt capability), 
NOT config files. See section 3 for the decision flow.
```

---

## 15. README.md Template

For the public repo, here's a starter `README.md`:

```markdown
<div align="center">

# byreis

**Send secrets. Not see them.**

Friendly GitOps secrets management with asymmetric access control.

[Quick Start](docs/quickstart.md) • [Documentation](https://byreis.dev) • [Examples](examples/)

</div>

---

## What is byreis?

byreis lets your team manage secrets in git, with a twist:
**contributors can submit secrets, but only admins can read them.**

```bash
# Developer adds a new secret (write-only)
$ byreis submit STRIPE_KEY --env dev
✓ PR #1234 created. Admin will review.

# Admin reviews and merges (read + write)
$ byreis review --pr 1234
```

No server. No subscription. Just git + age encryption.

## Why?

Existing tools force a choice:
- **SOPS**: everyone with access can read everything
- **Sealed Secrets**: Kubernetes-only, no good local UX
- **Vault/Doppler**: requires infrastructure or vendor lock-in

byreis gives you:
- ✅ Asymmetric access (write-only for contributors)
- ✅ Pure GitOps (no server)
- ✅ Friendly UX (interactive TUI + smart CLI)
- ✅ SOPS-compatible format
- ✅ Works in any CI/CD

## Quick start

```bash
# Install
curl -sSL byreis.dev/install.sh | bash

# Setup
byreis init

# Submit a secret (contributors)
byreis submit

# View secrets (admins only)
byreis tui
```

## Status

🚧 Early development. v0.1 expected Q2 2025.

## License

Apache 2.0
```

---

**END OF PLAN**

*This is your first project under the `byreis` brand. Build it well — it sets the standard for everything that follows.*
