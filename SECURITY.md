# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security problems.** Report privately via
GitHub's *"Report a vulnerability"* form:

  https://github.com/ByReisK/byreis/security/advisories/new

Please include a description, reproduction steps, affected version/commit, and
impact. We aim to acknowledge within a few days and will coordinate a fix and
disclosure timeline with you.

## Supported versions

byreis is in early development (pre-1.0). Only the latest `main` is supported;
there are no backported security releases yet.

| Version | Supported |
|---------|-----------|
| `main` | ✅ |
| < 0.1   | ❌ |

## Threat model (summary)

byreis enforces **asymmetric access**: contributors can encrypt and submit
secrets (write-only) but cannot decrypt them; only admins holding private keys
can read. Access level is derived from cryptographic reality, never from a
config flag. Reports that demonstrate a contributor reading a secret, a write
path clobbering the live secrets file, signed-record forgery/rollback, or a
registry trust bypass are highest priority.

Do not include real secrets, private keys, or production data in a report.
