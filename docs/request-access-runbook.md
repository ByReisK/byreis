# Request-access runbook: opening, reviewing, and absorbing access-request PRs

This runbook is the operator-facing procedure for the `byreis request-access`
contributor verb and the `byreis rotate --add --from-request <PR>` admin
verb. Together they form the in-band promotion path: a contributor proposes
that their age public key be added to a project's recipient set; an admin
reviews the proposal as a pull request against the registry repo, then
absorbs the proposed key into the recipient set through a normal rotation.

The two verbs preserve the asymmetric-access invariant: the contributor uses
their own GitHub identity and acquires no admin credential or registry-write
key at any step; the admin uses their existing keychain-backed admin
identity and never re-derives a contributor signing capability. The rotation
that absorbs the request is a normal `rotate --add` with the PR provenance
recorded in the audit log.

Read this end-to-end before opening or absorbing a request-access PR. The
state-machine matrix and exit-code table in this document are the canonical
references for the verb's accept/refuse decisions.

## TL;DR

- **Contributor side**: `byreis request-access --key <age1...>
  --justification "..." --registry <owner/repo>` opens a PR against the
  registry repo. The PR adds a single file at `requests/<your-handle>.yaml`
  containing the proposed pubkey, your GitHub login, and a free-text
  justification. The PR is opened from your own fork using your own GitHub
  identity; no admin credential or registry-write key is acquired.
- **Admin side**: `byreis rotate --add --from-request <registry>#<number>
  --project <id>` fetches the PR's YAML, runs the 9-mode state-machine
  validation, prints the admin warning explaining the PR-author-vs-YAML
  byte-compare semantics, then fires the typed-fingerprint confirm gate
  before absorbing the proposed pubkey into a rotation.
- **Quota**: at most 5 open `request-access` PRs per contributor identity
  per registry. Close stale PRs before opening a new one.
- **Public-registry caveat**: if the registry repo is public, the linkage
  `handle -> age_pubkey` is publicly readable. See "Public-registry-repo
  disclosure surface" below.

## Contributor procedure

### Prerequisites

- A GitHub identity with `read` access to the registry repo (the standard
  shape; the registry adopter MAY configure broader access, see the
  "Adopter configuration" section below).
- A personal fork of the registry repo. If you do not have one, create it
  with `gh repo fork <registry>` before running the verb. The fork is the
  source-of-record for the PR's HEAD; same-repo PRs from a contributor with
  registry-write access are an adopter-configuration concern (see
  "Same-repo PR adopter footgun" below).
- An `age` keypair. The verb takes only the public key (`age1...`); the
  private key never leaves your machine and is never sent to the registry.
- A GitHub token in `BYREIS_GITHUB_TOKEN` or `GH_TOKEN`. The verb uses the
  same authentication source as `byreis submit`; no new keychain credential
  is required, and no admin or registry-write capability is acquired.

### Opening a request

Run, from any directory:

```
byreis request-access \
  --key age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --justification "team A onboarding for project foo" \
  --registry myorg/byreis-admins
```

The verb:

1. Refuses if your current mode is ADMIN or SUPER (the verb is
   contributor-only; admins do not need to open access requests).
2. Reads your GitHub login from the token-bearer identity (or accepts an
   explicit `--handle <login>` override if you need to disambiguate).
3. Checks your open-PR quota against the registry; refuses with
   `ErrRequestAccessQuotaExceeded` if you already have 5 or more open
   `request-access` PRs.
4. Builds a single `requests/<your-handle>.yaml` file with your pubkey,
   handle, justification, and an RFC3339 timestamp; verifies the YAML
   parses through the schema strict-decoder before pushing anything.
5. Creates a branch named `byreis/request-access-<handle>-<unix-time>` on
   your fork, commits the YAML file with a fixed-template commit message
   (no operator-controlled body), and opens a PR against the registry's
   default branch.

The verb prints the PR URL on success. The next step is admin review.

### What an admin will see and do

The admin runs `byreis rotate --add --from-request <registry>#<number>
--project <id>` against the same project they would otherwise rotate. The
admin's tool fetches your YAML at the PR HEAD, performs the state-machine
validation described below, displays the admin warning explaining the
byte-compare semantics, then asks the admin to type the full 64-character
SHA-256 fingerprint of your proposed pubkey to confirm.

If the validation refuses, the admin sees a sentinel error with a hint
pointing back to the action you need to take (e.g. "close the PR and reopen
with a clean commit set", "regenerate via `byreis request-access`"). The
admin does NOT have to merge the registry PR before running the rotation;
the rotation commit IS the endorsement, and the rotation audit row records
the PR URL, PR HEAD SHA, and your validated GitHub login as the proof of
provenance.

If the validation succeeds and the admin completes the fingerprint
confirmation, your pubkey is added to the project's recipient set in a
single rotation transaction. From the next rotation forward, you can
decrypt the project's secrets (subject to the project's normal admin
read-path discipline).

### Updating or rotating your own pubkey

The runbook above is also the procedure for replacing your own pubkey: open
a new `request-access` PR with the new pubkey; the admin absorbs it via
`rotate --add --from-request`, then independently removes the old key via
`rotate --remove <old-age1-key>` (which fires the forward-secrecy warning).
Combining the two intents into a single transaction is also supported via
`rotate --replace <old>=<new>` after the new key is already in the
recipient set.

## Admin procedure

### Prerequisites

- ADMIN mode resolved cryptographically by `byreis` startup (admin private
  key present, perms 0600, registered in the admin set). The verb is
  denied-by-policy for CONTRIBUTOR before any registry fetch.
- `BYREIS_GITHUB_TOKEN` (or `GH_TOKEN`) with read access to the registry
  repo's PR list. The verb reads exclusively; no write capability against
  the registry repo is acquired through this verb.
- A `--project` flag identifying which project to rotate. Absorbing a
  request-access PR against project A does not change project B's
  recipient set; rotations are per-project.

### Running the absorption

```
byreis rotate --add --from-request myorg/byreis-admins#42 \
  --project my-project-id
```

The verb:

1. Mode-gates first: CONTRIBUTOR is denied with no network contact.
2. Parses the PR ref into `<owner>/<repo>#<number>` form; rejects
   malformed values.
3. Fetches the PR HEAD SHA and the `requests/<handle>.yaml` content at that
   SHA via a read-only GitHub call. The HEAD SHA is pinned for the
   force-push-race re-check at step 5.
4. Runs the state-machine validation described in
   [State-machine matrix](#state-machine-matrix) below. A refusal returns
   the matching sentinel with an actionable hint and exits without any
   Phase-1 work.
5. Prints the verbatim `RequestAccessAdminWarning` block (see
   [Admin warning](#admin-warning) below).
6. Displays a confirm prompt showing the PR author login, the YAML handle,
   the sanitized justification, and the first 16 chars of the proposed
   pubkey's SHA-256 fingerprint. The admin must type the full 64-char
   fingerprint to proceed; mismatch refuses with
   `ErrRotationFingerprintMismatch`.
7. Re-fetches the PR HEAD SHA and asserts byte-equal to the pinned value.
   A drift means the contributor pushed between plan and execute; the
   verb refuses with `ErrRequestAccessPRForcePushed`. Re-run to re-fetch
   and re-review the new content.
8. Proceeds into the normal `rotate --add` Phase-1 / Phase-2 pipeline with
   the validated pubkey injected into the add list. The rotation audit
   event records the PR URL, PR HEAD SHA, the validated YAML handle, and
   the validated PR author login as proof of provenance.

### Admin warning

The verb prints this block verbatim before the fingerprint-confirm prompt.
The exact wording is the single source of truth in the shipped code; this
runbook reproduces it for operator reference, but the live emission is the
authoritative copy:

```
WARNING: this rotation absorbs a recipient pubkey from a contributor's
request-access PR. Before confirming:

  - The YAML's github_handle field is byte-compared to the PR opener's
    GitHub login (`pull_request.user.login`). It is NOT compared to
    the PR title, body, description, comments, or any commit-author email.
  - Visually verify the PR opener IS the human you intend to grant access
    to (run `gh pr view <PR>` to confirm the GitHub account is the
    intended contributor). A login byte-match alone is not a substitute
    for that visual check.
  - Commit-author divergence (a PR whose commits are authored by a
    different identity than the PR opener) AND force-push races between
    plan and execute are caught structurally, but the typed-fingerprint
    confirm below is your last line of defense — inspect the SHA-256
    fingerprint of the recipient and type the full 64-char value to
    proceed. Mismatch refuses the rotation.
```

### What the tool catches structurally vs what you must verify manually

Caught structurally (you can rely on these without inspection):

- Closed, draft, merged, or bot-authored PRs are refused before validation.
- YAML `github_handle` not matching `pull_request.user.login` byte-equal
  (post-lowercase) is refused with `ErrRequestAccessIdentityMismatch`.
- Any commit on the PR whose author login diverges from the PR opener is
  refused with `ErrRequestAccessCommitAuthorDivergence`.
- Force-push between fetch and confirm (a content swap on the PR head
  branch) is caught by the HEAD SHA pin: the SHA captured at plan time is
  re-asserted byte-equal at execute time, and any drift is refused with
  `ErrRequestAccessPRForcePushed`.
- Fork-ownership transfer between fetch and confirm (a source swap, where
  the PR head branch points at the same SHA but the fork repository has
  changed hands) is caught by a separate byte-equal re-assertion of
  `pull_request.head.repo.owner.login` at execute time; any drift is
  refused with `ErrRequestAccessForkOwnershipChanged`. The SHA pin alone
  is not sufficient for this case because a transferred fork can retain
  identical content, so the fork-owner login is checked independently.
- YAML schema violations, unknown fields, non-ASCII handles, justifications
  over 1000 bytes, and malformed `age1` pubkeys are all refused at decode
  time with `ErrRequestAccessSchemaInvalid`.
- File-set changes outside `requests/<handle>.yaml` are refused with
  `ErrRequestAccessPRFilePathInvalid`.

You MUST verify manually before typing the fingerprint:

- Visually confirm the PR opener (`gh pr view <PR>`) is the human you
  intend to grant access to. The structural checks prove that
  `pull_request.user.login` matches the YAML handle byte-for-byte, but
  they do not prove that this GitHub account belongs to the person you
  think it does.
- Confirm the project ID on your `--project` flag is the project you
  intend to rotate. The PR is project-agnostic; the rotation is
  per-project.
- Confirm the proposed pubkey is one the contributor actually controls
  (out-of-band: a fingerprint exchange over a side-channel before they
  open the PR is a common pattern at scale).

## State-machine matrix

The validation step accepts exactly one PR shape and refuses every other.
The matrix below is the canonical reference; the live behaviour is asserted
by the `request_test.go` table-driven test row-by-row.

```yaml
# PR-state acceptance matrix for `byreis rotate --add --from-request <PR>`
# Source-of-truth GitHub API fields:
#   pull_request.state                  ∈ {"open", "closed"}
#   pull_request.draft                  bool
#   pull_request.merged                 bool
#   pull_request.user.login             string (must equal yaml.github_handle byte-equal post-lowercase)
#   pull_request.head.sha               string (pinned at fetch-time, re-asserted at execute-time)
#   pull_request.head.repo.owner.login  string (pinned for fork-ownership-change detection)

accepted:
  - {state: open, draft: false, merged: false, user.login: <non-empty, non-"ghost">}

refused_with_sentinel:
  - condition: {state: closed, merged: true}
    sentinel: ErrRequestAccessPRStateInvalid
    hint: "this PR has already been merged; if you intend to re-rotate the same recipient, run rotate --add directly"
  - condition: {state: closed, merged: false}
    sentinel: ErrRequestAccessPRStateInvalid
    hint: "this PR has been closed; the contributor must reopen or open a new request-access PR"
  - condition: {state: open, draft: true}
    sentinel: ErrRequestAccessPRStateInvalid
    hint: "this PR is a draft; the contributor must mark it ready-for-review before admin absorption"
  - condition: {user.login: "ghost" OR ""}
    sentinel: ErrRequestAccessIdentityMismatch
    hint: "the PR author's GitHub account is deleted or anonymous; refuse the request"
  - condition: {yaml.github_handle != user.login (post-lowercase, post-ASCII-validation)}
    sentinel: ErrRequestAccessIdentityMismatch
    hint: "the YAML github_handle does not match the PR author's GitHub login"
  - condition: {any commit author.login != user.login}
    sentinel: ErrRequestAccessCommitAuthorDivergence
    hint: "the PR contains commits whose author differs from the PR opener; the contributor must close and reopen with a clean commit set"
  - condition: {head.sha at execute != head.sha at fetch}
    sentinel: ErrRequestAccessPRForcePushed
    hint: "the PR was force-pushed between plan and execute; re-run `byreis rotate --add --from-request <PR>` to re-fetch and review the new content"
  - condition: {head.repo.owner.login at execute != head.repo.owner.login at fetch}
    sentinel: ErrRequestAccessForkOwnershipChanged
    hint: "the contributor's fork ownership changed between plan and execute; re-run to re-evaluate"
  - condition: {files-changed contains anything outside requests/<handle>.yaml}
    sentinel: ErrRequestAccessPRFilePathInvalid
    hint: "the PR changes files outside the requests/ namespace; refuse"
  - condition: {YAML strict-decode fails (unknown field, duplicate key, malformed)}
    sentinel: ErrRequestAccessSchemaInvalid
    hint: "the YAML payload does not match the schema; the contributor must regenerate via `byreis request-access`"
  - condition: {YAML justification > 1000 bytes}
    sentinel: ErrRequestAccessSchemaInvalid
    hint: "justification exceeds 1000 bytes; the contributor must shorten and regenerate"
  - condition: {YAML github_handle contains non-ASCII or invalid GitHub login chars}
    sentinel: ErrRequestAccessSchemaInvalid
    hint: "github_handle must be ASCII-only and conform to GitHub's login alphabet ([A-Za-z0-9-]{1,39})"

advisory_only (NOT refused, logged as warning):
  - condition: {PR has been closed-then-reopened}
    action: log warning, proceed if all other state checks pass
    hint: "visually verify the reopen reason via `gh pr view`"
```

## Exit codes

The contributor verb (`byreis request-access`) and the admin path
(`byreis rotate --add --from-request`) share the project's standard exit
classes:

- `ok` (`0`) — verb completed; PR opened (contributor) or rotation
  absorbed (admin).
- `permission-denied` (`3`) — the caller is not in the required mode.
  Contributor verb denies ADMIN/SUPER; admin path denies CONTRIBUTOR.
- `auth-error` (`4`) — GitHub token is missing or invalid; admin path
  also surfaces this when the admin's keychain identity cannot be loaded
  or the admin is outside the project's pre-rotation recipient set
  (a different admin in the pre-rotation set must run the rotation).
- `counter-reconcile` (`6`) — the admin path observed a partial rotation
  state and refused to start a new rotation against it. Run
  `byreis admin rotation reconcile` against the project to recover; then
  re-run the absorption.
- `trust-error` (`7`) — registry view is stale or unverified; refresh
  with `byreis registry refresh` and retry. Also surfaces on rotation
  reversal probe defects (re-run `byreis admin rotation reconcile`).
- `decode-malformed` (`9`) — the YAML payload failed schema strict-decode
  on the admin path. The contributor must regenerate via
  `byreis request-access`.
- `general-error` (`1`) — anything else, including
  `ErrRequestAccessPRStateInvalid`, `ErrRequestAccessPRForcePushed`,
  `ErrRequestAccessForkOwnershipChanged`,
  `ErrRequestAccessQuotaExceeded`, and `ErrRotationFingerprintMismatch`.
  Each of these arrives with an actionable hint; the hint identifies
  the next operator step.

## Public-registry-repo disclosure surface

Some adopters configure the admin registry repo as a public GitHub
repository (for example, to use GitHub Pages or to make the admin set
visible to external auditors). For those adopters, the `requests/`
namespace is also publicly readable: every `requests/<handle>.yaml`
file (including the contributor's GitHub handle and age public key) is
visible to anyone with a browser.

The age public key itself is by construction a public key; the
cryptographic guarantees of `age` Model B are not weakened by its
publication. However, the **linkage** `<github-handle> -> <age public key>`
becomes a public fact. For adopters who treat their recipient set as
semi-confidential (for example, organisations that do not publicly
disclose which engineers have access to production), this linkage is an
information disclosure.

If your adopter is in that category, the operational guidance is:

- Configure the registry repo as a PRIVATE GitHub repository. The verb
  works identically against a private registry; the only difference is
  who can browse the repo's files.
- Treat the registry repo's access list as part of your asymmetric-access
  invariant: anyone who can read the registry can read every contributor's
  pubkey-to-handle linkage and every admin's pubkey.
- The byreis tool does not refuse to operate against a public registry;
  the public-vs-private choice is the adopter's, and the tool surfaces
  this notice exactly once, here in the runbook, rather than as a
  repeated CLI warning.

If you are unsure about your registry's visibility, run
`gh repo view <registry> --json visibility` before opening a
`request-access` PR.

## Adopter configuration

### Same-repo PR adopter footgun

The canonical request-access flow assumes the contributor opens the PR
from a fork of the registry repo. The PR is then a fork-PR: the head
repo is the contributor's fork, and the contributor has no registry-write
capability.

Some adopters configure their registry repo so that all members of the
organisation have push access (a "small team, everyone is trusted"
shape). In that configuration, a contributor with registry-repo write
access could open a same-repo PR — pushing the `requests/<handle>.yaml`
branch directly to the registry repo rather than to a fork.

The byreis tool does NOT distinguish a fork-PR from a same-repo PR at
the validation layer: both pass through the same state-machine matrix.
The structural checks remain effective:

- The single-file scope check refuses any PR that modifies files outside
  `requests/<handle>.yaml`, so a same-repo PR cannot smuggle in a
  recipient-set change to a separate file.
- The PR-author-vs-YAML byte-compare refuses any PR whose `user.login`
  does not match the YAML's `github_handle`, so a same-repo PR cannot
  spoof a different contributor's identity.

However, the canonical adopter configuration is "contributors have ZERO
registry-repo write; only fork-PR path", because that configuration
also rules out direct branch manipulation of the registry repo by
non-admins (a broader concern than the request-access flow). To pin
that configuration:

- Configure the registry repo's branch-protection to require fork-PR
  review for any change to `requests/*` paths.
- Restrict registry-repo push access to admins only; require
  contributors to fork the repo for any change, including
  `request-access`.

These are registry-repo configuration choices, not byreis settings. The
tool's behaviour is unchanged either way; the operator's trust posture
is the variable.

### Quota tuning

The per-contributor open-PR quota (default 5) is a client-side
advisory limit enforced by the `byreis request-access` verb. It is not
a server-side enforcement; a contributor who runs an unmodified `gh pr
create` directly against the registry can still open arbitrarily many
PRs. The quota is calibrated to the routine case (one open PR per
in-flight pubkey rotation), not the adversarial case.

For the adversarial case, the registry repo's branch-protection rules
are the enforcement layer: configure them to require admin review on
all `requests/*` paths, and the volume of open PRs becomes a denial-of-
service nuisance at most.

The quota check is itself a best-effort early-fail: between the open-PR
count probe and the actual PR creation (a few network round-trips), the
same contributor — or a parallel `byreis request-access` invocation on
a different machine under the same account — can race additional PRs
past the limit. GitHub's server-side rate limits and the registry's
branch-protection rules are the authoritative quota enforcers; the
client-side check exists to give a cleaner error message in the common
case, not to bind an adversary.

## Related reading

- `docs/forward-secrecy.md` — what `byreis rotate --remove` does and does
  not guarantee about pre-rotation ciphertext. A request-access absorption
  is an additive `--add`; it does not touch the forward-secrecy question
  unless the same rotation also removes a recipient.
- `docs/rotation-runbook.md` — recovering from a partial rotation via
  `byreis admin rotation reconcile`, including the Phase-1/Phase-2
  classification and the manual Phase-2 mid-flight recovery procedure.
  An absorption rotation that lands a partial state surfaces through the
  same recovery path.
- `byreis doctor` — general diagnostic verb; surfaces counter drift,
  unverified registry trust, and key/permission issues. Run before
  opening or absorbing a request-access PR if anything about the
  project's recipient set looks unexpected.
