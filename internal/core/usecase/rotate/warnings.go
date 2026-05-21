package rotate

// RequestAccessHonestyContract is the verbatim operator-honesty contract string
// the contributor-side `byreis request-access` verb embeds in its `--help`
// long description. It is the single source of truth for the asymmetric-access
// guarantee surfaced at the verb's first contact: the verb opens a PR using
// the contributor's own GitHub identity and does not, at any point, acquire
// an admin credential or a registry-write key. A docgate row asserts this
// string is present in the verb's help output byte-for-byte.
//
// The wording is domain-English and carries no internal review IDs. A change
// here is a deliberate review event: the help text is the operator-facing
// trust contract for the contributor write path.
const RequestAccessHonestyContract = "this verb opens a PR using your own GitHub identity; " +
	"no admin credential or registry-write key is acquired"

// RequestAccessAdminWarning is the verbatim warning string the CLI emits on
// stdout whenever `byreis rotate --add --from-request <PR>` is invoked. It
// documents the operator-visible trust surface of absorbing a contributor-
// authored PR pubkey: the byte-equal compare semantics of the
// PR-author-vs-YAML check, the visual verification the operator still owes,
// and the fingerprint-confirm gate that follows. The string is single
// source-of-truth; the docgate suite asserts it byte-for-byte at a later
// slice. A change here is a deliberate review event.
//
// The wording is domain-English and carries no internal review IDs — the
// public history of this repo treats this constant as a load-bearing operator
// honesty assertion, not as agent-pipeline metadata.
const RequestAccessAdminWarning = `WARNING: this rotation absorbs a recipient pubkey from a contributor's
request-access PR. Before confirming:

  - The YAML's github_handle field is byte-compared to the PR opener's
    GitHub login (` + "`pull_request.user.login`" + `). It is NOT compared to
    the PR title, body, description, comments, or any commit-author email.
  - Visually verify the PR opener IS the human you intend to grant access
    to (run ` + "`gh pr view <PR>`" + ` to confirm the GitHub account is the
    intended contributor). A login byte-match alone is not a substitute
    for that visual check.
  - Commit-author divergence (a PR whose commits are authored by a
    different identity than the PR opener) AND force-push races between
    plan and execute are caught structurally, but the typed-fingerprint
    confirm below is your last line of defense — inspect the SHA-256
    fingerprint of the recipient and type the full 64-char value to
    proceed. Mismatch refuses the rotation.

`

// ForwardSecrecyWarning is the single source-of-truth warning string both
// `byreis rotate --remove` CLI output and `byreis doctor --rotation-history`
// reference, and that the doc-gate test fixture asserts against. The string
// is pinned verbatim; any change is a deliberate review event because the
// honesty of this warning is a load-bearing user-trust assertion.
//
// The fixture in the doc-gate test embeds the same text as a []byte literal
// (not via Go string-import of this constant) so that the constant and the
// fixture are independently asserted against the same source-of-truth text.
// A typo in either fails the test by design.
const ForwardSecrecyWarning = `WARNING: forward secrecy over git history is NOT provided by rotation.

A removed recipient's private key, if retained, can still decrypt the
pre-rotation ciphertext from any retained clone or fork of the project
git history. byreis rotation re-encrypts every CURRENT secrets file to
the new recipient set, but it CANNOT retroactively remove past
ciphertext from past commits. If the removed recipient is a compromised
party, you MUST treat all secret values that were ever encrypted under
the pre-rotation recipient set as compromised and rotate the
underlying values (passwords, tokens, keys) themselves out-of-band.

This is a property of the ` + "`age`" + ` cryptographic primitive (Model B) and
of git's append-only history, not a byreis bug. See docs/forward-
secrecy.md for the runbook.`
