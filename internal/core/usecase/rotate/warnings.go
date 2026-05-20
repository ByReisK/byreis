package rotate

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
