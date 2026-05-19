//go:build shipgate

// Package usecase — asymmetric-access behavioral ship-gate suite.
//
// This file implements the enumerated ship-gate suite. The suite proves the
// observable behavior that a contributor-mode process with no private key
// cannot, by any command/flag/env/output channel, emit a plaintext secret
// value from a real encrypted project file.
//
// Gate: a red ship-gate job hard-fails the release pipeline. The release
// workflow has needs: [shipgate] with no manual-override path.
//
// A red result here blocks the release regardless of other green tests.
//
// Still to implement — the full enumerated matrix:
//   - Commands × flags: version, init, doctor, submit (--add/--replace/--key/
//     --value/stdin/--justification/--non-interactive/--json), plus attempted
//     get/decrypt/edit (denied-by-policy assertion).
//   - Keyless states (a) no admin key file; (b) BYREIS_KEY unset; (c)
//     BYREIS_KEY_FILE unset; (d) empty/no keychain; (e) all simultaneously.
//   - Output channels observed: stdout, stderr, any generated/temp file, the
//     structured log sink, --json payload, error %v/%+v text, any exit-data blob.
//   - Assertions:
//     1. No-plaintext invariant: no secret plaintext value appears verbatim,
//     base64'd, or hex'd in any observed channel for any command×state cell.
//     2. Denied-by-policy (not attempted-then-failed): get/decrypt/edit are
//     rejected by mode policy before any decrypt/identity code is reached.
//     Assert denial sentinel + call-graph spy shows no crypto/decrypt entry.
//
// The fixture requires real age ciphertext to a known test recipient set whose
// private key is never provided to the test process. The test holds the
// cleartext only to assert its absence.
package usecase_test

import "testing"

// TestAsymmetryShipGate is the ship-gate entry point.
// Currently a structured stub; the t.Skip call is replaced by the real suite.
func TestAsymmetryShipGate(t *testing.T) {
	t.Skip("ship-gate suite not yet implemented — " +
		"a red result here blocks the release pipeline once implemented")
}
