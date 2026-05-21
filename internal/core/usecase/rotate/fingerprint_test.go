package rotate_test

// V5.FP.* rows — RecipientFingerprintFull helper.
//
// Row IDs (audit-trail anchors permitted in _test.go ONLY):
//   - V5.FP.known-vector
//   - V5.FP.stability
//   - V5.FP.distinctness
//
// Discharges BO-V5-4: the typed-fingerprint confirm in --remove/--replace
// path requires a single source of truth for fingerprint computation so the
// CLI's typed-confirm path and any displayed fingerprint always agree on
// shape. Full 64-char SHA-256 hex; truncated digests are forbidden.

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// V5.FP.known-vector — known pubkey string produces the byte-correct
// sha256 hex digest. The reference digest is computed inline from the same
// known input (no test-vector file dependency); this anchors the helper's
// shape and length on every CI run.
func TestRecipientFingerprintFull_KnownVector(t *testing.T) {
	t.Parallel()

	pubkey := "age1exampleexampleexampleexampleexampleexampleexampleexampleabcd"
	want := sha256.Sum256([]byte(pubkey))
	wantHex := hex.EncodeToString(want[:])

	got := rotate.RecipientFingerprintFull(rectypes.Recipient{AgePubKey: pubkey})
	if got != wantHex {
		t.Fatalf("RecipientFingerprintFull = %q, want %q", got, wantHex)
	}
	if len(got) != 64 {
		t.Errorf("fingerprint length = %d, want 64 (full sha256 hex; truncation is forbidden)",
			len(got))
	}
}

// V5.FP.stability — same input twice produces byte-equal output. Computation
// is pure / deterministic; any state-dependent drift is a defect.
func TestRecipientFingerprintFull_Stability(t *testing.T) {
	t.Parallel()

	r := rectypes.Recipient{AgePubKey: "age1stableinputstableinputstableinputstableinput"}
	first := rotate.RecipientFingerprintFull(r)
	second := rotate.RecipientFingerprintFull(r)
	if first != second {
		t.Fatalf("non-deterministic fingerprint: first=%q second=%q", first, second)
	}
}

// V5.FP.distinctness — two distinct pubkeys produce distinct fingerprints.
// SHA-256 collisions are not a realistic risk; this row defends the helper's
// input plumbing (a regression that fed a constant string would still pass
// the stability row but fail here).
func TestRecipientFingerprintFull_Distinctness(t *testing.T) {
	t.Parallel()

	a := rotate.RecipientFingerprintFull(rectypes.Recipient{AgePubKey: "age1alice"})
	b := rotate.RecipientFingerprintFull(rectypes.Recipient{AgePubKey: "age1bob"})
	if a == b {
		t.Fatalf("two distinct pubkeys produced the same fingerprint: %q", a)
	}
}
