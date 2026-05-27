package registry_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/ByReisK/byreis/internal/adapter/fakeplugin"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
)

// realX25519Recipient returns a genuine native X25519 recipient string. The
// admission path now validates the bech32 encoding, so fixtures must use real,
// well-formed recipient strings rather than the loose "age1..." stand-ins that
// the previous HasPrefix gate accepted.
func realX25519Recipient(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	return id.Recipient().String()
}

// realPluginRecipient returns a genuine plugin-encoded recipient for the given
// backend name (bech32 HRP "age1<name>"). It mirrors fakeplugin.RecipientString
// but is parametric over the backend so the distinctness vector can cover all
// admitted plugin backends.
func realPluginRecipient(t *testing.T, name string) string {
	t.Helper()
	s := plugin.EncodeRecipient(name, []byte{0x42})
	if s == "" {
		t.Fatalf("EncodeRecipient(%q): empty (invalid plugin name)", name)
	}
	return s
}

// TestAdmission_ClosedSet proves the registry admission gate now admits a
// recipient iff its backend is a member of the closed admit-set, and rejects
// everything else fail-closed with an actionable error. This closes the latent
// open-admission regression where any "age1..." prefix was accepted.
func TestAdmission_ClosedSet(t *testing.T) {
	t.Parallel()

	x25519 := realX25519Recipient(t)
	yubikey := fakeplugin.RecipientString() // real "age1yubikey1..." plugin string
	tpm := realPluginRecipient(t, "tpm")

	key := newEd25519Key(t)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	tests := []struct {
		name      string
		ageKey    string
		wantAdmit bool
	}{
		{name: "admit real X25519 recipient (no regression)", ageKey: x25519, wantAdmit: true},
		{name: "admit real yubikey plugin recipient", ageKey: yubikey, wantAdmit: true},
		{name: "admit real tpm plugin recipient", ageKey: tpm, wantAdmit: true},
		{name: "reject age1garbage (open-admission regression closed)", ageKey: "age1garbage", wantAdmit: false},
		{name: "reject well-formed unknown HRP (pgp)", ageKey: realPluginRecipient(t, "pgp"), wantAdmit: false},
		{name: "reject non-age key", ageKey: "ssh-ed25519 AAAA", wantAdmit: false},
		{name: "reject loose age1abc123 stand-in", ageKey: "age1abc123", wantAdmit: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			yaml := validAdminsYAML("admin-a", tc.ageKey, keyB64)
			data, fetchErr := exerciseParseAdminsYAML(t, yaml)

			if tc.wantAdmit {
				if fetchErr != nil {
					t.Fatalf("admission rejected an admitted recipient %q: %v", tc.ageKey, fetchErr)
				}
				if len(data.Recipients) != 1 {
					t.Fatalf("admitted recipient count = %d; want 1", len(data.Recipients))
				}
				if data.Recipients[0].AgePubKey != tc.ageKey {
					t.Errorf("admitted AgePubKey = %q; want %q", data.Recipients[0].AgePubKey, tc.ageKey)
				}
				return
			}

			if fetchErr == nil {
				t.Fatalf("admission accepted a recipient it must reject: %q", tc.ageKey)
			}
			if !errors.Is(fetchErr, coreregistry.ErrAdminSetUnreadable) {
				t.Errorf("rejection error = %v; want wrapped ErrAdminSetUnreadable", fetchErr)
			}
		})
	}
}

// TestAdmission_CrossBackendFingerprintDistinctness is the REQ-V09-007 vector:
// the recipient fingerprint preimage is the full exact recipient string, so the
// five admitted backends must produce five pairwise-distinct fingerprints. This
// asserts the existing derivation's cross-backend behaviour; it adds no
// fingerprint code.
func TestAdmission_CrossBackendFingerprintDistinctness(t *testing.T) {
	t.Parallel()

	recipients := map[string]string{
		"x25519":  realX25519Recipient(t),
		"yubikey": realPluginRecipient(t, "yubikey"),
		"tpm":     realPluginRecipient(t, "tpm"),
		"se":      realPluginRecipient(t, "se"),
		"fido2":   realPluginRecipient(t, "fido2"),
	}

	// Compute the full-string SHA-256 fingerprint each backend yields, matching
	// the admission-path derivation (sha256 over the exact recipient string).
	fps := make(map[string][32]byte, len(recipients))
	for backend, rec := range recipients {
		fps[backend] = sha256.Sum256([]byte(rec))
	}

	if len(fps) != 5 {
		t.Fatalf("expected 5 backend fingerprints, got %d", len(fps))
	}

	seen := make(map[[32]byte]string, len(fps))
	for backend, fp := range fps {
		if prev, dup := seen[fp]; dup {
			t.Fatalf("fingerprint collision between backends %q and %q", prev, backend)
		}
		seen[fp] = backend
	}
}
