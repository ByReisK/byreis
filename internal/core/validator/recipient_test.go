package validator_test

import (
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/ByReisK/byreis/internal/core/validator"
)

// genX25519Recipient returns a real native X25519 recipient string ("age1…",
// HRP "age", empty backend discriminator).
func genX25519Recipient(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity: %v", err)
	}
	return id.Recipient().String()
}

// pluginRecipient returns a real plugin-encoded recipient string for the given
// backend name. This is the exact encoding fakeplugin.RecipientString() uses
// (plugin.EncodeRecipient → bech32 HRP "age1<name>"); constructing it directly
// here keeps the core validator test free of any adapter import (RULE 3).
func pluginRecipient(t *testing.T, name string) string {
	t.Helper()
	s := plugin.EncodeRecipient(name, []byte{0x42})
	if s == "" {
		t.Fatalf("EncodeRecipient(%q): produced empty string (invalid plugin name)", name)
	}
	return s
}

func TestClassifyRecipient(t *testing.T) {
	t.Parallel()

	x25519 := genX25519Recipient(t)
	yubikey := pluginRecipient(t, "yubikey")
	tpm := pluginRecipient(t, "tpm")
	se := pluginRecipient(t, "se")
	fido2 := pluginRecipient(t, "fido2")
	unknownHRP := pluginRecipient(t, "pgp") // well-formed bech32, HRP not in the closed set

	tests := []struct {
		name        string
		input       string
		wantBackend string
		wantErr     bool
	}{
		{
			name:        "native X25519 string classifies as empty discriminator",
			input:       x25519,
			wantBackend: "", // native X25519
			wantErr:     false,
		},
		{
			name:        "fake-plugin yubikey string classifies as yubikey",
			input:       yubikey,
			wantBackend: "yubikey",
			wantErr:     false,
		},
		{
			name:        "tpm plugin string classifies as tpm",
			input:       tpm,
			wantBackend: "tpm",
			wantErr:     false,
		},
		{
			name:        "se plugin string classifies as se",
			input:       se,
			wantBackend: "se",
			wantErr:     false,
		},
		{
			name:        "fido2 plugin string classifies as fido2",
			input:       fido2,
			wantBackend: "fido2",
			wantErr:     false,
		},
		{
			name:    "well-formed but unknown HRP (pgp) is rejected — not in the closed set",
			input:   unknownHRP,
			wantErr: true,
		},
		{
			name:    "garbage age1 prefix with no valid bech32 checksum is rejected",
			input:   "age1garbage",
			wantErr: true,
		},
		{
			name:    "empty string is rejected",
			input:   "",
			wantErr: true,
		},
		{
			name:    "missing age1 prefix is rejected",
			input:   "ssh-ed25519 AAAA",
			wantErr: true,
		},
		{
			name:    "mixed-case bech32 is rejected (not a canonical recipient)",
			input:   strings.ToUpper(yubikey[:8]) + yubikey[8:],
			wantErr: true,
		},
		{
			name:    "truncated bech32 (corrupt checksum) is rejected",
			input:   yubikey[:len(yubikey)-2],
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			backend, err := validator.ClassifyRecipient(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ClassifyRecipient(%q) = (%q, nil); want a rejection error",
						tc.input, backend)
				}
				if !errors.Is(err, validator.ErrUnsupportedRecipient) {
					t.Errorf("ClassifyRecipient(%q) error = %v; want wrapped ErrUnsupportedRecipient",
						tc.input, err)
				}
				// Fail-closed must never return a member of the closed set on error.
				if backend != "" {
					t.Errorf("ClassifyRecipient(%q) returned backend %q alongside error; want empty",
						tc.input, backend)
				}
				// Actionable hint: the message must point at byreis doctor.
				if !strings.Contains(err.Error(), "doctor") {
					t.Errorf("ClassifyRecipient(%q) error %q lacks an actionable `byreis doctor` hint",
						tc.input, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("ClassifyRecipient(%q) unexpected error: %v", tc.input, err)
			}
			if backend != tc.wantBackend {
				t.Errorf("ClassifyRecipient(%q) backend = %q; want %q",
					tc.input, backend, tc.wantBackend)
			}
			if !validator.SupportedRecipientBackends[backend] {
				t.Errorf("ClassifyRecipient(%q) returned backend %q not in SupportedRecipientBackends",
					tc.input, backend)
			}
		})
	}
}

// TestSupportedRecipientBackends pins the exact closed admit-set. Adding or
// removing a backend is a deliberate security change that must update this test
// and pull a crypto/threat re-ack.
func TestSupportedRecipientBackends(t *testing.T) {
	t.Parallel()

	want := map[string]bool{
		"":        true, // native X25519
		"yubikey": true,
		"tpm":     true,
		"se":      true,
		"fido2":   true,
	}
	if len(validator.SupportedRecipientBackends) != len(want) {
		t.Fatalf("SupportedRecipientBackends has %d members; want %d (%v)",
			len(validator.SupportedRecipientBackends), len(want), want)
	}
	for k, v := range want {
		if validator.SupportedRecipientBackends[k] != v {
			t.Errorf("SupportedRecipientBackends[%q] = %v; want %v",
				k, validator.SupportedRecipientBackends[k], v)
		}
	}
	// Closed-world: an unlisted discriminator must be absent (not merely false).
	if _, present := validator.SupportedRecipientBackends["pgp"]; present {
		t.Errorf("SupportedRecipientBackends must not contain pgp")
	}
}
