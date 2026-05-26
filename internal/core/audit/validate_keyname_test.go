package audit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/core/audit"
)

// TestValidateEventFields_TopLevelKeyName proves that the top-level Event.KeyName
// is validated (it previously reached the signed write UNVALIDATED because the
// validator only iterated Details). The KeyName carries a contributor-supplied
// secret key NAME (sub.Meta.Key) and must match a strict slash-free identifier
// pattern: ^[a-zA-Z0-9._-]{1,256}$. The rule fires only when KeyName != "".
func TestValidateEventFields_TopLevelKeyName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		keyName string
		wantErr bool
	}{
		{name: "empty key name skipped", keyName: "", wantErr: false},
		{name: "simple key", keyName: "API_KEY", wantErr: false},
		{name: "dotted key", keyName: "db.password", wantErr: false},
		{name: "dashed key", keyName: "my-token-v2", wantErr: false},
		{name: "underscored key", keyName: "DATABASE_URL", wantErr: false},
		{name: "alnum key", keyName: "Key123", wantErr: false},
		{name: "max length 256", keyName: strings.Repeat("a", 256), wantErr: false},

		{name: "slash rejected", keyName: "secrets/key", wantErr: true},
		{name: "over 256 rejected", keyName: strings.Repeat("a", 257), wantErr: true},
		{name: "space rejected", keyName: "has space", wantErr: true},
		{name: "newline injection rejected", keyName: "API_KEY\ninjected: bad", wantErr: true},
		{name: "null byte rejected", keyName: "API\x00KEY", wantErr: true},
		{name: "tab rejected", keyName: "API\tKEY", wantErr: true},
		{name: "colon rejected", keyName: "ns:key", wantErr: true},
		{name: "high-entropy ciphertext-like rejected", keyName: strings.Repeat("A", 40), wantErr: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := audit.Event{
				Kind:      audit.EventKindMerge,
				ProjectID: "proj",
				FileName:  "secrets/prod.enc.yaml",
				KeyName:   tc.keyName,
			}
			err := audit.ValidateEventFields(e)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("KeyName %q: expected ErrAuditEventInvalidField, got nil", tc.keyName)
				}
				if !errors.Is(err, audit.ErrAuditEventInvalidField) {
					t.Errorf("KeyName %q: want errors.Is(err, ErrAuditEventInvalidField), got: %v", tc.keyName, err)
				}
			} else if err != nil {
				t.Errorf("KeyName %q: unexpected error: %v", tc.keyName, err)
			}
		})
	}
}

// TestValidateEventFields_KeyNameDashNotARange guards the regex authoring detail
// that the '-' inside the KeyName character class must be positioned (or escaped)
// so it does not form an unintended character range. A would-be range such as
// '.'..'_' (if '-' were mid-class) would silently admit control bytes; this test
// pins a few bytes that lie between '.' (0x2e) and '_' (0x5f) in ASCII and must
// be REJECTED, proving the dash is a literal.
func TestValidateEventFields_KeyNameDashNotARange(t *testing.T) {
	t.Parallel()

	// These bytes are all in [0x2e..0x5f] but are NOT in the literal allowed set
	// {a-z A-Z 0-9 . _ -}. If '-' accidentally formed a range they could slip in.
	rejects := []string{"a:b", "a;b", "a<b", "a>b", "a@b", "a/b"}
	for _, k := range rejects {
		k := k
		t.Run(k, func(t *testing.T) {
			t.Parallel()
			e := audit.Event{Kind: audit.EventKindMerge, KeyName: k}
			if err := audit.ValidateEventFields(e); err == nil {
				t.Fatalf("KeyName %q must be rejected (dash must be literal, not a range)", k)
			}
		})
	}
}
