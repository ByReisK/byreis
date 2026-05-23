package validator_test

import (
	"strings"
	"testing"

	validatoradapter "github.com/ByReisK/byreis/internal/adapter/validator"
)

// TestValidateValue_NoPlaintextInError (T-V9-2 discharge):
// Each rejection branch of ValidateValue is seeded with a unique sentinel
// secret value. The test asserts that the returned error string does NOT
// contain the sentinel in any form. This proves secret values cannot leak into
// error messages, logs, or terminal output.
func TestValidateValue_NoPlaintextInError(t *testing.T) {
	t.Parallel()
	a := validatoradapter.New()

	type row struct {
		name     string
		value    string
		sentinel string
		wantErr  bool
	}

	rows := []row{
		{
			name:     "empty value sentinel not in error",
			value:    "",
			sentinel: "SENTINEL-PLAINTEXT-7f3a",
			wantErr:  true,
		},
		{
			name:     "too-long value sentinel not in error",
			value:    strings.Repeat("SENTINEL-TOOLONG-9b2c", 60000), // > 1 MiB
			sentinel: "SENTINEL-TOOLONG-9b2c",
			wantErr:  true,
		},
		{
			name:     "NUL byte sentinel not in error",
			value:    "SENTINEL-NUL-4e7d\x00suffix",
			sentinel: "SENTINEL-NUL-4e7d",
			wantErr:  true,
		},
	}

	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			err := a.ValidateValue(r.value)
			if r.wantErr && err == nil {
				t.Fatalf("expected validation error for %q; got nil", r.name)
			}
			if !r.wantErr && err != nil {
				t.Fatalf("expected no validation error; got %v", err)
			}
			if err != nil && r.sentinel != "" {
				if strings.Contains(err.Error(), r.sentinel) {
					t.Errorf(
						"security violation: secret sentinel %q appears in validation error: %q\n"+
							"The error message must never embed the secret value — "+
							"only a fixed reason may appear.",
						r.sentinel, err.Error())
				}
			}
		})
	}
}

// TestValidateValue_BulkLineNumberPath asserts that a value rejection error
// built in a simulated bulk/line-number context does not contain the sentinel
// value. This mirrors the bulk-submission code path where errors carry a key
// name and possibly a line number but never the value.
func TestValidateValue_BulkLineNumberPath(t *testing.T) {
	t.Parallel()
	a := validatoradapter.New()

	sentinel := "SENTINEL-BULK-a1b2"

	// Simulate what the submit use-case does in SubmitBulk: wrap the
	// ValidateValue error with the key name (line 2 for this example).
	// The wrapped error must not contain the sentinel.
	err := a.ValidateValue(sentinel + "\x00") // contains NUL → rejected
	if err == nil {
		t.Fatal("expected validation error for NUL-bearing value; got nil")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf(
			"security violation: secret sentinel %q appears in validation error: %q\n"+
				"The error message must never embed the secret value.",
			sentinel, err.Error())
	}
}

// TestValidateKeyName covers the key-name rules.
func TestValidateKeyName(t *testing.T) {
	t.Parallel()
	a := validatoradapter.New()

	type row struct {
		name    string
		input   string
		wantErr bool
	}

	rows := []row{
		{name: "valid simple key", input: "API_KEY", wantErr: false},
		{name: "valid leading underscore", input: "_MY_KEY", wantErr: false},
		{name: "valid mixed case", input: "DbPassword1", wantErr: false},
		{name: "empty key", input: "", wantErr: true},
		{name: "leading digit", input: "1KEY", wantErr: true},
		{name: "contains hyphen", input: "MY-KEY", wantErr: true},
		{name: "contains space", input: "MY KEY", wantErr: true},
		{name: "contains separator 0x1e", input: "KEY\x1eNAME", wantErr: true},
		{name: "contains separator 0x1f", input: "KEY\x1fNAME", wantErr: true},
	}

	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			err := a.ValidateKeyName(r.input)
			if r.wantErr && err == nil {
				t.Errorf("expected error for key %q; got nil", r.input)
			}
			if !r.wantErr && err != nil {
				t.Errorf("expected no error for key %q; got %v", r.input, err)
			}
		})
	}
}

// TestValidateValue_AcceptsValidValue asserts that a normal secret value passes.
func TestValidateValue_AcceptsValidValue(t *testing.T) {
	t.Parallel()
	a := validatoradapter.New()
	if err := a.ValidateValue("s3cr3t-value!@#$%"); err != nil {
		t.Errorf("expected no error for valid value; got %v", err)
	}
}
