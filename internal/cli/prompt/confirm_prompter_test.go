package prompt

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestConfirmPrompterConfirmSignerFingerprint(t *testing.T) {
	const fp = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"

	cases := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "exact match accepts",
			input:   fp + "\n",
			wantErr: false,
		},
		{
			name:    "case-insensitive match accepts",
			input:   strings.ToLower(fp) + "\n",
			wantErr: false,
		},
		{
			name:        "mismatch aborts with actionable message",
			input:       "SHA256:wrongfingerprint\n",
			wantErr:     true,
			errContains: "mismatch",
		},
		{
			name:        "empty input aborts with accept-signer hint",
			input:       "\n",
			wantErr:     true,
			errContains: "--accept-signer",
		},
		{
			name:        "EOF aborts with non-interactive hint",
			input:       "",
			wantErr:     true,
			errContains: "--accept-signer",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdin := strings.NewReader(tc.input)
			out := &bytes.Buffer{}
			p := NewConfirmPrompterWithDeps(stdin, out)

			err := p.ConfirmSignerFingerprint(context.Background(), fp)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errContains)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestConfirmPrompterCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := NewConfirmPrompterWithDeps(strings.NewReader("anything\n"), io.Discard)
	err := p.ConfirmSignerFingerprint(ctx, "fingerprint")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("error %q should mention 'cancelled'", err.Error())
	}
}
