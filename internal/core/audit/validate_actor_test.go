package audit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ByReisK/byreis/internal/core/audit"
)

// TestValidateEventFields_TopLevelActor proves that the top-level Event.Actor is
// rejected when it carries an age1 recipient pubkey. The actor label is a human
// identity attested by the registry signer record; an age1... value in Actor
// means the producer leaked a recipient pubkey into the actor slot, which the
// validator must refuse fail-closed (write-side defense-in-depth). A normal
// human label or an empty Actor (system / contributor event) passes. The rule
// mirrors the top-level KeyName block: Actor was previously written UNVALIDATED
// because the validator only iterated Details and checked KeyName.
func TestValidateEventFields_TopLevelActor(t *testing.T) {
	t.Parallel()

	// A canonical age recipient: "age1" + exactly 58 bech32 chars (62 total).
	ageRecipient := "age1" + strings.Repeat("q", 58)

	cases := []struct {
		name    string
		actor   string
		wantErr bool
	}{
		{name: "empty actor skipped", actor: "", wantErr: false},
		{name: "human login", actor: "alice", wantErr: false},
		{name: "email-like label", actor: "alice@example.com", wantErr: false},
		{name: "display name with space", actor: "Alice Smith", wantErr: false},
		{name: "system marker", actor: "system", wantErr: false},

		{name: "age1 recipient pubkey rejected", actor: ageRecipient, wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := audit.Event{
				Kind:      audit.EventKindRotation,
				ProjectID: "proj",
				Actor:     tc.actor,
			}
			err := audit.ValidateEventFields(e)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Actor %q: expected ErrAuditEventInvalidField, got nil", tc.actor)
				}
				if !errors.Is(err, audit.ErrAuditEventInvalidField) {
					t.Errorf("Actor %q: want errors.Is(err, ErrAuditEventInvalidField), got: %v", tc.actor, err)
				}
			} else if err != nil {
				t.Errorf("Actor %q: unexpected error: %v", tc.actor, err)
			}
		})
	}
}

// TestValidateEventFields_ActorAge1Anchored confirms the age1 rejection keys on
// the anchored agePubkeyRE (^age1[0-9a-z]{58}$), so a label that merely starts
// with "age1" but is not a full canonical recipient (e.g. a human handle that
// happens to begin "age1...") is NOT mistakenly rejected, while the exact-length
// canonical recipient IS rejected.
func TestValidateEventFields_ActorAge1Anchored(t *testing.T) {
	t.Parallel()

	canonical := "age1" + strings.Repeat("q", 58)

	// Not a canonical recipient: too short / wrong length — must pass.
	accepts := []string{"age1team", "age1-rollout", "age1" + strings.Repeat("q", 10)}
	for _, a := range accepts {
		a := a
		t.Run("accept/"+a, func(t *testing.T) {
			t.Parallel()
			e := audit.Event{Kind: audit.EventKindRotation, Actor: a}
			if err := audit.ValidateEventFields(e); err != nil {
				t.Fatalf("Actor %q must pass (not a canonical age1 recipient): %v", a, err)
			}
		})
	}

	// The exact canonical recipient must be rejected.
	e := audit.Event{Kind: audit.EventKindRotation, Actor: canonical}
	if err := audit.ValidateEventFields(e); !errors.Is(err, audit.ErrAuditEventInvalidField) {
		t.Fatalf("canonical age1 recipient in Actor must be rejected, got: %v", err)
	}
}
