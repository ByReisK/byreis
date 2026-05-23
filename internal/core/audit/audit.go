// Package audit defines the append-only audit log port and domain events.
// No filesystem import — the port abstracts the storage backend.
// The concrete append-only implementation lives in an adapter.
package audit

import (
	"context"
	"time"
)

// EventKind classifies an auditable event.
type EventKind string

// EventKind values enumerate all auditable event types.
const (
	EventKindModePromotion   EventKind = "mode.promotion"
	EventKindSubmit          EventKind = "submit"
	EventKindReview          EventKind = "review"
	EventKindMerge           EventKind = "merge"
	EventKindPendingBump     EventKind = "counter.pending_bump"
	EventKindCommitBump      EventKind = "counter.commit_bump"
	EventKindRegistryRefresh EventKind = "registry.refresh"
	EventKindAuthLogin       EventKind = "auth.login"

	// EventKindRotation is emitted when a rotation transaction completes
	// successfully. It is appended in the same signed registry commit as the
	// CommitRotation counter advance (same-commit atomicity per the rotation
	// protocol). Only the registry-side audit sink persists this event kind.
	EventKindRotation EventKind = "rotation"

	// EventKindReject is emitted when an admin closes a request or submission PR
	// with a structured reason. Reject is a PR-close action with no decrypt and
	// no merge, so it is a distinct kind from EventKindReview rather than a review
	// outcome string. The free-text reason is NEVER stored on the event — only a
	// reason-length byte count — so audit search/diff cannot leak it.
	EventKindReject EventKind = "request.reject"
)

// Event is an append-only audit log entry. No secret values are ever stored;
// only key names, project IDs, and outcome metadata.
type Event struct {
	Kind       EventKind         `json:"kind"`
	OccurredAt time.Time         `json:"occurred_at"`
	Actor      string            `json:"actor,omitempty"` // user/identity identifier; empty for contributor actions
	ProjectID  string            `json:"project_id,omitempty"`
	FileName   string            `json:"file_name,omitempty"`
	KeyName    string            `json:"key_name,omitempty"` // NOT the secret value
	PRRef      string            `json:"pr_ref,omitempty"`
	Outcome    string            `json:"outcome,omitempty"` // "ok" | "error: <hint>"
	Details    map[string]string `json:"details,omitempty"` // additional diagnostic fields; NEVER secret values
}

// Logger is the append-only audit log port. Implementations MUST be append-only
// and MUST never log secret values. Context is carried for cancellation.
type Logger interface {
	// Append records an audit event. Returns an error only if the event cannot
	// be durably written (e.g. disk full); callers should surface this loudly.
	Append(ctx context.Context, e Event) error
}

// Discard is a no-op Logger for tests.
var Discard Logger = discardLogger{}

type discardLogger struct{}

func (discardLogger) Append(_ context.Context, _ Event) error { return nil }
