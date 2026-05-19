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
)

// Event is an append-only audit log entry. No secret values are ever stored;
// only key names, project IDs, and outcome metadata.
type Event struct {
	Kind      EventKind
	OccuredAt time.Time
	Actor     string // user/identity identifier; empty for contributor actions
	ProjectID string
	FileName  string
	KeyName   string // NOT the secret value
	PRRef     string
	Outcome   string            // "ok" | "error: <hint>"
	Details   map[string]string // additional diagnostic fields; NEVER secret values
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
