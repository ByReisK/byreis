// Package audit provides a durable, append-only audit log adapter backed by
// a local file. It satisfies the internal/core/audit.Logger port.
//
// Each Append call writes a single JSON-encoded audit.Event on its own line
// (newline-delimited JSON). The file is opened append-only with O_APPEND|O_SYNC
// so every write is durable even under concurrent use. The file is NOT
// world-readable: it is created 0600.
//
// Placement: OUTER adapter layer (internal/adapter/audit). Core packages never
// import this package; it is wired at the composition root.
//
// Security: no secret values are written. Audit events must never include
// plaintext, ciphertext, or key material — that invariant is enforced by the
// core audit.Event type (which only carries key names, project IDs, and outcome
// metadata). This adapter writes the event as-is without re-inspecting the
// content; core is responsible for the content constraint.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/ByReisK/byreis/internal/core/audit"
)

// FileLogger is a durable audit.Logger backed by a newline-delimited JSON file.
// The file is opened once at construction and kept open; writes are serialized
// by a mutex so concurrent promotions do not interleave.
type FileLogger struct {
	mu sync.Mutex
	f  *os.File
}

// New opens (or creates) the audit log file at path and returns a FileLogger.
// The file is opened append-only with O_APPEND|O_SYNC|O_CREATE, mode 0600.
// Returns an error if the file cannot be opened — the caller (composition root)
// must treat this as a fatal startup error and refuse to run rather than
// silently discarding promotion audits.
func New(path string) (*FileLogger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE|os.O_SYNC, 0o600) //nolint:gosec // 0600 is intentional; path is composition-root-supplied, not user-controlled
	if err != nil {
		return nil, fmt.Errorf("opening audit log %q: %w — check permissions and path", path, err)
	}
	return &FileLogger{f: f}, nil
}

// Close releases the underlying file handle. Call at process exit.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// Append writes the event as a single JSON line to the audit file.
// The write is serialized and fsynced (O_SYNC). Returns an error only when the
// write cannot be durably recorded.
//
// Context cancellation is checked before acquiring the lock; a cancelled context
// returns an error rather than potentially blocking on a slow fsync.
func (l *FileLogger) Append(ctx context.Context, e audit.Event) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("audit append cancelled: %w", err)
	}

	b, err := json.Marshal(jsonEvent{
		Kind:      string(e.Kind),
		OccuredAt: e.OccuredAt.UTC().Format("2006-01-02T15:04:05Z"),
		Actor:     e.Actor,
		ProjectID: e.ProjectID,
		FileName:  e.FileName,
		KeyName:   e.KeyName,
		PRRef:     e.PRRef,
		Outcome:   e.Outcome,
		Details:   e.Details,
	})
	if err != nil {
		return fmt.Errorf("audit marshal: %w", err)
	}
	b = append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.f == nil {
		return fmt.Errorf("audit log is closed — cannot append event")
	}

	if _, err := l.f.Write(b); err != nil {
		return fmt.Errorf("audit log write: %w — promotion record may be incomplete", err)
	}
	return nil
}

// Compile-time assertion that *FileLogger satisfies audit.Logger.
var _ audit.Logger = (*FileLogger)(nil)

// jsonEvent is the wire type for audit log lines. It mirrors audit.Event but
// uses only JSON-safe primitive types. Time is formatted as RFC3339 UTC.
type jsonEvent struct {
	Kind      string            `json:"kind"`
	OccuredAt string            `json:"occurred_at"`
	Actor     string            `json:"actor,omitempty"`
	ProjectID string            `json:"project_id,omitempty"`
	FileName  string            `json:"file_name,omitempty"`
	KeyName   string            `json:"key_name,omitempty"`
	PRRef     string            `json:"pr_ref,omitempty"`
	Outcome   string            `json:"outcome"`
	Details   map[string]string `json:"details,omitempty"`
}
