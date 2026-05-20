// Package auditsink implements the audit.Logger port by appending events to
// audit/<project>.jsonl in the registry repository. The write path is always
// the same signed registry commit as the counter-store advance — atomicity is
// provided by git commit atomicity, not by application-level coordination.
//
// Event class enforcement: only EventKindRotation, EventKindMerge, and
// EventKindCommitBump are persisted by this sink. Any other EventKind is
// silently dropped with a structured log warning. Event field corruption
// (canonical-typed field values failing the validation rules) is a hard error:
// ErrAuditEventInvalidField is returned and the event is not written.
//
// The Sink does not acquire a registry-write token directly. It delegates all
// token acquisition and git operations to the transport layer that owns the
// signed commit. The Sink's Append method is called from within the transport's
// doCommitRotation / CommitBump flows, which already hold the token.
//
// Constructor injection is used throughout. No package-level state, no init()
// side effects, no sync.Once on global state.
package auditsink

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/logging"
)

// ErrAuditEventInvalidField is re-exported from the audit package for callers
// that import only the sink. The canonical definition and sentinel value live
// in internal/core/audit.ErrAuditEventInvalidField; this alias keeps existing
// errors.Is(err, auditsink.ErrAuditEventInvalidField) call sites working.
var ErrAuditEventInvalidField = audit.ErrAuditEventInvalidField

// acceptedEventKinds enumerates the EventKind values the registry sink
// persists. Any other kind is silently dropped with a structured log warning.
var acceptedEventKinds = map[audit.EventKind]struct{}{
	audit.EventKindRotation:   {},
	audit.EventKindMerge:      {},
	audit.EventKindCommitBump: {},
}

// SinkConfig holds all injected dependencies for a Sink. All fields are
// required unless noted.
type SinkConfig struct {
	// AuditDir is the path to the directory where audit/<project>.jsonl files
	// are written. When set, Append writes to AuditDir/<projectID>.jsonl.
	// This is the absolute path to the audit/ subtree in the registry clone.
	AuditDir string

	// Logger is the structured log sink for operational warnings. When nil, a
	// no-op logger is used.
	Logger logging.Logger
}

// Sink implements audit.Logger by writing events to audit/<project>.jsonl.
// It enforces event-class enumeration and field-value validation.
//
// The zero value is not usable; construct via New.
type Sink struct {
	cfg    SinkConfig
	logger logging.Logger
}

// New constructs a Sink. Returns an error if AuditDir is empty.
func New(cfg SinkConfig) (*Sink, error) {
	if cfg.AuditDir == "" {
		return nil, fmt.Errorf("auditsink.New: AuditDir must be non-empty — " +
			"pass the path to the audit/ directory in the registry clone")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = logging.Discard
	}
	return &Sink{cfg: cfg, logger: logger}, nil
}

// Append records an audit event. If the event's Kind is not in the accepted
// set, it is silently dropped with a structured log warning (event-class
// enumeration per the registry protocol). If any Details field value fails
// canonical validation, ErrAuditEventInvalidField is returned (hard error).
//
// Callers that write the event as part of a git commit must NOT call Append
// directly from the Sink when the write already happens inside
// buildAuditJSONLEntry (the transport layer). The Sink is provided as a
// standalone logger for contexts where the event must be appended to an
// existing file outside a git commit (e.g. read-side audit fetch).
func (s *Sink) Append(ctx context.Context, e audit.Event) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("auditsink.Append: context cancelled: %w", err)
	}

	// Event-class enumeration: silently drop unknown kinds with a structured
	// log warning. This is NOT a hard error — the registry sink is selective.
	if _, ok := acceptedEventKinds[e.Kind]; !ok {
		s.logger.Log(ctx, logging.LevelWarn,
			"auditsink: dropping event with unsupported kind — registry sink accepts only rotation, merge, commit_bump",
			"kind", string(e.Kind),
			"projectID", e.ProjectID,
		)
		return nil
	}

	// Hard-error on canonical field validation failure; field corruption is
	// never silently dropped — callers must be alerted on schema violations.
	if err := audit.ValidateEventFields(e); err != nil {
		return err
	}

	raw, marshalErr := json.Marshal(e)
	if marshalErr != nil {
		return fmt.Errorf("auditsink.Append: marshalling event: %w — "+
			"internal error; run `byreis doctor`", marshalErr)
	}
	line := append(raw, '\n')

	filePath := s.auditFilePath(e.ProjectID)
	dir := filepath.Dir(filePath)
	if mkdirErr := os.MkdirAll(dir, 0o700); mkdirErr != nil {
		return fmt.Errorf("auditsink.Append: creating audit directory: %w — "+
			"check filesystem permissions: run `byreis doctor`", mkdirErr)
	}

	f, openErr := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // 0600 for audit file: owner-only
	if openErr != nil {
		return fmt.Errorf("auditsink.Append: opening audit file for append: %w — "+
			"check filesystem permissions: run `byreis doctor`", openErr)
	}
	_, writeErr := f.Write(line)
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("auditsink.Append: writing audit entry: %w — "+
			"check filesystem permissions: run `byreis doctor`", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("auditsink.Append: closing audit file: %w — "+
			"check filesystem permissions: run `byreis doctor`", closeErr)
	}
	return nil
}

// auditFilePath returns the absolute path to audit/<projectID>.jsonl.
func (s *Sink) auditFilePath(projectID string) string {
	return s.cfg.AuditDir + "/" + projectID + ".jsonl"
}
