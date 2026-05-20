package audit_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	auditadapter "github.com/ByReisK/byreis/internal/adapter/audit"
	"github.com/ByReisK/byreis/internal/core/audit"
)

// TestFileLogger_AppendAndRead proves that Append durably writes a
// newline-delimited JSON event that can be read back with the correct fields.
func TestFileLogger_AppendAndRead(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "audit.log")

	logger, err := auditadapter.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = logger.Close() }()

	ev := audit.Event{
		Kind:       audit.EventKindModePromotion,
		OccurredAt: time.Unix(1_700_000_000, 0).UTC(),
		ProjectID:  "proj-1",
		Outcome:    "ok",
		Details:    map[string]string{"resolved_mode": "ADMIN"},
	}

	err = logger.Append(context.Background(), ev)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 log line, got %d", len(lines))
	}

	var got map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got["kind"] != string(audit.EventKindModePromotion) {
		t.Errorf("kind: got %v, want %q", got["kind"], audit.EventKindModePromotion)
	}
	if got["project_id"] != "proj-1" {
		t.Errorf("project_id: got %v, want proj-1", got["project_id"])
	}
	if got["outcome"] != "ok" {
		t.Errorf("outcome: got %v, want ok", got["outcome"])
	}
}

// TestFileLogger_MultipleAppends proves that multiple Append calls produce
// multiple distinct lines.
func TestFileLogger_MultipleAppends(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "audit.log")

	logger, err := auditadapter.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = logger.Close() }()

	for i := 0; i < 5; i++ {
		ev := audit.Event{
			Kind:       audit.EventKindModePromotion,
			OccurredAt: time.Now().UTC(),
			ProjectID:  "proj-1",
			Outcome:    "ok",
		}
		appendErr := logger.Append(context.Background(), ev)
		if appendErr != nil {
			t.Fatalf("Append[%d]: %v", i, appendErr)
		}
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	if count != 5 {
		t.Errorf("expected 5 log lines, got %d", count)
	}
}

// TestFileLogger_FileMode_0600 proves the audit log file is created with 0600
// permissions (not world-readable).
func TestFileLogger_FileMode_0600(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "audit.log")

	logger, err := auditadapter.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = logger.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("audit log has group/world bits set: %04o (want 0600)", info.Mode().Perm())
	}
}

// TestFileLogger_CtxCancel_ReturnsError proves a cancelled context causes
// Append to return an error without writing.
func TestFileLogger_CtxCancel_ReturnsError(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "audit.log")

	logger, err := auditadapter.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = logger.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ev := audit.Event{
		Kind:       audit.EventKindModePromotion,
		OccurredAt: time.Now().UTC(),
		Outcome:    "ok",
	}
	err = logger.Append(ctx, ev)
	if err == nil {
		t.Error("expected error from Append with cancelled context")
	}
}

// TestFileLogger_SatisfiesAuditLogger proves the adapter satisfies the
// audit.Logger interface at compile time (redundant with the var _ = line but
// useful for the test report).
func TestFileLogger_SatisfiesAuditLogger(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "audit.log")

	logger, err := auditadapter.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = logger.Close() }()

	var _ audit.Logger = logger
}
