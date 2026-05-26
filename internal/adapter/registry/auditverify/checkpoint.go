// Package auditverify provides the verified-HEAD checkpoint cache for the
// per-line audit-binding verifier. The checkpoint is a host-local performance
// amortisation: it records the last registry HEAD for which the full per-line
// walk completed clean. It is a trust-hint only — security never flows from
// the checkpoint. Any ancestry mismatch, project-ID mismatch, or missing SHA
// forces a full cold re-walk.
//
// Storage follows the countercache Alt-β posture: JSON file at a predictable
// path under ~/.cache/byreis/registry/<regprefix>/. No HMAC. The checkpoint
// can only cause MORE verification work (a forced cold re-walk on any error),
// never less.
package auditverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Checkpoint holds the state of the last completed full per-line binding walk
// for one project channel. It is diagnostic only — it does not carry a trust
// claim. VerifiedLineCount is a display hint and must never bound how many
// lines are re-checked in an incremental run.
type Checkpoint struct {
	// ProjectID is the registry-canonical project identifier this checkpoint
	// belongs to. Checked on load to refuse cross-project reuse.
	ProjectID string `json:"project_id"`
	// VerifiedHeadSHA is the registry HEAD commit SHA at which the last clean
	// full walk completed.
	VerifiedHeadSHA string `json:"verified_head_sha"`
	// VerifiedLineCount is the number of non-synthetic JSONL lines that were
	// verified at VerifiedHeadSHA. Diagnostic only — never used as a stop
	// condition or as a trust signal. An incremental run always re-checks every
	// line in the new-commit range regardless of this field.
	VerifiedLineCount int `json:"verified_line_count"`
	// VerifiedAt is the UTC wall-clock time of the last completed walk. Display
	// and diagnostic only; trust never flows from a wall-clock timestamp.
	VerifiedAt time.Time `json:"verified_at"`
}

// checkpointEnvelope is the on-disk JSON schema.
type checkpointEnvelope struct {
	SchemaVersion int        `json:"schema_version"`
	Checkpoint    Checkpoint `json:"checkpoint"`
}

const checkpointSchemaVersion = 1

// Store is the on-disk checkpoint cache for audit-binding verification.
// The zero value is not valid; use NewStore.
type Store struct {
	cacheRoot   string
	registryURL string
}

// NewStore constructs a Store. cacheRoot is the parent cache directory
// (e.g. ~/.cache/byreis/registry); registryURL scopes the per-registry
// subdirectory.
func NewStore(cacheRoot, registryURL string) (*Store, error) {
	if cacheRoot == "" {
		return nil, errors.New("auditverify.NewStore: cacheRoot must not be empty")
	}
	if registryURL == "" {
		return nil, errors.New("auditverify.NewStore: registryURL must not be empty")
	}
	return &Store{cacheRoot: cacheRoot, registryURL: registryURL}, nil
}

// registryPrefix returns the 16-hex-char sha256 prefix of the registry URL,
// mirroring the countercache.RegistryIDPrefix naming convention.
func (s *Store) registryPrefix() string {
	sum := sha256.Sum256([]byte(s.registryURL))
	return hex.EncodeToString(sum[:])[:16]
}

// checkpointFilePath returns the path to the checkpoint JSON file for the
// given project.
func (s *Store) checkpointFilePath(projectID string) string {
	safeID := sha256.Sum256([]byte(projectID))
	idHex := hex.EncodeToString(safeID[:])[:16]
	return filepath.Join(s.cacheRoot, s.registryPrefix(), "auditverify_"+idHex+".json")
}

// Load reads the checkpoint for projectID. Returns (nil, nil) when no
// checkpoint exists or the stored checkpoint is invalid (schema mismatch,
// project-ID mismatch, or malformed JSON). Any of these non-error absence
// signals force a full cold re-walk at the caller.
func (s *Store) Load(_ context.Context, projectID string) (*Checkpoint, error) {
	path := s.checkpointFilePath(projectID)
	raw, err := os.ReadFile(path) //nolint:gosec // path derived from hashed projectID + cacheRoot
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no checkpoint yet
		}
		// Unreadable checkpoint: treat as absent (cold re-walk).
		return nil, nil
	}

	var env checkpointEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		// Corrupt checkpoint: treat as absent.
		return nil, nil
	}
	if env.SchemaVersion != checkpointSchemaVersion {
		// Schema mismatch: stale or downgraded file. Treat as absent.
		return nil, nil
	}
	if env.Checkpoint.ProjectID != projectID {
		// Cross-project collision: refuse and treat as absent.
		return nil, nil
	}
	cp := env.Checkpoint
	return &cp, nil
}

// Store writes the checkpoint durably for projectID. A write failure is
// non-fatal: the checkpoint is a performance hint, not a trust artefact. The
// caller logs the error and proceeds.
func (s *Store) Store(_ context.Context, projectID string, cp Checkpoint) error {
	cp.ProjectID = projectID
	env := checkpointEnvelope{
		SchemaVersion: checkpointSchemaVersion,
		Checkpoint:    cp,
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("auditverify checkpoint: marshal: %w", err)
	}

	path := s.checkpointFilePath(projectID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("auditverify checkpoint: mkdir %q: %w", dir, err)
	}

	// Write to a temp file and rename for atomicity (prevents a half-written
	// checkpoint from being read on a crash).
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil { //nolint:gosec // 0600: owner-only checkpoint
		return fmt.Errorf("auditverify checkpoint: write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) // best-effort cleanup
		return fmt.Errorf("auditverify checkpoint: rename: %w", err)
	}
	return nil
}
