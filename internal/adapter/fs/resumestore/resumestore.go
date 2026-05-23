// Package resumestore implements the submit.ResumeStore port. It persists an
// encrypted-at-rest PendingSubmission so an interrupted submit can resume
// without re-entering the secret value.
//
// Security contract:
//
//   - On-disk content: ONLY the already-encrypted artifact.Unsigned plus
//     non-secret metadata (projectID, logical file, key name, action, branch,
//     paths, justification, SavedAt). Plaintext is NEVER written to disk — the
//     artifact field carries the age ciphertext; there is no plaintext field on
//     PendingSubmission by construction.
//
//   - Zero-value artifact guard: Save rejects a PendingSubmission
//     whose Artifact is the zero value (no encrypted bytes, no metadata). An
//     empty artifact cannot be a valid encryption result; persisting it would
//     record a useless resume record and could mask a bug in the encrypt path.
//
//   - Write posture: atomic write via atomicwrite.WriteFile (O_CREAT|O_EXCL +
//     crypto/rand temp suffix + fsync + rename). Mode 0600.
//
//   - Read posture: lstat-reject-symlink + O_NOFOLLOW open before read,
//     same posture as the trust-anchor reader.
//
//   - Storage path: ~/.cache/byreis/resume/<projectID-hash>/<key-hash>.json
//     Key names are hashed into the filename so a directory listing does not
//     leak key names. The un-hashed key + projectID live inside the file body
//     (non-secret fields for cross-check).
//
//   - Discard: idempotent; prunes an empty parent directory; returns
//     nil if the file does not exist.
//
//   - Same on-disk identity key for single-key (p.Key) and bulk (p.Branch)
//     submissions, ensuring a successful submit in either mode leaves zero
//     residual resume files.
//
//   - Load: exists for port completeness; the production submit path does NOT
//     consume Load results to drive a submission.
//
// Placement: OUTER adapter layer (internal/adapter/fs/resumestore). Core
// packages never import this adapter.
package resumestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/fs/atomicwrite"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// Store implements submit.ResumeStore backed by the local filesystem.
type Store struct {
	cacheDir string
}

// New constructs a Store rooted at cacheDir (e.g. ~/.cache/byreis).
// The store manages its own resume/ sub-tree.
func New(cacheDir string) (*Store, error) {
	if cacheDir == "" {
		return nil, fmt.Errorf(
			"resumestore.New: cacheDir is empty — set BYREIS_CACHE or ensure ~/.cache/byreis exists")
	}
	return &Store{cacheDir: cacheDir}, nil
}

// Save persists the pending submission as a 0600 JSON file via
// atomicwrite.WriteFile (O_CREAT|O_EXCL + fsync + rename).
//
// Returns an error (not panic) when p.Artifact is the zero value.
func (s *Store) Save(ctx context.Context, p submit.PendingSubmission) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("resumestore: save cancelled: %w", err)
	}

	if isZeroArtifact(p.Artifact) {
		return fmt.Errorf(
			"resumestore: refusing to persist a PendingSubmission with a zero-value Artifact "+
				"for project %q key %q — the Artifact must be a valid encrypted result "+
				"produced by the encryptor (this is a programming error, not a user error)",
			p.ProjectID, resumeKey(p))
	}

	dir, file := s.paths(p.ProjectID, resumeKey(p))

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("resumestore: creating resume directory %q: %w", dir, err)
	}

	data, err := json.Marshal(toPendingRecord(p))
	if err != nil {
		return fmt.Errorf("resumestore: marshalling pending submission: %w", err)
	}

	path := filepath.Join(dir, file)
	if err := atomicwrite.WriteFile(ctx, path, data, 0o600); err != nil {
		return fmt.Errorf("resumestore: writing resume file %q: %w", path, err)
	}
	return nil
}

// Load reads a previously saved pending submission for (projectID, key). When
// no resume file exists the method returns (zero, false, nil).
//
// Read posture: lstat rejects symlinks before O_NOFOLLOW open, mirroring the
// trust-anchor reader posture.
//
// The production submit path does NOT call Load to drive a submission. This
// method satisfies the port contract only.
func (s *Store) Load(ctx context.Context, projectID, key string) (submit.PendingSubmission, bool, error) {
	if err := ctx.Err(); err != nil {
		return submit.PendingSubmission{}, false, fmt.Errorf("resumestore: load cancelled: %w", err)
	}

	dir, file := s.paths(projectID, key)
	path := filepath.Join(dir, file)

	data, err := readNoFollow(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return submit.PendingSubmission{}, false, nil
		}
		return submit.PendingSubmission{}, false, fmt.Errorf(
			"resumestore: reading resume file %q: %w", path, err)
	}

	var rec pendingRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return submit.PendingSubmission{}, false, fmt.Errorf(
			"resumestore: unmarshalling resume file %q: %w", path, err)
	}

	return rec.toPendingSubmission(), true, nil
}

// Discard removes the resume file and prunes an empty parent directory.
// Idempotent: returns nil if the file does not exist.
func (s *Store) Discard(ctx context.Context, projectID, key string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("resumestore: discard cancelled: %w", err)
	}

	dir, file := s.paths(projectID, key)
	path := filepath.Join(dir, file)

	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("resumestore: removing resume file %q: %w", path, err)
	}

	// Best-effort prune of empty parent directory.
	_ = os.Remove(dir)
	return nil
}

// paths returns the (directory, filename) for a (projectID, key) record.
// Both components are hashed so directory listings do not leak project/key names.
func (s *Store) paths(projectID, key string) (dir, file string) {
	projHash := hashStr(projectID)
	keyHash := hashStr(key)
	dir = filepath.Join(s.cacheDir, "resume", projHash)
	file = keyHash + ".json"
	return dir, file
}

// resumeKey returns the on-disk identity key for a PendingSubmission.
//
// Single-key: when p.Key is set, use p.Key. The use-case calls
// Discard(projectID, p.Key) on success.
//
// Bulk: when p.Key is empty, use p.Branch. The use-case calls
// Discard(projectID, branch) on bulk success.
func resumeKey(p submit.PendingSubmission) string {
	if p.Key != "" {
		return p.Key
	}
	return p.Branch
}

// hashStr returns the hex-encoded sha256 truncated to 32 hex chars (16 bytes).
// Used for directory/file naming to avoid leaking key or project names.
func hashStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:16])
}

// isZeroArtifact reports whether the artifact.Unsigned is the zero value.
// An artifact is zero when its Values map is nil/empty AND the FormatVersion
// is empty (no metadata was set by the encryptor).
func isZeroArtifact(a artifact.Unsigned) bool {
	return len(a.Values) == 0 && a.Byreis.FormatVersion == ""
}

// readNoFollow opens a file with O_NOFOLLOW and reads its contents.
// Rejects symlinks at the final path component.
func readNoFollow(path string) ([]byte, error) {
	// Lstat before open to check for symlinks. Honest pre-check; O_NOFOLLOW
	// provides the TOCTOU-safe gate below.
	info, statErr := os.Lstat(path)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("lstat resume file %q: %w", path, statErr)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf(
			"resume file %q is a symlink — refusing to read "+
				"(a symlink at a resume path is a security violation)", path)
	}

	// O_NOFOLLOW: reject symlinks at the final component even in the race
	// window between lstat and open.
	fd, openErr := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if openErr != nil {
		if openErr == syscall.ENOENT {
			return nil, os.ErrNotExist
		}
		if openErr == syscall.ELOOP || openErr == syscall.ENOTDIR {
			return nil, fmt.Errorf(
				"resume file %q is a symlink (O_NOFOLLOW): refusing to read", path)
		}
		return nil, fmt.Errorf("open resume file %q: %w", path, openErr)
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading resume file %q: %w", path, err)
	}
	return data, nil
}

// pendingRecord is the stable on-disk JSON schema for a PendingSubmission.
type pendingRecord struct {
	ProjectID       string          `json:"project_id"`
	LogicalFileName string          `json:"logical_file_name"`
	Key             string          `json:"key,omitempty"`
	Action          int             `json:"action,omitempty"`
	Keys            []openPRKeyJSON `json:"keys,omitempty"`
	Branch          string          `json:"branch"`
	SecretsPath     string          `json:"secrets_path"`
	BaseFilePath    string          `json:"base_file_path"`
	Justification   string          `json:"justification"`
	Artifact        json.RawMessage `json:"artifact"`
	SavedAtUnix     int64           `json:"saved_at_unix"`
}

type openPRKeyJSON struct {
	Key    string `json:"key"`
	Action int    `json:"action"`
}

// toPendingRecord converts a PendingSubmission to the on-disk record.
func toPendingRecord(p submit.PendingSubmission) pendingRecord {
	artBytes, _ := json.Marshal(p.Artifact)
	keys := make([]openPRKeyJSON, 0, len(p.Keys))
	for _, k := range p.Keys {
		keys = append(keys, openPRKeyJSON{Key: k.Key, Action: int(k.Action)})
	}
	return pendingRecord{
		ProjectID:       p.ProjectID,
		LogicalFileName: p.LogicalFileName,
		Key:             p.Key,
		Action:          int(p.Action),
		Keys:            keys,
		Branch:          p.Branch,
		SecretsPath:     p.SecretsPath,
		BaseFilePath:    p.BaseFilePath,
		Justification:   p.Justification,
		Artifact:        json.RawMessage(artBytes),
		SavedAtUnix:     p.SavedAt.Unix(),
	}
}

// toPendingSubmission reconstructs a PendingSubmission from the on-disk record.
func (r *pendingRecord) toPendingSubmission() submit.PendingSubmission {
	keys := make([]submit.OpenPRKey, 0, len(r.Keys))
	for _, k := range r.Keys {
		keys = append(keys, submit.OpenPRKey{Key: k.Key, Action: submit.SubmitAction(k.Action)})
	}

	var art artifact.Unsigned
	_ = json.Unmarshal(r.Artifact, &art)

	return submit.PendingSubmission{
		ProjectID:       r.ProjectID,
		LogicalFileName: r.LogicalFileName,
		Key:             r.Key,
		Action:          submit.SubmitAction(r.Action),
		Keys:            keys,
		Branch:          r.Branch,
		SecretsPath:     r.SecretsPath,
		BaseFilePath:    r.BaseFilePath,
		Justification:   r.Justification,
		Artifact:        art,
		SavedAt:         time.Unix(r.SavedAtUnix, 0),
	}
}

// Compile-time assertion.
var _ submit.ResumeStore = (*Store)(nil)
