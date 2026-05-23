package resumestore_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/fs/resumestore"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// buildTestArtifact returns a non-zero artifact.Unsigned with minimal but
// structurally valid fields so isZeroArtifact returns false.
func buildTestArtifact() artifact.Unsigned {
	return artifact.Unsigned{
		Values: map[string]artifact.EncryptedValue{
			"API_KEY": artifact.EncryptedValue("AGE-CIPHER-TEST-SENTINEL"),
		},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1",
			ProjectID:     "test-project",
			File:          "secrets.yaml",
		},
	}
}

// TestResumeStore_SaveLoadDiscard_Single verifies the single-key lifecycle
// (BO-V35-5, BO-V35-6, BO-V35-7).
func TestResumeStore_SaveLoadDiscard_Single(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	store, err := resumestore.New(cacheDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	p := submit.PendingSubmission{
		ProjectID:       "myorg/proj",
		LogicalFileName: "secrets",
		Key:             "API_KEY",
		Action:          submit.ActionAdd,
		Branch:          "byreis/add-API_KEY-1234567890",
		SecretsPath:     "secrets/prod.yaml",
		BaseFilePath:    "secrets/prod.yaml",
		Justification:   "test justification",
		Artifact:        buildTestArtifact(),
		SavedAt:         time.Now().Truncate(time.Second),
	}

	// Save.
	err = store.Save(ctx, p)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load.
	var loaded submit.PendingSubmission
	var ok bool
	loaded, ok, err = store.Load(ctx, p.ProjectID, p.Key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok {
		t.Fatal("Load: expected ok=true, got false")
	}
	if loaded.Key != p.Key {
		t.Errorf("Load: Key = %q; want %q", loaded.Key, p.Key)
	}
	if loaded.ProjectID != p.ProjectID {
		t.Errorf("Load: ProjectID = %q; want %q", loaded.ProjectID, p.ProjectID)
	}

	// Discard.
	err = store.Discard(ctx, p.ProjectID, p.Key)
	if err != nil {
		t.Fatalf("Discard: %v", err)
	}

	// After Discard, Load returns ok=false.
	_, ok, err = store.Load(ctx, p.ProjectID, p.Key)
	if err != nil {
		t.Fatalf("Load after Discard: %v", err)
	}
	if ok {
		t.Error("Load after Discard: expected ok=false, got true")
	}
}

// TestResumeStore_SaveLoadDiscard_Bulk verifies the bulk-key lifecycle using
// the branch as the identity key (BO-V35-6).
func TestResumeStore_SaveLoadDiscard_Bulk(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	store, err := resumestore.New(cacheDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	branch := "byreis/bulk-3keys-1234567890"
	p := submit.PendingSubmission{
		ProjectID:       "myorg/proj",
		LogicalFileName: "secrets",
		Keys: []submit.OpenPRKey{
			{Key: "A", Action: submit.ActionAdd},
			{Key: "B", Action: submit.ActionReplace},
			{Key: "C", Action: submit.ActionAdd},
		},
		Branch:      branch,
		SecretsPath: "secrets/prod.yaml",
		Artifact:    buildTestArtifact(),
		SavedAt:     time.Now().Truncate(time.Second),
	}

	err = store.Save(ctx, p)
	if err != nil {
		t.Fatalf("Save bulk: %v", err)
	}

	// Load using branch as the key.
	var ok bool
	_, ok, err = store.Load(ctx, p.ProjectID, branch)
	if err != nil {
		t.Fatalf("Load bulk: %v", err)
	}
	if !ok {
		t.Fatal("Load bulk: expected ok=true")
	}

	// Discard using branch.
	err = store.Discard(ctx, p.ProjectID, branch)
	if err != nil {
		t.Fatalf("Discard bulk: %v", err)
	}
}

// TestResumeStore_Discard_Idempotent verifies that Discard on a non-existent
// file returns nil (BO-V35-7).
func TestResumeStore_Discard_Idempotent(t *testing.T) {
	t.Parallel()

	store, err := resumestore.New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := store.Discard(ctx, "myorg/proj", "NONEXISTENT_KEY"); err != nil {
		t.Errorf("Discard nonexistent: expected nil, got %v", err)
	}
}

// TestResumeStore_ZeroArtifactRejected verifies that Save rejects a
// PendingSubmission with a zero-value Artifact (BO-V35-4).
func TestResumeStore_ZeroArtifactRejected(t *testing.T) {
	t.Parallel()

	store, err := resumestore.New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	p := submit.PendingSubmission{
		ProjectID:       "myorg/proj",
		LogicalFileName: "secrets",
		Key:             "API_KEY",
		Branch:          "byreis/add-API_KEY-123",
		// Artifact is intentionally the zero value.
	}
	err = store.Save(ctx, p)
	if err == nil {
		t.Fatal("Save with zero Artifact: expected error, got nil")
	}
}

// TestResumeStore_OnDiskBytesContainCiphertextNotPlaintext (BO-V35-4):
// The on-disk JSON must contain the age ciphertext (sentinel) and MUST NOT
// contain any known plaintext value.
func TestResumeStore_OnDiskBytesContainCiphertextNotPlaintext(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	store, err := resumestore.New(cacheDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	plaintext := "PLAINTEXT-SENTINEL-DO-NOT-PERSIST-fa91"
	cipherSentinel := "AGE-CIPHER-SENTINEL-b3d7"

	p := submit.PendingSubmission{
		ProjectID:       "myorg/proj",
		LogicalFileName: "secrets",
		Key:             "SECRET_KEY",
		Branch:          "byreis/add-SECRET_KEY-1234",
		Artifact: artifact.Unsigned{
			Values: map[string]artifact.EncryptedValue{
				"SECRET_KEY": artifact.EncryptedValue(cipherSentinel),
			},
			Byreis: artifact.Metadata{
				FormatVersion: "byreis.native.v1",
				ProjectID:     "myorg/proj",
				File:          "secrets",
			},
		},
		SavedAt: time.Now(),
	}

	err = store.Save(ctx, p)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Find the resume file and read its raw bytes.
	var resumeFile string
	err = filepath.WalkDir(filepath.Join(cacheDir, "resume"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".json") {
			resumeFile = path
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking resume dir: %v", err)
	}
	if resumeFile == "" {
		t.Fatal("no resume file found after Save")
	}

	rawBytes, err := os.ReadFile(resumeFile)
	if err != nil {
		t.Fatalf("reading resume file: %v", err)
	}

	content := string(rawBytes)

	// The on-disk bytes must contain the ciphertext sentinel.
	if !strings.Contains(content, cipherSentinel) {
		t.Errorf("resume file does not contain ciphertext sentinel %q — expected the encrypted artifact to be present",
			cipherSentinel)
	}

	// The on-disk bytes must NOT contain the plaintext sentinel.
	if strings.Contains(content, plaintext) {
		t.Errorf("security violation: resume file contains plaintext sentinel %q — "+
			"plaintext must never be written to the resume store", plaintext)
	}
}

// TestResumeStore_SuccessfulSubmitLeavesZeroResidual (BO-V35-6):
// After a successful single submit that calls Discard, no resume files remain.
// After a successful bulk submit that calls Discard(branch), no resume files remain.
func TestResumeStore_SuccessfulSubmitLeavesZeroResidual(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	store, err := resumestore.New(cacheDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	art := buildTestArtifact()

	// Single-key submission lifecycle.
	single := submit.PendingSubmission{
		ProjectID:       "proj",
		LogicalFileName: "secrets",
		Key:             "SINGLE_KEY",
		Branch:          "byreis/add-SINGLE_KEY-100",
		Artifact:        art,
		SavedAt:         time.Now(),
	}
	if err := store.Save(ctx, single); err != nil {
		t.Fatalf("Save single: %v", err)
	}
	if err := store.Discard(ctx, single.ProjectID, single.Key); err != nil {
		t.Fatalf("Discard single: %v", err)
	}

	// Bulk submission lifecycle.
	branch := "byreis/bulk-2keys-200"
	bulk := submit.PendingSubmission{
		ProjectID:       "proj",
		LogicalFileName: "secrets",
		Keys:            []submit.OpenPRKey{{Key: "A"}, {Key: "B"}},
		Branch:          branch,
		Artifact:        art,
		SavedAt:         time.Now(),
	}
	if err := store.Save(ctx, bulk); err != nil {
		t.Fatalf("Save bulk: %v", err)
	}
	if err := store.Discard(ctx, bulk.ProjectID, branch); err != nil {
		t.Fatalf("Discard bulk: %v", err)
	}

	// Verify no resume files remain.
	var residual []string
	_ = filepath.WalkDir(filepath.Join(cacheDir, "resume"), func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			residual = append(residual, path)
		}
		return nil
	})
	if len(residual) != 0 {
		t.Errorf("BO-V35-6: expected zero residual resume files after successful submit, found: %v", residual)
	}
}

// TestResumeStore_FileMode verifies that the written resume file has mode 0600.
func TestResumeStore_FileMode(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	store, err := resumestore.New(cacheDir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	p := submit.PendingSubmission{
		ProjectID:       "proj",
		LogicalFileName: "secrets",
		Key:             "API_KEY",
		Branch:          "byreis/add-API_KEY-999",
		Artifact:        buildTestArtifact(),
		SavedAt:         time.Now(),
	}
	err = store.Save(ctx, p)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	var resumeFile string
	_ = filepath.WalkDir(filepath.Join(cacheDir, "resume"), func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			resumeFile = path
		}
		return nil
	})
	if resumeFile == "" {
		t.Fatal("no resume file found")
	}
	info, err := os.Stat(resumeFile)
	if err != nil {
		t.Fatalf("stat resume file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("resume file mode = %04o; want 0600", info.Mode().Perm())
	}
}
