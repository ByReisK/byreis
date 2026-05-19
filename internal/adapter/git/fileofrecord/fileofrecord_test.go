package fileofrecord_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/git/fileofrecord"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// fakeResolver implements fileofrecord.ConfiguredPathResolver for tests.
type fakeResolver struct {
	paths map[string]string // "projectID/fileName" -> configured path
	err   error
}

func (r *fakeResolver) ConfiguredPath(_ context.Context, projectID, fileName string) (string, error) {
	if r.err != nil {
		return "", r.err
	}
	key := projectID + "/" + fileName
	p, ok := r.paths[key]
	if !ok {
		return "", fmt.Errorf("%w: no configured path for %q/%q",
			usecase.ErrFileOfRecordNotFound, projectID, fileName)
	}
	return p, nil
}

// fakeFetcher implements fileofrecord.FileFetcher for tests.
type fakeFetcher struct {
	files    map[string][]byte
	notFound map[string]bool
	err      error
}

func (f *fakeFetcher) FetchCommittedFile(_ context.Context, path, _ string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.notFound[path] {
		return nil, fileofrecord.ErrFetchNotFound
	}
	b, ok := f.files[path]
	if !ok {
		return nil, fileofrecord.ErrFetchNotFound
	}
	return b, nil
}

// refCaptureFetcher captures the ref argument passed to FetchCommittedFile.
type refCaptureFetcher struct {
	bytes       []byte
	capturedRef *string
}

func (f *refCaptureFetcher) FetchCommittedFile(_ context.Context, _, ref string) ([]byte, error) {
	*f.capturedRef = ref
	return f.bytes, nil
}

// TestFileOfRecordSource_ExactBytesReturned verifies that the exact committed
// bytes are returned with zero normalization and ContentSHA = sha256(bytes).
func TestFileOfRecordSource_ExactBytesReturned(t *testing.T) {
	expectedBytes := []byte("exact-yaml-bytes-no-normalization\n")

	resolver := &fakeResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: YAML repo-path string in a test fixture, not a credential
	fetcher := &fakeFetcher{files: map[string][]byte{"secrets/prod.enc.yaml": expectedBytes}}

	src, err := fileofrecord.New(fetcher, resolver, "main")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	record, err := src.FileOfRecord(context.Background(), "proj", "secrets")
	if err != nil {
		t.Fatalf("FileOfRecord: %v", err)
	}

	if string(record.Bytes) != string(expectedBytes) {
		t.Errorf("Bytes not byte-identical: got %q want %q", record.Bytes, expectedBytes)
	}

	sum := sha256.Sum256(expectedBytes)
	want := hex.EncodeToString(sum[:])
	if record.ContentSHA != want {
		t.Errorf("ContentSHA mismatch: got %q want %q", record.ContentSHA, want)
	}
}

// TestFileOfRecordSource_MissingFile_ErrFileOfRecordNotFound verifies that a
// missing configured file returns ErrFileOfRecordNotFound.
func TestFileOfRecordSource_MissingFile_ErrFileOfRecordNotFound(t *testing.T) {
	resolver := &fakeResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: YAML repo-path string in a test fixture, not a credential
	fetcher := &fakeFetcher{notFound: map[string]bool{"secrets/prod.enc.yaml": true}}

	src, err := fileofrecord.New(fetcher, resolver, "main")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, gotErr := src.FileOfRecord(context.Background(), "proj", "secrets")
	if gotErr == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !errors.Is(gotErr, usecase.ErrFileOfRecordNotFound) {
		t.Errorf("want errors.Is(err, ErrFileOfRecordNotFound); got: %T %v", gotErr, gotErr)
	}
}

// TestFileOfRecordSource_UnconfiguredFile_ErrFileOfRecordNotFound verifies
// that a file with no registry-configured path returns ErrFileOfRecordNotFound.
func TestFileOfRecordSource_UnconfiguredFile_ErrFileOfRecordNotFound(t *testing.T) {
	resolver := &fakeResolver{paths: map[string]string{}} // no configured paths
	fetcher := &fakeFetcher{files: map[string][]byte{}}

	src, err := fileofrecord.New(fetcher, resolver, "main")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, gotErr := src.FileOfRecord(context.Background(), "proj", "secrets")
	if gotErr == nil {
		t.Fatal("expected error for unconfigured file, got nil")
	}
	if !errors.Is(gotErr, usecase.ErrFileOfRecordNotFound) {
		t.Errorf("want errors.Is(err, ErrFileOfRecordNotFound); got: %T %v", gotErr, gotErr)
	}
}

// TestFileOfRecordSource_NeverReadsPRBranch verifies that the source always
// fetches from the configured base branch and never a PR/submission branch.
func TestFileOfRecordSource_NeverReadsPRBranch(t *testing.T) {
	var capturedRef string
	cf := &refCaptureFetcher{bytes: []byte("data"), capturedRef: &capturedRef}

	resolver := &fakeResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: YAML repo-path string in a test fixture, not a credential
	src, err := fileofrecord.New(cf, resolver, "main")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = src.FileOfRecord(context.Background(), "proj", "secrets")
	if err != nil {
		t.Fatalf("FileOfRecord: %v", err)
	}

	if capturedRef != "main" {
		t.Errorf("expected ref %q, got %q — source MUST NOT read a PR branch", "main", capturedRef)
	}
}

// TestFileOfRecordSource_ContextCancelled verifies that a pre-cancelled
// context returns a context.Canceled error.
func TestFileOfRecordSource_ContextCancelled(t *testing.T) {
	resolver := &fakeResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: YAML repo-path string in a test fixture, not a credential
	fetcher := &fakeFetcher{files: map[string][]byte{"secrets/prod.enc.yaml": []byte("data")}}

	src, err := fileofrecord.New(fetcher, resolver, "main")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, gotErr := src.FileOfRecord(ctx, "proj", "secrets")
	if gotErr == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if !errors.Is(gotErr, context.Canceled) {
		t.Errorf("want context.Canceled; got: %v", gotErr)
	}
}

// TestFileOfRecordSource_ContextDeadline verifies that an expired deadline
// context returns a context.DeadlineExceeded error.
func TestFileOfRecordSource_ContextDeadline(t *testing.T) {
	resolver := &fakeResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: YAML repo-path string in a test fixture, not a credential
	fetcher := &fakeFetcher{files: map[string][]byte{"secrets/prod.enc.yaml": []byte("data")}}

	src, err := fileofrecord.New(fetcher, resolver, "main")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)

	_, gotErr := src.FileOfRecord(ctx, "proj", "secrets")
	if gotErr == nil {
		t.Fatal("expected error on expired deadline, got nil")
	}
	if !errors.Is(gotErr, context.DeadlineExceeded) {
		t.Errorf("want context.DeadlineExceeded; got: %v", gotErr)
	}
}

// TestFileOfRecordSource_FetchError_Wrapped verifies that non-404 fetch errors
// are wrapped with an actionable hint and the original error is in the chain.
func TestFileOfRecordSource_FetchError_Wrapped(t *testing.T) {
	resolver := &fakeResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: YAML repo-path string in a test fixture, not a credential
	fetchErr := errors.New("network timeout")
	fetcher := &fakeFetcher{err: fetchErr}

	src, err := fileofrecord.New(fetcher, resolver, "main")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, gotErr := src.FileOfRecord(context.Background(), "proj", "secrets")
	if gotErr == nil {
		t.Fatal("expected error on fetch failure, got nil")
	}
	if !errors.Is(gotErr, fetchErr) {
		t.Errorf("want original error in chain; got: %v", gotErr)
	}
}

// TestFileOfRecordSource_ContentSHA_IsRawBufferHash documents and asserts that
// ContentSHA is sha256 of the raw bytes (for move detection), NOT the of-
// record verify.ContentSHA (which is over the canonical manifest preimage).
func TestFileOfRecordSource_ContentSHA_IsRawBufferHash(t *testing.T) {
	raw := []byte("some yaml content\nwith multiple lines\n")
	resolver := &fakeResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: YAML repo-path string in a test fixture, not a credential
	fetcher := &fakeFetcher{files: map[string][]byte{"secrets/prod.enc.yaml": raw}}

	src, err := fileofrecord.New(fetcher, resolver, "main")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	record, err := src.FileOfRecord(context.Background(), "proj", "secrets")
	if err != nil {
		t.Fatalf("FileOfRecord: %v", err)
	}

	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])
	if record.ContentSHA != want {
		t.Errorf("ContentSHA is not sha256(raw bytes): got %q want %q", record.ContentSHA, want)
	}
}

// TestFileOfRecordSource_New_RequiresAllParams checks constructor validation.
func TestFileOfRecordSource_New_RequiresAllParams(t *testing.T) {
	resolver := &fakeResolver{}
	fetcher := &fakeFetcher{}

	if _, err := fileofrecord.New(nil, resolver, "main"); err == nil {
		t.Error("expected error for nil fetcher")
	}
	if _, err := fileofrecord.New(fetcher, nil, "main"); err == nil {
		t.Error("expected error for nil resolver")
	}
	if _, err := fileofrecord.New(fetcher, resolver, ""); err == nil {
		t.Error("expected error for empty baseBranch")
	}
}
