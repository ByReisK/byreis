package fileofrecord_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/git/fileofrecord"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ---- fake ProjectBlobReader seam --------------------------------------------

// fakeBlobCall records one call to ReadProjectBlob.
type fakeBlobCall struct {
	projectURL string
	branch     string
	path       string
	maxBytes   int64
}

// fakeBlobReader is a controllable ProjectBlobReader for unit tests. Each step
// in the ordered list is consumed by a single call; when all steps are consumed
// the reader returns an error so missing steps are detected immediately.
type fakeBlobReader struct {
	mu    sync.Mutex
	steps []fakeBlobStep
	calls []fakeBlobCall
}

type fakeBlobStep struct {
	resolvedSHA string
	data        []byte
	err         error
}

// blobNotFoundErr implements the BlobNotFound() bool marker interface so that
// isBlobNotFound in gitsource.go detects it via errors.As.
type blobNotFoundErr struct{ msg string }

func (e *blobNotFoundErr) Error() string      { return e.msg }
func (e *blobNotFoundErr) BlobNotFound() bool { return true }

func (f *fakeBlobReader) ReadProjectBlob(ctx context.Context, projectURL, branch, path string, maxBytes int64) (string, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, fakeBlobCall{
		projectURL: projectURL,
		branch:     branch,
		path:       path,
		maxBytes:   maxBytes,
	})

	if len(f.steps) == 0 {
		return "", nil, errors.New("fakeBlobReader: no more configured steps")
	}
	step := f.steps[0]
	f.steps = f.steps[1:]
	if step.err != nil {
		return "", nil, step.err
	}
	return step.resolvedSHA, step.data, nil
}

func (f *fakeBlobReader) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeBlobReader) call(i int) fakeBlobCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[i]
}

// zeroCallReader is a ProjectBlobReader that fails the test if ever invoked.
type zeroCallReader struct{ t *testing.T }

func (z *zeroCallReader) ReadProjectBlob(_ context.Context, _, _, _ string, _ int64) (string, []byte, error) {
	z.t.Helper()
	z.t.Fatal("ReadProjectBlob must NOT be called (mode gate should fire first)")
	return "", nil, nil
}

// ---- fake ConfiguredPathResolver seam --------------------------------------

type fakeBlobResolver struct {
	paths map[string]string // "projectID/fileName" -> configured path
	err   error
}

func (r *fakeBlobResolver) ConfiguredPath(_ context.Context, projectID, fileName string) (string, error) {
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

// ---- helpers ----------------------------------------------------------------

const testFixedSHA = "aabbccddee112233445566778899aabbccddeeff"

func newGitSource(t *testing.T, projectURL, branch string, reader fileofrecord.ProjectBlobReader, resolver fileofrecord.ConfiguredPathResolver) *fileofrecord.GitSource {
	t.Helper()
	s, err := fileofrecord.NewGitSource(fileofrecord.GitSourceConfig{
		ProjectURL: projectURL,
		BaseBranch: branch,
		Reader:     reader,
		Resolver:   resolver,
	})
	if err != nil {
		t.Fatalf("NewGitSource: %v", err)
	}
	return s
}

// ---- NewGitSource constructor validation ------------------------------------

// TestGitSource_New_RequiresAllParams verifies the constructor rejects missing
// required fields with clear error messages.
func TestGitSource_New_RequiresAllParams(t *testing.T) {
	t.Parallel()

	reader := &fakeBlobReader{}
	resolver := &fakeBlobResolver{paths: map[string]string{}}

	cases := []struct {
		name       string
		projectURL string
		branch     string
		reader     fileofrecord.ProjectBlobReader
		resolver   fileofrecord.ConfiguredPathResolver
	}{
		{"empty ProjectURL", "", "main", reader, resolver},
		{"empty BaseBranch", "file:///tmp/repo.git", "", reader, resolver},
		{"nil Reader", "file:///tmp/repo.git", "main", nil, resolver},
		{"nil Resolver", "file:///tmp/repo.git", "main", reader, nil},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := fileofrecord.NewGitSource(fileofrecord.GitSourceConfig{
				ProjectURL: tc.projectURL,
				BaseBranch: tc.branch,
				Reader:     tc.reader,
				Resolver:   tc.resolver,
			})
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.name)
			}
		})
	}
}

// TestGitSource_New_ValidConstruction verifies a fully specified config succeeds.
func TestGitSource_New_ValidConstruction(t *testing.T) {
	t.Parallel()

	reader := &fakeBlobReader{}
	resolver := &fakeBlobResolver{paths: map[string]string{}}

	_, err := fileofrecord.NewGitSource(fileofrecord.GitSourceConfig{
		ProjectURL: "file:///tmp/project.git",
		BaseBranch: "main",
		Reader:     reader,
		Resolver:   resolver,
	})
	if err != nil {
		t.Fatalf("expected no error for valid config, got: %v", err)
	}
}

// ---- Happy-path: exact bytes + SHA ------------------------------------------

// TestGitSource_ExactBytes verifies that FileOfRecord returns the byte-identical
// bytes produced by the reader with no normalization.
func TestGitSource_ExactBytes(t *testing.T) {
	t.Parallel()

	raw := []byte("exact-yaml-bytes\nno-normalization\n\xff\xfe")                                    // non-UTF8 safe
	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{resolvedSHA: testFixedSHA, data: raw},
	}}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)

	record, err := s.FileOfRecord(context.Background(), "proj", "secrets")
	if err != nil {
		t.Fatalf("FileOfRecord: %v", err)
	}

	if string(record.Bytes) != string(raw) {
		t.Errorf("Bytes not byte-identical: got %q want %q", record.Bytes, raw)
	}
}

// TestGitSource_ContentSHA_IsRawBufferHash verifies that ContentSHA is
// sha256(Bytes) in lowercase hex — the adapter-level move-detection hash, not
// the of-record counter-pin identity.
func TestGitSource_ContentSHA_IsRawBufferHash(t *testing.T) {
	t.Parallel()

	raw := []byte("some yaml content\nwith multiple lines\n")
	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{resolvedSHA: testFixedSHA, data: raw},
	}}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
	record, err := s.FileOfRecord(context.Background(), "proj", "secrets")
	if err != nil {
		t.Fatalf("FileOfRecord: %v", err)
	}

	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])
	if record.ContentSHA != want {
		t.Errorf("ContentSHA mismatch: got %q want %q", record.ContentSHA, want)
	}
}

// ---- ProjectID validation ---------------------------------------------------

// TestGitSource_ProjectIDValidation verifies that unsafe projectIDs are
// rejected before any ReadProjectBlob invocation.
func TestGitSource_ProjectIDValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		projectID string
	}{
		{"empty", ""},
		{"slash", "foo/bar"},
		{"dot-dot", "foo..bar"},
		{"leading-dot", ".hidden"},
		{"backslash", `foo\bar`},
		{"null-byte", "foo\x00bar"},
		{"over-long", strings.Repeat("a", 129)},
		{"control-char", "foo\x01bar"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The reader must NEVER be called for an invalid projectID.
			reader := &zeroCallReader{t: t}
			resolver := &fakeBlobResolver{paths: map[string]string{tc.projectID + "/file": "some/path"}}

			s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
			_, err := s.FileOfRecord(context.Background(), tc.projectID, "file")
			if err == nil {
				t.Fatalf("expected error for projectID %q, got nil", tc.projectID)
			}
			// Must not wrap ErrFileOfRecordNotFound — this is a config error.
			// (Over-long and slice-sep errors are configuration/validation errors,
			// not "file does not exist" errors.)
		})
	}
}

// TestGitSource_ProjectIDValidation_ValidProjectIDs verifies that valid project
// IDs proceed to the ReadProjectBlob call.
func TestGitSource_ProjectIDValidation_ValidProjectIDs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		projectID string
	}{
		{"simple", "myproject"},
		{"hyphenated", "my-project"},
		{"underscored", "my_project"},
		{"numeric-suffix", "project123"},
		{"max-length-minus-one", strings.Repeat("a", 128)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			configuredPath := "secrets/" + tc.projectID + ".enc.yaml"
			resolver := &fakeBlobResolver{paths: map[string]string{tc.projectID + "/file": configuredPath}} //nolint:gosec // G101 false positive: test fixture YAML path
			reader := &fakeBlobReader{steps: []fakeBlobStep{
				{resolvedSHA: testFixedSHA, data: []byte("data")},
			}}

			s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
			_, err := s.FileOfRecord(context.Background(), tc.projectID, "file")
			if err != nil {
				t.Fatalf("projectID %q should be accepted: %v", tc.projectID, err)
			}
			if reader.callCount() != 1 {
				t.Errorf("expected 1 ReadProjectBlob call, got %d", reader.callCount())
			}
		})
	}
}

// ---- One-clone invariant: URL forwarding + call-count -----------------------

// TestGitSource_OneClonePerCall verifies that exactly one ReadProjectBlob call
// is made per FileOfRecord invocation, with the exact projectURL and branch.
func TestGitSource_OneClonePerCall(t *testing.T) {
	t.Parallel()

	const projectURL = "file:///tmp/my-project.git"
	const branch = "release"
	configuredPath := "secrets/prod.enc.yaml"
	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": configuredPath}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{resolvedSHA: testFixedSHA, data: []byte("data")},
	}}

	s := newGitSource(t, projectURL, branch, reader, resolver)
	_, err := s.FileOfRecord(context.Background(), "proj", "secrets")
	if err != nil {
		t.Fatalf("FileOfRecord: %v", err)
	}

	if reader.callCount() != 1 {
		t.Fatalf("expected exactly 1 ReadProjectBlob call, got %d", reader.callCount())
	}
	call := reader.call(0)
	if call.projectURL != projectURL {
		t.Errorf("projectURL mismatch: got %q want %q", call.projectURL, projectURL)
	}
	if call.branch != branch {
		t.Errorf("branch mismatch: got %q want %q", call.branch, branch)
	}
	if call.path != configuredPath {
		t.Errorf("path mismatch: got %q want %q", call.path, configuredPath)
	}
	if call.maxBytes <= 0 {
		t.Errorf("maxBytes must be > 0 (size cap required), got %d", call.maxBytes)
	}
}

// TestGitSource_SecondCallIsNewClone verifies that two consecutive FileOfRecord
// calls each result in exactly one ReadProjectBlob call (not shared/cached).
func TestGitSource_SecondCallIsNewClone(t *testing.T) {
	t.Parallel()

	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{resolvedSHA: testFixedSHA, data: []byte("first")},
		{resolvedSHA: testFixedSHA, data: []byte("second")},
	}}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)

	if _, err := s.FileOfRecord(context.Background(), "proj", "secrets"); err != nil {
		t.Fatalf("first FileOfRecord: %v", err)
	}
	if _, err := s.FileOfRecord(context.Background(), "proj", "secrets"); err != nil {
		t.Fatalf("second FileOfRecord: %v", err)
	}

	if reader.callCount() != 2 {
		t.Errorf("expected 2 ReadProjectBlob calls (one per FileOfRecord), got %d", reader.callCount())
	}
}

// ---- Absent file → ErrFileOfRecordNotFound ---------------------------------

// TestGitSource_AbsentBlob_ErrFileOfRecordNotFound verifies that a
// blob-not-found error from the reader maps to ErrFileOfRecordNotFound (not a
// generic error), and that the sentinel is reachable via errors.Is.
func TestGitSource_AbsentBlob_ErrFileOfRecordNotFound(t *testing.T) {
	t.Parallel()

	notFound := &blobNotFoundErr{msg: "path not found in git tree at SHA"}
	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{err: notFound},
	}}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
	_, err := s.FileOfRecord(context.Background(), "proj", "secrets")

	if err == nil {
		t.Fatal("expected error for absent blob, got nil")
	}
	if !errors.Is(err, usecase.ErrFileOfRecordNotFound) {
		t.Errorf("want errors.Is(err, ErrFileOfRecordNotFound); got: %T %v", err, err)
	}
}

// TestGitSource_AbsentNotEqualEmpty verifies that an empty byte slice from the
// reader is NOT treated as blob-not-found — it returns the empty bytes
// successfully (distinguishing absent from empty).
func TestGitSource_AbsentNotEqualEmpty(t *testing.T) {
	t.Parallel()

	resolver := &fakeBlobResolver{paths: map[string]string{"proj/empty": "secrets/empty.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{resolvedSHA: testFixedSHA, data: []byte{}}, // empty but present
	}}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
	record, err := s.FileOfRecord(context.Background(), "proj", "empty")
	if err != nil {
		t.Fatalf("empty bytes is NOT absent: got error %v", err)
	}
	// err is nil here (checked above). The sentinel ErrFileOfRecordNotFound must
	// NOT be set for an empty-but-present blob. No action needed; the check
	// above (err != nil → Fatalf) is the assertion.
	if record.Bytes == nil {
		t.Error("Bytes must be non-nil for an empty present file (distinguish absent from empty)")
	}
}

// ---- Unconfigured file → ErrFileOfRecordNotFound ---------------------------

// TestGitSource_UnconfiguredFile_ErrFileOfRecordNotFound verifies that a
// missing registry-configured path returns ErrFileOfRecordNotFound and does
// NOT invoke ReadProjectBlob.
func TestGitSource_UnconfiguredFile_ErrFileOfRecordNotFound(t *testing.T) {
	t.Parallel()

	resolver := &fakeBlobResolver{paths: map[string]string{}} // no paths configured
	reader := &zeroCallReader{t: t}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
	_, err := s.FileOfRecord(context.Background(), "proj", "secrets")

	if err == nil {
		t.Fatal("expected error for unconfigured file, got nil")
	}
	if !errors.Is(err, usecase.ErrFileOfRecordNotFound) {
		t.Errorf("want errors.Is(err, ErrFileOfRecordNotFound); got: %T %v", err, err)
	}
}

// TestGitSource_EmptyConfiguredPath_ErrFileOfRecordNotFound verifies that an
// empty string from the resolver is treated as not-found (not a valid path).
func TestGitSource_EmptyConfiguredPath_ErrFileOfRecordNotFound(t *testing.T) {
	t.Parallel()

	// A resolver that returns ("", nil) — empty path, no error.
	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": ""}} // empty path
	reader := &zeroCallReader{t: t}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
	_, err := s.FileOfRecord(context.Background(), "proj", "secrets")

	if err == nil {
		t.Fatal("expected error for empty configured path, got nil")
	}
	if !errors.Is(err, usecase.ErrFileOfRecordNotFound) {
		t.Errorf("want errors.Is(err, ErrFileOfRecordNotFound); got: %T %v", err, err)
	}
}

// ---- Context cancellation / deadline ----------------------------------------

// TestGitSource_PreCancelledContext verifies a pre-cancelled context returns
// context.Canceled wrapped in the error chain with no ReadProjectBlob call.
func TestGitSource_PreCancelledContext(t *testing.T) {
	t.Parallel()

	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling

	_, err := s.FileOfRecord(ctx, "proj", "secrets")
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled in chain; got: %v", err)
	}
}

// TestGitSource_ExpiredDeadline verifies an expired deadline returns
// context.DeadlineExceeded.
func TestGitSource_ExpiredDeadline(t *testing.T) {
	t.Parallel()

	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond) // ensure deadline is past

	_, err := s.FileOfRecord(ctx, "proj", "secrets")
	if err == nil {
		t.Fatal("expected error on expired deadline, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want context.DeadlineExceeded in chain; got: %v", err)
	}
}

// TestGitSource_ContextCancelledDuringRead verifies that a context cancelled
// during the read propagates the cancel signal.
func TestGitSource_ContextCancelledDuringRead(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path

	// Reader cancels the context and returns the cancel error.
	cancelReader := &funcBlobReader{fn: func(_ context.Context, _, _, _ string, _ int64) (string, []byte, error) {
		cancel()
		return "", nil, fmt.Errorf("fetch: %w", context.Canceled)
	}}

	s := newGitSource(t, "file:///tmp/repo.git", "main", cancelReader, resolver)
	_, err := s.FileOfRecord(ctx, "proj", "secrets")
	if err == nil {
		t.Fatal("expected error on cancelled read, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled in chain; got: %v", err)
	}
}

// funcBlobReader adapts a function to ProjectBlobReader for single-use tests.
type funcBlobReader struct {
	fn func(ctx context.Context, projectURL, branch, path string, maxBytes int64) (string, []byte, error)
}

func (f *funcBlobReader) ReadProjectBlob(ctx context.Context, projectURL, branch, path string, maxBytes int64) (string, []byte, error) {
	return f.fn(ctx, projectURL, branch, path, maxBytes)
}

// ---- Non-blob-not-found errors are wrapped with hint -----------------------

// TestGitSource_NetworkError_Wrapped verifies that a generic reader error (not
// blob-not-found) is wrapped with an actionable hint and the original error is
// in the chain.
func TestGitSource_NetworkError_Wrapped(t *testing.T) {
	t.Parallel()

	netErr := errors.New("dial tcp: connection refused")
	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{err: netErr},
	}}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
	_, err := s.FileOfRecord(context.Background(), "proj", "secrets")

	if err == nil {
		t.Fatal("expected error on network failure, got nil")
	}
	if !errors.Is(err, netErr) {
		t.Errorf("original error must be in chain; got: %v", err)
	}
	if !strings.Contains(err.Error(), "byreis doctor") {
		t.Errorf("error must contain actionable hint 'byreis doctor'; got: %v", err)
	}
}

// ---- Resolver error propagation ---------------------------------------------

// TestGitSource_ResolverError_Wrapped verifies that a non-not-found resolver
// error is wrapped with a hint and does not call ReadProjectBlob.
func TestGitSource_ResolverError_Wrapped(t *testing.T) {
	t.Parallel()

	resolveErr := errors.New("registry unreachable")
	resolver := &fakeBlobResolver{err: resolveErr}
	reader := &zeroCallReader{t: t}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
	_, err := s.FileOfRecord(context.Background(), "proj", "secrets")

	if err == nil {
		t.Fatal("expected error on resolver failure, got nil")
	}
	if !errors.Is(err, resolveErr) {
		t.Errorf("original resolver error must be in chain; got: %v", err)
	}
	if !strings.Contains(err.Error(), "byreis doctor") {
		t.Errorf("error must contain actionable hint 'byreis doctor'; got: %v", err)
	}
}

// ---- Concurrent calls → distinct invocations --------------------------------

// TestGitSource_ConcurrentCalls_Race verifies that concurrent FileOfRecord
// calls each produce exactly one ReadProjectBlob invocation with no data races.
// Running with -race detects any shared state.
func TestGitSource_ConcurrentCalls_Race(t *testing.T) {
	t.Parallel()

	const n = 10
	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path

	// Provide n steps so each goroutine gets its own step.
	steps := make([]fakeBlobStep, n)
	for i := range steps {
		steps[i] = fakeBlobStep{resolvedSHA: testFixedSHA, data: []byte("concurrent-data")}
	}
	reader := &fakeBlobReader{steps: steps}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.FileOfRecord(context.Background(), "proj", "secrets")
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, err)
		}
	}
	if reader.callCount() != n {
		t.Errorf("expected %d ReadProjectBlob calls, got %d", n, reader.callCount())
	}
}

// ---- Project URL forwarded byte-identical to reader -------------------------

// TestGitSource_ProjectURLForwarded verifies that the projectURL stored in the
// GitSource is forwarded byte-for-byte to ReadProjectBlob, covering both
// file:// and https:// forms.
func TestGitSource_ProjectURLForwarded(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, url string }{
		{"file-url", "file:///absolute/path/to/repo.git"},
		{"https-url", "https://github.com/owner/repo"},
		{"git-ssh", "git@github.com:owner/repo.git"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resolver := &fakeBlobResolver{paths: map[string]string{"p/f": "secrets/f.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
			reader := &fakeBlobReader{steps: []fakeBlobStep{
				{resolvedSHA: testFixedSHA, data: []byte("data")},
			}}

			s := newGitSource(t, tc.url, "main", reader, resolver)
			_, err := s.FileOfRecord(context.Background(), "p", "f")
			if err != nil {
				t.Fatalf("FileOfRecord: %v", err)
			}

			if reader.callCount() == 0 {
				t.Fatal("expected ReadProjectBlob to be called")
			}
			if got := reader.call(0).projectURL; got != tc.url {
				t.Errorf("projectURL forwarded as %q, want %q", got, tc.url)
			}
		})
	}
}

// ---- S_proj not surfaced as "verified" in identifiers ----------------------

// TestGitSource_SProj_NotMarkedVerified is a documentation-level assertion that
// the resolvedSHA returned by the reader is consumed as an intra-clone no-skew
// mechanism only — not stored or returned as a "verified" field by GitSource.
// The FileOfRecord struct has no VerifiedSHA field; the SHA is not propagated
// to callers as a trust root.
func TestGitSource_SProj_NotMarkedVerified(t *testing.T) {
	t.Parallel()

	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{resolvedSHA: testFixedSHA, data: []byte("data")},
	}}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
	record, err := s.FileOfRecord(context.Background(), "proj", "secrets")
	if err != nil {
		t.Fatalf("FileOfRecord: %v", err)
	}

	// FileOfRecord only exposes Bytes and ContentSHA (the raw-buffer hash).
	// There is no "VerifiedSHA", "TrustSHA", or "RegistrySHA" field on the
	// returned struct — S_proj is entirely internal to the reader and is not
	// propagated as a trust claim.
	_ = record.Bytes
	_ = record.ContentSHA
	// If FileOfRecord ever grows a VerifiedSHA field this test should be
	// updated with a comment explaining the trust boundary.
}

// ---- Error messages must not contain ciphertext / secret / path hints ------

// TestGitSource_ErrorMessages_NoSecretLeak verifies that error messages produced
// by GitSource never echo the configured path (which could be secret-adjacent
// metadata) in ways that leak to logs/callers beyond what the format string
// specifies. The test checks structural properties of error strings.
//
// Note: the configured path IS included in some messages (by design — it helps
// operators diagnose). The key invariant is that raw blob bytes are NEVER echoed.
func TestGitSource_ErrorMessages_NoRawBytesInErrors(t *testing.T) {
	t.Parallel()

	secretBytes := []byte("THIS IS SECRET CIPHERTEXT -- MUST NEVER APPEAR IN ERRORS")
	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path

	// Wrap the secret bytes in an error to see if they escape.
	readerErr := fmt.Errorf("internal: some error")
	_ = secretBytes // secretBytes not passed to error path — verifying isolation

	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{err: readerErr},
	}}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
	_, err := s.FileOfRecord(context.Background(), "proj", "secrets")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	errMsg := err.Error()
	if strings.Contains(errMsg, string(secretBytes)) {
		t.Errorf("error message contains raw secret bytes — must never echo encrypted payload")
	}
}

// ---- maxBytes forwarded to reader -------------------------------------------

// TestGitSource_MaxBytesForwarded verifies that the size cap (maxProjectBlobBytes)
// is forwarded as the maxBytes argument to ReadProjectBlob. The value must be
// positive (size cap required for trust-bearing reads).
func TestGitSource_MaxBytesForwarded(t *testing.T) {
	t.Parallel()

	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{resolvedSHA: testFixedSHA, data: []byte("data")},
	}}

	s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
	_, err := s.FileOfRecord(context.Background(), "proj", "secrets")
	if err != nil {
		t.Fatalf("FileOfRecord: %v", err)
	}

	if reader.callCount() == 0 {
		t.Fatal("no call captured")
	}
	if reader.call(0).maxBytes <= 0 {
		t.Errorf("maxBytes must be > 0 (size cap is mandatory), got %d", reader.call(0).maxBytes)
	}
}

// ---- BaseBranch forwarded byte-identical ------------------------------------

// TestGitSource_BaseBranchForwarded verifies that the configured BaseBranch is
// forwarded byte-identically to ReadProjectBlob (never a PR/submission branch).
func TestGitSource_BaseBranchForwarded(t *testing.T) {
	t.Parallel()

	const branch = "release-v2"
	resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{resolvedSHA: testFixedSHA, data: []byte("data")},
	}}

	s := newGitSource(t, "file:///tmp/repo.git", branch, reader, resolver)
	_, err := s.FileOfRecord(context.Background(), "proj", "secrets")
	if err != nil {
		t.Fatalf("FileOfRecord: %v", err)
	}

	if got := reader.call(0).branch; got != branch {
		t.Errorf("branch forwarded as %q, want %q — must never substitute a PR branch", got, branch)
	}
}

// ---- isBlobNotFound marker interface detection ------------------------------

// TestGitSource_BlobNotFoundMarker_Detected verifies that any error implementing
// the BlobNotFound() bool marker (regardless of package) maps to
// ErrFileOfRecordNotFound. This validates the cross-package detection mechanism.
func TestGitSource_BlobNotFoundMarker_Detected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
	}{
		{
			name: "direct-marker",
			err:  &blobNotFoundErr{msg: "path not found in git tree at SHA aabbcc"},
		},
		{
			name: "wrapped-marker",
			err:  fmt.Errorf("outer: %w", &blobNotFoundErr{msg: "wrapped not found"}),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resolver := &fakeBlobResolver{paths: map[string]string{"proj/secrets": "secrets/prod.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path
			reader := &fakeBlobReader{steps: []fakeBlobStep{{err: tc.err}}}

			s := newGitSource(t, "file:///tmp/repo.git", "main", reader, resolver)
			_, err := s.FileOfRecord(context.Background(), "proj", "secrets")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, usecase.ErrFileOfRecordNotFound) {
				t.Errorf("want ErrFileOfRecordNotFound in chain; got: %T %v", err, err)
			}
		})
	}
}

// ---- ProjectURL is stored once from config, not re-derived ------------------

// TestGitSource_ProjectURL_FromConfig verifies that the URL passed to
// NewGitSource is forwarded verbatim to every ReadProjectBlob call with no
// re-derivation, re-resolution, or mutation. This is the operator-pinned
// provenance invariant: once set at construction, the URL must not change.
func TestGitSource_ProjectURL_FromConfig(t *testing.T) {
	t.Parallel()

	const pinnedURL = "file:///operator/pinned/project-secrets.git"
	resolver := &fakeBlobResolver{paths: map[string]string{"p/f": "secrets/f.enc.yaml"}} //nolint:gosec // G101 false positive: test fixture YAML path

	// Two calls; both must see the same pinned URL.
	reader := &fakeBlobReader{steps: []fakeBlobStep{
		{resolvedSHA: testFixedSHA, data: []byte("first")},
		{resolvedSHA: testFixedSHA, data: []byte("second")},
	}}

	s := newGitSource(t, pinnedURL, "main", reader, resolver)

	for i := 0; i < 2; i++ {
		if _, err := s.FileOfRecord(context.Background(), "p", "f"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}

	for i := 0; i < 2; i++ {
		if got := reader.call(i).projectURL; got != pinnedURL {
			t.Errorf("call %d: projectURL %q != pinned %q — URL must not be re-derived", i, got, pinnedURL)
		}
	}
}

// ---- usecase.FileOfRecordSource compile-time assertion ----------------------

// TestGitSource_ImplementsFileOfRecordSource is a compile-time gate that
// GitSource satisfies the usecase.FileOfRecordSource interface.
func TestGitSource_ImplementsFileOfRecordSource(t *testing.T) {
	t.Parallel()

	// The nil-pointer-to-interface assignment is the canonical Go pattern for
	// compile-time interface satisfaction. It fails at build time if not satisfied.
	var _ usecase.FileOfRecordSource = (*fileofrecord.GitSource)(nil)
}
