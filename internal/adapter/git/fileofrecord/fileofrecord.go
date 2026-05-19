// Package fileofrecord implements the usecase.FileOfRecordSource port. It
// fetches the LIVE committed signed file-of-record bytes for a (projectID,
// fileName) pair from the configured project repository base branch.
//
// Placement: OUTER adapter layer (internal/adapter/git/fileofrecord). Core
// packages never import this adapter; it is injected at the composition root.
//
// Zero-normalization contract: the bytes returned by FileOfRecord are the
// exact bytes retrieved from the git object store, with no CRLF rewriting,
// key reordering, or any other transformation. FileOfRecord.ContentSHA is
// sha256 of those exact bytes (for repo-side move detection only; it is NOT
// the of-record counter-pin identity).
//
// Branch isolation contract: this adapter NEVER reads a PR/submission branch.
// It always fetches from the configured base branch (e.g. "main"). Reading a
// submission branch here would break the asymmetric-access boundary.
//
// ErrFileOfRecordNotFound (wrapped from usecase) is returned when the
// registry-configured file does not exist on the base branch.
package fileofrecord

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/ByReisK/byreis/internal/core/usecase"
)

// FileFetcher is the transport port for fetching committed file bytes. The
// concrete implementation wraps the GitHub API (or any git host adapter); the
// interface is defined here so tests can inject a fake without touching real
// network or git processes.
//
// Fetch MUST return exactly the committed bytes at the given ref with no
// transformation. When the file does not exist it MUST return a non-nil error
// that satisfies the adapter's not-found detection (an HTTP-404-style error
// wrapping ErrNotFound or returning HTTP status 404 via errors.As).
type FileFetcher interface {
	// FetchCommittedFile returns the raw committed bytes of path at ref. Ref
	// is always the base branch (never a PR branch). An HTTP 404 / not-found
	// error is expected when the file does not yet exist.
	FetchCommittedFile(ctx context.Context, path, ref string) ([]byte, error)
}

// ErrFetchNotFound is the sentinel the adapter recognises as a not-found
// signal from the underlying transport. The transport implementation MUST
// wrap this error (or return an error satisfying errors.Is(err, ErrFetchNotFound))
// when the file does not exist at the given ref.
var ErrFetchNotFound = errors.New("file not found at the given ref")

// ConfiguredPathResolver resolves the registry-configured repo-relative path
// for a (projectID, fileName) pair. The resolution MUST originate from the
// SAME signature-verified registry fetch that produced the recipient set;
// this adapter calls the resolver at FileOfRecord time and never caches the
// result beyond the single call's lifetime.
type ConfiguredPathResolver interface {
	// ConfiguredPath returns the repo-relative path for the given logical file
	// within the project. The path MUST come from a signature-verified registry
	// fetch. If the (projectID, fileName) pair has no configured path, the
	// resolver returns ("", ErrFileOfRecordNotFound) so the source can surface
	// the correct sentinel.
	ConfiguredPath(ctx context.Context, projectID, fileName string) (string, error)
}

// Source implements usecase.FileOfRecordSource. It is constructed via New and
// has no mutable state; all methods are safe for concurrent use.
type Source struct {
	fetcher    FileFetcher
	resolver   ConfiguredPathResolver
	baseBranch string
}

// New constructs a Source. All parameters are required.
//
// baseBranch is the repository base branch to fetch from (e.g. "main"). The
// adapter NEVER reads a PR branch; it always fetches from this branch.
// fetcher provides the raw committed bytes. resolver maps (projectID, fileName)
// → registry-configured repo-relative path.
func New(fetcher FileFetcher, resolver ConfiguredPathResolver, baseBranch string) (*Source, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("fileofrecord.New: fetcher is required")
	}
	if resolver == nil {
		return nil, fmt.Errorf("fileofrecord.New: resolver is required")
	}
	if baseBranch == "" {
		return nil, fmt.Errorf("fileofrecord.New: baseBranch is required")
	}
	return &Source{fetcher: fetcher, resolver: resolver, baseBranch: baseBranch}, nil
}

// Compile-time assertion: Source implements usecase.FileOfRecordSource.
var _ usecase.FileOfRecordSource = (*Source)(nil)

// FileOfRecord implements usecase.FileOfRecordSource. It returns the LIVE
// committed signed file-of-record bytes for the given (projectID, fileName)
// pair from the base branch.
//
// The bytes returned in FileOfRecord.Bytes are the exact raw bytes from the
// git object store — zero normalization, zero transformation.
//
// FileOfRecord.ContentSHA is sha256(Bytes) in lowercase hex. This is the
// adapter-level raw-buffer hash used by the use-case for repo-side move
// detection only. It is NOT the of-record counter-pin identity (which the
// use-case recomputes via verify.ContentSHA over the decoded manifest).
//
// Returns an error satisfying errors.Is(err, usecase.ErrFileOfRecordNotFound)
// when the registry-configured file does not exist on the base branch.
// Context cancellation/deadline is honored; a cancelled context returns the
// context error wrapped as a fetch error.
func (s *Source) FileOfRecord(ctx context.Context, projectID, fileName string) (usecase.FileOfRecord, error) {
	if err := ctx.Err(); err != nil {
		return usecase.FileOfRecord{}, fmt.Errorf(
			"FileOfRecord cancelled for project %q file %q: %w",
			projectID, fileName, err)
	}

	// Resolve the registry-configured path. This MUST come from a verified
	// registry fetch; the resolver is responsible for that contract.
	configuredPath, err := s.resolver.ConfiguredPath(ctx, projectID, fileName)
	if err != nil {
		if errors.Is(err, usecase.ErrFileOfRecordNotFound) {
			return usecase.FileOfRecord{}, fmt.Errorf(
				"%w: no configured path for project %q file %q — "+
					"check the admin registry project config",
				usecase.ErrFileOfRecordNotFound, projectID, fileName)
		}
		return usecase.FileOfRecord{}, fmt.Errorf(
			"resolving configured path for project %q file %q failed — "+
				"run `byreis doctor` to check the registry: %w",
			projectID, fileName, err)
	}

	if configuredPath == "" {
		return usecase.FileOfRecord{}, fmt.Errorf(
			"%w: empty configured path for project %q file %q — "+
				"check the admin registry project config",
			usecase.ErrFileOfRecordNotFound, projectID, fileName)
	}

	// Fetch from the base branch ONLY — never from a PR or submission branch.
	raw, err := s.fetcher.FetchCommittedFile(ctx, configuredPath, s.baseBranch)
	if err != nil {
		if errors.Is(err, ErrFetchNotFound) || isHTTP404(err) {
			return usecase.FileOfRecord{}, fmt.Errorf(
				"%w: file %q at configured path %q does not exist on branch %q — "+
					"it may not have been merged yet; run `byreis doctor` to diagnose",
				usecase.ErrFileOfRecordNotFound, fileName, configuredPath, s.baseBranch)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return usecase.FileOfRecord{}, fmt.Errorf(
				"FileOfRecord fetch cancelled for project %q file %q: %w",
				projectID, fileName, err)
		}
		return usecase.FileOfRecord{}, fmt.Errorf(
			"fetching file-of-record for project %q file %q from branch %q failed — "+
				"check network connectivity and run `byreis doctor`: %w",
			projectID, fileName, s.baseBranch, err)
	}

	// Compute the adapter-level raw-buffer hash. This is for repo-side move
	// detection only; the use-case recomputes the of-record pin separately.
	sum := sha256.Sum256(raw)
	contentSHA := hex.EncodeToString(sum[:])

	return usecase.FileOfRecord{
		Bytes:      raw,
		ContentSHA: contentSHA,
	}, nil
}

// isHTTP404 returns true if err represents an HTTP 404 response. It uses
// errors.As to unwrap to a *http404Error or checks for the status code via
// the httpStatusErr interface to remain transport-agnostic.
func isHTTP404(err error) bool {
	var sc interface{ StatusCode() int }
	if errors.As(err, &sc) {
		return sc.StatusCode() == http.StatusNotFound
	}
	return false
}
