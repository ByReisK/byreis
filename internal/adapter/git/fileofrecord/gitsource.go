// Package fileofrecord — git-based file-of-record source.
//
// GitSource reads the LIVE committed signed file-of-record bytes for a
// (projectID, fileName) pair from a local or remote git repository, using a
// single shallow clone per call with a hardened isolated environment. The
// project-branch SHA (S_proj) is an intra-clone NO-SKEW mechanism only — it
// is NOT a signed or verified SHA. Project-repo trust is the manifest
// signature (verify.VerifyOfRecord over the registry-attested set per
// ADR-0008/0009); the project leg is structurally weaker than the registry leg.
//
// Placement: OUTER adapter layer (internal/adapter/git/fileofrecord). Core
// packages never import this adapter; it is injected at the composition root.
package fileofrecord

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/ByReisK/byreis/internal/core/usecase"
)

// maxProjectBlobBytes is the pre-read size cap for file-of-record blobs.
// A blob exceeding this limit is rejected before return to prevent OOM.
// The encrypted-secret bytes are the most sensitive payload; they are never
// logged or echoed in any error string.
const maxProjectBlobBytes = 1 << 20 // 1 MiB

// ProjectBlobReader is the transport seam for git-based project blob reads.
// Defined here (consumer-defined port) so tests can inject fakes without
// importing any specific implementation package.
//
// When the path does not exist in the project repo at the resolved S_proj SHA,
// implementations MUST return an error whose chain contains a value
// implementing the BlobNotFound() bool marker interface (i.e. an error whose
// BlobNotFound() method returns true). GitSource detects this via errors.As
// on the anonymous interface without importing the implementation package.
type ProjectBlobReader interface {
	// ReadProjectBlob clones projectURL (once per call), resolves branch to
	// S_proj exactly once inside that clone, then reads path via
	// git cat-file blob at S_proj. Returns the resolved S_proj SHA and the
	// raw bytes. S_proj is an intra-clone no-skew invariant, not a trust root.
	// When the path does not exist at S_proj, returns an error satisfying
	// isBlobNotFound (see below).
	ReadProjectBlob(ctx context.Context, projectURL, branch, path string, maxBytes int64) (resolvedSHA string, data []byte, err error)
}

// isBlobNotFound detects a blob-not-found error from the underlying git
// reader. The detection uses the BlobNotFound() bool marker interface so no
// import of the implementation package (fetchtransport) is needed.
func isBlobNotFound(err error) bool {
	var m interface{ BlobNotFound() bool }
	return errors.As(err, &m) && m.BlobNotFound()
}

// GitSource implements usecase.FileOfRecordSource by reading the committed
// signed file-of-record bytes from the project secrets repository using a
// single hardened git clone per call.
//
// The project-repo clone URL is sourced ONLY from operator-pinned
// configuration (BYREIS_PROJECT_REPO or the operator-trusted .byreis.yaml);
// it is never derived from a registry-fetched, network, artifact, or
// project-repo-content value. A URL not from operator-pinned config is a
// fail-closed configuration error.
//
// S_proj (the in-clone resolved branch SHA) is an intra-clone NO-SKEW
// mechanism only — it prevents read-skew within the single clone. It is
// structurally weaker than the registry verifiedSHA because there is no
// signed-commit verifier on the project repo. Trust derives from
// verify.VerifyOfRecord over the registry-attested recipient/signer set
// and counter authority (readpath.go; ADR-0008/0009; DESIGN §3.5).
type GitSource struct {
	// projectURL is the operator-pinned project secrets-repo clone URL.
	// Sourced from BYREIS_PROJECT_REPO env or the operator-trusted .byreis.yaml.
	// Never from registry/artifact/network content.
	projectURL string

	// baseBranch is the configured base branch (e.g. "main"). The adapter
	// always fetches from this branch and never from a PR or submission branch.
	baseBranch string

	// reader performs the clone+rev-parse+cat-file pipeline.
	reader ProjectBlobReader

	// resolver maps (projectID, fileName) to the repo-relative path.
	// Must originate from a signature-verified registry fetch.
	resolver ConfiguredPathResolver
}

// GitSourceConfig holds the injected dependencies for GitSource.
type GitSourceConfig struct {
	// ProjectURL is the operator-pinned project repo URL. Required.
	// Must come from BYREIS_PROJECT_REPO or operator-trusted .byreis.yaml.
	ProjectURL string

	// BaseBranch is the base branch to read from (e.g. "main"). Required.
	BaseBranch string

	// Reader is the git blob reader. Required.
	Reader ProjectBlobReader

	// Resolver maps (projectID, fileName) to the repo-relative path. Required.
	Resolver ConfiguredPathResolver
}

// NewGitSource constructs a GitSource from the given config. All fields are
// required; returns an error if any is absent.
func NewGitSource(cfg GitSourceConfig) (*GitSource, error) {
	if cfg.ProjectURL == "" {
		return nil, fmt.Errorf(
			"fileofrecord.NewGitSource: ProjectURL is required — " +
				"set BYREIS_PROJECT_REPO to the operator-pinned project repo URL")
	}
	if cfg.BaseBranch == "" {
		return nil, fmt.Errorf(
			"fileofrecord.NewGitSource: BaseBranch is required")
	}
	if cfg.Reader == nil {
		return nil, fmt.Errorf(
			"fileofrecord.NewGitSource: Reader is required")
	}
	if cfg.Resolver == nil {
		return nil, fmt.Errorf(
			"fileofrecord.NewGitSource: Resolver is required")
	}
	return &GitSource{
		projectURL: cfg.ProjectURL,
		baseBranch: cfg.BaseBranch,
		reader:     cfg.Reader,
		resolver:   cfg.Resolver,
	}, nil
}

// Compile-time assertion: GitSource implements usecase.FileOfRecordSource.
var _ usecase.FileOfRecordSource = (*GitSource)(nil)

// FileOfRecord implements usecase.FileOfRecordSource. It performs one project
// clone per call, resolves the base branch to S_proj exactly once inside that
// clone, and reads the committed bytes at S_proj:<configuredPath> via
// git cat-file blob. The clone is removed on every exit path.
//
// S_proj is an intra-clone NO-SKEW mechanism — it prevents within-call
// read skew. It is NOT a signed or trust-verified SHA.
// Project-repo trust is the manifest signature, not the project commit.
//
// The bytes returned in FileOfRecord.Bytes are the exact raw bytes from the
// git object store — zero normalization, zero transformation. The encrypted
// secret bytes are NEVER echoed in any error or log message.
//
// Returns an error satisfying errors.Is(err, usecase.ErrFileOfRecordNotFound)
// when the configured file does not exist in the project repo at S_proj.
// Context cancellation/deadline is honored; a cancelled context returns a
// wrapped cancel error with no clone or temp-dir leak.
func (s *GitSource) FileOfRecord(ctx context.Context, projectID, fileName string) (usecase.FileOfRecord, error) {
	if err := ctx.Err(); err != nil {
		return usecase.FileOfRecord{}, fmt.Errorf(
			"FileOfRecord cancelled for project %q file %q: %w",
			projectID, fileName, err)
	}

	// Validate the projectID before any path composition.
	// Mirrors fetchtransport.ValidateProjectID: rejects empty, over-long, path
	// separators, dot-dot, leading dot, backslash, null, and control characters.
	if err := validateProjectIDForGitSource(projectID); err != nil {
		return usecase.FileOfRecord{}, fmt.Errorf(
			"FileOfRecord: invalid projectID: %w", err)
	}

	// Resolve the registry-configured path. Must originate from a verified
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

	// Perform ONE clone of the project repo, resolve branch→S_proj once,
	// read via cat-file blob at S_proj:<configuredPath>.
	// The clone and temp dir are removed by ReadProjectBlob on every exit path.
	_, raw, readErr := s.reader.ReadProjectBlob(ctx, s.projectURL, s.baseBranch, configuredPath, maxProjectBlobBytes)
	if readErr != nil {
		if isBlobNotFound(readErr) {
			return usecase.FileOfRecord{}, fmt.Errorf(
				"%w: file %q at configured path %q does not exist in project repo at resolved branch SHA — "+
					"it may not have been merged yet; run `byreis doctor` to diagnose",
				usecase.ErrFileOfRecordNotFound, fileName, configuredPath)
		}
		if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
			return usecase.FileOfRecord{}, fmt.Errorf(
				"FileOfRecord fetch cancelled for project %q file %q: %w",
				projectID, fileName, readErr)
		}
		// The encrypted bytes are NEVER echoed in any error message.
		return usecase.FileOfRecord{}, fmt.Errorf(
			"fetching file-of-record for project %q file %q from branch %q failed — "+
				"check connectivity and run `byreis doctor`: %w",
			projectID, fileName, s.baseBranch, readErr)
	}

	// Compute the adapter-level raw-buffer hash. This is for repo-side move
	// detection only; the use-case recomputes the of-record pin separately via
	// verify.ContentSHA over the decoded manifest.
	sum := sha256.Sum256(raw)
	contentSHA := hex.EncodeToString(sum[:])

	return usecase.FileOfRecord{
		Bytes:      raw,
		ContentSHA: contentSHA,
	}, nil
}

// maxProjectIDLen mirrors fetchtransport.maxProjectIDLen — bounded to prevent
// path traversal via over-long identifiers.
const maxProjectIDLen = 128

// validateProjectIDForGitSource checks that projectID is safe to use in
// path composition. It mirrors fetchtransport.ValidateProjectID exactly:
// rejects empty, over-long, any '/', any '..', leading '.', backslash, null,
// or control characters. Applied before any path composition.
func validateProjectIDForGitSource(projectID string) error {
	if projectID == "" {
		return fmt.Errorf(
			"project ID must not be empty — pass --project or set BYREIS_PROJECT")
	}
	if len(projectID) > maxProjectIDLen {
		return fmt.Errorf(
			"project ID is too long (%d bytes, max %d) — check BYREIS_PROJECT",
			len(projectID), maxProjectIDLen)
	}
	if strings.Contains(projectID, "/") {
		return fmt.Errorf(
			"project ID %q contains a path separator ('/') — "+
				"project IDs must be a single path component with no slashes",
			projectID)
	}
	if strings.Contains(projectID, "\\") {
		return fmt.Errorf(
			"project ID %q contains a backslash — "+
				"project IDs must use forward-slash paths only",
			projectID)
	}
	if strings.Contains(projectID, "\x00") {
		return fmt.Errorf(
			"project ID %q contains a null byte — "+
				"project IDs must not contain null bytes",
			projectID)
	}
	if strings.HasPrefix(projectID, ".") {
		return fmt.Errorf(
			"project ID %q starts with '.' — project IDs must not start with a dot",
			projectID)
	}
	if strings.Contains(projectID, "..") {
		return fmt.Errorf(
			"project ID %q contains a dot-dot component ('..') — "+
				"project IDs must not contain path traversal sequences",
			projectID)
	}
	for _, r := range projectID {
		if unicode.IsControl(r) {
			return fmt.Errorf(
				"project ID %q contains a control character (0x%X) — "+
					"project IDs must contain only printable characters",
				projectID, r)
		}
	}
	return nil
}
