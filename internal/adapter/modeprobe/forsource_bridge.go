// Package modeprobe (bridge file): ForSourceBridge adapts a
// usecase.FileOfRecordSource + usecase.ArtifactCodec + ConfiguredFileChooser
// trio into the narrow modeprobe.ArtifactFetcher port consumed by KeyProbe.
//
// Security contract:
//
//   - Bridge returns only artifact.Signed; it never returns, logs, or formats
//     decoded plaintext. The probe layer (probeDecryptOne) handles plaintext at
//     the io.Discard floor inside modeprobe.go; the bridge stops before that.
//
//   - The chooser MUST consult only ConfiguredFiles from a SourceVerified &&
//     !Stale AdminSet. Any other source for the fileName is a construction error.
//     The bridge constructor enforces this via ConfiguredFileChooser.
//
//   - anchor-key trust dependency: the AdminSet read by the chooser travels the
//     same registry fetch path that enforces commit-signature verification at
//     modeprobe.go:304-315 (IsRegisteredAdmin) and wrapper.go:143-149
//     (adminSetToVerifiedRecipients). A stale or unverified chooser result maps
//     to ErrArtifactNotFound — identical to the empty-ConfiguredFiles row.
//
//   - usecase.ErrFileOfRecordNotFound is translated to modeprobe.ErrArtifactNotFound
//     so CanDecryptAny correctly returns (false, nil) for a new project.
//     Transient network errors and codec failures are NOT collapsed; they
//     propagate wrapped so byreis doctor can distinguish them.
//
//   - Environment variable reads: zero. No env, flag, artifact field, or
//     content-derived hint can inject a fileName through the chooser interface.
//
// UX gap (v0.1-acceptable): when the probe returns (false, nil) the mode
// resolver collapses to CONTRIBUTOR. The caller cannot distinguish "probe ran
// and rejected" from "no file yet". Use byreis doctor to disambiguate; it
// inspects the registry ConfiguredFiles and the project repo independently.
package modeprobe

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/ByReisK/byreis/internal/adapter/artifactcodec"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// ConfiguredFileChooser selects a single fileName (the lex-first entry) from a
// SourceVerified, non-stale registry AdminSet.ConfiguredFiles for the given
// projectID. It returns ("", ErrArtifactNotFound) when:
//
//   - the AdminSet is not SourceVerified or is Stale, or
//   - ConfiguredFiles is empty or nil.
//
// Implementations MUST source fileName ONLY from AdminSet.ConfiguredFiles
// (registry-attested, signed). No env var, flag, artifact field, or
// content-derived hint may be injected through this interface — the bridge
// constructor accepts no field that could carry such a bypass, and this file
// contains no environment variable reads.
type ConfiguredFileChooser interface {
	ChooseFile(ctx context.Context, projectID string) (string, error)
}

// ForSourceBridge adapts a FileOfRecordSource + ArtifactCodec + ConfiguredFileChooser
// to the ArtifactFetcher port. It is constructed at the composition root and
// injected into NewKeyProbe as the second argument, replacing the prior nil.
//
// Immutable after construction; safe for concurrent use.
type ForSourceBridge struct {
	source  usecase.FileOfRecordSource
	codec   usecase.ArtifactCodec
	chooser ConfiguredFileChooser
}

// NewForSourceBridge constructs a ForSourceBridge. All three arguments are
// required; a nil argument returns (nil, err) following the (nil, err) discipline
// used for other fail-closed construction paths in this codebase.
func NewForSourceBridge(
	source usecase.FileOfRecordSource,
	codec usecase.ArtifactCodec,
	chooser ConfiguredFileChooser,
) (*ForSourceBridge, error) {
	if source == nil {
		return nil, fmt.Errorf(
			"modeprobe.NewForSourceBridge: FileOfRecordSource is required — " +
				"run `byreis init` to configure the project repository")
	}
	if codec == nil {
		return nil, fmt.Errorf(
			"modeprobe.NewForSourceBridge: ArtifactCodec is required — " +
				"this is a programming error at the composition root")
	}
	if chooser == nil {
		return nil, fmt.Errorf(
			"modeprobe.NewForSourceBridge: ConfiguredFileChooser is required — " +
				"run `byreis init` to configure the registry")
	}
	return &ForSourceBridge{source: source, codec: codec, chooser: chooser}, nil
}

// FetchArtifact implements ArtifactFetcher. It:
//  1. Asks the chooser for the lex-first registry-attested fileName.
//  2. Fetches the FileOfRecord from the source.
//  3. Decodes the bytes into artifact.Signed via the codec.
//
// Fail-closed taxonomy (six rows):
//
//   - chooser returns ErrArtifactNotFound (empty/stale/unverified ConfiguredFiles)      → ErrArtifactNotFound
//   - source returns usecase.ErrFileOfRecordNotFound (file not yet merged)              → ErrArtifactNotFound
//   - codec returns artifactcodec.ErrTypedMismatch (file exists but has no manifest_sig,
//     i.e. an unsigned contributor submission artifact on a fresh project before the
//     first admin merge)                                                                 → ErrArtifactNotFound
//   - codec returns any other error (malformed/decode fault)                            → wrapped (not ErrArtifactNotFound)
//   - source returns a transient network/IO error                                       → wrapped (not ErrArtifactNotFound)
//   - ctx cancelled                                                                     → ctx error (not ErrArtifactNotFound)
//
// The ErrTypedMismatch row is fail-closed by construction: both pre- and post-patch
// resolve to CONTRIBUTOR. Before this row existed, a project file present but lacking a
// manifest_sig surfaced as a wrapped codec error; CanDecryptAny returned (false, err) and
// mode.Detect step 3 short-circuited to CONTRIBUTOR on the err != nil branch. After this
// row, the same input returns ErrArtifactNotFound; CanDecryptAny returns (false, nil) and
// step 3 short-circuits to CONTRIBUTOR on the !canDecrypt branch. The downstream
// IsRegisteredAdmin step is never reached when canDecrypt is false, so no promotion path
// is created by this softening — it only suppresses a misleading "malformed file"
// diagnostic on the probe path when the project is in the legitimate "contributor has
// submitted but no admin has merged yet" intermediate state. The asymmetric guarantee
// holds for the same reason it held before: an attacker without the private key cannot
// pass the decrypt probe regardless of how a benign no-signed-artifact-yet input is
// classified. Note: this row does NOT solve the genuine "fresh-project bootstrap"
// UX question (how a real admin runs the first merge on a project that has never been
// signed) — that remains a known gap to address in a future cycle, not here.
//
// The bridge NEVER logs the probe outcome, audits on error, or caches the
// returned artifact.Signed across calls. Plaintext stays at the io.Discard
// floor inside probeDecryptOne (modeprobe.go); this method stops at artifact.Signed.
func (b *ForSourceBridge) FetchArtifact(ctx context.Context, projectID string) (artifact.Signed, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Signed{}, fmt.Errorf("FetchArtifact cancelled: %w", err)
	}

	fileName, chooseErr := b.chooser.ChooseFile(ctx, projectID)
	if chooseErr != nil {
		if errors.Is(chooseErr, ErrArtifactNotFound) {
			return artifact.Signed{}, ErrArtifactNotFound
		}
		return artifact.Signed{}, fmt.Errorf(
			"choosing configured file for project %q: %w — run `byreis doctor` to diagnose",
			projectID, chooseErr)
	}

	rec, fetchErr := b.source.FileOfRecord(ctx, projectID, fileName)
	if fetchErr != nil {
		if errors.Is(fetchErr, usecase.ErrFileOfRecordNotFound) {
			return artifact.Signed{}, fmt.Errorf(
				"%w: project %q file %q has no committed file-of-record",
				ErrArtifactNotFound, projectID, fileName)
		}
		// Transient network/IO error: propagate wrapped, not collapsed to
		// ErrArtifactNotFound, so byreis doctor can surface the distinction.
		return artifact.Signed{}, fmt.Errorf(
			"fetching file-of-record for project %q file %q: %w",
			projectID, fileName, fetchErr)
	}

	signed, decodeErr := b.codec.DecodeSigned(rec.Bytes)
	if decodeErr != nil {
		// A file that exists but carries no manifest_sig block is an unsigned
		// contributor submission artifact — present on a fresh project where a
		// contributor has submitted but no admin has merged yet. Treat this
		// identically to a missing file: the probe has nothing signed to attempt
		// decryption against, so return ErrArtifactNotFound rather than a hard
		// decode error. This is error-class hygiene on the probe path; it does not
		// create any new mode-promotion path (see the taxonomy comment above for the
		// fail-closed argument).
		if errors.Is(decodeErr, artifactcodec.ErrTypedMismatch) {
			return artifact.Signed{}, fmt.Errorf(
				"%w: project %q file %q exists but has no manifest_sig block "+
					"(unsigned submission artifact — no signed file-of-record yet)",
				ErrArtifactNotFound, projectID, fileName)
		}
		return artifact.Signed{}, fmt.Errorf(
			"decoding file-of-record for project %q file %q (contentSHA %s): %w",
			projectID, fileName, rec.ContentSHA, decodeErr)
	}

	return signed, nil
}

// LexFirstChooser is a ConfiguredFileChooser that picks the lexicographically-first
// key from a caller-supplied map of configuredFiles (logical_file_name → path).
// It is used in tests and as the shared implementation primitive for the
// production chooser (prodRegistryConfiguredPathChooser in internal/app).
//
// The map MUST come from a SourceVerified, non-stale AdminSet.ConfiguredFiles;
// that invariant is enforced by the caller (the production chooser or the test
// setup), not here.
type LexFirstChooser struct {
	// configuredFiles maps logical_file_name → repo-relative path.
	// It is set once at construction and never mutated.
	configuredFiles map[string]string
}

// NewLexFirstChooser constructs a LexFirstChooser from a pre-validated
// ConfiguredFiles map. Returns (nil, ErrArtifactNotFound) when the map is
// empty or nil.
func NewLexFirstChooser(configuredFiles map[string]string) (*LexFirstChooser, error) {
	if len(configuredFiles) == 0 {
		return nil, fmt.Errorf(
			"%w: ConfiguredFiles is empty — no registry-attested file names for this project",
			ErrArtifactNotFound)
	}
	// Defensive copy: the caller retains ownership of the original map.
	cp := make(map[string]string, len(configuredFiles))
	for k, v := range configuredFiles {
		cp[k] = v
	}
	return &LexFirstChooser{configuredFiles: cp}, nil
}

// ChooseFile returns the lexicographically-first logical file name. The
// ordering is deterministic regardless of Go map-iteration order:
// sort.Strings produces lex-ascending order and the first element is returned.
func (c *LexFirstChooser) ChooseFile(_ context.Context, _ string) (string, error) {
	if len(c.configuredFiles) == 0 {
		return "", fmt.Errorf(
			"%w: ConfiguredFiles is empty",
			ErrArtifactNotFound)
	}
	keys := make([]string, 0, len(c.configuredFiles))
	for k := range c.configuredFiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys[0], nil
}

// Compile-time assertions.
var (
	_ ArtifactFetcher       = (*ForSourceBridge)(nil)
	_ ConfiguredFileChooser = (*LexFirstChooser)(nil)
)
