// Package keyprobe implements the submit.KeyExistenceProbe port.
//
// This adapter determines whether a secret key already exists in the live
// secrets file by reading KEY NAMES ONLY from the YAML envelope — it never
// decrypts any value and never loads any identity material.
//
// Security contract:
//   - The read path is: forSource.FileOfRecordBytes → raw YAML bytes →
//     DecodeKeyNames (names only, no values) → membership check.
//   - This package MUST NOT import crypto/decrypt, crypto/identity,
//     core/registry, core/registry/countertypes, or crypto/ed25519.
//     The interface types are defined locally so that no dependency path to
//     those packages is introduced transitively via core/usecase.
//     Verified by the negative import test over this package's transitive
//     dependency set.
//   - A probe error (network failure, cache miss, codec error) is a HARD
//     error. The use-case REFUSES the submission; it never defaults to
//     "assume ADD" on an unknown existence result (fail-closed on ambiguity).
//
// Placement: OUTER adapter layer (internal/adapter/git/keyprobe). Core
// packages never import this adapter; it is wired only at the composition root
// via internal/app.
package keyprobe

import (
	"context"
	"errors"
	"fmt"
)

// ErrFileNotFound is the sentinel that FileOfRecordBytesSource implementations
// must wrap when the live file does not exist yet (first-ever submission). The
// composition root wraps usecase.ErrFileOfRecordNotFound with this sentinel.
var ErrFileNotFound = errors.New("file-of-record not found")

// FileOfRecordBytesSource is the narrow port needed by the probe: fetch the
// raw YAML bytes of the live signed file-of-record for a (projectID,
// logicalFile) pair. Returning ErrFileNotFound (or a wrapping error) means the
// file does not exist yet, which the probe treats as "key cannot exist".
//
// This interface returns only raw bytes — not usecase.FileOfRecord — so the
// probe package has no compile-time dependency on core/usecase (which
// transitively imports core/crypto/identity, core/crypto/decrypt, and
// core/registry, all of which are forbidden on the contributor encrypt path).
type FileOfRecordBytesSource interface {
	FileOfRecordBytes(ctx context.Context, projectID, fileName string) ([]byte, error)
}

// KeyNameDecoder is the adapter-layer-only method that decodes top-level key
// names from a raw YAML envelope WITHOUT decrypting values or touching identity
// material. Defined as a minimal interface so the probe never reaches the full
// ArtifactCodec port (which includes DecodeSigned/DecodeUnsigned).
type KeyNameDecoder interface {
	DecodeKeyNames(b []byte) ([]string, error)
}

// Probe implements submit.KeyExistenceProbe. It reads key names from the live
// file-of-record via the injected source and decoder. No decrypt, no identity.
type Probe struct {
	source  FileOfRecordBytesSource
	decoder KeyNameDecoder
}

// New constructs a Probe. Both source and decoder are required.
func New(source FileOfRecordBytesSource, decoder KeyNameDecoder) (*Probe, error) {
	if source == nil {
		return nil, fmt.Errorf("keyprobe.New: FileOfRecordBytesSource is nil — wire the file-of-record source")
	}
	if decoder == nil {
		return nil, fmt.Errorf("keyprobe.New: KeyNameDecoder is nil — wire the artifact codec")
	}
	return &Probe{source: source, decoder: decoder}, nil
}

// KeyExists reports whether key is present in the live secrets file for
// (projectID, logicalFile). It reads key names only — no decrypt, no identity.
//
// When the file-of-record does not exist (first-ever submission, no live
// secrets file yet) the method returns (false, nil): the key cannot be present
// in a file that does not exist, so ADD is correct. All other errors from the
// source or decoder are returned as hard errors so the use-case refuses rather
// than silently defaulting to ADD.
func (p *Probe) KeyExists(ctx context.Context, projectID, logicalFile, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("key existence probe cancelled: %w", err)
	}

	rawBytes, err := p.source.FileOfRecordBytes(ctx, projectID, logicalFile)
	if err != nil {
		// A not-found error means there is no live file yet. The key cannot
		// exist in a file that does not exist: ADD is the correct action.
		if errors.Is(err, ErrFileNotFound) {
			return false, nil
		}
		// All other source errors are hard failures: the probe cannot determine
		// existence, so the use-case must refuse rather than assume ADD.
		return false, fmt.Errorf(
			"key existence probe: fetching file-of-record for project %q file %q failed: %w — "+
				"run `byreis doctor` to check registry and project-repo connectivity",
			projectID, logicalFile, err)
	}

	if len(rawBytes) == 0 {
		// Empty file: treat as no keys present.
		return false, nil
	}

	names, err := p.decoder.DecodeKeyNames(rawBytes)
	if err != nil {
		return false, fmt.Errorf(
			"key existence probe: decoding key names from file-of-record for project %q file %q failed: %w — "+
				"the live secrets file may be corrupt; run `byreis doctor` to diagnose",
			projectID, logicalFile, err)
	}

	for _, n := range names {
		if n == key {
			return true, nil
		}
	}
	return false, nil
}
