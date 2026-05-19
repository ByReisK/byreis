package usecase

import "context"

// FileOfRecord is the live, committed signed file-of-record as fetched from the
// project repository. Bytes is the EXACT untransformed on-disk byte sequence
// (zero normalization); ContentSHA is the adapter-computed raw-buffer move-
// detection pin. The of-record identity the read path binds to is NOT this
// value: it is recomputed by the use-case as verify.ContentSHA over the
// canonical manifest recovered from the decoded artifact, never the wire bytes.
type FileOfRecord struct {
	// Bytes is the exact, untransformed on-disk file-of-record byte sequence.
	Bytes []byte
	// ContentSHA is the adapter's raw-buffer hash, used only for repo-side
	// move detection. It is never the of-record / counter-pin identity.
	ContentSHA string
}

// FileOfRecordSource is the consumer-defined port that yields the LIVE
// committed signed file-of-record for a (projectID, fileName) pair. The read
// path (Get/Decrypt/Edit) reads the live file, never a PR branch. The concrete
// implementation wraps the git adapter at the CLI/CI layer; it MUST return the
// exact committed bytes with zero normalization and MUST surface
// ErrFileOfRecordNotFound when the configured file does not exist.
type FileOfRecordSource interface {
	FileOfRecord(ctx context.Context, projectID, fileName string) (FileOfRecord, error)
}

// EditSession is the data the Editor port presents to the operator. Plaintext
// is the decrypted value set the operator may edit; it MUST be zeroized by the
// adapter after the editor exits. No ciphertext or key material is ever placed
// here.
type EditSession struct {
	ProjectID string
	FileName  string
	// Plaintext maps key name → decrypted plaintext the operator edits.
	Plaintext map[string]string
}

// Editor is the consumer-defined port for the interactive $EDITOR round trip.
// The concrete implementation lives at the CLI layer (TTY/$EDITOR handling);
// core stays UI-free. It returns the edited plaintext map. A non-zero editor
// exit, an aborted edit, or an unreadable buffer is an error and the use-case
// aborts WITHOUT mutating the live file.
type Editor interface {
	Edit(ctx context.Context, in EditSession) (map[string]string, error)
}

// AtomicWriteInput carries the no-clobber atomic write contract for Edit. The
// adapter MUST: create the temp file 0600 with O_EXCL in the SAME directory as
// the live file, write SignedBytes, fsync, and atomically rename over the live
// path as the ONLY live-path mutation; it MUST NOT follow a symlink at the live
// path and MUST NOT widen a pre-existing mode/owner. Any failure leaves the
// live file byte-identical and removes the temp residue.
type AtomicWriteInput struct {
	// ProjectID and FileName identify the slot (audit/diagnostic only).
	ProjectID string
	FileName  string
	// LiveRelPath is the registry-configured repo-relative path of the live
	// file-of-record (resolved from the SAME signature-verified registry fetch
	// as the recipient set, never the artifact's self-declared metadata).
	LiveRelPath string
	// SignedBytes is the fully-formed, re-signed file-of-record to commit. The
	// use-case produces this ONLY after a valid signed artifact exists; the
	// adapter never re-encodes or normalizes it.
	SignedBytes []byte
}

// AtomicFileWriter is the consumer-defined port for the no-clobber atomic
// write. It is injected so core stays filesystem-free in unit tests; the real
// fs adapter (O_EXCL/fsync/rename/no-symlink-follow/perms-preserve) is the
// backend's responsibility. The use-case calls it exactly once, only after a
// fully-formed valid signed artifact exists, as the only live-path mutation.
type AtomicFileWriter interface {
	WriteFileOfRecord(ctx context.Context, in AtomicWriteInput) error
}
