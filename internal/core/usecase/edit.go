package usecase

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/logging"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// editCancelled returns a classified pre-write abort error iff ctx is done. It
// keeps the cancellation check out of the main function's err scope so the live
// file is provably never mutated on a cancelled context (the live mutation is
// the single atomic write at the very end).
func editCancelled(ctx context.Context, when string) error {
	if err := ctx.Err(); err != nil {
		return readErr("edit", ExitInternal,
			fmt.Errorf("edit cancelled %s; the live file was left unchanged: %w",
				when, err))
	}
	return nil
}

// EditInput selects a project file-of-record to open in $EDITOR and re-save.
type EditInput struct {
	ProjectID string
	FileName  string
}

// EditResult is returned by a successful Edit.
type EditResult struct {
	// ContentSHA is the of-record content SHA of the freshly re-signed file
	// (verify.ContentSHA over the recovered canonical manifest of the new
	// artifact), NOT the codec wire bytes.
	ContentSHA string
	// ReEncrypted is always true on success: Edit ALWAYS re-encrypts the whole
	// file fresh from the edited plaintext to the current verified recipient
	// set (zero ciphertext carry-forward), then re-signs.
	ReEncrypted bool
	// KeyNames is the sorted set of key names in the saved file (not secret).
	KeyNames []string
}

// EditDeps bundles the injected ports for the Edit use-case.
type EditDeps struct {
	Source     FileOfRecordSource
	Codec      ArtifactCodec
	Decryptor  decrypt.Decryptor
	Encryptor  encrypt.Encryptor
	IDLoader   IDLoader
	Verifier   verify.VerifierOfRecord
	Recipients RecipientSource
	Counter    CounterStore
	Signer     ManifestSigner
	Writer     AtomicFileWriter
	Editor     Editor
	Mode       ModeGate
	Audit      audit.Logger
	Log        logging.Logger
}

// EditUseCase is the consumer-defined interface for the admin Edit use-case.
type EditUseCase interface {
	// Edit fetches the live file-of-record, VerifyOfRecord-FIRST, decrypts under
	// the executing admin identity, presents the plaintext to $EDITOR, then
	// re-encrypts the WHOLE file fresh to the current verified recipient set
	// (zero ciphertext carry-forward), re-signs the fresh artifact, and writes
	// it via the no-clobber atomic write contract. Any failure before the atomic
	// rename leaves the live file byte-identical. ADMIN-only.
	Edit(ctx context.Context, in EditInput) (EditResult, error)
}

type editUseCase struct {
	d   readPathDeps
	enc encrypt.Encryptor
	sgn ManifestSigner
	w   AtomicFileWriter
	ed  Editor
}

// NewEditor returns an EditUseCase. All collaborators are injected; nil
// optional sinks fall back to the no-op discard.
func NewEditor(deps EditDeps) (EditUseCase, error) {
	if deps.Source == nil || deps.Codec == nil || deps.Decryptor == nil ||
		deps.Encryptor == nil || deps.IDLoader == nil || deps.Verifier == nil ||
		deps.Recipients == nil || deps.Counter == nil || deps.Signer == nil ||
		deps.Writer == nil || deps.Editor == nil || deps.Mode == nil {
		return nil, errors.New(
			"usecase.NewEditor: a required port is nil — wire Source, Codec, " +
				"Decryptor, Encryptor, IDLoader, Verifier, RecipientSource, " +
				"CounterStore, ManifestSigner, AtomicFileWriter, Editor and Mode")
	}
	if deps.Audit == nil {
		deps.Audit = audit.Discard
	}
	if deps.Log == nil {
		deps.Log = logging.Discard
	}
	return &editUseCase{
		d: readPathDeps{
			source: deps.Source, codec: deps.Codec, decryptor: deps.Decryptor,
			idLoader: deps.IDLoader, verifier: deps.Verifier,
			recipients: deps.Recipients, counter: deps.Counter, gate: deps.Mode,
			audit: deps.Audit, log: deps.Log,
		},
		enc: deps.Encryptor, sgn: deps.Signer, w: deps.Writer, ed: deps.Editor,
	}, nil
}

// Edit runs the strictly-ordered, fail-closed edit sequence. No step may be
// reordered and every pre-write failure leaves the live file byte-identical:
//
//  1. mode gate → fetch → decode(Signed) → resolve verified set → VerifyOfRecord
//     (the shared verify-first prefix; denied-not-attempted in CONTRIBUTOR)
//  2. load the executing admin identity (only after verify passes)
//  3. decrypt every value under that identity
//  4. present the plaintext to $EDITOR; accept the edited plaintext
//  5. resolve the CURRENT verified recipient set and re-encrypt the WHOLE file
//     FRESH from the edited plaintext (zero prior ciphertext carried forward)
//  6. re-sign the freshly produced artifact (never a blind blob)
//  7. encode + atomic no-clobber write (the ONLY live-path mutation); any
//     failure up to and including the rename leaves the live file untouched
func (e *editUseCase) Edit(ctx context.Context, in EditInput) (EditResult, error) {
	// (1) Shared verify-first prefix. Returns a typed ReadPathError already
	// classified; on any failure here the live file is untouched (no write
	// collaborator has been invoked).
	signed, _, err := e.d.loadVerified(
		ctx, "edit", mode.CommandEdit, in.ProjectID, in.FileName)
	if err != nil {
		return EditResult{}, err
	}

	// (2) Identity, (3) decrypt — only after VerifyOfRecord passed.
	id, err := e.d.loadIdentity(ctx, "edit")
	if err != nil {
		return EditResult{}, err
	}
	plaintext, err := e.d.decryptAll(ctx, "edit", signed, id)
	if err != nil {
		return EditResult{}, err
	}

	// (4) Present to $EDITOR. An editor failure / abort is a pre-write abort:
	// the live file is byte-identical (no write collaborator invoked).
	edited, err := e.ed.Edit(ctx, EditSession{
		ProjectID: in.ProjectID, FileName: in.FileName, Plaintext: plaintext,
	})
	if err != nil {
		return EditResult{}, readErr("edit", ExitInternal,
			fmt.Errorf("editor session failed; the live file was left unchanged: %w", err))
	}
	if len(edited) == 0 {
		return EditResult{}, readErr("edit", ExitInternal,
			fmt.Errorf("%w: the editor returned an empty value set; "+
				"the live file was left unchanged", ErrReadReEncrypt))
	}

	if cErr := editCancelled(ctx, "before re-encrypt"); cErr != nil {
		return EditResult{}, cErr
	}

	// (5) Re-resolve the CURRENT verified recipient set and re-encrypt the WHOLE
	// file FRESH from the edited plaintext. This mirrors the merge re-encrypt
	// contract: a fresh whole-file age.Encrypt of every value, zero prior
	// ciphertext spliced, re-wrapped, or carried forward. An unverified/stale
	// set is a hard pre-write refusal.
	rec, err := e.d.recipients.ExpectedRecipients(ctx, in.ProjectID)
	if err != nil {
		return EditResult{}, readErr("edit", ExitVerifyFailure,
			fmt.Errorf("resolving verified admin recipients failed; the live "+
				"file was left unchanged: %w", err))
	}
	if len(rec.Set) == 0 || !rec.SourceVerified || rec.Stale ||
		len(rec.TrustedSigners) == 0 {
		return EditResult{}, readErr("edit", ExitVerifyFailure,
			fmt.Errorf("%w", ErrReadRecipientsNotVerified))
	}
	configuredPath, ok := rec.ConfiguredFiles[signed.Byreis.File]
	if !ok || configuredPath == "" {
		return EditResult{}, readErr("edit", ExitVerifyFailure,
			fmt.Errorf("%w: the signed logical file %q has no registry-"+
				"configured path in the verified project config; the live file "+
				"was left unchanged", ErrReadRecipientsNotVerified, signed.Byreis.File))
	}

	fresh, err := e.enc.Encrypt(ctx, encrypt.EncryptInput{
		ProjectID:       signed.Byreis.ProjectID,
		LogicalFileName: signed.Byreis.File,
		Counter:         signed.Byreis.Counter,
		Recipients:      rec.Set,
		Values:          edited,
	})
	if err != nil {
		return EditResult{}, readErr("edit", ExitInternal,
			fmt.Errorf("%w: %v (the live file was left unchanged)",
				ErrReadReEncrypt, err))
	}
	body := artifact.Signed{Values: fresh.Values, Byreis: fresh.Byreis}

	// (6) Re-sign the FRESHLY produced artifact's canonical manifest. The signer
	// signs only what we recompute from the fresh body — never the prior
	// signature, never a blind blob.
	man := manifestFromSigned(body)
	signerID, sig, err := e.sgn.Sign(ctx, man)
	if err != nil {
		return EditResult{}, readErr("edit", ExitInternal,
			fmt.Errorf("%w: re-signing the edited file-of-record failed: %v "+
				"(the live file was left unchanged)", ErrReadReEncrypt, err))
	}
	body.ManifestSig = artifact.ManifestSig{
		Signer: signerID, Sig: hex.EncodeToString(sig),
	}

	contentSHA := verify.ContentSHA(body)
	if contentSHA == "" {
		return EditResult{}, readErr("edit", ExitInternal,
			fmt.Errorf("%w: the freshly signed file-of-record is not "+
				"canonically encodable (the live file was left unchanged)",
				ErrReadReEncrypt))
	}

	signedBytes, err := e.d.codec.EncodeSigned(body)
	if err != nil {
		return EditResult{}, readErr("edit", ExitInternal,
			fmt.Errorf("%w: serialising the freshly signed file-of-record "+
				"failed: %v (the live file was left unchanged)",
				ErrReadReEncrypt, err))
	}

	if cErr := editCancelled(ctx, "before the atomic write"); cErr != nil {
		return EditResult{}, cErr
	}

	// (7) The ONLY live-path mutation: a single no-clobber atomic write of the
	// fully-formed, valid, freshly re-signed artifact. The adapter creates the
	// temp 0600 O_EXCL in the live file's directory, fsyncs, and atomically
	// renames; it does not follow a symlink and does not widen pre-existing
	// mode/owner. Any failure (including a failed rename) leaves the live file
	// byte-identical and removes the temp residue.
	if err := e.w.WriteFileOfRecord(ctx, AtomicWriteInput{
		ProjectID:   in.ProjectID,
		FileName:    in.FileName,
		LiveRelPath: configuredPath,
		SignedBytes: signedBytes,
	}); err != nil {
		return EditResult{}, readErr("edit", ExitInternal,
			fmt.Errorf("%w: the atomic write failed; the live file was left "+
				"byte-identical: %v", ErrReadReEncrypt, err))
	}

	e.d.auditOK(ctx, in.ProjectID, in.FileName, "", "edit")
	return EditResult{
		ContentSHA:  contentSHA,
		ReEncrypted: true,
		KeyNames:    sortedKeyNames(body.Values),
	}, nil
}

// Compile-time assertion.
var _ EditUseCase = (*editUseCase)(nil)
