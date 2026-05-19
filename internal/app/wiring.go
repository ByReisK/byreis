package app

// BuildReadPathDeps constructs the admin read-path use-cases (Getter,
// Decryptor, Editor) from the injected ports and returns them as narrow
// consumer-defined interfaces.
//
// ISP contract (BINDING): every use-case receives only its NARROW port
// interface, never the concrete adapter (*PortAdapter or any other). The
// composition root passes each collaborator as the minimal interface the use-
// case requires. Passing *PortAdapter directly into a use-case is an ISP
// violation and is rejected at review.
//
// Null guard: if any required base port is nil, BuildReadPathDeps returns a
// descriptive error and nil use-cases. The caller (cmd/byreis/main.go) must
// treat a non-nil error as "adapters not wired yet" and fall back to nil
// use-cases in Deps so the CLI can surface a helpful "not configured" error
// rather than panicking.
//
// Edit-specific ports (encryptor, signer, writer, editor): when any of these
// is nil, the returned EditUseCase is nil without an error. The CLI surfaces
// "edit not available" when it encounters a nil Editor. This is the expected
// interim when admin key / repo config are not yet wired.

import (
	"errors"
	"fmt"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/logging"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// BuildReadPathDeps constructs the three admin read-path use-cases and returns
// them as narrow interfaces. Each use-case is wired against the minimal port
// interface it needs:
//
//   - source    → usecase.FileOfRecordSource  (Get/Decrypt/Edit)
//   - codec     → usecase.ArtifactCodec       (Get/Decrypt/Edit)
//   - dec       → decrypt.Decryptor           (Get/Decrypt/Edit)
//   - idLoader  → identity.Loader             (Get/Decrypt/Edit)
//   - verifier  → verify.VerifierOfRecord     (Get/Decrypt/Edit)
//   - recips    → usecase.RecipientSource     (Get/Decrypt/Edit)
//   - counter   → usecase.CounterStore        (Get/Decrypt/Edit)
//   - gate      → usecase.ModeGate            (Get/Decrypt/Edit)
//
// Edit-only ports (all four must be non-nil for a non-nil EditUseCase):
//
//   - encryptor → encrypt.Encryptor           (Edit only)
//   - signer    → usecase.ManifestSigner      (Edit only)
//   - writer    → usecase.AtomicFileWriter    (Edit only)
//   - editor    → usecase.Editor              (Edit only)
//
// Returns (nil, nil, nil, err) if any required base port is nil.
// Returns a nil EditUseCase without error when any Edit-only port is nil.
func BuildReadPathDeps(
	source usecase.FileOfRecordSource,
	codec usecase.ArtifactCodec,
	dec decrypt.Decryptor,
	idLoader identity.Loader,
	verifier verify.VerifierOfRecord,
	recips usecase.RecipientSource,
	counter usecase.CounterStore,
	gate usecase.ModeGate,
	encryptor encrypt.Encryptor,
	signer usecase.ManifestSigner,
	writer usecase.AtomicFileWriter,
	editor usecase.Editor,
) (usecase.Getter, usecase.DecryptUseCase, usecase.EditUseCase, error) {
	if source == nil || codec == nil || dec == nil || idLoader == nil ||
		verifier == nil || recips == nil || counter == nil || gate == nil {
		return nil, nil, nil, errors.New(
			"app.BuildReadPathDeps: one or more required ports are nil — " +
				"wire FileOfRecordSource, ArtifactCodec, Decryptor, IdentityLoader, " +
				"VerifierOfRecord, RecipientSource, CounterStore and ModeGate")
	}

	sharedGetDeps := usecase.GetDeps{
		Source:     source,
		Codec:      codec,
		Decryptor:  dec,
		IDLoader:   idLoader,
		Verifier:   verifier,
		Recipients: recips,
		Counter:    counter,
		Mode:       gate,
		Audit:      audit.Discard,
		Log:        logging.Discard,
	}

	getter, err := usecase.NewGetter(sharedGetDeps)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("constructing Getter: %w", err)
	}

	decryptorUC, err := usecase.NewDecryptor(usecase.DecryptDeps{
		Source:     source,
		Codec:      codec,
		Decryptor:  dec,
		IDLoader:   idLoader,
		Verifier:   verifier,
		Recipients: recips,
		Counter:    counter,
		Mode:       gate,
		Audit:      audit.Discard,
		Log:        logging.Discard,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("constructing Decryptor: %w", err)
	}

	// Edit requires four additional ports beyond the shared base set. When any
	// is nil (the expected interim when admin key / repo config are not yet
	// wired), return nil EditUseCase without error. The CLI nil-guard in
	// newEditCmd surfaces the "not configured" message to the operator.
	//
	// Invariant: a non-nil error is ONLY produced by an unexpected NewEditor
	// failure given non-nil ports — that signals a programming error at the
	// composition root, not a missing-adapter interim.
	if encryptor == nil || signer == nil || writer == nil || editor == nil {
		return getter, decryptorUC, nil, nil
	}

	editorUC, err := usecase.NewEditor(usecase.EditDeps{
		Source:     source,
		Codec:      codec,
		Decryptor:  dec,
		Encryptor:  encryptor,
		IDLoader:   idLoader,
		Verifier:   verifier,
		Recipients: recips,
		Counter:    counter,
		Signer:     signer,
		Writer:     writer,
		Editor:     editor,
		Mode:       gate,
		Audit:      audit.Discard,
		Log:        logging.Discard,
	})
	if err != nil {
		// NewEditor failed despite all ports being non-nil: this is an unexpected
		// construction error, not the expected nil-port interim. Fail closed loudly.
		return nil, nil, nil, fmt.Errorf("constructing Editor (unexpected — all ports are non-nil): %w", err)
	}

	return getter, decryptorUC, editorUC, nil
}
