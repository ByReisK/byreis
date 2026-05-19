package usecase

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/logging"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// ExitClass is the documented, distinct failure classification the read path
// surfaces to the CLI/CI layer via a typed error. Core stays UI-free: it never
// chooses a process exit code, it only tags the class so the front-end maps it
// to its own documented code and message. The classes are mutually exclusive
// and ordered by where they occur in the fail-closed sequence.
type ExitClass int

const (
	// ExitPermissionDenied means the mode policy denied the command (denied,
	// not attempted-then-failed) — Get/Decrypt/Edit are ADMIN-only.
	ExitPermissionDenied ExitClass = iota + 1
	// ExitNotFound means the configured file-of-record does not exist.
	ExitNotFound
	// ExitDecodeMalformed means the fetched bytes could not be decoded into the
	// expected (signed) domain artifact — typed mismatch, no silent coerce.
	ExitDecodeMalformed
	// ExitVerifyFailure means VerifyOfRecord failed closed (unsigned, untrusted
	// signer, replay, rollback, identity/recipient mismatch, bad signature).
	ExitVerifyFailure
	// ExitDecryptNoIdentity means no admin decrypting identity was available, or
	// the available identity could not decrypt a value.
	ExitDecryptNoIdentity
	// ExitInternal means a re-encrypt / sign / atomic-write step failed on Edit.
	// The live file is left byte-identical (pre-write abort).
	ExitInternal
)

func (c ExitClass) String() string {
	switch c {
	case ExitPermissionDenied:
		return "permission-denied"
	case ExitNotFound:
		return "not-found"
	case ExitDecodeMalformed:
		return "decode-malformed"
	case ExitVerifyFailure:
		return "verify-failure"
	case ExitDecryptNoIdentity:
		return "decrypt-no-identity"
	case ExitInternal:
		return "internal"
	default:
		return "unknown"
	}
}

// ReadPathError is the typed error every read-path failure returns. It carries
// the ExitClass for the CLI/CI layer to map to a documented exit code, wraps
// the underlying sentinel with %w (so errors.Is keeps working), and NEVER
// contains plaintext, ciphertext, or key material in its message — the message
// is a fixed actionable hint, the wrapped error carries only non-secret detail.
type ReadPathError struct {
	Class ExitClass
	// Op is the read-path operation ("get" | "decrypt" | "edit").
	Op  string
	err error
}

func (e *ReadPathError) Error() string {
	return fmt.Sprintf("%s failed (%s): %v", e.Op, e.Class, e.err)
}

func (e *ReadPathError) Unwrap() error { return e.err }

// readErr builds a ReadPathError. The wrapped err must already be free of
// secret material (the crypto packages guarantee this for their sentinels).
func readErr(op string, class ExitClass, err error) error {
	return &ReadPathError{Class: class, Op: op, err: err}
}

// Sentinel errors owned by the read path. Each carries an actionable hint and
// never any secret material.
var (
	// ErrReadDecode: the fetched file-of-record bytes could not be decoded into
	// a signed domain artifact (malformed/duplicate-key/typed mismatch — e.g. an
	// unsigned file presented where a signed file-of-record is required). There
	// is no silent coerce to unsigned on the read path: the live file MUST be a
	// signed, merged file-of-record.
	ErrReadDecode = errors.New(
		"file-of-record could not be decoded as a signed artifact — the live " +
			"secrets file may be malformed or was never merged via `byreis merge`; " +
			"run `byreis doctor` and verify the file against the registry")

	// ErrReadNoIdentity: no admin decrypting identity was available, or it could
	// not decrypt. Fails closed; there is no nil-key downgrade.
	ErrReadNoIdentity = errors.New(
		"no admin identity available to decrypt the file-of-record — " +
			"run `byreis auth login` or check that your admin key is present")

	// ErrFileOfRecordNotFound: the configured file-of-record does not exist in
	// the project repository.
	ErrFileOfRecordNotFound = errors.New(
		"file-of-record not found for the requested project/file — " +
			"check the file name and the registry-configured path")

	// ErrReadRecipientsNotVerified: the admin recipient set / trusted signer set
	// did not come from a signature-verified, fresh registry fetch. The read
	// path verifies of-record against a verified set ONLY; an unverified/stale
	// set is a hard refusal, never a downgrade.
	ErrReadRecipientsNotVerified = errors.New(
		"refusing to read: admin recipient set is not signature-verified " +
			"(stale or unsigned registry) — run `byreis doctor` and retry when " +
			"the registry is reachable and verified")

	// ErrReadKeyNotFound: the requested key is not present in the decrypted
	// file-of-record (Get only). Not secret: key names are not secret.
	ErrReadKeyNotFound = errors.New(
		"the requested key is not present in the file-of-record — " +
			"run `byreis decrypt` to list the available keys")

	// ErrReadReEncrypt: Edit could not produce a fresh whole-file re-encrypt or
	// re-sign the result. Fail-closed; the live file is left byte-identical.
	ErrReadReEncrypt = errors.New(
		"refusing to save: re-encrypting/re-signing the edited file to the " +
			"current verified admin set failed — the live file was left unchanged; " +
			"resolve the registry/recipient error and retry")
)

// readPathDeps is the shared read-side collaborator set. Get and Decrypt use
// exactly these; Edit extends it with the write/encrypt/sign collaborators.
type readPathDeps struct {
	source     FileOfRecordSource
	codec      ArtifactCodec
	decryptor  decrypt.Decryptor
	idLoader   identity.Loader
	verifier   verify.VerifierOfRecord
	recipients RecipientSource
	counter    CounterStore
	gate       ModeGate
	audit      audit.Logger
	log        logging.Logger
}

// loadVerified runs the strict, fail-closed prefix shared by all three
// read-path use-cases:
//
//	(0) ctx liveness
//	(1) mode gate (ADMIN-only) — BEFORE any fetch/decode/identity/decrypt
//	(2) fetch the LIVE signed file-of-record bytes
//	(3) decode as Signed (typed; an unsigned/malformed file is a hard refusal,
//	    no silent coerce, no decrypt attempted)
//	(4) resolve the signature-verified recipient/signer set + counter authority
//	(5) VerifyOfRecord FIRST (fail-closed; no nil-key downgrade)
//
// It returns the verified signed artifact and the recomputed of-record content
// SHA (verify.ContentSHA over the recovered canonical manifest — never the wire
// bytes). Decrypt/identity-load are the CALLER's next step and are deliberately
// NOT reached here, so the call-graph spy can prove verify-first.
func (d readPathDeps) loadVerified(
	ctx context.Context, op string, cmd mode.Command, projectID, fileName string,
) (artifact.Signed, string, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Signed{}, "", readErr(op, ExitInternal,
			fmt.Errorf("%s cancelled: %w", op, err))
	}

	// (1) Mode gate FIRST. Denied-by-policy, not attempted-then-failed: no
	// fetch, decode, identity-load, or decrypt happens on denial.
	if err := d.gate.Allow(cmd); err != nil {
		return artifact.Signed{}, "", readErr(op, ExitPermissionDenied,
			fmt.Errorf("%s not permitted: %w", op, err))
	}

	// (2) Fetch the LIVE committed file-of-record bytes (never a PR branch).
	for_, err := d.source.FileOfRecord(ctx, projectID, fileName)
	if err != nil {
		if errors.Is(err, ErrFileOfRecordNotFound) {
			return artifact.Signed{}, "", readErr(op, ExitNotFound, err)
		}
		return artifact.Signed{}, "", readErr(op, ExitNotFound,
			fmt.Errorf("%w: %v", ErrFileOfRecordNotFound, err))
	}

	// (3) Decode as a SIGNED file-of-record. The read path requires a signed,
	// merged file: an unsigned or malformed file is a typed hard refusal with
	// NO silent coerce and NO partial domain value — and crucially no decrypt or
	// identity-load is attempted.
	signed, err := d.codec.DecodeSigned(for_.Bytes)
	if err != nil {
		return artifact.Signed{}, "", readErr(op, ExitDecodeMalformed,
			fmt.Errorf("%w: %v", ErrReadDecode, err))
	}

	// (4) Resolve the signature-verified recipient + trusted-signer set and the
	// counter authority. Both MUST originate from the SAME signature-verified,
	// fresh registry fetch — never the artifact, the project repo, or a stale
	// cache. An unverified/stale set is a hard refusal.
	rec, err := d.recipients.ExpectedRecipients(ctx, projectID)
	if err != nil {
		return artifact.Signed{}, "", readErr(op, ExitVerifyFailure,
			fmt.Errorf("resolving verified admin recipients failed: %w", err))
	}
	if len(rec.Set) == 0 || !rec.SourceVerified || rec.Stale ||
		len(rec.TrustedSigners) == 0 {
		return artifact.Signed{}, "", readErr(op, ExitVerifyFailure,
			fmt.Errorf("%w", ErrReadRecipientsNotVerified))
	}
	auth, err := d.counter.CounterAuthority(ctx, projectID, fileName)
	if err != nil {
		return artifact.Signed{}, "", readErr(op, ExitVerifyFailure,
			fmt.Errorf("reading counter authority failed: %w", err))
	}

	// (5) VerifyOfRecord FIRST — fail-closed, BEFORE any identity load or
	// decrypt. The signature is mandatory; there is no nil-key downgrade path
	// (VerifierOfRecord requires a non-empty trusted-signer set by construction).
	if err := d.verifier.VerifyOfRecord(ctx, verify.OfRecordInput{
		Artifact:           signed,
		ExpectedProjectID:  projectID,
		ExpectedFileName:   fileName,
		ExpectedRecipients: rec.Set,
		TrustedSigners:     rec.TrustedSigners,
		Counter:            auth,
	}); err != nil {
		// Every VerifyOfRecord/counter failure (unsigned, untrusted signer,
		// replay, rollback, identity/recipient mismatch, bad signature) is the
		// single verify-failure exit class; the wrapped sentinel keeps errors.Is.
		return artifact.Signed{}, "", readErr(op, ExitVerifyFailure,
			fmt.Errorf("of-record verification failed: %w", err))
	}

	// Of-record identity is bound to the recovered canonical manifest, NEVER the
	// codec wire bytes (zero normalization). Empty SHA = unencodable = treat as
	// a verify failure (fail closed) — this is unreachable after a passing
	// VerifyOfRecord but is asserted defensively.
	contentSHA := verify.ContentSHA(signed)
	if contentSHA == "" {
		return artifact.Signed{}, "", readErr(op, ExitVerifyFailure,
			fmt.Errorf("%w: file-of-record is not canonically encodable", verify.ErrManifestMismatch))
	}
	return signed, contentSHA, nil
}

// loadIdentity loads the executing admin's identity AFTER VerifyOfRecord has
// passed. A missing/unparseable identity is the decrypt-no-identity class; nil
// is treated identically (no nil-key downgrade reaches decrypt).
func (d readPathDeps) loadIdentity(ctx context.Context, op string) (identity.Identity, error) {
	id, err := d.idLoader.Load(ctx)
	if err != nil {
		return nil, readErr(op, ExitDecryptNoIdentity,
			fmt.Errorf("%w: %v", ErrReadNoIdentity, err))
	}
	if id == nil {
		return nil, readErr(op, ExitDecryptNoIdentity, fmt.Errorf("%w", ErrReadNoIdentity))
	}
	return id, nil
}

// decryptAll decrypts every value under the executing admin identity. A decrypt
// failure is the decrypt-no-identity class and carries no secret material.
func (d readPathDeps) decryptAll(
	ctx context.Context, op string, signed artifact.Signed, id identity.Identity,
) (map[string]string, error) {
	pt, err := d.decryptor.Decrypt(ctx, signed, id)
	if err != nil {
		return nil, readErr(op, ExitDecryptNoIdentity,
			fmt.Errorf("%w: %v", ErrReadNoIdentity, err))
	}
	return pt, nil
}

func sortedKeyNames(vals map[string]artifact.EncryptedValue) []string {
	out := make([]string, 0, len(vals))
	for k := range vals {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

// GetInput selects one key from a project's live file-of-record.
type GetInput struct {
	ProjectID string
	FileName  string
	Key       string
}

// GetResult is the structured result for one key. The CLI layer owns the
// masking/TTY/--json decision; core returns the value and the of-record pin.
type GetResult struct {
	Key string
	// Value is the decrypted plaintext of Key. The caller MUST zeroize it after
	// rendering. It is never logged or placed in an error.
	Value string
	// ContentSHA is the of-record content SHA over the recovered canonical
	// manifest (verify.ContentSHA), NOT the codec wire bytes.
	ContentSHA string
	// KeyNames is the sorted set of key names present (not secret).
	KeyNames []string
}

// GetDeps bundles the injected ports for the Get use-case.
type GetDeps struct {
	Source     FileOfRecordSource
	Codec      ArtifactCodec
	Decryptor  decrypt.Decryptor
	IDLoader   identity.Loader
	Verifier   verify.VerifierOfRecord
	Recipients RecipientSource
	Counter    CounterStore
	Mode       ModeGate
	Audit      audit.Logger
	Log        logging.Logger
}

// Getter is the consumer-defined interface for the admin Get use-case.
type Getter interface {
	// Get fetches the live file-of-record, VerifyOfRecord-FIRST, then returns
	// the requested key's decrypted plaintext under the executing admin
	// identity. ADMIN-only: denied by the mode gate in CONTRIBUTOR mode before
	// any fetch/decode/identity/decrypt.
	Get(ctx context.Context, in GetInput) (GetResult, error)
}

type getUseCase struct{ d readPathDeps }

// NewGetter returns a Getter. All collaborators are injected; nil optional
// sinks fall back to the no-op discard so core never panics on a missing sink.
func NewGetter(deps GetDeps) (Getter, error) {
	if deps.Source == nil || deps.Codec == nil || deps.Decryptor == nil ||
		deps.IDLoader == nil || deps.Verifier == nil || deps.Recipients == nil ||
		deps.Counter == nil || deps.Mode == nil {
		return nil, errors.New(
			"usecase.NewGetter: a required port is nil — wire Source, Codec, " +
				"Decryptor, IDLoader, Verifier, RecipientSource, CounterStore and Mode")
	}
	if deps.Audit == nil {
		deps.Audit = audit.Discard
	}
	if deps.Log == nil {
		deps.Log = logging.Discard
	}
	return &getUseCase{d: readPathDeps{
		source: deps.Source, codec: deps.Codec, decryptor: deps.Decryptor,
		idLoader: deps.IDLoader, verifier: deps.Verifier,
		recipients: deps.Recipients, counter: deps.Counter, gate: deps.Mode,
		audit: deps.Audit, log: deps.Log,
	}}, nil
}

func (g *getUseCase) Get(ctx context.Context, in GetInput) (GetResult, error) {
	signed, contentSHA, err := g.d.loadVerified(
		ctx, "get", mode.CommandGet, in.ProjectID, in.FileName)
	if err != nil {
		return GetResult{}, err
	}
	keyNames := sortedKeyNames(signed.Values)

	// VerifyOfRecord has passed: ONLY now do we touch identity/decrypt.
	id, err := g.d.loadIdentity(ctx, "get")
	if err != nil {
		return GetResult{}, err
	}
	plaintext, err := g.d.decryptAll(ctx, "get", signed, id)
	if err != nil {
		return GetResult{}, err
	}

	val, ok := plaintext[in.Key]
	if !ok {
		// Key names are not secret; the value never existed in the result.
		return GetResult{}, readErr("get", ExitNotFound,
			fmt.Errorf("%w: key %q", ErrReadKeyNotFound, in.Key))
	}

	g.d.auditOK(ctx, in.ProjectID, in.FileName, in.Key, "get")
	return GetResult{
		Key: in.Key, Value: val, ContentSHA: contentSHA, KeyNames: keyNames,
	}, nil
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

// DecryptInput selects a whole project file-of-record (optionally a key subset)
// for full decryption. This is the use-case the CI-decrypt entrypoint calls;
// it is headless (injected identity/recipients/clock, no TTY assumption).
type DecryptInput struct {
	ProjectID string
	FileName  string
	// Keys, when non-empty, restricts the returned plaintext to this subset
	// (missing keys are an error). Empty means decrypt every value.
	Keys []string
}

// DecryptResult is the full (or subset) decrypted plaintext set.
type DecryptResult struct {
	// Plaintext maps key name → decrypted value. The caller MUST zeroize after
	// use. Never logged or placed in an error.
	Plaintext map[string]string
	// ContentSHA is the of-record content SHA over the recovered canonical
	// manifest.
	ContentSHA string
	KeyNames   []string
}

// DecryptDeps bundles the injected ports for the Decrypt use-case.
type DecryptDeps struct {
	Source     FileOfRecordSource
	Codec      ArtifactCodec
	Decryptor  decrypt.Decryptor
	IDLoader   identity.Loader
	Verifier   verify.VerifierOfRecord
	Recipients RecipientSource
	Counter    CounterStore
	Mode       ModeGate
	Audit      audit.Logger
	Log        logging.Logger
}

// DecryptUseCase is the consumer-defined interface for the admin Decrypt
// use-case. The name is not "Decryptor" to avoid colliding with the crypto
// decrypt.Decryptor port this package consumes.
type DecryptUseCase interface {
	// Decrypt fetches the live file-of-record, VerifyOfRecord-FIRST, then
	// returns every (or the selected) decrypted value under the executing admin
	// identity. ADMIN-only; headless and callable by CI.
	Decrypt(ctx context.Context, in DecryptInput) (DecryptResult, error)
}

type decryptUseCase struct{ d readPathDeps }

// NewDecryptor returns a DecryptUseCase. All collaborators are injected.
func NewDecryptor(deps DecryptDeps) (DecryptUseCase, error) {
	if deps.Source == nil || deps.Codec == nil || deps.Decryptor == nil ||
		deps.IDLoader == nil || deps.Verifier == nil || deps.Recipients == nil ||
		deps.Counter == nil || deps.Mode == nil {
		return nil, errors.New(
			"usecase.NewDecryptor: a required port is nil — wire Source, Codec, " +
				"Decryptor, IDLoader, Verifier, RecipientSource, CounterStore and Mode")
	}
	if deps.Audit == nil {
		deps.Audit = audit.Discard
	}
	if deps.Log == nil {
		deps.Log = logging.Discard
	}
	return &decryptUseCase{d: readPathDeps{
		source: deps.Source, codec: deps.Codec, decryptor: deps.Decryptor,
		idLoader: deps.IDLoader, verifier: deps.Verifier,
		recipients: deps.Recipients, counter: deps.Counter, gate: deps.Mode,
		audit: deps.Audit, log: deps.Log,
	}}, nil
}

func (u *decryptUseCase) Decrypt(ctx context.Context, in DecryptInput) (DecryptResult, error) {
	signed, contentSHA, err := u.d.loadVerified(
		ctx, "decrypt", mode.CommandDecrypt, in.ProjectID, in.FileName)
	if err != nil {
		return DecryptResult{}, err
	}
	keyNames := sortedKeyNames(signed.Values)

	id, err := u.d.loadIdentity(ctx, "decrypt")
	if err != nil {
		return DecryptResult{}, err
	}
	plaintext, err := u.d.decryptAll(ctx, "decrypt", signed, id)
	if err != nil {
		return DecryptResult{}, err
	}

	if len(in.Keys) > 0 {
		subset := make(map[string]string, len(in.Keys))
		for _, k := range in.Keys {
			v, ok := plaintext[k]
			if !ok {
				return DecryptResult{}, readErr("decrypt", ExitNotFound,
					fmt.Errorf("%w: key %q", ErrReadKeyNotFound, k))
			}
			subset[k] = v
		}
		plaintext = subset
	}

	u.d.auditOK(ctx, in.ProjectID, in.FileName, "", "decrypt")
	return DecryptResult{
		Plaintext: plaintext, ContentSHA: contentSHA, KeyNames: keyNames,
	}, nil
}

// auditOK appends a success audit event (no secret material — key names only).
// An audit failure is logged but does not fail a completed read.
func (d readPathDeps) auditOK(ctx context.Context, projectID, fileName, key, op string) {
	if aErr := d.audit.Append(ctx, audit.Event{
		Kind:      audit.EventKindReview, // closest existing read-side kind
		ProjectID: projectID,
		FileName:  fileName,
		KeyName:   key,
		Outcome:   "ok",
		Details:   map[string]string{"op": op},
	}); aErr != nil {
		d.log.Log(ctx, logging.LevelWarn,
			"read completed but audit append failed",
			"project", projectID, "op", op, "error", aErr.Error())
	}
}

// Compile-time assertions.
var (
	_ Getter         = (*getUseCase)(nil)
	_ DecryptUseCase = (*decryptUseCase)(nil)
)
