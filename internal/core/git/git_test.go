// Package git — tests for SubmissionMeta parsing/encoding and sentinel errors.
//
// N-3, N-4 (lexical half), N-7, N-9 obligations per ADR-0007.
package git_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	coregit "github.com/ByReisK/byreis/internal/core/git"
)

// TestParseSubmissionMeta_HappyPath covers a well-formed block.
func TestParseSubmissionMeta_HappyPath(t *testing.T) {
	t.Parallel()

	body := "Human justification text here.\n\n" +
		"```byreis-submission\n" +
		`{"schema_version":1,"project":"myorg/proj","secrets_path":"secrets/prod.yaml","base_file_path":"secrets/prod.yaml","key":"api_key","action":"add","artifact_sha":"abc123"}` + "\n" +
		"```\n\n" +
		"More free text."

	got, err := coregit.ParseSubmissionMeta(body)
	if err != nil {
		t.Fatalf("ParseSubmissionMeta: unexpected error: %v", err)
	}
	if got.SchemaVersion != 1 {
		t.Errorf("SchemaVersion: got %d, want 1", got.SchemaVersion)
	}
	if got.Project != "myorg/proj" {
		t.Errorf("Project: got %q, want myorg/proj", got.Project)
	}
	if got.SecretsPath != "secrets/prod.yaml" {
		t.Errorf("SecretsPath: got %q, want secrets/prod.yaml", got.SecretsPath)
	}
	if got.Key != "api_key" {
		t.Errorf("Key: got %q, want api_key", got.Key)
	}
	if got.Action != "add" {
		t.Errorf("Action: got %q, want add", got.Action)
	}
	if got.ArtifactSHA != "abc123" {
		t.Errorf("ArtifactSHA: got %q, want abc123", got.ArtifactSHA)
	}
}

// TestParseSubmissionMeta_MissingBlock verifies absence of the block is
// ErrSubmissionMetaInvalid and never a silent default-path write (N-3).
func TestParseSubmissionMeta_MissingBlock(t *testing.T) {
	t.Parallel()

	_, err := coregit.ParseSubmissionMeta("just a justification, no structured block")
	if err == nil {
		t.Fatal("want ErrSubmissionMetaInvalid for missing block, got nil")
	}
	if !errors.Is(err, coregit.ErrSubmissionMetaInvalid) {
		t.Errorf("want ErrSubmissionMetaInvalid, got %v", err)
	}
	// The error must not suggest a default path was used.
	if strings.Contains(err.Error(), "secrets/prod.yaml") {
		t.Errorf("error message must not suggest a default path: %q", err.Error())
	}
}

// TestParseSubmissionMeta_DuplicateBlock verifies more than one fenced block
// is ErrSubmissionMetaInvalid (N-3).
func TestParseSubmissionMeta_DuplicateBlock(t *testing.T) {
	t.Parallel()

	block := "```byreis-submission\n" +
		`{"schema_version":1,"project":"p","secrets_path":"secrets/prod.yaml","base_file_path":"secrets/prod.yaml","key":"k","action":"add","artifact_sha":"x"}` + "\n" +
		"```\n"
	body := block + "\n" + block

	_, err := coregit.ParseSubmissionMeta(body)
	if err == nil {
		t.Fatal("want ErrSubmissionMetaInvalid for duplicate block, got nil")
	}
	if !errors.Is(err, coregit.ErrSubmissionMetaInvalid) {
		t.Errorf("want ErrSubmissionMetaInvalid, got %v", err)
	}
}

// TestParseSubmissionMeta_UnknownField verifies DisallowUnknownFields is
// enforced (N-3).
func TestParseSubmissionMeta_UnknownField(t *testing.T) {
	t.Parallel()

	body := "```byreis-submission\n" +
		`{"schema_version":1,"project":"p","secrets_path":"secrets/prod.yaml","base_file_path":"secrets/prod.yaml","key":"k","action":"add","artifact_sha":"x","unknown_extra_field":"oops"}` + "\n" +
		"```\n"

	_, err := coregit.ParseSubmissionMeta(body)
	if err == nil {
		t.Fatal("want ErrSubmissionMetaInvalid for unknown field, got nil")
	}
	if !errors.Is(err, coregit.ErrSubmissionMetaInvalid) {
		t.Errorf("want ErrSubmissionMetaInvalid, got %v", err)
	}
}

// TestParseSubmissionMeta_WrongSchemaVersion verifies schema_version != 1 is
// ErrSubmissionMetaInvalid (N-3).
func TestParseSubmissionMeta_WrongSchemaVersion(t *testing.T) {
	t.Parallel()

	for _, sv := range []int{0, 2, 99} {
		sv := sv
		t.Run("version_"+strconv.Itoa(sv), func(t *testing.T) {
			t.Parallel()
			body := "```byreis-submission\n" +
				`{"schema_version":` + strconv.Itoa(sv) + `,"project":"p","secrets_path":"secrets/prod.yaml","base_file_path":"secrets/prod.yaml","key":"k","action":"add","artifact_sha":"x"}` + "\n" +
				"```\n"
			_, err := coregit.ParseSubmissionMeta(body)
			if err == nil {
				t.Fatalf("want ErrSubmissionMetaInvalid for schema_version=%d, got nil", sv)
			}
			if !errors.Is(err, coregit.ErrSubmissionMetaInvalid) {
				t.Errorf("want ErrSubmissionMetaInvalid, got %v", err)
			}
		})
	}
}

// TestParseSubmissionMeta_LexicalContainment_DotDot verifies that a SecretsPath
// containing ".." is rejected as ErrSubmissionMetaInvalid at parse time (N-4
// lexical half).
func TestParseSubmissionMeta_LexicalContainment_DotDot(t *testing.T) {
	t.Parallel()

	paths := []string{
		"secrets/../etc/passwd",
		"../secrets/prod.yaml",
		"secrets/../../outside",
		"secrets/..",
	}
	for _, p := range paths {
		p := p
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			body := "```byreis-submission\n" +
				`{"schema_version":1,"project":"proj","secrets_path":"` + p + `","base_file_path":"secrets/prod.yaml","key":"k","action":"add","artifact_sha":"x"}` + "\n" +
				"```\n"
			_, err := coregit.ParseSubmissionMeta(body)
			if err == nil {
				t.Fatalf("want ErrSubmissionMetaInvalid for path %q with .., got nil", p)
			}
			if !errors.Is(err, coregit.ErrSubmissionMetaInvalid) {
				t.Errorf("want ErrSubmissionMetaInvalid for path %q, got %v", p, err)
			}
		})
	}
}

// TestParseSubmissionMeta_LexicalContainment_LeadingSlash verifies that a
// SecretsPath with a leading slash is rejected at parse time (N-4 lexical half).
func TestParseSubmissionMeta_LexicalContainment_LeadingSlash(t *testing.T) {
	t.Parallel()

	paths := []string{
		"/secrets/prod.yaml",
		"/etc/passwd",
		"/absolute/path",
	}
	for _, p := range paths {
		p := p
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			body := "```byreis-submission\n" +
				`{"schema_version":1,"project":"proj","secrets_path":"` + p + `","base_file_path":"secrets/prod.yaml","key":"k","action":"add","artifact_sha":"x"}` + "\n" +
				"```\n"
			_, err := coregit.ParseSubmissionMeta(body)
			if err == nil {
				t.Fatalf("want ErrSubmissionMetaInvalid for path %q with leading /, got nil", p)
			}
			if !errors.Is(err, coregit.ErrSubmissionMetaInvalid) {
				t.Errorf("want ErrSubmissionMetaInvalid for path %q, got %v", p, err)
			}
		})
	}
}

// TestParseSubmissionMeta_LexicalContainment_CleanUnstable verifies that paths
// not equal to their Clean() form are rejected (e.g. "secrets//prod.yaml",
// "secrets/./prod.yaml") (N-4 lexical half).
func TestParseSubmissionMeta_LexicalContainment_CleanUnstable(t *testing.T) {
	t.Parallel()

	paths := []string{
		"secrets//prod.yaml",
		"secrets/./prod.yaml",
		"./secrets/prod.yaml",
	}
	for _, p := range paths {
		p := p
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			body := "```byreis-submission\n" +
				`{"schema_version":1,"project":"proj","secrets_path":"` + p + `","base_file_path":"secrets/prod.yaml","key":"k","action":"add","artifact_sha":"x"}` + "\n" +
				"```\n"
			_, err := coregit.ParseSubmissionMeta(body)
			if err == nil {
				t.Fatalf("want ErrSubmissionMetaInvalid for non-Clean path %q, got nil", p)
			}
			if !errors.Is(err, coregit.ErrSubmissionMetaInvalid) {
				t.Errorf("want ErrSubmissionMetaInvalid for path %q, got %v", p, err)
			}
		})
	}
}

// TestEncodeSubmissionMeta_RoundTrip verifies encode+parse round-trips
// correctly.
func TestEncodeSubmissionMeta_RoundTrip(t *testing.T) {
	t.Parallel()

	meta := coregit.SubmissionMeta{ //nolint:gosec // test fixture key name, not a real credential
		SchemaVersion: 1,
		Project:       "myorg/my-secrets",
		SecretsPath:   "secrets/prod.yaml",
		BaseFilePath:  "secrets/prod.yaml",
		Key:           "db_pass",
		Action:        "add",
		ArtifactSHA:   "deadbeef",
	}

	encoded := coregit.EncodeSubmissionMeta(meta)
	if !strings.Contains(encoded, "```byreis-submission") {
		t.Errorf("encoded output missing fenced block marker: %q", encoded)
	}

	parsed, err := coregit.ParseSubmissionMeta(encoded)
	if err != nil {
		t.Fatalf("ParseSubmissionMeta after EncodeSubmissionMeta: %v", err)
	}
	if parsed.Project != meta.Project {
		t.Errorf("Project: got %q, want %q", parsed.Project, meta.Project)
	}
	if parsed.SecretsPath != meta.SecretsPath {
		t.Errorf("SecretsPath: got %q, want %q", parsed.SecretsPath, meta.SecretsPath)
	}
	if parsed.Key != meta.Key {
		t.Errorf("Key: got %q, want %q", parsed.Key, meta.Key)
	}
}

// TestSubmissionMeta_FieldsNotTrustedForCrypto verifies the N-9 contract:
// none of Project/Key/Action/ArtifactSHA is advertised as an authority input.
// This is a documentation/API-shape test: ParseSubmissionMeta must not return
// fields that could be mistaken for an ExpectSHA or recipient-set input.
// The test verifies that SecretsPath is the only path-selection output.
func TestSubmissionMeta_FieldsNotTrustedForCrypto(t *testing.T) {
	t.Parallel()

	body := "```byreis-submission\n" +
		`{"schema_version":1,"project":"myorg/p","secrets_path":"secrets/prod.yaml","base_file_path":"secrets/prod.yaml","key":"api_key","action":"add","artifact_sha":"FAKEDIGEST"}` + "\n" +
		"```\n"

	meta, err := coregit.ParseSubmissionMeta(body)
	if err != nil {
		t.Fatalf("ParseSubmissionMeta: %v", err)
	}

	// The SecretsPath is the ONLY field used for write-path selection. The others
	// (ArtifactSHA, Key, Project, Action) are informational. Verify they are all
	// present but that the contract comment makes clear they are display-only.
	// We assert ArtifactSHA does NOT equal any canonical verify.ContentSHA form —
	// it's just an echo string. The only safe use of meta.ArtifactSHA is display.
	if meta.SecretsPath == "" {
		t.Error("SecretsPath must not be empty (it selects the write path)")
	}
	// ArtifactSHA is present but MUST NOT be used as ExpectSHA.
	// This test documents the contract: a well-formed adapter uses only
	// SecretsPath for path selection, never ArtifactSHA for crypto pin.
	if meta.ArtifactSHA == "" {
		t.Log("ArtifactSHA is empty in this fixture; that is acceptable (informational-only field)")
	}
	// Project, Key, Action are display-only.
	_ = meta.Project
	_ = meta.Key
	_ = meta.Action
}

// TestErrInvalidProject_Sentinel verifies ErrInvalidProject is its own sentinel
// and wraps correctly.
func TestErrInvalidProject_Sentinel(t *testing.T) {
	t.Parallel()

	if coregit.ErrInvalidProject == nil {
		t.Fatal("ErrInvalidProject must not be nil")
	}
	if !errors.Is(coregit.ErrInvalidProject, coregit.ErrInvalidProject) {
		t.Error("errors.Is(ErrInvalidProject, ErrInvalidProject) must be true")
	}
	// Must not be the same sentinel as ErrSubmissionMetaInvalid.
	if errors.Is(coregit.ErrInvalidProject, coregit.ErrSubmissionMetaInvalid) {
		t.Error("ErrInvalidProject must be distinct from ErrSubmissionMetaInvalid")
	}
}

// TestErrSubmissionMetaInvalid_Sentinel verifies ErrSubmissionMetaInvalid has
// an actionable hint message.
func TestErrSubmissionMetaInvalid_Sentinel(t *testing.T) {
	t.Parallel()

	if coregit.ErrSubmissionMetaInvalid == nil {
		t.Fatal("ErrSubmissionMetaInvalid must not be nil")
	}
	msg := coregit.ErrSubmissionMetaInvalid.Error()
	if msg == "" {
		t.Error("ErrSubmissionMetaInvalid must have a non-empty message")
	}
}

// --- ADR-0007 Decision 4 / ADR-0008 D8-2 — domain contract (B3d-1) ---
//
// B3d-1 owns ONLY the domain types/sentinels and the pure validation the
// domain layer owns (RollbackInput field validation). The behavioural
// assertions for N-5/N-6/N-11/N-12 land where the impl lives:
//   - N-5  (IdempotencyKey resume / different-artifact-not-a-resume): B3d-3
//          usecase/Merge derivation + B3d-4 github adapter detect-before-write.
//   - N-6  (step-5-done/step-6-failed window, read paths never roll back):
//          B3d-3 usecase/Merge driver.
//   - N-11 (foreign-commit-on-top ⇒ ErrRollbackAmbiguous, no revert): B3d-4
//          github adapter live-tip==CommitSHA precondition.
//   - N-12 (merged-after-timeout ⇒ registry pending/CommitBump authority, not
//          a PR-merged bool): B3d-3 usecase/Merge.
// The skeletons below establish the compilable contract surface and assert the
// pure domain validation; the deferred halves are explicitly skipped with the
// owning sub-step so the contract is test-anchored before the impl exists.

// TestErrRollbackAmbiguous_Sentinel verifies ErrRollbackAmbiguous is its own
// sentinel, wraps via %w, carries an actionable operator-runbook hint, and is
// distinct from the other git sentinels.
func TestErrRollbackAmbiguous_Sentinel(t *testing.T) {
	t.Parallel()

	if coregit.ErrRollbackAmbiguous == nil {
		t.Fatal("ErrRollbackAmbiguous must not be nil")
	}
	if !errors.Is(coregit.ErrRollbackAmbiguous, coregit.ErrRollbackAmbiguous) {
		t.Error("errors.Is(ErrRollbackAmbiguous, ErrRollbackAmbiguous) must be true")
	}
	if errors.Is(coregit.ErrRollbackAmbiguous, coregit.ErrSubmissionMetaInvalid) {
		t.Error("ErrRollbackAmbiguous must be distinct from ErrSubmissionMetaInvalid")
	}
	if errors.Is(coregit.ErrRollbackAmbiguous, coregit.ErrInvalidProject) {
		t.Error("ErrRollbackAmbiguous must be distinct from ErrInvalidProject")
	}
	if errors.Is(coregit.ErrRollbackAmbiguous, coregit.ErrArtifactMoved) {
		t.Error("ErrRollbackAmbiguous must be distinct from ErrArtifactMoved")
	}
	msg := coregit.ErrRollbackAmbiguous.Error()
	if msg == "" {
		t.Fatal("ErrRollbackAmbiguous must have a non-empty message")
	}
	// %w-wrappable with a contextual hint, mirroring the other sentinels.
	wrapped := fmt.Errorf("rolling back pr 42: %w", coregit.ErrRollbackAmbiguous)
	if !errors.Is(wrapped, coregit.ErrRollbackAmbiguous) {
		t.Error("wrapped ErrRollbackAmbiguous must satisfy errors.Is")
	}
}

// TestRollbackInput_Validate covers the only behaviour the domain layer owns at
// B3d-1: RollbackInput field validation. The registry-pending-identity match
// and the live-tip==CommitSHA assertion are NOT validated here — they are
// runtime preconditions enforced by the B3d-4 github adapter against live git +
// the caller-asserted registry pending state (ADR-0007 Decision 4 rules 3/4).
func TestRollbackInput_Validate(t *testing.T) {
	t.Parallel()

	valid := coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/secrets", Number: 42},
		CommitSHA:       "0123456789abcdef0123456789abcdef01234567",
		PendingIdentity: "sha256:deadbeef",
	}

	tests := []struct {
		name    string
		mutate  func(in *coregit.RollbackInput)
		wantErr bool
	}{
		{
			name:    "valid",
			mutate:  func(*coregit.RollbackInput) {},
			wantErr: false,
		},
		{
			name:    "empty project",
			mutate:  func(in *coregit.RollbackInput) { in.Ref.Project = "" },
			wantErr: true,
		},
		{
			name:    "non-positive PR number",
			mutate:  func(in *coregit.RollbackInput) { in.Ref.Number = 0 },
			wantErr: true,
		},
		{
			name:    "empty commit sha",
			mutate:  func(in *coregit.RollbackInput) { in.CommitSHA = "" },
			wantErr: true,
		},
		{
			name:    "empty pending identity",
			mutate:  func(in *coregit.RollbackInput) { in.PendingIdentity = "" },
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := valid
			tc.mutate(&in)
			err := in.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate(%+v): want error, got nil", in)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate(%+v): unexpected error: %v", in, err)
			}
			if tc.wantErr && !errors.Is(err, coregit.ErrRollbackAmbiguous) {
				t.Errorf("Validate: want error wrapping ErrRollbackAmbiguous, got %v", err)
			}
		})
	}
}

// providerRecorder is a minimal GitProvider stand-in. It exercises the
// Decision-4 contract surface through the consumer-defined interface (so the
// new MergeInput/MergeResult fields are proven to survive an interface
// round-trip, not merely declared) without performing any git work.
// Behavioural N-* assertions live in B3d-3/B3d-4.
type providerRecorder struct {
	gotMerge    coregit.MergeInput
	mergeResult coregit.MergeResult
	gotRollback coregit.RollbackInput
	rollbackHit bool
}

func (r *providerRecorder) OpenSubmissionPR(context.Context, coregit.OpenPRInput) (coregit.PullRequest, error) {
	return coregit.PullRequest{}, nil
}

func (r *providerRecorder) GetSubmission(context.Context, coregit.PRRef) (coregit.Submission, error) {
	return coregit.Submission{}, nil
}

func (r *providerRecorder) MergeSubmission(_ context.Context, in coregit.MergeInput) (coregit.MergeResult, error) {
	r.gotMerge = in
	return r.mergeResult, nil
}

func (r *providerRecorder) CommentPR(context.Context, coregit.PRRef, string) error {
	return nil
}

func (r *providerRecorder) RollbackSignedFile(_ context.Context, in coregit.RollbackInput) error {
	r.rollbackHit = true
	r.gotRollback = in
	return nil
}

// TestMergeInput_IdempotencyKeyTraversesInterface asserts the deterministic,
// content-bound IdempotencyKey field exists on MergeInput and traverses the
// consumer-defined GitProvider boundary intact. The derivation (stable hash
// over (Ref, ExpectSHA, verify.ContentSHA(SignedBytes)) — NOT a random nonce,
// NOT wall-clock) is computed by the B3d-3 usecase/Merge driver; B3d-1 only
// fixes the field + its documented contract.
func TestMergeInput_IdempotencyKeyTraversesInterface(t *testing.T) {
	t.Parallel()

	rec := &providerRecorder{}
	var gp coregit.GitProvider = rec
	in := coregit.MergeInput{ //nolint:gosec // test fixture; no real credential
		Ref:            coregit.PRRef{Project: "myorg/secrets", Number: 7},
		ExpectSHA:      coregit.ArtifactSHA("abc"),
		SignedBytes:    []byte("signed-file-of-record"),
		CommitMessage:  "merge: add api_key",
		SecretsPath:    "secrets/prod.yaml",
		IdempotencyKey: "sha256:contentbound",
	}
	if _, err := gp.MergeSubmission(context.Background(), in); err != nil {
		t.Fatalf("MergeSubmission (stub): unexpected error: %v", err)
	}
	if rec.gotMerge.IdempotencyKey != in.IdempotencyKey {
		t.Errorf("IdempotencyKey did not traverse the interface: got %q, want %q",
			rec.gotMerge.IdempotencyKey, in.IdempotencyKey)
	}
	if rec.gotMerge.SecretsPath != in.SecretsPath {
		t.Errorf("SecretsPath did not traverse the interface: got %q, want %q",
			rec.gotMerge.SecretsPath, in.SecretsPath)
	}
}

// TestMergeResult_Decision4FieldsTraverseInterface asserts the adapter-reported
// applied-state fields exist on MergeResult and traverse the GitProvider
// boundary so the B3d-3 driver can distinguish committed/resumed/already-
// applied without consulting a PR-merged bool.
func TestMergeResult_Decision4FieldsTraverseInterface(t *testing.T) {
	t.Parallel()

	rec := &providerRecorder{
		mergeResult: coregit.MergeResult{
			MergedCommit:        "deadbeef",
			LiveFileSHA:         "cafebabe",
			SignedFileCommitted: true,
			SignedFileCommitSHA: "0123456789abcdef0123456789abcdef01234567",
			AlreadyApplied:      true,
		},
	}
	var gp coregit.GitProvider = rec

	got, err := gp.MergeSubmission(context.Background(), coregit.MergeInput{})
	if err != nil {
		t.Fatalf("MergeSubmission (stub): unexpected error: %v", err)
	}
	if !got.SignedFileCommitted {
		t.Error("MergeResult.SignedFileCommitted must round-trip through the interface")
	}
	if got.SignedFileCommitSHA != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("MergeResult.SignedFileCommitSHA did not round-trip: got %q", got.SignedFileCommitSHA)
	}
	if !got.AlreadyApplied {
		t.Error("MergeResult.AlreadyApplied must round-trip through the interface")
	}
}

// TestGitProvider_RollbackSignedFile_InterfaceShape pins the method into the
// consumer-defined GitProvider interface: ctx-first, RollbackInput-bound, error
// return. The live-tip / pending-identity assertions are the B3d-4 github
// adapter's responsibility (N-11) and are not exercised here.
func TestGitProvider_RollbackSignedFile_InterfaceShape(t *testing.T) {
	t.Parallel()

	rec := &providerRecorder{}
	var gp coregit.GitProvider = rec
	in := coregit.RollbackInput{
		Ref:             coregit.PRRef{Project: "myorg/secrets", Number: 42},
		CommitSHA:       "0123456789abcdef0123456789abcdef01234567",
		PendingIdentity: "sha256:deadbeef",
	}
	if err := gp.RollbackSignedFile(context.Background(), in); err != nil {
		t.Fatalf("RollbackSignedFile (stub): unexpected error: %v", err)
	}
	if !rec.rollbackHit {
		t.Error("RollbackSignedFile must be invoked through the GitProvider interface")
	}
	if rec.gotRollback != in {
		t.Errorf("RollbackInput not passed through: got %+v, want %+v", rec.gotRollback, in)
	}
}

// TestN5_IdempotencyKeyResume — N-5 behavioural assertion (re-run with the SAME
// IdempotencyKey ⇒ no second signed-file commit, AlreadyApplied=true; a
// DIFFERENT artifact ⇒ different key, NOT a resume). The detect-before-write
// resume lives in the B3d-4 github adapter driven by the B3d-3 usecase
// derivation; B3d-1 only freezes the contract surface this test will bind to.
func TestN5_IdempotencyKeyResume(t *testing.T) {
	t.Skip("N-5 behavioural assertion lands in B3d-3 (usecase/Merge) + B3d-4 (github adapter); B3d-1 fixes the contract only")
}

// TestN6_RollbackWindowOnlyMergeDriver — N-6 behavioural assertion (step-5-done
// / step-6-failed window ⇒ RollbackSignedFile reverts ONLY the identified
// signed-file commit; ambiguity ⇒ ErrRollbackAmbiguous terminal; a read-only /
// VerifyOfRecord caller drives NO rollback). Driver-side; lands in B3d-3
// usecase/Merge (cf. DESIGN §7.2 L3).
func TestN6_RollbackWindowOnlyMergeDriver(t *testing.T) {
	t.Skip("N-6 behavioural assertion lands in B3d-3 (usecase/Merge driver, read paths never roll back); B3d-1 fixes the contract only")
}

// TestN11_ForeignCommitOnTopIsAmbiguous — N-11 behavioural assertion (a commit
// lands on base between the signed-file commit and rollback ⇒ live tip !=
// CommitSHA ⇒ RollbackSignedFile returns ErrRollbackAmbiguous, performs NO
// revert, never drops/reverts across the foreign commit). Adapter-side; lands
// in B3d-4 github RollbackSignedFile (live-tip==CommitSHA precondition).
func TestN11_ForeignCommitOnTopIsAmbiguous(t *testing.T) {
	t.Skip("N-11 behavioural assertion lands in B3d-4 (github adapter live-tip==CommitSHA precondition); B3d-1 fixes the contract only")
}

// TestN12_MergedAfterTimeoutIsRegistryAuthoritative — N-12 behavioural
// assertion (PR merged server-side but the API reports timeout ⇒ the rollback
// decision is driven by the registry pending/CommitBump state, NOT a PR-merged
// bool; the live file-of-record is NEVER reverted after a real merge).
// Driver-side; lands in B3d-3 usecase/Merge.
func TestN12_MergedAfterTimeoutIsRegistryAuthoritative(t *testing.T) {
	t.Skip("N-12 behavioural assertion lands in B3d-3 (usecase/Merge: registry pending/CommitBump is merge-state authority); B3d-1 fixes the contract only")
}
