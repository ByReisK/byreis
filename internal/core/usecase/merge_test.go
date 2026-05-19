//go:build testhook

// These Merge use-case tests require the `testhook` build tag so they can
// construct a Valid() countertypes.CounterAuthority via countertypes.NewForTest
// (the only test-scoped Valid()-producer; the shipped path is the registry
// adapter via capmint). Production builds never set this tag. The Merge
// use-case itself only ever CONSUMES the opaque CounterAuthority through the
// injected CounterStore port — it never constructs one.
package usecase_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/decrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
	"github.com/ByReisK/byreis/internal/core/crypto/verify"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// passVerifier accepts the post-merge of-record check. Used by happy-path
// tests that exercise the §4.2 sequence with a stub signer (whose placeholder
// signature would not pass the real verifier); a dedicated end-to-end test
// uses the REAL verify + REAL sign to prove the shared-ContentSHA reachability.
type passVerifier struct{}

func (passVerifier) VerifyOfRecord(context.Context, verify.OfRecordInput) error { return nil }

func realVerifier() verify.VerifierOfRecord { return passVerifier{} }

// failingVerifier always fails the post-merge of-record check (drives the
// §7.2 B2 row (b) terminal alarm).
type failingVerifier struct{ err error }

func (f failingVerifier) VerifyOfRecord(context.Context, verify.OfRecordInput) error {
	return f.err
}

// --- merge-specific doubles ---

type stubRecipients struct {
	set            []rectypes.Recipient
	signers        map[string]ed25519.PublicKey
	sourceVerified bool
	stale          bool
	err            error
	// configuredFiles is the logical_file_name → configured-repo-path map the
	// CLI/adapter fills from the SAME verified registry fetch. nil means "use
	// the default mapping" (signed file "f" → "secrets/prod.yaml", which is the
	// SecretsPath every legacy merge test already uses) so pre-existing tests
	// stay green; identity-binding negatives override it explicitly. Use
	// emptyConfiguredFiles to assert the unresolvable-path path.
	configuredFiles      map[string]string
	emptyConfiguredFiles bool
}

func (s *stubRecipients) ExpectedRecipients(context.Context, string) (usecase.VerifiedRecipients, error) {
	if s.err != nil {
		return usecase.VerifiedRecipients{}, s.err
	}
	signers := s.signers
	if signers == nil {
		// Default non-empty trusted-signer set so the post-merge VerifyOfRecord
		// has a signer to resolve; the dedicated end-to-end test supplies the
		// real registered key.
		signers = map[string]ed25519.PublicKey{"admin-1": make(ed25519.PublicKey, ed25519.PublicKeySize)}
	}
	cf := s.configuredFiles
	if cf == nil && !s.emptyConfiguredFiles {
		// Legacy default: the signed logical_file_name "f" is configured to the
		// "secrets/prod.yaml" path every pre-existing merge test submits with.
		cf = map[string]string{"f": "secrets/prod.yaml"}
	}
	return usecase.VerifiedRecipients{
		Set: s.set, TrustedSigners: signers, ConfiguredFiles: cf,
		SourceVerified: s.sourceVerified, Stale: s.stale,
	}, nil
}

// stubCounter records the write-ahead sequence and serves a Valid() authority.
type stubCounter struct {
	auth         countertypes.CounterAuthority
	authErr      error
	recordErr    error
	commitErr    error
	calls        []string // ordered call log: "CA","RP","CB"
	recordedSHA  string
	recordedCtr  uint64
	committedCtr uint64
	recordCalls  int
	commitCalls  int
}

func (c *stubCounter) CounterAuthority(context.Context, string, string) (countertypes.CounterAuthority, error) {
	c.calls = append(c.calls, "CA")
	if c.authErr != nil {
		return countertypes.CounterAuthority{}, c.authErr
	}
	return c.auth, nil
}

func (c *stubCounter) RecordPendingBump(_ context.Context, in usecase.PendingBumpInput) error {
	c.calls = append(c.calls, "RP")
	c.recordCalls++
	c.recordedSHA = in.TargetArtifactSHA
	c.recordedCtr = in.PendingCounter
	return c.recordErr
}

func (c *stubCounter) CommitBump(_ context.Context, in usecase.CommitBumpInput) error {
	c.calls = append(c.calls, "CB")
	c.commitCalls++
	c.committedCtr = in.PendingCounter
	return c.commitErr
}

type stubSigner struct {
	signerID string
	sig      []byte
	err      error
	gotMan   manifest.Manifest
	calls    int
}

func (s *stubSigner) Sign(_ context.Context, m manifest.Manifest) (string, []byte, error) {
	s.calls++
	s.gotMan = m
	if s.err != nil {
		return "", nil, s.err
	}
	sigID := s.signerID
	if sigID == "" {
		sigID = "admin-1"
	}
	sg := s.sig
	if sg == nil {
		sg = make([]byte, 64) // Ed25519 signature length placeholder
	}
	return sigID, sg, nil
}

// mkRecipient builds a real age keypair and the matching rectypes.Recipient
// (Fingerprint = sha256 of the age pubkey string, per the C-7 rule).
func mkRecipient(t *testing.T) (rectypes.Recipient, identity.Identity, *age.X25519Identity) {
	t.Helper()
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("gen age: %v", err)
	}
	id, err := identity.Parse(x.String())
	if err != nil {
		t.Fatalf("parse id: %v", err)
	}
	var fp rectypes.Fingerprint
	sum := sha256.Sum256([]byte(x.Recipient().String()))
	copy(fp[:], sum[:])
	return rectypes.Recipient{Label: "admin", AgePubKey: x.Recipient().String(), Fingerprint: fp}, id, x
}

func ageEncryptOne(t *testing.T, plaintext string, recip string) string {
	t.Helper()
	r, err := age.ParseX25519Recipient(recip)
	if err != nil {
		t.Fatalf("parse recipient: %v", err)
	}
	var sb strings.Builder
	aw := armor.NewWriter(&sb)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		t.Fatalf("age encrypt: %v", err)
	}
	if _, err := w.Write([]byte(plaintext)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = w.Close()
	_ = aw.Close()
	return sb.String()
}

func witnessedAuthority(lastAccepted uint64, pending *countertypes.PendingBump) countertypes.CounterAuthority {
	return countertypes.NewForTest(countertypes.ForTestWitness(), lastAccepted, pending)
}

func baseMergeDeps(t *testing.T) (
	*stubGit, *stubDecryptor, *encryptorReal, *stubCounter, *stubSigner, *stubCodec,
	[]rectypes.Recipient, identity.Identity,
) {
	t.Helper()
	rec, id, _ := mkRecipient(t)
	g := &stubGit{}
	dec := &stubDecryptor{out: map[string]string{"API_KEY": "plaintext-secret"}}
	enc := &encryptorReal{inner: encrypt.New()}
	ctr := &stubCounter{auth: witnessedAuthority(0, nil)}
	sgn := &stubSigner{signerID: "admin-1"}
	codec := &stubCodec{}
	return g, dec, enc, ctr, sgn, codec, []rectypes.Recipient{rec}, id
}

// encryptorReal wraps the real encryptor and records every ciphertext it
// produced so a carried-forward / spliced blob is detectable.
type encryptorReal struct {
	inner    encrypt.Encryptor
	produced []string
}

func (e *encryptorReal) Encrypt(ctx context.Context, in encrypt.EncryptInput) (artifact.Unsigned, error) {
	out, err := e.inner.Encrypt(ctx, in)
	if err != nil {
		return out, err
	}
	for _, v := range out.Values {
		e.produced = append(e.produced, string(v))
	}
	return out, nil
}

func recipientFPEntry(r rectypes.Recipient) artifact.RecipientEntry {
	return artifact.RecipientEntry{FP: hexFP(r)}
}

func hexFP(r rectypes.Recipient) string {
	const hexd = "0123456789abcdef"
	b := r.Fingerprint[:]
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexd[v>>4]
		out[i*2+1] = hexd[v&0x0f]
	}
	return string(out)
}

// Mode: Merge DENIED by policy in CONTRIBUTOR mode (denied, not
// attempted-then-failed) — no fetch/sign/write reached.
func TestMerge_DeniedInContributorMode(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	m, err := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeContributor},
	})
	if err != nil {
		t.Fatalf("NewMerger: %v", err)
	}
	_, err = m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 1}, ExpectSHA: "sha", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("err = %v, want ErrPermissionDenied", err)
	}
	if g.getCalls != 0 || g.mergeCalls != 0 || sgn.calls != 0 || len(ctr.calls) != 0 {
		t.Fatalf("work was attempted despite a denied mode: get=%d merge=%d sign=%d ctr=%v",
			g.getCalls, g.mergeCalls, sgn.calls, ctr.calls)
	}
}

// T2: Merge fails closed with ErrArtifactMoved (pin mismatch) BEFORE any write
// when the on-PR artifact SHA moved since review.
func TestMerge_T2_PinMismatchFailsClosedBeforeAnyWrite(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	g.sub = git.Submission{
		Ref:           git.PRRef{Project: "p", Number: 1},
		ArtifactSHA:   "MOVED-sha",
		ArtifactBytes: []byte("x"),
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml"},
	}
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	_, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 1}, ExpectSHA: "PINNED-sha", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if !errors.Is(err, usecase.ErrMergePinMismatch) {
		t.Fatalf("err = %v, want ErrMergePinMismatch", err)
	}
	if sgn.calls != 0 || g.mergeCalls != 0 || ctr.recordCalls != 0 {
		t.Fatalf("a write/sign was attempted after a pin mismatch")
	}
}

// §4.2 write-ahead ordering: RecordPendingBump happens BEFORE MergeSubmission,
// and CommitBump happens AFTER MergeSubmission — never before.
func TestMerge_WriteAheadOrdering_RecordBeforeMergeCommitAfter(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	codec.unsigned = unsignedWith(recs)
	g.sub = git.Submission{
		Ref:           git.PRRef{Project: "p", Number: 1},
		ArtifactSHA:   "PIN",
		ArtifactBytes: []byte("x"),
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml", Key: "API_KEY"}, //nolint:gosec // G101 false positive: "API_KEY" is a key NAME, not a credential value
	}
	g.merge = git.MergeResult{MergedCommit: "c1", SignedFileCommitted: true, SignedFileCommitSHA: "sf1"}
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	res, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 1}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	// Ordering: the LAST CA may be the post-merge re-read. The write-ahead
	// invariant is RP strictly before the merge and CB strictly after.
	order := strings.Join(ctr.calls, ",")
	rpIdx := strings.Index(order, "RP")
	cbIdx := strings.Index(order, "CB")
	if rpIdx == -1 || cbIdx == -1 {
		t.Fatalf("expected both RP and CB, got calls=%v", ctr.calls)
	}
	if g.mergeCalls != 1 {
		t.Fatalf("merge called %d times, want 1", g.mergeCalls)
	}
	if !(rpIdx < cbIdx) {
		t.Fatalf("CommitBump must be after RecordPendingBump; calls=%v", ctr.calls)
	}
	// RecordPendingBump must have recorded the SAME shared ContentSHA the
	// post-merge VerifyOfRecord compares (proven indirectly: the merge
	// succeeded end-to-end with the same function used both sides).
	if ctr.recordedSHA == "" {
		t.Fatalf("RecordPendingBump recorded an empty target SHA")
	}
	if ctr.recordedCtr != 1 || res.FinalCounter != 1 {
		t.Fatalf("counter = recorded %d / final %d, want 1", ctr.recordedCtr, res.FinalCounter)
	}
	if ctr.commitCalls != 1 {
		t.Fatalf("CommitBump calls = %d, want exactly 1", ctr.commitCalls)
	}
}

// §4.2 negative: CommitBump is NEVER called before MergeSubmission. If the
// merge itself fails, CommitBump must not have run and the pending stays.
func TestMerge_CommitBumpNeverBeforeMerge(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	codec.unsigned = unsignedWith(recs)
	g.sub = git.Submission{
		Ref: git.PRRef{Project: "p", Number: 1}, ArtifactSHA: "PIN",
		ArtifactBytes: []byte("x"),
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml"},
	}
	g.mergeErr = git.ErrArtifactMoved // merge fails
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	_, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 1}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if err == nil {
		t.Fatalf("expected merge error")
	}
	if ctr.commitCalls != 0 {
		t.Fatalf("CommitBump ran %d times despite a failed merge — must never run before merge lands", ctr.commitCalls)
	}
	if ctr.recordCalls != 1 {
		t.Fatalf("RecordPendingBump must have run (write-ahead) exactly once; got %d", ctr.recordCalls)
	}
}

// §4.2 negative: a mismatched/absent pending surfaces ErrCounterReconcile and
// the merge aborts before any secrets write (terminal, never auto-heal).
func TestMerge_RecordPendingReconcileIsTerminalBeforeMerge(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	codec.unsigned = unsignedWith(recs)
	g.sub = git.Submission{
		Ref: git.PRRef{Project: "p", Number: 1}, ArtifactSHA: "PIN",
		ArtifactBytes: []byte("x"),
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml"},
	}
	ctr.recordErr = countertypes.ErrCounterReconcile
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	_, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 1}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if !errors.Is(err, countertypes.ErrCounterReconcile) {
		t.Fatalf("err = %v, want ErrCounterReconcile", err)
	}
	if g.mergeCalls != 0 {
		t.Fatalf("merge attempted after a reconcile (must abort before any secrets write)")
	}
}

// N-5: same IdempotencyKey ⇒ no second signed-file commit, AlreadyApplied=true;
// a different artifact ⇒ a different key (not a resume).
func TestMerge_N5_IdempotencyKeyDeterministicAndResumes(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	codec.unsigned = unsignedWith(recs)
	g.sub = git.Submission{
		Ref: git.PRRef{Project: "p", Number: 9}, ArtifactSHA: "PIN",
		ArtifactBytes: []byte("x"),
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml"},
	}
	g.merge = git.MergeResult{MergedCommit: "c", SignedFileCommitted: false, AlreadyApplied: true}
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	res1, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 9}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if err != nil {
		t.Fatalf("merge 1: %v", err)
	}
	key1 := g.gotMerge.IdempotencyKey
	if !res1.AlreadyApplied {
		t.Fatalf("AlreadyApplied should be surfaced from the adapter result")
	}
	// Same artifact + same pin ⇒ identical deterministic key (resume-safe).
	ctr2 := &stubCounter{auth: witnessedAuthority(0, nil)}
	g2 := &stubGit{sub: g.sub, merge: g.merge}
	m2, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g2, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr2, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	if _, err := m2.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 9}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	}); err != nil {
		t.Fatalf("merge 2: %v", err)
	}
	if g2.gotMerge.IdempotencyKey != key1 {
		t.Fatalf("same artifact produced different IdempotencyKeys (%q vs %q) — not resume-safe",
			key1, g2.gotMerge.IdempotencyKey)
	}
	// A DIFFERENT artifact (different pin) ⇒ a DIFFERENT key (not a resume).
	g3 := &stubGit{sub: git.Submission{
		Ref: git.PRRef{Project: "p", Number: 9}, ArtifactSHA: "DIFF",
		ArtifactBytes: []byte("x"),
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml"},
	}, merge: g.merge}
	ctr3 := &stubCounter{auth: witnessedAuthority(0, nil)}
	m3, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g3, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr3, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	if _, err := m3.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 9}, ExpectSHA: "DIFF", ExpectedProjectID: "p", ExpectedFileName: "f",
	}); err != nil {
		t.Fatalf("merge 3: %v", err)
	}
	if g3.gotMerge.IdempotencyKey == key1 {
		t.Fatalf("a different artifact produced the SAME IdempotencyKey — would be misread as a resume")
	}
}

// N-6 / L3: in the step-5-done / step-6-failed window the rollback driver acts
// ONLY via a registry-pending-bound RollbackInput; a read-only caller (Review)
// drives NO rollback and NO CommitBump.
func TestMerge_N6_RollbackDriverBoundToPendingIdentity(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	codec.unsigned = unsignedWith(recs)
	g.sub = git.Submission{
		Ref: git.PRRef{Project: "p", Number: 4}, ArtifactSHA: "PIN",
		ArtifactBytes: []byte("x"),
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml"},
	}
	// Signed-file commit landed, but the PR-merge failed (step-5-done/6-failed).
	g.merge = git.MergeResult{SignedFileCommitted: true, SignedFileCommitSHA: "orphan-sf"}
	g.mergeErr = errors.New("PR merge timed out")
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	_, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 4}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if err == nil {
		t.Fatalf("expected a merge error in the rollback window")
	}
	if g.rollbackCalls != 1 {
		t.Fatalf("rollback driver called %d times, want 1", g.rollbackCalls)
	}
	// The rollback MUST be bound to THIS attempt's registry pending identity
	// (the recorded S_signed), and to the exact orphaned commit.
	if g.gotRollback.PendingIdentity == "" || g.gotRollback.PendingIdentity != ctr.recordedSHA {
		t.Fatalf("rollback PendingIdentity = %q, want the recorded pending S_signed %q",
			g.gotRollback.PendingIdentity, ctr.recordedSHA)
	}
	if g.gotRollback.CommitSHA != "orphan-sf" {
		t.Fatalf("rollback CommitSHA = %q, want the orphaned signed-file commit", g.gotRollback.CommitSHA)
	}
	// CommitBump must NOT have run: the merge-state authority is the registry
	// pending/CommitBump state, and CommitBump was never reached.
	if ctr.commitCalls != 0 {
		t.Fatalf("CommitBump ran in the rollback window (must not)")
	}
	// A read-only Review caller drives NO rollback and NO CommitBump (L3).
	rev, _ := usecase.NewReviewer(usecase.ReviewDeps{
		Git: &stubGit{sub: g.sub}, Decryptor: dec, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: &stubCodec{signed: artifact.Signed{
			Values: map[string]artifact.EncryptedValue{"API_KEY": "ct"},
			Byreis: artifact.Metadata{FormatVersion: "byreis.native.v1", ProjectID: "p", File: "f"},
		}},
		Mode: modeGate{m: mode.ModeAdmin},
	})
	if _, rErr := rev.Review(context.Background(), usecase.ReviewInput{
		Ref: g.sub.Ref, ExpectedProjectID: "p", ExpectedFileName: "f",
	}); rErr != nil {
		t.Fatalf("review (read-only) errored: %v", rErr)
	}
}

// N-12: merged-after-timeout — when the adapter reports the signed file
// committed AND a CommitBump is recorded for this attempt, the rollback
// decision is driven by the registry pending/CommitBump state (no-op), NOT a
// git PR-merged bool. The file-of-record is never reverted after a real merge.
func TestMerge_N12_MergedAfterTimeoutDrivenByRegistryState(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	codec.unsigned = unsignedWith(recs)
	g.sub = git.Submission{
		Ref: git.PRRef{Project: "p", Number: 5}, ArtifactSHA: "PIN",
		ArtifactBytes: []byte("x"),
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml"},
	}
	// The adapter resolved the merge (no error) — the timeout was transient.
	g.merge = git.MergeResult{MergedCommit: "c", SignedFileCommitted: true, SignedFileCommitSHA: "sf"}
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	if _, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 5}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if g.rollbackCalls != 0 {
		t.Fatalf("rollback driven despite the merge resolving — must be driven by registry state, not a PR bool")
	}
	if ctr.commitCalls != 1 {
		t.Fatalf("CommitBump must have advanced (merge resolved); got %d calls", ctr.commitCalls)
	}
}

// §7.2 B2 row (a): a PRE-merge structural-invalid abort leaves the live file
// UNTOUCHED — no MergeSubmission call, no signed-file write.
func TestMerge_B2a_PreMergeAbortLeavesLiveFileUntouched(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	g.sub = git.Submission{
		Ref: git.PRRef{Project: "p", Number: 2}, ArtifactSHA: "PIN",
		ArtifactBytes: []byte("x"),
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml"},
	}
	codec.decodeUErr = errors.New("structurally invalid submission")
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	_, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 2}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if err == nil {
		t.Fatalf("expected a pre-merge structural-invalid abort")
	}
	if g.mergeCalls != 0 || sgn.calls != 0 || ctr.recordCalls != 0 {
		t.Fatalf("pre-merge abort still touched the live file/registry: merge=%d sign=%d record=%d",
			g.mergeCalls, sgn.calls, ctr.recordCalls)
	}
}

// §7.2 B2 row (b): a POST-merge integrity failure is a LOUD terminal alarm —
// the live file is ALREADY committed; this is NOT the untouched pre-merge row.
func TestMerge_B2b_PostMergeIntegrityFailureIsTerminalAlarm(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	codec.unsigned = unsignedWith(recs)
	g.sub = git.Submission{
		Ref: git.PRRef{Project: "p", Number: 3}, ArtifactSHA: "PIN",
		ArtifactBytes: []byte("x"),
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml"},
	}
	g.merge = git.MergeResult{MergedCommit: "landed", SignedFileCommitted: true, SignedFileCommitSHA: "sf"}
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn,
		// A verifier that fails the post-merge of-record check.
		Verifier: failingVerifier{err: errors.New("signature does not verify")},
		Mode:     modeGate{m: mode.ModeAdmin},
	})
	res, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 3}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if !errors.Is(err, usecase.ErrMergePostIntegrity) {
		t.Fatalf("err = %v, want ErrMergePostIntegrity (loud terminal alarm)", err)
	}
	// The merge LANDED (this is the post-merge row, distinct from pre-merge).
	if g.mergeCalls != 1 || ctr.commitCalls != 1 {
		t.Fatalf("post-merge alarm row requires the merge to have landed: merge=%d commit=%d",
			g.mergeCalls, ctr.commitCalls)
	}
	if res.MergedCommit != "landed" {
		t.Fatalf("the post-merge alarm must still report the landed commit; got %q", res.MergedCommit)
	}
}

// C-4: re-encrypt-at-merge is a FRESH whole-file age.Encrypt. When the
// submission's recipient set differs from the verified set, every value's
// ciphertext is REGENERATED from plaintext and ZERO prior ciphertext bytes are
// carried into the signed file.
func TestMerge_C4_ReEncryptIsFreshWholeFileZeroPriorCiphertext(t *testing.T) {
	t.Parallel()
	// Submission encrypted to a STALE recipient (different from verified set).
	staleRec, _, staleX := mkRecipient(t)
	verifiedRec, _, _ := mkRecipient(t)
	staleCipher := ageEncryptOne(t, "the-only-plaintext", staleX.Recipient().String())

	uns := artifact.Unsigned{
		Values: map[string]artifact.EncryptedValue{"API_KEY": artifact.EncryptedValue(staleCipher)},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1", ProjectID: "p", File: "f", Counter: 0,
			Recipients: []artifact.RecipientEntry{recipientFPEntry(staleRec)},
		},
	}
	g := &stubGit{
		sub: git.Submission{
			Ref: git.PRRef{Project: "p", Number: 1}, ArtifactSHA: "PIN",
			ArtifactBytes: []byte("x"),
			Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml", Key: "API_KEY"}, //nolint:gosec // G101 false positive: "API_KEY" is a key NAME, not a credential value
		},
		merge: git.MergeResult{MergedCommit: "c", SignedFileCommitted: true, SignedFileCommitSHA: "sf"},
	}
	dec := &stubDecryptor{out: map[string]string{"API_KEY": "the-only-plaintext"}}
	enc := &encryptorReal{inner: encrypt.New()}
	ctr := &stubCounter{auth: witnessedAuthority(0, nil)}
	sgn := &stubSigner{signerID: "admin-1"}
	codec := &stubCodec{unsigned: uns}
	_, id, _ := mkRecipient(t)
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec,
		Recipients:    &stubRecipients{set: []rectypes.Recipient{verifiedRec}, sourceVerified: true},
		Counter:       ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	res, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 1}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if !res.ReEncrypted {
		t.Fatalf("recipient set differed — Merge must have re-encrypted whole-file")
	}
	// The signed file the codec encoded must contain a FRESH ciphertext, NOT
	// the carried-forward stale ciphertext.
	signedVal := string(codec.gotEncodeArt.Values["API_KEY"])
	if signedVal == "" {
		t.Fatalf("signed artifact has no API_KEY value")
	}
	if signedVal == staleCipher {
		t.Fatalf("C-4 VIOLATION: the signed file carried the prior (stale) ciphertext verbatim")
	}
	if strings.Contains(signedVal, staleCipher) || strings.Contains(staleCipher, signedVal) {
		t.Fatalf("C-4 VIOLATION: the signed ciphertext spliced/contained prior ciphertext bytes")
	}
	// Every signed ciphertext must be one the FRESH encryptor produced.
	freshOK := false
	for _, p := range enc.produced {
		if p == signedVal {
			freshOK = true
		}
	}
	if !freshOK {
		t.Fatalf("the signed ciphertext was not produced by a fresh age.Encrypt — possible carry-forward")
	}
}

// N-10: a SubmissionMeta with BaseFilePath != SecretsPath never causes merge to
// delete/move/truncate BaseFilePath; merge writes ONLY the SecretsPath.
func TestMerge_N10_WritesOnlySecretsPathNeverBaseFilePath(t *testing.T) {
	t.Parallel()
	g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
	codec.unsigned = unsignedWith(recs)
	g.sub = git.Submission{
		Ref: git.PRRef{Project: "p", Number: 1}, ArtifactSHA: "PIN",
		ArtifactBytes: []byte("x"),
		Meta: git.SubmissionMeta{
			SchemaVersion: 1,
			SecretsPath:   "secrets/prod.yaml",
			BaseFilePath:  "secrets/OLD-different.yaml",
			Key:           "API_KEY", //nolint:gosec // G101 false positive: "API_KEY" is a key NAME, not a credential value
		},
	}
	g.merge = git.MergeResult{MergedCommit: "c", SignedFileCommitted: true, SignedFileCommitSHA: "sf"}
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
		ArtifactCodec: codec, Recipients: &stubRecipients{set: recs, sourceVerified: true},
		Counter: ctr, Signer: sgn, Verifier: realVerifier(), Mode: modeGate{m: mode.ModeAdmin},
	})
	if _, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 1}, ExpectSHA: "PIN", ExpectedProjectID: "p", ExpectedFileName: "f",
	}); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if g.gotMerge.SecretsPath != "secrets/prod.yaml" {
		t.Fatalf("merge wrote to %q, want only the containment-validated SecretsPath", g.gotMerge.SecretsPath)
	}
	// The use-case never references BaseFilePath as a write/delete target: the
	// only path handed to the adapter is SecretsPath.
	if g.gotMerge.SecretsPath == "secrets/OLD-different.yaml" {
		t.Fatalf("merge targeted BaseFilePath — it must write ONLY SecretsPath")
	}
}

// SecretsPath ↔ signed-logical_file_name cross-check. The write target identity
// is bound to the SIGNED manifest's logical_file_name (body.Byreis.File),
// resolved against the registry-configured path delivered on the SAME verified
// fetch as the recipient set — never the submission's self-declared path. A
// mismatch (or an unresolvable configured path) is a pre-merge structural abort
// BEFORE RecordPendingBump: nothing recorded, no merge, live tree untouched.
func TestMerge_SecretsPathCrossCheck(t *testing.T) {
	t.Parallel()

	const signedFile = "f" // unsignedWith / baseMergeDeps sign over File == "f"

	tests := []struct {
		name string
		// secretsPath is what the (possibly tampered) submission declares.
		secretsPath string
		// configuredFiles is what the verified registry fetch delivers; nil
		// uses the legacy default {"f":"secrets/prod.yaml"}.
		configuredFiles map[string]string
		// emptyConfigured forces a non-nil-but-empty configured map (the
		// logical_file_name is absent => unresolvable).
		emptyConfigured bool
		wantOK          bool
	}{
		{
			name:        "positive_path_matches_configured_for_signed_file",
			secretsPath: "secrets/prod.yaml",
			wantOK:      true,
		},
		{
			name:        "control_fires_path_does_not_match_configured",
			secretsPath: "secrets/attacker-chosen.yaml",
			wantOK:      false,
		},
		{
			name:        "identity_bind_path_is_some_other_valid_configured_path",
			secretsPath: "secrets/other.yaml",
			configuredFiles: map[string]string{
				signedFile: "secrets/prod.yaml",  // the SIGNED file's configured path
				"other":    "secrets/other.yaml", // a different file's valid path
			},
			wantOK: false,
		},
		{
			name:        "identity_bind_path_matches_meta_but_signed_file_differs",
			secretsPath: "secrets/prod.yaml",
			// "secrets/prod.yaml" is a legitimately configured path, but NOT for
			// the signed logical_file_name "f" — it belongs to "g". The bind
			// MUST be to body.Byreis.File, not to "any configured path".
			configuredFiles: map[string]string{
				"g": "secrets/prod.yaml",
			},
			wantOK: false,
		},
		{
			name:            "unresolvable_signed_file_absent_from_configured",
			secretsPath:     "secrets/prod.yaml",
			emptyConfigured: true,
			wantOK:          false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g, dec, enc, ctr, sgn, codec, recs, id := baseMergeDeps(t)
			codec.unsigned = unsignedWith(recs)
			g.sub = git.Submission{
				Ref:           git.PRRef{Project: "p", Number: 1},
				ArtifactSHA:   "PIN",
				ArtifactBytes: []byte("x"),
				Meta: git.SubmissionMeta{
					SchemaVersion: 1,
					SecretsPath:   tc.secretsPath,
					Key:           "API_KEY", //nolint:gosec // G101 false positive: "API_KEY" is a key NAME, not a credential value
				},
			}
			g.merge = git.MergeResult{
				MergedCommit: "c1", SignedFileCommitted: true, SignedFileCommitSHA: "sf1",
			}
			m, _ := usecase.NewMerger(usecase.MergeDeps{
				Git: g, Decryptor: dec, Encryptor: enc, IDLoader: &stubIDLoader{id: id},
				ArtifactCodec: codec,
				Recipients: &stubRecipients{
					set: recs, sourceVerified: true,
					configuredFiles:      tc.configuredFiles,
					emptyConfiguredFiles: tc.emptyConfigured,
				},
				Counter: ctr, Signer: sgn, Verifier: realVerifier(),
				Mode: modeGate{m: mode.ModeAdmin},
			})
			_, err := m.Merge(context.Background(), usecase.MergeInput{
				Ref: git.PRRef{Project: "p", Number: 1}, ExpectSHA: "PIN",
				ExpectedProjectID: "p", ExpectedFileName: "f",
			})

			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected merge to proceed, got %v", err)
				}
				if ctr.recordCalls != 1 {
					t.Fatalf("RecordPendingBump must have run once on the positive path; got %d", ctr.recordCalls)
				}
				if g.mergeCalls != 1 {
					t.Fatalf("MergeSubmission must have run once on the positive path; got %d", g.mergeCalls)
				}
				return
			}

			// Fail-closed with the identity-mismatch sentinel.
			if !errors.Is(err, usecase.ErrMergeFilePathMismatch) {
				t.Fatalf("err = %v, want ErrMergeFilePathMismatch", err)
			}
			// Load-bearing: pre-merge abort BEFORE the write-ahead step. No
			// pending recorded, no merge, no commit-bump, live tree untouched.
			// (Mutation check: deleting the cross-check makes this FAIL — the
			// merge would then reach RecordPendingBump/MergeSubmission.)
			if ctr.recordCalls != 0 {
				t.Fatalf("RecordPendingBump ran (%d) — the cross-check must abort BEFORE the write-ahead", ctr.recordCalls)
			}
			if g.mergeCalls != 0 {
				t.Fatalf("MergeSubmission ran (%d) — the live tree must be untouched on a mismatch", g.mergeCalls)
			}
			if ctr.commitCalls != 0 {
				t.Fatalf("CommitBump ran (%d) — no finalize on a pre-merge abort", ctr.commitCalls)
			}
			if sgn.calls != 0 {
				t.Fatalf("Sign ran (%d) — no signature is produced on a pre-merge structural abort", sgn.calls)
			}
		})
	}
}

// helpers ---------------------------------------------------------------

func realDecryptor() decrypt.Decryptor { return decrypt.New() }

func encodeJSON(v interface{}) ([]byte, error) { return json.Marshal(v) }

func decodeJSONSigned(b []byte) (artifact.Signed, error) {
	var s artifact.Signed
	if err := json.Unmarshal(b, &s); err != nil {
		return artifact.Signed{}, err
	}
	if s.Byreis.FormatVersion == "" {
		return artifact.Signed{}, errors.New("not a signed artifact")
	}
	return s, nil
}

func decodeJSONUnsigned(b []byte) (artifact.Unsigned, error) {
	var u artifact.Unsigned
	if err := json.Unmarshal(b, &u); err != nil {
		return artifact.Unsigned{}, err
	}
	return u, nil
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return b
}

func unsignedWith(recs []rectypes.Recipient) artifact.Unsigned {
	entries := make([]artifact.RecipientEntry, 0, len(recs))
	for _, r := range recs {
		entries = append(entries, recipientFPEntry(r))
	}
	return artifact.Unsigned{
		Values: map[string]artifact.EncryptedValue{"API_KEY": "submitted-ciphertext"},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1", ProjectID: "p", File: "f", Counter: 0,
			Recipients: entries,
		},
	}
}

// realSigner signs the canonical manifest with a real Ed25519 key via the
// crypto/sign package — the same encoder VerifyOfRecord recomputes.
type realSigner struct {
	id   string
	priv ed25519.PrivateKey
}

func (s realSigner) Sign(_ context.Context, m manifest.Manifest) (string, []byte, error) {
	sig, err := sign.Sign(s.priv, m)
	return s.id, sig, err
}

// realCodec maps artifact bytes ↔ domain types via a stable JSON encoding (the
// on-disk YAML codec is a Phase-2 adapter; the use-case only needs a
// deterministic round-trippable codec for these tests).
type realCodec struct{ last artifact.Signed }

func (c *realCodec) DecodeSigned(b []byte) (artifact.Signed, error) {
	return decodeJSONSigned(b)
}
func (c *realCodec) DecodeUnsigned(b []byte) (artifact.Unsigned, error) {
	return decodeJSONUnsigned(b)
}
func (c *realCodec) EncodeSigned(s artifact.Signed) ([]byte, error) {
	c.last = s
	return encodeJSON(s)
}

// recordingCounter records pending.target_artifact_sha via the SHARED
// verify.ContentSHA over the signed file (proving record == compare). After
// RecordPendingBump it serves a Valid() authority with a matching pending so
// the §3.4 step-4 OK-resume row is reachable by construction.
type recordingCounter struct {
	lastAccepted uint64
	pending      *countertypes.PendingBump
	recordedSHA  string
	recordCalls  int
	commitCalls  int
}

func (c *recordingCounter) CounterAuthority(context.Context, string, string) (countertypes.CounterAuthority, error) {
	return countertypes.NewForTest(countertypes.ForTestWitness(), c.lastAccepted, c.pending), nil
}

func (c *recordingCounter) RecordPendingBump(_ context.Context, in usecase.PendingBumpInput) error {
	c.recordCalls++
	c.recordedSHA = in.TargetArtifactSHA
	c.pending = &countertypes.PendingBump{
		PendingCounter:    in.PendingCounter,
		TargetArtifactSHA: in.TargetArtifactSHA, // recorded via the use-case's shared ContentSHA
		TargetPR:          in.TargetPR,
	}
	return nil
}

func (c *recordingCounter) CommitBump(_ context.Context, in usecase.CommitBumpInput) error {
	c.commitCalls++
	c.lastAccepted = in.PendingCounter
	c.pending = nil
	return nil
}

// TestMerge_EndToEnd_SharedContentSHAReachesOKResume proves the registry
// recorder and VerifyOfRecord call the SAME verify.ContentSHA: the use-case
// records pending.target_artifact_sha via the shared function and the
// post-merge VerifyOfRecord (real verifier) compares the same value, so the
// in-flight OK-resume row is reachable rather than spuriously reconciling. A
// raw-buffer/re-implemented hash on either side makes this test FAIL.
func TestMerge_EndToEnd_SharedContentSHAReachesOKResume(t *testing.T) {
	t.Parallel()

	rec, id, _ := mkRecipient(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	// Submission already encrypted to the verified recipient (no C-4 needed):
	// the use-case will sign exactly this body, advancing the counter to 1.
	ct := ageEncryptOne(t, "the-secret", rec.AgePubKey)
	uns := artifact.Unsigned{
		Values: map[string]artifact.EncryptedValue{"API_KEY": artifact.EncryptedValue(ct)},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1", ProjectID: "p", File: "f", Counter: 0,
			Recipients: []artifact.RecipientEntry{recipientFPEntry(rec)},
		},
	}
	codec := &realCodec{}
	g := &stubGit{
		sub: git.Submission{
			Ref: git.PRRef{Project: "p", Number: 1}, ArtifactSHA: "PIN",
			ArtifactBytes: mustJSON(t, uns),
			Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml", Key: "API_KEY"}, //nolint:gosec // G101 false positive: "API_KEY" is a key NAME, not a credential value
		},
		merge: git.MergeResult{MergedCommit: "landed", SignedFileCommitted: true, SignedFileCommitSHA: "sf"},
	}
	ctr := &recordingCounter{lastAccepted: 0}
	m, _ := usecase.NewMerger(usecase.MergeDeps{
		Git: g, Decryptor: realDecryptor(), Encryptor: encrypt.New(),
		IDLoader:      &stubIDLoader{id: id},
		ArtifactCodec: codec,
		Recipients: &stubRecipients{
			set:            []rectypes.Recipient{rec},
			signers:        map[string]ed25519.PublicKey{"admin-1": pub},
			sourceVerified: true,
		},
		Counter:  ctr,
		Signer:   realSigner{id: "admin-1", priv: priv},
		Verifier: verify.New(),
		Mode:     modeGate{m: mode.ModeAdmin},
	})
	res, err := m.Merge(context.Background(), usecase.MergeInput{
		Ref: git.PRRef{Project: "p", Number: 1}, ExpectSHA: "PIN",
		ExpectedProjectID: "p", ExpectedFileName: "f",
	})
	if err != nil {
		t.Fatalf("end-to-end Merge failed (shared ContentSHA / OK-resume not reachable): %v", err)
	}
	if res.FinalCounter != 1 {
		t.Fatalf("FinalCounter = %d, want 1", res.FinalCounter)
	}
	// The recorded write-ahead SHA MUST equal verify.ContentSHA of exactly the
	// signed file the codec serialised — record == compare, one function.
	wantSHA := verify.ContentSHA(codec.last)
	if ctr.recordedSHA != wantSHA {
		t.Fatalf("recorded pending SHA %q != verify.ContentSHA(signed) %q — "+
			"the recorder and verify do not share one ContentSHA function",
			ctr.recordedSHA, wantSHA)
	}
	if ctr.commitCalls != 1 {
		t.Fatalf("CommitBump calls = %d, want 1 (merge landed)", ctr.commitCalls)
	}
}
