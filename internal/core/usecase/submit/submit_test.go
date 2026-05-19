package submit_test

// Table-driven + negative tests for the keyless contributor Submit spine.
//
// Every collaborator is an in-memory fake injected at construction: no real
// fs/net/clock/tty/keychain. The fakes deliberately carry NO decrypting
// identity — a decrypting identity is never constructed anywhere on the Submit
// path, which is also proven mechanically by the allowlist test in this same
// package (allowlist_test.go).
//
// Named obligations covered here:
//   - REQ-A-003: invalid value/key refuses with an actionable hint and creates
//     NO branch/commit/PR (no side effect) — TestSubmit_InvalidValue_NoSideEffect.
//   - §4.3: a stale/unverified/SourceVerified==false recipient set refuses;
//     never falls back to artifact/repo recipients —
//     TestSubmit_RecipientSourcing_RefusesUnverified.
//   - §7.2 A3: TTY double-entry vs pipe single-entry; irreversibility ack;
//     validation-before-commit — TestSubmit_ValueEntry_TTYvsPipe.
//   - §7.2 C1: concurrent-submission branch conflict REFUSES, never silently
//     drops a secret — TestSubmit_ConcurrentBranchConflict_Refuses.
//   - §7.2 C3: REPLACE for an existing key writes/truncates nothing live and
//     reaches no decrypt/identity code — TestSubmit_Replace_NoLiveWrite_NoDecrypt.
//   - REQ-B-001: the whole path runs with NO admin private key present and
//     never errors because a key is absent —
//     TestSubmit_Keyless_NoPrivateKeyEverNeeded.
//   - REQ-C-005: only the encrypted artifact is persisted for resume, never
//     plaintext — TestSubmit_Resume_PersistsOnlyEncrypted.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/encrypt"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase/submit"
)

// ---- fakes (no real fs/net/clock/tty; no decrypting identity anywhere) ----

type fakeRecips struct {
	out submit.Recipients
	err error
}

func (f fakeRecips) Recipients(_ context.Context, _ string) (submit.Recipients, error) {
	return f.out, f.err
}

type fakeValidator struct {
	keyErr error
	valErr error
}

func (f fakeValidator) ValidateKeyName(string) error { return f.keyErr }
func (f fakeValidator) ValidateValue(string) error   { return f.valErr }

// fakeKeyProbe records that it was called and returns existence by NAME only.
// It holds no ciphertext and no identity — REPLACE detection cannot decrypt.
type fakeKeyProbe struct {
	exists bool
	err    error
	calls  int
}

func (f *fakeKeyProbe) KeyExists(_ context.Context, _, _, _ string) (bool, error) {
	f.calls++
	return f.exists, f.err
}

type fakeGit struct {
	branchExists bool
	branchErr    error
	openErr      error
	openCalls    int
	lastOpen     submit.OpenPRInput
	result       submit.OpenedPR
}

func (g *fakeGit) BranchExists(_ context.Context, _, _ string) (bool, error) {
	return g.branchExists, g.branchErr
}

func (g *fakeGit) OpenSubmissionPR(_ context.Context, in submit.OpenPRInput) (submit.OpenedPR, error) {
	g.openCalls++
	g.lastOpen = in
	if g.openErr != nil {
		return submit.OpenedPR{}, g.openErr
	}
	r := g.result
	if r.Ref.Project == "" {
		r = submit.OpenedPR{
			Ref:         submit.PRRef{Project: in.ProjectID, Number: 7},
			URL:         "https://example.test/pr/7",
			Branch:      in.Branch,
			ArtifactSHA: "deadbeef",
		}
	}
	return r, nil
}

// recordingResume records every saved PendingSubmission so a test can assert
// no plaintext is persisted.
type recordingResume struct {
	mu      sync.Mutex
	saved   []submit.PendingSubmission
	discard int
	saveErr error
}

func (r *recordingResume) Save(_ context.Context, p submit.PendingSubmission) error {
	if r.saveErr != nil {
		return r.saveErr
	}
	r.mu.Lock()
	r.saved = append(r.saved, p)
	r.mu.Unlock()
	return nil
}

func (r *recordingResume) Load(_ context.Context, _, _ string) (submit.PendingSubmission, bool, error) {
	return submit.PendingSubmission{}, false, nil
}

func (r *recordingResume) Discard(_ context.Context, _, _ string) error {
	r.mu.Lock()
	r.discard++
	r.mu.Unlock()
	return nil
}

type fakePrompter struct {
	entry submit.ValueEntry
	err   error
}

func (f fakePrompter) CollectValue(_ context.Context, _ string, _ submit.SubmitAction) (submit.ValueEntry, error) {
	return f.entry, f.err
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// ---- helpers ----

func recipient() rectypes.Recipient {
	// A deterministic, well-formed age recipient. This is a PUBLIC key only;
	// no identity is constructed in any test on the Submit path.
	return rectypes.Recipient{
		Label:     "admin-1",
		AgePubKey: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
	}
}

func verifiedRecips() submit.Recipients {
	return submit.Recipients{
		Set:            []rectypes.Recipient{recipient()},
		SourceVerified: true,
		Stale:          false,
	}
}

func okEntry(value string) submit.ValueEntry {
	// Piped/single-entry by default (Interactive=false).
	return submit.ValueEntry{Value: value}
}

func baseInput() submit.Input {
	return submit.Input{ //nolint:gosec // G101 false positive: domain field SecretsPath / "secrets/..." path, not a hardcoded credential
		ProjectID:       "myorg/app",
		LogicalFileName: "prod",
		Key:             "SVC_ENDPOINT",
		Counter:         5,
		Justification:   "rotate the service endpoint value",
		SecretsPath:     "secrets/prod.enc.yaml",
		BaseFilePath:    "secrets/prod.enc.yaml",
	}
}

func newSUT(t *testing.T, d submit.Deps) submit.Submitter {
	t.Helper()
	if d.Recipients == nil {
		d.Recipients = fakeRecips{out: verifiedRecips()}
	}
	if d.Encryptor == nil {
		d.Encryptor = encrypt.New()
	}
	if d.Validator == nil {
		d.Validator = fakeValidator{}
	}
	if d.KeyProbe == nil {
		d.KeyProbe = &fakeKeyProbe{}
	}
	if d.Git == nil {
		d.Git = &fakeGit{}
	}
	if d.Resume == nil {
		d.Resume = &recordingResume{}
	}
	if d.Prompter == nil {
		d.Prompter = fakePrompter{entry: okEntry("s3cr3t")}
	}
	if d.Clock == nil {
		d.Clock = fixedClock{t: time.Unix(1_700_000_000, 0)}
	}
	if d.Audit == nil {
		d.Audit = audit.Discard
	}
	s, err := submit.New(d)
	if err != nil {
		t.Fatalf("submit.New: %v", err)
	}
	return s
}

// ---- happy path ----

func TestSubmit_HappyPath_Add(t *testing.T) {
	t.Parallel()
	git := &fakeGit{}
	res := &recordingResume{}
	s := newSUT(t, submit.Deps{Git: git, Resume: res})

	out, err := s.Submit(context.Background(), baseInput())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if out.Action != submit.ActionAdd {
		t.Fatalf("action = %v, want add", out.Action)
	}
	if git.openCalls != 1 {
		t.Fatalf("OpenSubmissionPR calls = %d, want 1", git.openCalls)
	}
	if !strings.HasPrefix(git.lastOpen.Branch, "byreis/add-SVC_ENDPOINT-") {
		t.Fatalf("branch = %q, want byreis/add-SVC_ENDPOINT-<ts>", git.lastOpen.Branch)
	}
	if len(git.lastOpen.Artifact.Values) != 1 {
		t.Fatalf("artifact must carry exactly the submitted key")
	}
	if res.discard != 1 {
		t.Fatalf("resume record not discarded after success (discard=%d)", res.discard)
	}
}

// ---- REQ-A-003: invalid value/key refuses BEFORE any branch/commit/PR ----

func TestSubmit_InvalidValue_NoSideEffect(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		val  fakeValidator
	}{
		{"invalid value", fakeValidator{valErr: errors.New("empty value")}},
		{"invalid key name", fakeValidator{keyErr: errors.New("bad key")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			git := &fakeGit{}
			res := &recordingResume{}
			s := newSUT(t, submit.Deps{Validator: tc.val, Git: git, Resume: res})

			_, err := s.Submit(context.Background(), baseInput())
			if !errors.Is(err, submit.ErrInvalidValue) {
				t.Fatalf("err = %v, want ErrInvalidValue", err)
			}
			if !strings.Contains(err.Error(), "no branch") &&
				!strings.Contains(err.Error(), "validation") {
				t.Fatalf("error must carry an actionable hint: %v", err)
			}
			if git.openCalls != 0 {
				t.Fatalf("REQ-A-003 violated: PR opened on invalid input")
			}
			res.mu.Lock()
			n := len(res.saved)
			res.mu.Unlock()
			if n != 0 {
				t.Fatalf("REQ-A-003 violated: resume record persisted on invalid input")
			}
		})
	}
}

// ---- §4.3: recipients only from a SourceVerified, non-stale fetch ----

func TestSubmit_RecipientSourcing_RefusesUnverified(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		rs   submit.Recipients
		rErr error
		want error
	}{
		{
			name: "SourceVerified false",
			rs:   submit.Recipients{Set: []rectypes.Recipient{recipient()}, SourceVerified: false},
			want: submit.ErrRecipientsNotVerified,
		},
		{
			name: "stale cache (verified flag but stale)",
			rs:   submit.Recipients{Set: []rectypes.Recipient{recipient()}, SourceVerified: true, Stale: true},
			want: submit.ErrRecipientsNotVerified,
		},
		{
			name: "empty verified set",
			rs:   submit.Recipients{Set: nil, SourceVerified: true},
			want: submit.ErrNoRecipients,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			git := &fakeGit{}
			s := newSUT(t, submit.Deps{
				Recipients: fakeRecips{out: tc.rs, err: tc.rErr},
				Git:        git,
			})
			_, err := s.Submit(context.Background(), baseInput())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if git.openCalls != 0 {
				t.Fatalf("must NOT open a PR / encrypt to an unverified or empty set")
			}
		})
	}
}

// ---- §7.2 A3: TTY double-entry vs pipe single-entry; irreversibility ack ----

func TestSubmit_ValueEntry_TTYvsPipe(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		entry   submit.ValueEntry
		wantErr error // nil => success
	}{
		{
			name:  "pipe single-entry: no confirm, no ack required",
			entry: submit.ValueEntry{Value: "s3cr3t", Interactive: false},
		},
		{
			name: "TTY double-entry match + ack: ok",
			entry: submit.ValueEntry{
				Value: "s3cr3t", Confirm: "s3cr3t",
				Interactive: true, IrreversibleAcknowledged: true,
			},
		},
		{
			name: "TTY mismatch: refuse",
			entry: submit.ValueEntry{
				Value: "s3cr3t", Confirm: "s3cr3X",
				Interactive: true, IrreversibleAcknowledged: true,
			},
			wantErr: submit.ErrValueMismatch,
		},
		{
			name: "TTY ack declined: refuse",
			entry: submit.ValueEntry{
				Value: "s3cr3t", Confirm: "s3cr3t",
				Interactive: true, IrreversibleAcknowledged: false,
			},
			wantErr: submit.ErrIrreversibleNotAcknowledged,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			git := &fakeGit{}
			s := newSUT(t, submit.Deps{
				Prompter: fakePrompter{entry: tc.entry},
				Git:      git,
			})
			_, err := s.Submit(context.Background(), baseInput())
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				if git.openCalls != 1 {
					t.Fatalf("PR not opened on valid entry")
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if git.openCalls != 0 {
				t.Fatalf("A3 violated: PR opened despite a refused value entry")
			}
		})
	}
}

// ---- §7.2 C1: concurrent-submission branch conflict refuses ----

func TestSubmit_ConcurrentBranchConflict_Refuses(t *testing.T) {
	t.Parallel()

	t.Run("pre-check finds existing branch", func(t *testing.T) {
		t.Parallel()
		git := &fakeGit{branchExists: true}
		s := newSUT(t, submit.Deps{Git: git})
		_, err := s.Submit(context.Background(), baseInput())
		if !errors.Is(err, submit.ErrBranchConflict) {
			t.Fatalf("err = %v, want ErrBranchConflict", err)
		}
		if git.openCalls != 0 {
			t.Fatalf("must not open a PR over an existing branch")
		}
	})

	t.Run("lost the create race at push time", func(t *testing.T) {
		t.Parallel()
		// Pre-check clear, but the adapter loses the concurrent-create race and
		// returns ErrBranchTaken. The secret must NOT be silently dropped: the
		// caller gets an explicit refusal and the encrypted resume record is
		// still on disk so nothing is lost.
		git := &fakeGit{branchExists: false, openErr: submit.ErrBranchTaken}
		res := &recordingResume{}
		s := newSUT(t, submit.Deps{Git: git, Resume: res})
		_, err := s.Submit(context.Background(), baseInput())
		if !errors.Is(err, submit.ErrBranchConflict) {
			t.Fatalf("err = %v, want ErrBranchConflict", err)
		}
		res.mu.Lock()
		saved := len(res.saved)
		res.mu.Unlock()
		if saved != 1 {
			t.Fatalf("encrypted submission must remain persisted (not dropped) on conflict; saved=%d", saved)
		}
		if res.discard != 0 {
			t.Fatalf("must NOT discard the resume record when the submission was refused")
		}
	})
}

// ---- §7.2 C3: REPLACE for an existing key writes/truncates nothing live ----

func TestSubmit_Replace_NoLiveWrite_NoDecrypt(t *testing.T) {
	t.Parallel()
	probe := &fakeKeyProbe{exists: true} // key already exists -> REPLACE
	git := &fakeGit{}
	s := newSUT(t, submit.Deps{KeyProbe: probe, Git: git})

	out, err := s.Submit(context.Background(), baseInput())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if out.Action != submit.ActionReplace {
		t.Fatalf("action = %v, want replace", out.Action)
	}
	if probe.calls != 1 {
		t.Fatalf("REPLACE detection must consult the name-only probe exactly once")
	}
	if !strings.HasPrefix(git.lastOpen.Branch, "byreis/replace-SVC_ENDPOINT-") {
		t.Fatalf("branch = %q, want byreis/replace-SVC_ENDPOINT-<ts>", git.lastOpen.Branch)
	}
	// The use-case has NO live-file writer port at all: the only git operation
	// is OpenSubmissionPR (branch/commit on a NEW submission branch). There is
	// no MergeSubmission / file-write port on the Submit Deps surface, so a
	// contributor command structurally cannot write/truncate the live file.
	// The companion allowlist_test.go proves no decrypt/identity package is
	// reachable, so REPLACE detection provably reaches no decrypt code.
	if git.openCalls != 1 {
		t.Fatalf("REPLACE must still open a normal submission PR")
	}
}

// ---- REQ-B-001: keyless — never needs/derives a private key ----

func TestSubmit_Keyless_NoPrivateKeyEverNeeded(t *testing.T) {
	t.Parallel()
	// No identity/keychain/key port is wired anywhere (Deps has none). The full
	// path completes successfully with zero private-key material present and
	// never errors *because* a key is absent.
	git := &fakeGit{}
	s := newSUT(t, submit.Deps{Git: git})
	out, err := s.Submit(context.Background(), baseInput())
	if err != nil {
		t.Fatalf("keyless Submit must succeed with no private key present: %v", err)
	}
	if git.openCalls != 1 || out.PRRef.Number == 0 {
		t.Fatalf("keyless submit did not complete: calls=%d ref=%+v", git.openCalls, out.PRRef)
	}
	// The artifact handed to git is artifact.Unsigned by type: it has no
	// manifest-signature field at all, so there is nothing to assert-absent —
	// the type enforces it. assertUnsigned pins that static type and would not
	// compile if the field type changed. No decrypting identity is ever
	// constructed (allowlist_test.go proves crypto/identity & crypto/decrypt
	// are unreachable from this package's transitive set).
	assertUnsigned(git.lastOpen.Artifact)
}

// assertUnsigned fails to compile if the git port is ever handed anything other
// than an artifact.Unsigned (e.g. a signed artifact bearing a manifest sig).
func assertUnsigned(_ artifact.Unsigned) {}

// ---- REQ-C-005: only the encrypted artifact is persisted, never plaintext ----

func TestSubmit_Resume_PersistsOnlyEncrypted(t *testing.T) {
	t.Parallel()
	const secret = "p1aintext-should-never-be-persisted"
	res := &recordingResume{}
	s := newSUT(t, submit.Deps{
		Prompter: fakePrompter{entry: okEntry(secret)},
		Resume:   res,
	})
	if _, err := s.Submit(context.Background(), baseInput()); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	res.mu.Lock()
	defer res.mu.Unlock()
	if len(res.saved) != 1 {
		t.Fatalf("want exactly one persisted pending submission, got %d", len(res.saved))
	}
	p := res.saved[0]
	// The persisted artifact must be the UNSIGNED (encrypted) artifact and must
	// not contain the plaintext anywhere in its ciphertext blobs.
	for k, v := range p.Artifact.Values {
		if strings.Contains(string(v), secret) {
			t.Fatalf("REQ-C-005 violated: plaintext leaked into persisted ciphertext for key %q", k)
		}
	}
	// PendingSubmission must not carry a plaintext field; assert structurally
	// that the only value-bearing field is the encrypted artifact.
	if len(p.Artifact.Values) != 1 {
		t.Fatalf("persisted artifact must carry exactly the one encrypted value")
	}
}

// ---- nil-dependency guard (constructor injection, fail-closed) ----

func TestSubmit_New_RejectsNilPorts(t *testing.T) {
	t.Parallel()
	if _, err := submit.New(submit.Deps{}); err == nil {
		t.Fatalf("submit.New with no ports must return an error")
	}
}

// ---- ctx cancellation honored ----

func TestSubmit_ContextCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := newSUT(t, submit.Deps{})
	if _, err := s.Submit(ctx, baseInput()); err == nil {
		t.Fatalf("cancelled context must produce an error")
	}
}
