package usecase_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/identity"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// --- shared test doubles for review + merge ---

type stubGit struct {
	sub           git.Submission
	subErr        error
	getCalls      int
	merge         git.MergeResult
	mergeErr      error
	mergeCalls    int
	gotMerge      git.MergeInput
	rollbackCalls int
	gotRollback   git.RollbackInput
	rollbackErr   error
	commentBodies []string
}

func (g *stubGit) OpenSubmissionPR(context.Context, git.OpenPRInput) (git.PullRequest, error) {
	return git.PullRequest{}, errors.New("OpenSubmissionPR not used in review/merge tests")
}

func (g *stubGit) GetSubmission(_ context.Context, _ git.PRRef) (git.Submission, error) {
	g.getCalls++
	if g.subErr != nil {
		return git.Submission{}, g.subErr
	}
	return g.sub, nil
}

func (g *stubGit) MergeSubmission(_ context.Context, in git.MergeInput) (git.MergeResult, error) {
	g.mergeCalls++
	g.gotMerge = in
	if g.mergeErr != nil {
		return g.merge, g.mergeErr
	}
	return g.merge, nil
}

func (g *stubGit) RollbackSignedFile(_ context.Context, in git.RollbackInput) error {
	g.rollbackCalls++
	g.gotRollback = in
	return g.rollbackErr
}

func (g *stubGit) CommentPR(_ context.Context, _ git.PRRef, body string) error {
	g.commentBodies = append(g.commentBodies, body)
	return nil
}

// stubDecryptor returns a fixed plaintext map and records the artifact it was
// handed (proving review/merge decrypt the artifact, never the PR diff).
type stubDecryptor struct {
	out         map[string]string
	err         error
	gotArtifact artifact.Signed
	calls       int
}

func (d *stubDecryptor) Decrypt(
	_ context.Context, art artifact.Signed, _ identity.Identity,
) (map[string]string, error) {
	d.calls++
	d.gotArtifact = art
	if d.err != nil {
		return nil, d.err
	}
	out := make(map[string]string, len(d.out))
	for k, v := range d.out {
		out[k] = v
	}
	return out, nil
}

func (d *stubDecryptor) RoundTripAll(context.Context, artifact.Signed, []identity.Identity) error {
	return nil
}

type stubIDLoader struct {
	id  identity.Identity
	err error
}

func (l *stubIDLoader) Load(context.Context) (identity.Identity, error) {
	return l.id, l.err
}

// modeGate wires the real mode.Policy so denial is the genuine policy sentinel.
type modeGate struct{ m mode.Mode }

func (g modeGate) Allow(cmd mode.Command) error {
	return (&mode.Policy{}).Allow(g.m, cmd)
}

// stubCodec decodes artifact bytes into fixed artifacts and records inputs.
type stubCodec struct {
	signed       artifact.Signed
	unsigned     artifact.Unsigned
	decodeSErr   error
	decodeUErr   error
	encodeOut    []byte
	encodeErr    error
	gotEncodeArt artifact.Signed
	encodeCalls  int
}

func (c *stubCodec) DecodeSigned([]byte) (artifact.Signed, error) {
	if c.decodeSErr != nil {
		return artifact.Signed{}, c.decodeSErr
	}
	return c.signed, nil
}

func (c *stubCodec) DecodeUnsigned([]byte) (artifact.Unsigned, error) {
	if c.decodeUErr != nil {
		return artifact.Unsigned{}, c.decodeUErr
	}
	return c.unsigned, nil
}

func (c *stubCodec) EncodeSigned(s artifact.Signed) ([]byte, error) {
	c.encodeCalls++
	c.gotEncodeArt = s
	if c.encodeErr != nil {
		return nil, c.encodeErr
	}
	if c.encodeOut != nil {
		return c.encodeOut, nil
	}
	return []byte("signed-on-disk-bytes"), nil
}

func newTestIdentity(t *testing.T) (identity.Identity, *age.X25519Identity) {
	t.Helper()
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	id, err := identity.Parse(x.String())
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	return id, x
}

// T1: Review decrypts the value(s) from the fetched ARTIFACT bytes, never the
// PR diff/description.
func TestReview_DecryptsFromArtifactBytesNotPRDiff(t *testing.T) {
	t.Parallel()

	wantArt := artifact.Signed{
		Values: map[string]artifact.EncryptedValue{"API_KEY": "real-ciphertext-blob"},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1",
			ProjectID:     "proj", File: "prod", Counter: 1,
		},
	}
	dec := &stubDecryptor{out: map[string]string{"API_KEY": "s3cr3t-from-artifact"}}
	g := &stubGit{sub: git.Submission{
		Ref:           git.PRRef{Project: "proj", Number: 7},
		Author:        "alice",
		Justification: "PR body falsely claims API_KEY=ATTACKER-VALUE-IN-DIFF",
		ArtifactBytes: []byte("byreis:\n  format_version: byreis.native.v1\n"),
		ArtifactSHA:   "pin-unsigned-abc",
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml", Key: "API_KEY", Action: "add"}, //nolint:gosec // G101 false positive: "API_KEY" is a key NAME, not a credential value
	}}
	id, _ := newTestIdentity(t)

	r, err := usecase.NewReviewer(usecase.ReviewDeps{
		Git:           g,
		Decryptor:     dec,
		IDLoader:      &stubIDLoader{id: id},
		ArtifactCodec: &stubCodec{signed: wantArt},
		Mode:          modeGate{m: mode.ModeAdmin},
	})
	if err != nil {
		t.Fatalf("NewReviewer: %v", err)
	}

	res, err := r.Review(context.Background(), usecase.ReviewInput{
		Ref: git.PRRef{Project: "proj", Number: 7}, ExpectedProjectID: "proj", ExpectedFileName: "prod",
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if dec.calls != 1 {
		t.Fatalf("decryptor calls = %d, want 1", dec.calls)
	}
	// The decryptor must have been handed the artifact decoded from the fetched
	// bytes, NOT the PR description text.
	if _, ok := dec.gotArtifact.Values["API_KEY"]; !ok {
		t.Fatalf("decryptor was not handed the decoded artifact")
	}
	if got := res.Plaintext["API_KEY"]; got != "s3cr3t-from-artifact" {
		t.Fatalf("plaintext = %q, want the value decrypted from the artifact", got)
	}
	if strings.Contains(res.Plaintext["API_KEY"], "ATTACKER-VALUE-IN-DIFF") {
		t.Fatalf("review trusted the PR description instead of the artifact bytes")
	}
	if res.PinnedSHA != "pin-unsigned-abc" {
		t.Fatalf("PinnedSHA = %q, want the S_unsigned pin over the fetched bytes", res.PinnedSHA)
	}
	if res.Author != "alice" {
		t.Fatalf("Author = %q, want alice", res.Author)
	}
}

// Mode: Review is DENIED by policy in CONTRIBUTOR mode (denied, not
// attempted-then-failed) — no git fetch or decrypt is reached.
func TestReview_DeniedInContributorMode(t *testing.T) {
	t.Parallel()

	dec := &stubDecryptor{}
	g := &stubGit{}
	id, _ := newTestIdentity(t)
	r, err := usecase.NewReviewer(usecase.ReviewDeps{
		Git:           g,
		Decryptor:     dec,
		IDLoader:      &stubIDLoader{id: id},
		ArtifactCodec: &stubCodec{},
		Mode:          modeGate{m: mode.ModeContributor},
	})
	if err != nil {
		t.Fatalf("NewReviewer: %v", err)
	}

	_, err = r.Review(context.Background(), usecase.ReviewInput{
		Ref: git.PRRef{Project: "proj", Number: 7}, ExpectedProjectID: "proj", ExpectedFileName: "prod",
	})
	if !errors.Is(err, mode.ErrPermissionDenied) {
		t.Fatalf("Review in contributor mode err = %v, want ErrPermissionDenied", err)
	}
	if g.getCalls != 0 {
		t.Fatalf("git.GetSubmission called %d times despite denied mode", g.getCalls)
	}
	if dec.calls != 0 {
		t.Fatalf("decryptor entered %d times despite denied mode", dec.calls)
	}
}

// Review must NOT approve from the diff when the artifact cannot be decoded:
// it is a hard refusal, not a fall-back to the PR body.
func TestReview_UndecodableArtifactIsHardRefusal(t *testing.T) {
	t.Parallel()

	dec := &stubDecryptor{out: map[string]string{"K": "v"}}
	g := &stubGit{sub: git.Submission{
		Ref:           git.PRRef{Project: "proj", Number: 1},
		ArtifactBytes: []byte("not-an-artifact"),
		ArtifactSHA:   "x",
		Meta:          git.SubmissionMeta{SchemaVersion: 1},
	}}
	id, _ := newTestIdentity(t)
	r, _ := usecase.NewReviewer(usecase.ReviewDeps{
		Git:       g,
		Decryptor: dec,
		IDLoader:  &stubIDLoader{id: id},
		ArtifactCodec: &stubCodec{
			decodeSErr: errors.New("bad signed"),
			decodeUErr: errors.New("bad unsigned"),
		},
		Mode: modeGate{m: mode.ModeAdmin},
	})
	_, err := r.Review(context.Background(), usecase.ReviewInput{
		Ref: git.PRRef{Project: "proj", Number: 1}, ExpectedProjectID: "proj", ExpectedFileName: "prod",
	})
	if !errors.Is(err, usecase.ErrReviewDecode) {
		t.Fatalf("err = %v, want ErrReviewDecode", err)
	}
	if dec.calls != 0 {
		t.Fatalf("decrypt attempted on an undecodable artifact (calls=%d)", dec.calls)
	}
}

// stubValueValidator validates per-key values for the review per-key display.
// It marks any key whose decrypted value contains "BAD" as invalid.
type stubValueValidator struct{ calls int }

func (v *stubValueValidator) ValidateKeyName(string) error { return nil }

func (v *stubValueValidator) ValidateValue(value string) error {
	v.calls++
	if strings.Contains(value, "BAD") {
		return errors.New("value failed policy")
	}
	return nil
}

// Review of a bulk (v2) PR produces a per-key view in file order, each line
// carrying its own action and a per-key validation result.
func TestReview_BulkV2_PerKeyView(t *testing.T) {
	t.Parallel()

	wantArt := artifact.Signed{
		Values: map[string]artifact.EncryptedValue{
			"DATABASE_URL": "ct1",
			"API_TOKEN":    "ct2",
		},
		Byreis: artifact.Metadata{FormatVersion: "byreis.native.v1", ProjectID: "proj", File: "prod", Counter: 1},
	}
	dec := &stubDecryptor{out: map[string]string{
		"DATABASE_URL": "postgres://ok",
		"API_TOKEN":    "tok-BAD-value",
	}}
	g := &stubGit{sub: git.Submission{
		Ref:           git.PRRef{Project: "proj", Number: 9},
		Author:        "carol",
		ArtifactBytes: []byte("byreis:\n"),
		ArtifactSHA:   "pin-bulk",
		Meta: git.SubmissionMeta{
			SchemaVersion: 2,
			SecretsPath:   "secrets/prod.yaml",
			Keys: []git.KeyAction{
				{Key: "DATABASE_URL", Action: "add"},
				{Key: "API_TOKEN", Action: "replace"},
			},
		},
	}}
	id, _ := newTestIdentity(t)
	val := &stubValueValidator{}

	r, err := usecase.NewReviewer(usecase.ReviewDeps{
		Git:           g,
		Decryptor:     dec,
		IDLoader:      &stubIDLoader{id: id},
		ArtifactCodec: &stubCodec{signed: wantArt},
		Mode:          modeGate{m: mode.ModeAdmin},
		Validator:     val,
	})
	if err != nil {
		t.Fatalf("NewReviewer: %v", err)
	}

	res, err := r.Review(context.Background(), usecase.ReviewInput{
		Ref: git.PRRef{Project: "proj", Number: 9}, ExpectedProjectID: "proj", ExpectedFileName: "prod",
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}

	if len(res.PerKey) != 2 {
		t.Fatalf("PerKey len = %d, want 2 (%+v)", len(res.PerKey), res.PerKey)
	}
	// File order preserved.
	if res.PerKey[0].Key != "DATABASE_URL" || res.PerKey[1].Key != "API_TOKEN" {
		t.Fatalf("PerKey order not preserved: %+v", res.PerKey)
	}
	// Per-key action.
	if res.PerKey[0].Action != "add" || res.PerKey[1].Action != "replace" {
		t.Fatalf("PerKey actions wrong: %+v", res.PerKey)
	}
	// Per-key validation: DATABASE_URL ok, API_TOKEN fails.
	if !res.PerKey[0].ValidationOK {
		t.Errorf("DATABASE_URL should validate OK")
	}
	if res.PerKey[1].ValidationOK {
		t.Errorf("API_TOKEN should fail validation")
	}
	if res.PerKey[1].ValidationMsg == "" {
		t.Errorf("a failed key must carry a validation message")
	}
	if val.calls != 2 {
		t.Errorf("validator should run once per key, got %d", val.calls)
	}
	// The validation message must never leak the plaintext value.
	for _, line := range res.PerKey {
		if strings.Contains(line.ValidationMsg, "tok-BAD-value") || strings.Contains(line.ValidationMsg, "postgres://ok") {
			t.Fatalf("validation message leaked plaintext: %q", line.ValidationMsg)
		}
	}
}

// A v1 single-key PR still produces a one-element PerKey view (back-compat),
// and the legacy scalar Action/Key fields remain populated.
func TestReview_V1_PerKeyView_OneElement(t *testing.T) {
	t.Parallel()

	wantArt := artifact.Signed{
		Values: map[string]artifact.EncryptedValue{"API_KEY": "ct"},
		Byreis: artifact.Metadata{FormatVersion: "byreis.native.v1", ProjectID: "proj", File: "prod", Counter: 1},
	}
	dec := &stubDecryptor{out: map[string]string{"API_KEY": "s3cr3t"}}
	g := &stubGit{sub: git.Submission{
		Ref:           git.PRRef{Project: "proj", Number: 3},
		ArtifactBytes: []byte("byreis:\n"),
		ArtifactSHA:   "pin",
		Meta:          git.SubmissionMeta{SchemaVersion: 1, SecretsPath: "secrets/prod.yaml", Key: "API_KEY", Action: "add"}, //nolint:gosec // G101 false positive: key NAME
	}}
	id, _ := newTestIdentity(t)
	r, _ := usecase.NewReviewer(usecase.ReviewDeps{
		Git:           g,
		Decryptor:     dec,
		IDLoader:      &stubIDLoader{id: id},
		ArtifactCodec: &stubCodec{signed: wantArt},
		Mode:          modeGate{m: mode.ModeAdmin},
	})
	res, err := r.Review(context.Background(), usecase.ReviewInput{
		Ref: git.PRRef{Project: "proj", Number: 3}, ExpectedProjectID: "proj", ExpectedFileName: "prod",
	})
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if len(res.PerKey) != 1 || res.PerKey[0].Key != "API_KEY" || res.PerKey[0].Action != "add" {
		t.Fatalf("v1 PerKey = %+v, want one {API_KEY add}", res.PerKey)
	}
	// With no validator wired, a key is reported OK (not asserted).
	if !res.PerKey[0].ValidationOK {
		t.Errorf("with no validator wired, key should report OK")
	}
	// Legacy scalar fields remain populated for back-compat.
	if res.Action != "add" || res.Key != "API_KEY" {
		t.Errorf("legacy scalar fields: action=%q key=%q", res.Action, res.Key)
	}
}
