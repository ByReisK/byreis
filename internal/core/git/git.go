// Package git defines the GitProvider interface (consumer-defined) and domain
// types for the git hosting integration. NO GitHub SDK types appear here.
// The concrete implementation lives in internal/adapter/git/github.
package git

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

// ArtifactSHA is the sha256 over the exact, untransformed byte sequence of an
// artifact file as fetched from or pushed to git, with zero normalization. Two
// files that "mean the same YAML" but differ by one byte have different SHAs by
// design — that is what makes the review-to-merge content pin meaningful.
//
// Adapters must not re-marshal or normalize before computing this hash.
type ArtifactSHA string

// SubmitAction classifies a submission as Add or Replace.
// The action is determined by whether the key already exists in the live file.
type SubmitAction int

const (
	// ActionAdd is used when the key does not exist in the current live file.
	ActionAdd SubmitAction = iota
	// ActionReplace is used when the key already exists (explicit ack required).
	ActionReplace
)

// PRRef identifies a pull request within a project repository.
type PRRef struct {
	Project string // e.g. "myorg/my-app-secrets"
	Number  int
}

// PullRequest is the result of opening a submission PR.
type PullRequest struct {
	Ref         PRRef
	URL         string
	Branch      string
	ArtifactSHA ArtifactSHA // SHA of the exact pushed artifact bytes
}

// KeyAction is one per-key entry of a bulk (v2) submission: a key name and its
// own add-vs-replace action. The two are an indivisible unit so a key can never
// drift apart from its action. Display / write-path-selection metadata only;
// never a crypto or authority input.
type KeyAction struct {
	// Key is the secret key name being added or replaced. Display only.
	Key string `json:"key"`
	// Action is "add" or "replace". Display only.
	Action string `json:"action"`
}

// SubmissionMeta is the structured metadata block embedded in the PR body as a
// single fenced byreis-submission block. It is informational for display and
// selects the secrets write path; it is NOT trusted for any crypto or authority
// decision.
//
// Two schema versions are carried:
//
//   - schema_version 1 (single-key): a scalar Key/Action pair.
//   - schema_version 2 (bulk): an ordered Keys array of per-key {key, action}
//     entries. One bulk submission of N pairs is ONE block carrying N Keys
//     entries — never N blocks.
//
// A single binary writes v2 for a bulk (multi-pair) submission and reads both
// versions; a pre-existing v1 PR still decodes. Consumers should read the
// normalised key list via NormalisedKeys, which yields an ordered list for both
// versions (a v1 block becomes a one-element list), so the review/merge spine
// is version-agnostic past the parser boundary.
//
// Carried in the PR body as:
//
//	```byreis-submission
//	{ ... JSON ... }
//	```
//
// The free-text justification surrounding the block is ignored by the parser.
type SubmissionMeta struct {
	// SchemaVersion must equal 1 or 2; any other value is rejected.
	SchemaVersion int `json:"schema_version"`
	// Project is the logical project identifier (e.g. "myorg/proj"). Display only.
	Project string `json:"project"`
	// SecretsPath is the repo-relative target path of the signed file-of-record.
	// This is the ONLY field used for write-path selection by MergeSubmission.
	// It must be lexically valid (no "..", no leading "/", Clean-stable) and
	// cross-checked against the signed logical_file_name at merge time. A bulk
	// submission targets ONE secrets_path for all of its keys.
	SecretsPath string `json:"secrets_path"`
	// BaseFilePath is the repo-relative current live file (informational; equals
	// SecretsPath unless the file is being renamed, which is not currently
	// supported).
	BaseFilePath string `json:"base_file_path"`
	// Key is the secret key being added or replaced (schema_version 1 only).
	// Display only. Empty on a v2 block.
	Key string `json:"key,omitempty"`
	// Action is "add" or "replace" (schema_version 1 only). Display only. Empty
	// on a v2 block.
	Action string `json:"action,omitempty"`
	// Keys is the ordered per-key set of a bulk (schema_version 2) submission, in
	// the contributor's file order. Display / write-path-selection only. Empty on
	// a v1 block.
	Keys []KeyAction `json:"keys,omitempty"`
	// ArtifactSHA is the of-record preimage SHA of the unsigned submission bytes
	// (informational echo only). MUST NOT be used as ExpectSHA or for any crypto
	// pin decision.
	ArtifactSHA string `json:"artifact_sha"`
}

// NormalisedKeys returns the submission's per-key set as an ordered list,
// uniformly across schema versions: a v1 block yields the single {Key, Action}
// as a one-element list; a v2 block yields its Keys array verbatim, in file
// order. Consumers use this to stay version-agnostic.
func (m SubmissionMeta) NormalisedKeys() []KeyAction {
	if m.SchemaVersion == 1 {
		return []KeyAction{{Key: m.Key, Action: m.Action}}
	}
	return m.Keys
}

const submissionMetaFence = "```byreis-submission"
const submissionMetaFenceClose = "```"

// EncodeSubmissionMeta serialises meta as a fenced byreis-submission JSON block
// suitable for embedding in a PR body. The block is surrounded by blank lines
// so human-readable justification text before and after is preserved.
//
// The version-specific fields are omitted when empty (omitempty), so a v1 meta
// emits scalar key/action and a v2 meta emits the keys array — each conforms to
// its version's strict decode shape.
func EncodeSubmissionMeta(meta SubmissionMeta) string {
	b, err := json.Marshal(meta)
	if err != nil {
		// SubmissionMeta contains only basic types; Marshal failure is a
		// programmer error. Return a sentinel block so callers can detect it.
		return submissionMetaFence + "\n{}\n" + submissionMetaFenceClose + "\n"
	}
	var buf bytes.Buffer
	buf.WriteString(submissionMetaFence)
	buf.WriteByte('\n')
	buf.Write(b)
	buf.WriteByte('\n')
	buf.WriteString(submissionMetaFenceClose)
	buf.WriteByte('\n')
	return buf.String()
}

// ParseSubmissionMeta extracts and validates the single byreis-submission
// fenced block from a PR body. It enforces:
//
//   - Exactly one fenced block; zero or >1 is ErrSubmissionMetaInvalid.
//   - schema_version is 1 or 2; any other value is ErrSubmissionMetaInvalid.
//   - No unknown JSON fields (DisallowUnknownFields), top-level AND per keys[i]
//     element.
//   - Per-version strict shape: a v1 block must carry the scalar key/action and
//     no keys array; a v2 block must carry a non-empty keys array and no
//     top-level scalar key/action. Each version is decoded into its own strict
//     target struct so neither shape silently tolerates the other's fields.
//   - SecretsPath and BaseFilePath are lexically valid repo-relative paths:
//     no ".." segment, no leading "/", Clean-stable (equal to path.Clean form).
//
// It does NOT enforce the write-time O_NOFOLLOW/realpath symlink containment
// check (that is enforced at commit time by the merge use-case). It does NOT enforce the
// SecretsPath vs signed logical_file_name cross-check (that is enforced at
// merge time by the adapter/use-case after the signed manifest is available).
func ParseSubmissionMeta(body string) (SubmissionMeta, error) {
	block, err := extractMetaBlock(body)
	if err != nil {
		return SubmissionMeta{}, err
	}

	// First pass: read only the schema_version so each version can then be
	// decoded into its own strict target. A lenient probe struct is used here so
	// a still-unknown shape surfaces as a version error, not a stray-field error.
	var probe struct {
		SchemaVersion int `json:"schema_version"`
	}
	if probeErr := json.Unmarshal([]byte(block), &probe); probeErr != nil {
		return SubmissionMeta{}, fmt.Errorf("%w: JSON decode failed (%v) — "+
			"check that the block is well-formed JSON",
			ErrSubmissionMetaInvalid, probeErr)
	}

	var meta SubmissionMeta
	switch probe.SchemaVersion {
	case 1:
		meta, err = decodeV1(block)
	case 2:
		meta, err = decodeV2(block)
	default:
		return SubmissionMeta{}, fmt.Errorf("%w: schema_version must be 1 or 2, got %d — "+
			"upgrade your byreis client",
			ErrSubmissionMetaInvalid, probe.SchemaVersion)
	}
	if err != nil {
		return SubmissionMeta{}, err
	}

	if err := validateMetaPath("secrets_path", meta.SecretsPath); err != nil {
		return SubmissionMeta{}, err
	}
	if meta.BaseFilePath != "" {
		if err := validateMetaPath("base_file_path", meta.BaseFilePath); err != nil {
			return SubmissionMeta{}, err
		}
	}
	return meta, nil
}

// decodeV1 strictly decodes a schema_version 1 block: scalar key/action, no
// keys array. DisallowUnknownFields rejects a stray keys field against this
// target shape.
func decodeV1(block string) (SubmissionMeta, error) {
	var v1 struct {
		SchemaVersion int    `json:"schema_version"`
		Project       string `json:"project"`
		SecretsPath   string `json:"secrets_path"`
		BaseFilePath  string `json:"base_file_path"`
		Key           string `json:"key"`
		Action        string `json:"action"`
		ArtifactSHA   string `json:"artifact_sha"`
	}
	if err := strictDecode(block, &v1); err != nil {
		return SubmissionMeta{}, err
	}
	return SubmissionMeta{
		SchemaVersion: v1.SchemaVersion,
		Project:       v1.Project,
		SecretsPath:   v1.SecretsPath,
		BaseFilePath:  v1.BaseFilePath,
		Key:           v1.Key,
		Action:        v1.Action,
		ArtifactSHA:   v1.ArtifactSHA,
	}, nil
}

// decodeV2 strictly decodes a schema_version 2 block: an ordered keys array, no
// top-level scalar key/action. DisallowUnknownFields rejects a stray scalar
// key/action against this target shape AND a stray field inside any keys
// element. An empty keys array is rejected (a bulk submission must carry at
// least one key).
func decodeV2(block string) (SubmissionMeta, error) {
	var v2 struct {
		SchemaVersion int         `json:"schema_version"`
		Project       string      `json:"project"`
		SecretsPath   string      `json:"secrets_path"`
		BaseFilePath  string      `json:"base_file_path"`
		Keys          []KeyAction `json:"keys"`
		ArtifactSHA   string      `json:"artifact_sha"`
	}
	if err := strictDecode(block, &v2); err != nil {
		return SubmissionMeta{}, err
	}
	if len(v2.Keys) == 0 {
		return SubmissionMeta{}, fmt.Errorf("%w: a bulk submission must carry at "+
			"least one key in the keys array",
			ErrSubmissionMetaInvalid)
	}
	// Each entry must carry both its key and its own action; a missing field
	// JSON-zero-fills rather than failing decode, so it is checked explicitly.
	// DisallowUnknownFields already rejects a stray field inside an entry.
	for i, ka := range v2.Keys {
		if ka.Key == "" {
			return SubmissionMeta{}, fmt.Errorf("%w: keys[%d] is missing its key name",
				ErrSubmissionMetaInvalid, i)
		}
		if ka.Action != "add" && ka.Action != "replace" {
			return SubmissionMeta{}, fmt.Errorf("%w: keys[%d] (key %q) has action %q; "+
				"each key's action must be \"add\" or \"replace\"",
				ErrSubmissionMetaInvalid, i, ka.Key, ka.Action)
		}
	}
	return SubmissionMeta{
		SchemaVersion: v2.SchemaVersion,
		Project:       v2.Project,
		SecretsPath:   v2.SecretsPath,
		BaseFilePath:  v2.BaseFilePath,
		Keys:          v2.Keys,
		ArtifactSHA:   v2.ArtifactSHA,
	}, nil
}

// strictDecode decodes block into target with DisallowUnknownFields, which
// applies recursively (including to each keys[i] element struct), and maps a
// decode failure to ErrSubmissionMetaInvalid with an actionable hint.
func strictDecode(block string, target any) error {
	dec := json.NewDecoder(strings.NewReader(block))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("%w: JSON decode failed (%v) — "+
			"check that all fields are present for the declared schema_version "+
			"and no extra fields are included",
			ErrSubmissionMetaInvalid, err)
	}
	return nil
}

// validateMetaPath enforces lexical containment for a repo-relative path field:
// no ".." segment, no leading "/", must be Clean-stable (equal to path.Clean form).
func validateMetaPath(field, p string) error {
	if p == "" {
		return fmt.Errorf("%w: %s is empty — a secrets path is required",
			ErrSubmissionMetaInvalid, field)
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("%w: %s %q has a leading slash — "+
			"paths must be repo-relative (no leading /)",
			ErrSubmissionMetaInvalid, field, p)
	}
	// Reject paths containing ".." segments.
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("%w: %s %q contains a '..' segment — "+
				"paths must not escape the repository root",
				ErrSubmissionMetaInvalid, field, p)
		}
	}
	// Enforce Clean-stable: the path must equal its path.Clean form.
	cleaned := path.Clean(p)
	if cleaned != p {
		return fmt.Errorf("%w: %s %q is not in canonical (Clean) form — "+
			"got %q after path.Clean (remove redundant separators or '.' segments)",
			ErrSubmissionMetaInvalid, field, p, cleaned)
	}
	return nil
}

// extractMetaBlock finds exactly one ```byreis-submission ... ``` block in body.
// Returns ErrSubmissionMetaInvalid if zero or more than one block is found.
func extractMetaBlock(body string) (string, error) {
	var blocks []string
	remaining := body
	for {
		startIdx := strings.Index(remaining, submissionMetaFence)
		if startIdx == -1 {
			break
		}
		// Skip past the opening fence line.
		afterFence := remaining[startIdx+len(submissionMetaFence):]
		// The opening fence may have trailing whitespace or a newline.
		nlIdx := strings.IndexByte(afterFence, '\n')
		if nlIdx == -1 {
			// No newline after fence — malformed.
			break
		}
		content := afterFence[nlIdx+1:]
		// Find the closing fence (a line that is exactly "```").
		closeIdx := findClosingFence(content)
		if closeIdx == -1 {
			break
		}
		blocks = append(blocks, strings.TrimSpace(content[:closeIdx]))
		remaining = content[closeIdx:]
	}
	if len(blocks) == 0 {
		return "", fmt.Errorf("%w: no byreis-submission block found in PR body — "+
			"submit must include a machine-parseable block; run `byreis submit` to generate one",
			ErrSubmissionMetaInvalid)
	}
	if len(blocks) > 1 {
		return "", fmt.Errorf("%w: %d byreis-submission blocks found; exactly one is required — "+
			"remove duplicate blocks from the PR body",
			ErrSubmissionMetaInvalid, len(blocks))
	}
	return blocks[0], nil
}

// findClosingFence finds the index in s where a line equal to "```" starts.
// It searches line by line. Returns -1 if not found.
func findClosingFence(s string) int {
	pos := 0
	for pos < len(s) {
		nlIdx := strings.IndexByte(s[pos:], '\n')
		var line string
		var end int
		if nlIdx == -1 {
			line = s[pos:]
			end = len(s)
		} else {
			line = s[pos : pos+nlIdx]
			end = pos + nlIdx + 1
		}
		if strings.TrimRight(line, "\r") == submissionMetaFenceClose {
			return pos
		}
		if nlIdx == -1 {
			break
		}
		pos = end
	}
	return -1
}

// Submission is the result of fetching a submission PR for review.
type Submission struct {
	Ref           PRRef
	Author        string
	Justification string
	// ArtifactBytes is the EXACT untransformed bytes fetched from git.
	ArtifactBytes []byte
	// ArtifactSHA is sha256(ArtifactBytes) over the raw fetched bytes.
	// Adapters must hash the raw fetched buffer, never a re-marshalled form.
	ArtifactSHA ArtifactSHA
	// BaseFileBytes is the current live secrets file bytes (may be empty for first add).
	BaseFileBytes []byte
	// Meta is the parsed SubmissionMeta from the PR body.
	Meta SubmissionMeta
}

// OpenPRInput carries inputs for GitProvider.OpenSubmissionPR.
type OpenPRInput struct {
	Project       string
	Branch        string // byreis/<add|replace>-<key>-<ts> or byreis/bulk-Nkeys-<ts>
	Action        SubmitAction
	Key           string
	ArtifactBytes []byte
	TitleTemplate string
	Justification string
	// SecretsPath is the repo-relative target path for the signed file-of-record.
	// It is written into the SubmissionMeta block in the PR body. It must be
	// lexically valid and is cross-checked against the signed logical_file_name
	// at merge time. It is NOT used for any crypto decision.
	SecretsPath string
	// BaseFilePath is the current live file path (informational; may equal SecretsPath).
	BaseFilePath string
	// Keys is the ordered per-key set for a bulk (schema_version 2) submission. When
	// non-nil and non-empty the adapter MUST encode the SubmissionMeta as v2 (keys
	// array); when nil or empty the adapter encodes v1 (scalar key/action). A nil
	// Keys with a non-empty Key is a single-key submission and is the only valid v1
	// shape. Keys and Key are mutually exclusive: the caller sets only one.
	Keys []KeyAction
}

// MergeInput carries inputs for GitProvider.MergeSubmission.
type MergeInput struct {
	Ref PRRef
	// ExpectSHA is the content pin: MergeSubmission fails closed with
	// ErrArtifactMoved if the on-PR artifact SHA no longer equals this value.
	ExpectSHA ArtifactSHA
	// SignedBytes is the signed file-of-record to commit to the protected
	// secrets path.
	SignedBytes   []byte
	CommitMessage string
	// SecretsPath is the repo-relative target path derived from the parsed
	// SubmissionMeta (already containment-validated and cross-checked against
	// the signed logical_file_name by the use-case). The adapter writes the
	// signed file to this path. It is NOT a crypto or authority input.
	SecretsPath string
	// IdempotencyKey is a deterministic, content-bound resume token derived by
	// the merge use-case as a stable hash over the tuple
	// (Ref, ExpectSHA, ContentSHA(SignedBytes)). It is NOT a random nonce and
	// NOT wall-clock derived: a retry of the same merge re-derives the same
	// key, so MergeSubmission can detect the already-committed signed file
	// (e.g. via a commit trailer) and resume instead of writing a duplicate
	// commit; a different artifact yields a different key and is never
	// confused with a resume. The use-case computes this value; the adapter
	// only consumes it for detect-before-write.
	IdempotencyKey string
}

// MergeResult is returned by MergeSubmission on success.
type MergeResult struct {
	MergedCommit string
	LiveFileSHA  string
	// SignedFileCommitted is true iff the signed file-of-record commit landed
	// on the base branch during this call.
	SignedFileCommitted bool
	// SignedFileCommitSHA is the base-branch commit that wrote the signed file.
	// It identifies the exact commit a rollback would target (see
	// RollbackInput.CommitSHA) and is recorded for audit.
	SignedFileCommitSHA string
	// AlreadyApplied is true iff this MergeInput.IdempotencyKey was already
	// fully applied by a prior attempt, so this call resumed as a no-op for
	// the signed-file write instead of creating a second commit.
	AlreadyApplied bool
}

// RollbackInput binds a rollback request to the registry-side pending identity
// of one specific merge attempt. The adapter must not revert anything unless
// the live base tip is exactly CommitSHA (a built-upon tip is
// ErrRollbackAmbiguous, never a merge-revert across a foreign commit) AND the
// caller has asserted, from the registry pending/CommitBump state (NOT a
// git-side PR-merged signal), that this attempt did not reach CommitBump.
type RollbackInput struct {
	// Ref identifies the submission PR whose signed-file commit is in question.
	Ref PRRef
	// CommitSHA is the exact orphaned signed-file commit from this attempt.
	// RollbackSignedFile reverts only this commit and only when the live base
	// tip equals it.
	CommitSHA string
	// PendingIdentity is the registry-side pending identity of this attempt
	// (the pending.target_artifact_sha / IdempotencyKey recorded write-ahead).
	// The adapter asserts it matches the caller-supplied registry pending
	// state before touching history; a mismatch is a fail-closed precondition
	// failure, never a revert.
	PendingIdentity string
}

// Validate checks the structural invariants RollbackInput owns: every binding
// field must be present. It does NOT — and cannot — verify the live base tip
// or that PendingIdentity matches the registry pending state; those are
// runtime preconditions the adapter enforces against live git and the
// caller-asserted registry state before any history rewrite. A structural
// failure here is terminal: it wraps ErrRollbackAmbiguous so the caller
// surfaces the operator-reconciliation runbook rather than guessing.
func (in RollbackInput) Validate() error {
	if in.Ref.Project == "" {
		return fmt.Errorf("%w: rollback input has an empty project — "+
			"the merge use-case must supply the submission PR project",
			ErrRollbackAmbiguous)
	}
	if in.Ref.Number <= 0 {
		return fmt.Errorf("%w: rollback input has a non-positive PR number %d — "+
			"the merge use-case must supply the submission PR number",
			ErrRollbackAmbiguous, in.Ref.Number)
	}
	if in.CommitSHA == "" {
		return fmt.Errorf("%w: rollback input has an empty commit sha — "+
			"the exact orphaned signed-file commit of this attempt is required; "+
			"reconcile the base branch manually",
			ErrRollbackAmbiguous)
	}
	if in.PendingIdentity == "" {
		return fmt.Errorf("%w: rollback input has an empty pending identity — "+
			"rollback must be bound to the registry pending identity of this "+
			"attempt; reconcile the base branch manually",
			ErrRollbackAmbiguous)
	}
	return nil
}

// Sentinel errors.
var (
	// ErrArtifactMoved is returned by MergeSubmission when the on-PR artifact
	// SHA no longer equals ExpectSHA, i.e. the branch was re-pushed between
	// review and sign. Hard error; the admin must re-run review.
	ErrArtifactMoved = errors.New(
		"artifact has moved since review (branch was re-pushed) — " +
			"re-run `byreis review --pr N` to re-pin the new artifact before merging")

	// ErrSubmissionMetaInvalid is returned by ParseSubmissionMeta when the PR
	// body is missing the byreis-submission block, contains more than one, has
	// unknown fields, an unsupported schema_version, or a path that fails lexical
	// containment. It is also returned by the adapter when the cross-check
	// between SecretsPath and the signed logical_file_name fails.
	// Owned by internal/core/git; wraps with %w and an actionable hint.
	ErrSubmissionMetaInvalid = errors.New(
		"submission PR body is missing or has an invalid byreis-submission block — " +
			"re-submit with `byreis submit` to generate a valid block")

	// ErrInvalidProject is returned by github.NewWithClient when the project
	// string is malformed (not "owner/repo"). Owned by internal/core/git.
	ErrInvalidProject = errors.New(
		"project string must be owner/repo (e.g. myorg/my-secrets) — " +
			"check your byreis configuration")

	// ErrRollbackAmbiguous is returned by RollbackSignedFile (and
	// RollbackInput.Validate) when the tool cannot prove the target commit is
	// the orphaned signed-file commit of this exact attempt: a foreign commit
	// built on top (live base tip != CommitSHA), a pending-identity mismatch,
	// or a structurally incomplete request. It is terminal-manual: byreis
	// refuses to auto-rewrite history it cannot prove, and the operator
	// reconciles the base branch by hand. Owned by internal/core/git; wraps
	// with %w and an operator-runbook hint.
	ErrRollbackAmbiguous = errors.New(
		"signed-file rollback is ambiguous and was refused — byreis will not " +
			"rewrite base-branch history it cannot prove is the orphaned " +
			"signed-file commit of this merge attempt; reconcile the base " +
			"branch manually (compare the base tip against the recorded " +
			"signed-file commit and the registry pending state) before retrying")
)

// GitProvider is the consumer-defined interface for git hosting operations.
// The concrete implementation lives in internal/adapter/git/github.
// GitLab is out of scope.
//
// All methods honor context cancellation/deadlines. All errors wrap with %w.
type GitProvider interface {
	// OpenSubmissionPR creates a branch + commit of the unsigned artifact and
	// opens a PR. It returns the PR and the full artifact content SHA actually
	// pushed (ArtifactSHA) — the content pin for review and merge. The PR body
	// contains a single byreis-submission fenced JSON block encoding the
	// SubmissionMeta (SecretsPath, Key, Action, etc.).
	OpenSubmissionPR(ctx context.Context, in OpenPRInput) (PullRequest, error)

	// GetSubmission fetches the artifact bytes and PR metadata for review. It
	// returns the artifact content SHA (sha256 over the exact untransformed
	// fetched bytes, zero normalization) so review can pin exactly these bytes.
	// It also parses and returns the SubmissionMeta from the PR body.
	// Returns ErrSubmissionMetaInvalid if the block is absent or malformed.
	GetSubmission(ctx context.Context, ref PRRef) (Submission, error)

	// MergeSubmission writes the signed file-of-record to the protected secrets
	// path (from MergeInput.SecretsPath, already containment-validated) and
	// merges, only if the live artifact SHA still equals ExpectSHA.
	// Fails closed with ErrArtifactMoved otherwise. It is detect-before-write
	// on MergeInput.IdempotencyKey: a retry with the same key resumes instead
	// of creating a second signed-file commit (MergeResult.AlreadyApplied).
	MergeSubmission(ctx context.Context, in MergeInput) (MergeResult, error)

	// RollbackSignedFile reverts the signed-file commit identified by
	// in.CommitSHA on the base branch, used only by the merge use-case in the
	// signed-file-committed / PR-merge-failed window. It reverts iff:
	//
	//   (1) the live base tip == in.CommitSHA (no foreign commit built on
	//       top); a built-upon tip is ErrRollbackAmbiguous — never a revert
	//       across, or one that drops, a foreign commit; and
	//   (2) in.PendingIdentity matches the registry-side pending identity for
	//       this attempt (a checked boundary precondition; fail-closed on
	//       mismatch).
	//
	// It is a no-op (returns nil) only when the commit is absent because it
	// was never written. It never reverts a file-of-record after a real PR
	// merge: the merge-state authority is the registry pending/CommitBump
	// state asserted by the caller, never a git-side PR-merged signal. On any
	// ambiguity it returns ErrRollbackAmbiguous and the operator reconciles
	// manually; it never rewrites history beyond the single identified
	// signed-file commit. Read-only callers never invoke this.
	RollbackSignedFile(ctx context.Context, in RollbackInput) error

	// CommentPR posts a comment on the PR (used for review summaries / audit).
	CommentPR(ctx context.Context, ref PRRef, body string) error
}
