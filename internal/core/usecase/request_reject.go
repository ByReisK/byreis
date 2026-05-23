package usecase

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
)

// Sentinel errors owned by the reject use-case. Each wraps with %w and carries
// an actionable hint for the CLI layer. No error ever contains the reason text,
// plaintext, ciphertext, or key material.
var (
	// ErrRejectWrongPRType is returned when the PR cannot be classified as a
	// submission or an access-request: the authoritative repo-kind and the
	// branch-prefix corroboration disagree, or the PR matches neither namespace.
	// The use-case closes NOTHING — a tampered branch name cannot coerce a
	// wrong-type close because the repo-kind is stamped by the adapter that owns
	// the connection, not parsed from contributor-controlled text.
	ErrRejectWrongPRType = errors.New(
		"refusing to reject: the PR is neither a recognised submission nor an " +
			"access-request (its source repo and branch prefix disagree, or it " +
			"matches no byreis namespace) — verify you targeted a byreis PR")

	// ErrRejectAlreadyMerged is returned when the target PR is already merged.
	// A merged PR cannot be rejected; no comment is posted (the merge-state check
	// runs before any close or comment).
	ErrRejectAlreadyMerged = errors.New(
		"refusing to reject: the PR is already merged — a merged submission " +
			"cannot be rejected; reverse it through the admin reversal flow instead")

	// ErrRejectReasonUnsafe is returned when the reason fails the core structural
	// constraint: it carries a control byte (other than newline/tab), a Unicode
	// bidi/format override (the Trojan-source class), or exceeds the length cap.
	// This is the fail-closed backstop for any non-CLI caller; the CLI sanitises
	// the reason before constructing the input.
	ErrRejectReasonUnsafe = errors.New(
		"refusing to reject: the reason contains control or bidirectional " +
			"override characters, or exceeds the length limit — provide a plain " +
			"single-paragraph reason")
)

// maxRejectReasonBytes is the core-side cap on the reason length, aligned to the
// CLI sanitiser's cap. The reason is posted to a world-readable PR comment, so
// it is bounded both at the CLI and here as a fail-closed backstop.
const maxRejectReasonBytes = 2000

// RepoKind identifies which repository a PR was fetched through. It is the
// authoritative PR-type signal: the adapter that performed the fetch stamps it,
// so a contributor-controlled branch name cannot forge it.
type RepoKind int

const (
	// RepoKindRegistry marks a PR fetched from the admin registry repo — the
	// repo that carries access-request PRs.
	RepoKindRegistry RepoKind = iota
	// RepoKindProject marks a PR fetched from a project secrets repo — the repo
	// that carries submission PRs.
	RepoKindProject
)

// RejectInput carries the inputs for a single Reject call.
type RejectInput struct {
	// Ref identifies the target PR.
	Ref git.PRRef
	// Reason is the close reason. The CLI sanitises it before constructing the
	// input; the use-case re-asserts a core structural constraint before any
	// adapter call. The reason is posted to a PUBLIC PR comment and is NEVER
	// stored in the audit event.
	Reason string
	// NonInteractive reflects BYREIS_NON_INTERACTIVE: an empty reason fails closed
	// rather than prompting or posting an empty comment.
	NonInteractive bool
}

// RejectResult is returned by a successful (or idempotent) Reject.
type RejectResult struct {
	// PR is the canonical owner/repo#number reference.
	PR string
	// URL is the PR URL when the adapter supplies one; empty otherwise.
	URL string
	// Status is "closed" on a fresh close or "already-closed" when the PR was
	// already closed (idempotent, no duplicate comment).
	Status string
	// Reason is the sanitised reason echoed back for the caller's confirmation.
	Reason string
}

// RejectPRState is the typed PR state the closer returns for fail-closed
// validation before the use-case authorises a close.
type RejectPRState struct {
	// Merged is true when the PR has already been merged.
	Merged bool
	// Closed is true when the PR is already closed.
	Closed bool
	// BranchName is the PR head branch, used as secondary corroboration of the
	// PR type. It MUST agree with SourceRepo.
	BranchName string
	// Labels are the PR labels (currently advisory; not load-bearing for type
	// dispatch, which is repo-bound).
	Labels []string
	// SourceRepo is the AUTHORITATIVE PR-type signal, stamped by the adapter that
	// fetched the state: the registry-repo reader stamps RepoKindRegistry, the
	// project-repo reader stamps RepoKindProject. A branch name cannot forge it.
	SourceRepo RepoKind
}

// PRCloser is the narrow write port the reject use-case depends on. It performs
// EXACTLY two operations: post a comment and close a PR. It exposes no
// file/ref/content write, no counter advance, and no registry-trust write.
type PRCloser interface {
	// FetchPRStateForReject returns the typed state needed for fail-closed
	// validation (merged? closed? branch prefix for type dispatch). The stamped
	// SourceRepo is the authoritative type signal.
	FetchPRStateForReject(ctx context.Context, ref git.PRRef) (RejectPRState, error)
	// CloseWithComment posts the (already-validated) reason then closes the PR.
	CloseWithComment(ctx context.Context, ref git.PRRef, sanitizedReason string) error
}

// RejectDeps bundles the injected ports for the Reject use-case. The set is
// deliberately narrow: the PR-close port, the mode gate, and the audit sink.
// There is no IDLoader, Decryptor, or CounterStore here — the reject path has no
// route to private-key, decrypt, or counter-advance capability by construction.
type RejectDeps struct {
	Closer PRCloser
	Mode   ModeGate
	Audit  audit.Logger
}

// RequestRejecter is the consumer-defined port for the admin reject use-case.
// PR-close-ONLY: it closes a PR and posts a comment. It NEVER loads identity,
// decrypts, or touches any trust/counter store.
type RequestRejecter interface {
	// Reject closes the target PR with the given reason. ADMIN-only: the mode
	// gate denies it before any network contact in CONTRIBUTOR mode.
	Reject(ctx context.Context, in RejectInput) (RejectResult, error)
}

type rejectUseCase struct {
	d RejectDeps
}

// NewRequestRejecter returns a RequestRejecter. All collaborators are injected;
// a nil audit sink falls back to the no-op discard.
func NewRequestRejecter(d RejectDeps) (RequestRejecter, error) {
	if d.Closer == nil || d.Mode == nil {
		return nil, errors.New(
			"usecase.NewRequestRejecter: a required port is nil — wire Closer and Mode")
	}
	if d.Audit == nil {
		d.Audit = audit.Discard
	}
	return &rejectUseCase{d: d}, nil
}

// Reject closes a request/submission PR with a structured reason. The order is
// a strict, fail-closed chain:
//
//  1. Mode gate (ADMIN-only) — denied before any network contact.
//  2. Reason structural constraint (control bytes / bidi overrides / length) +
//     non-interactive empty-reason refusal.
//  3. Fetch the typed PR state through the repo-bound closer.
//  4. PR-type dispatch: repo-kind (authoritative) AND branch prefix must agree.
//  5. Merge-state check BEFORE any comment (merged → refuse; closed → idempotent).
//  6. Close the PR with the reason as a PUBLIC comment.
//  7. Build the reject audit event (reason structurally ABSENT — reason_len only),
//     validate it, and append; a validation failure is surfaced loudly (the close
//     already happened, so it is non-fatal to the close but never silently dropped).
func (u *rejectUseCase) Reject(ctx context.Context, in RejectInput) (RejectResult, error) {
	if err := ctx.Err(); err != nil {
		return RejectResult{}, fmt.Errorf("reject cancelled: %w", err)
	}

	// (1) Mode gate FIRST: a contributor is denied by policy, not
	// attempted-then-failed. No fetch, comment, or close happens on denial.
	if err := u.d.Mode.Allow(mode.CommandRequestReject); err != nil {
		return RejectResult{}, fmt.Errorf("reject not permitted: %w", err)
	}

	// (2) Reason constraints. A non-interactive run with an empty reason fails
	// closed rather than posting an empty comment.
	if in.NonInteractive && strings.TrimSpace(in.Reason) == "" {
		return RejectResult{}, fmt.Errorf(
			"%w: a reason is required when running non-interactively (BYREIS_NON_INTERACTIVE)",
			ErrRejectReasonUnsafe)
	}
	if err := assertReasonSafe(in.Reason); err != nil {
		return RejectResult{}, err
	}

	// (3) Fetch the typed PR state through the repo-bound closer. The closer
	// stamps SourceRepo — the authoritative type signal.
	state, err := u.d.Closer.FetchPRStateForReject(ctx, in.Ref)
	if err != nil {
		return RejectResult{}, fmt.Errorf("fetching PR state for reject failed: %w", err)
	}

	// (4) PR-type dispatch: repo-kind (authoritative) and branch prefix must
	// agree, else fail closed and close NOTHING.
	prType, err := classifyPRType(state)
	if err != nil {
		return RejectResult{}, err
	}

	prRef := fmt.Sprintf("%s#%d", in.Ref.Project, in.Ref.Number)

	// (5) Merge-state check BEFORE any comment.
	if state.Merged {
		return RejectResult{}, fmt.Errorf("%w: %s", ErrRejectAlreadyMerged, prRef)
	}
	if state.Closed {
		// Idempotent: no error, no duplicate comment.
		return RejectResult{
			PR:     prRef,
			Status: "already-closed",
			Reason: in.Reason,
		}, nil
	}

	// (6) Close the PR with the reason as a PUBLIC comment.
	if err := u.d.Closer.CloseWithComment(ctx, in.Ref, in.Reason); err != nil {
		return RejectResult{}, fmt.Errorf("closing the PR failed: %w", err)
	}

	// (7) Audit. The reason is structurally ABSENT — only its byte length is
	// recorded, alongside the closed metadata set. The use-case validates the
	// event itself (the host-local file logger does not) and surfaces a
	// validation failure loudly rather than silently dropping the event.
	//
	// Event.Actor is intentionally left empty here: byreis does not yet resolve
	// a per-action actor identity at the use-case layer — merge, review, and the
	// rotation emitter all leave Actor empty for the same reason. The reject path
	// is also confined away from any private-key/signing capability by
	// construction (RejectDeps carries no identity or signer), so it has no
	// signing-key-label to attribute the close to even if the field were
	// populated. Reject therefore stays consistent with merge; when an
	// actor-identity slice lands a real signing-key-label, every emitter adopts
	// it together. Whatever that future source is, it must never be an age
	// recipient public key — an age key in an audit field is a key leak.
	keyName := ""
	if prType == "submission" {
		keyName = submissionKeyName(state.BranchName)
	}
	ev := audit.Event{
		Kind:    audit.EventKindReject,
		KeyName: keyName,
		Outcome: "ok",
		Details: map[string]string{
			"pr":         prRef,
			"pr_type":    prType,
			"project":    in.Ref.Project,
			"reason_len": strconv.Itoa(len(in.Reason)),
		},
	}
	if vErr := audit.ValidateEventFields(ev); vErr != nil {
		return RejectResult{
				PR:     prRef,
				Status: "closed",
				Reason: in.Reason,
			}, fmt.Errorf(
				"the PR was closed but the reject audit event failed validation and "+
					"was not recorded — investigate the audit-event producer: %w", vErr)
	}
	if aErr := u.d.Audit.Append(ctx, ev); aErr != nil {
		return RejectResult{
				PR:     prRef,
				Status: "closed",
				Reason: in.Reason,
			}, fmt.Errorf(
				"the PR was closed but the reject audit event could not be recorded — "+
					"the close stands; retry to re-emit the audit record: %w", aErr)
	}

	return RejectResult{
		PR:     prRef,
		Status: "closed",
		Reason: in.Reason,
	}, nil
}

// submissionBranchPrefixes are the disjoint submission-PR head-branch prefixes
// (the same set the submission-queue filter uses).
var submissionBranchPrefixes = []string{"byreis/add-", "byreis/replace-", "byreis/bulk-"}

// requestBranchPrefix is the access-request PR head-branch prefix.
const requestBranchPrefix = "requests/"

// classifyPRType derives the PR type from the AUTHORITATIVE repo-kind and
// requires the branch prefix to corroborate it. A mismatch or a PR matching
// neither namespace fails closed with ErrRejectWrongPRType.
func classifyPRType(s RejectPRState) (string, error) {
	switch s.SourceRepo {
	case RepoKindProject:
		if hasSubmissionPrefix(s.BranchName) {
			return "submission", nil
		}
	case RepoKindRegistry:
		if strings.HasPrefix(s.BranchName, requestBranchPrefix) {
			return "access-request", nil
		}
	}
	return "", fmt.Errorf(
		"%w: source repo and branch prefix do not agree on a known PR type",
		ErrRejectWrongPRType)
}

func hasSubmissionPrefix(branch string) bool {
	for _, p := range submissionBranchPrefixes {
		if strings.HasPrefix(branch, p) {
			return true
		}
	}
	return false
}

// submissionKeyName extracts the canonical key name from a submission head
// branch of the form byreis/<add|replace|bulk>-<key>-<timestamp>. The trailing
// -<timestamp> segment is dropped. If the branch does not parse to a
// validator-canonical key name, the empty string is returned so the audit event
// stays validatable rather than carrying a malformed key.
func submissionKeyName(branch string) string {
	rest := ""
	for _, p := range submissionBranchPrefixes {
		if strings.HasPrefix(branch, p) {
			rest = branch[len(p):]
			break
		}
	}
	if rest == "" {
		return ""
	}
	// Drop the trailing -<timestamp> segment.
	if i := strings.LastIndex(rest, "-"); i > 0 {
		rest = rest[:i]
	}
	if !isCanonicalKeyName(rest) {
		return ""
	}
	return rest
}

// isCanonicalKeyName mirrors the audit validator's key-name shape so a parsed
// key name never fails downstream validation.
func isCanonicalKeyName(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// assertReasonSafe is the core-side, render-independent structural constraint on
// the reason: it rejects any C0/C1 control rune (except newline and tab), any
// Unicode bidi/format override (the Trojan-source class), and any over-length
// reason. This is the fail-closed backstop for non-CLI callers; the CLI's full
// terminal sanitiser is the primary scrubber.
func assertReasonSafe(reason string) error {
	if len(reason) > maxRejectReasonBytes {
		return fmt.Errorf(
			"%w: reason is %d bytes, limit is %d",
			ErrRejectReasonUnsafe, len(reason), maxRejectReasonBytes)
	}
	for _, r := range reason {
		if isUnsafeReasonRune(r) {
			return fmt.Errorf(
				"%w: reason contains a disallowed control or bidi-override character (U+%04X)",
				ErrRejectReasonUnsafe, r)
		}
	}
	return nil
}

// isUnsafeReasonRune reports whether r is a C0/C1 control byte (other than \n
// and \t) or a Unicode bidirectional/format override in the Trojan-source class.
func isUnsafeReasonRune(r rune) bool {
	switch r {
	case '\n', '\t':
		return false
	}
	// C0 controls (U+0000–U+001F) and DEL (U+007F).
	if r < 0x20 || r == 0x7F {
		return true
	}
	// C1 controls (U+0080–U+009F).
	if r >= 0x80 && r <= 0x9F {
		return true
	}
	// Trojan-source bidirectional/format override class. Listed by explicit code
	// point so the disallowed set is auditable rather than relying on invisible
	// literal characters in source.
	switch r {
	case 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // LRE RLE PDF LRO RLO
		0x2066, 0x2067, 0x2068, 0x2069, // LRI RLI FSI PDI
		0x200E, 0x200F, // LRM RLM
		0x061C: // ALM
		return true
	}
	return false
}

// Compile-time assertion.
var _ RequestRejecter = (*rejectUseCase)(nil)
