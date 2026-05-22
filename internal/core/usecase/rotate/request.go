package rotate

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"go.yaml.in/yaml/v3"
)

// Strict-decoder + validation primitives for request-access YAML payloads.
//
// This file implements the pure validation half of the admin-side
// `byreis rotate --add --from-request <PR>` lift:
//
//   - DecodeRequestAccessYAML parses the canonical `requests/<handle>.yaml`
//     contributor-authored bytes into a typed RequestAccessFile with strict
//     decoder discipline (unknown fields and duplicate keys refused).
//   - ValidateRequestAccess enforces every per-field constraint AND the
//     PR-author-vs-YAML state machine refusing each of the 9 documented
//     impersonation/race modes plus the fork-ownership-change race.
//
// The adapter owns the github-side fetch (GitHub SDK client + path scope check
// + HEAD-SHA pinning); this file owns the domain layer and is exercised via
// in-memory fixtures only — no real network, fs, clock, or SDK contact.

// requestAccessSchemaVersionRE matches the canonical schema_version family.
// v0.2 accepts any non-negative integer suffix in the request_access family;
// future v0.3+ schemas would either bump the family or carry parallel logic.
var requestAccessSchemaVersionRE = regexp.MustCompile(`^byreis\.request_access\.v[0-9]+$`)

// githubLoginCharRE matches the base alphabet of GitHub's canonical login:
// 1–39 chars, ASCII alphanumeric or hyphen. The hyphen-position rules
// (no-leading / no-trailing / no-double) are checked structurally in
// isCanonicalGitHubLogin because Go's RE2 syntax does not support the
// look-ahead expressions GitHub's own rules require.
var githubLoginCharRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}$`)

// maxJustificationBytes pins the BYTE length cap on the contributor-authored
// free-text justification. BYTES (not runes) defeats the rune-counting bypass
// where an attacker probes the cutoff by writing multibyte chars; the value
// is the same threshold the canonical schema documents.
const maxJustificationBytes = 1000

// requestAccessYAML is the wire-format schema for decoding. We use pointer-
// typed required fields so missing keys are reliably distinguishable from
// empty-string values (a contributor cannot smuggle absence by writing the
// empty string explicitly: the field still decodes to a non-nil pointer
// pointing at the empty string, which the per-field validator then rejects).
type requestAccessYAML struct {
	SchemaVersion *string `yaml:"schema_version"`
	GitHubHandle  *string `yaml:"github_handle"`
	AgePubkey     *string `yaml:"age_pubkey"`
	Justification *string `yaml:"justification"`
	RequestedAt   *string `yaml:"requested_at"`
}

// DecodeRequestAccessYAML strict-decodes the on-the-wire YAML bytes into a
// RequestAccessFile. It refuses unknown fields (KnownFields(true)), duplicate
// keys, malformed YAML, missing-required fields, oversized justification, and
// any other shape outside the canonical schema with ErrRequestAccessSchemaInvalid.
//
// The function does NOT validate the cross-field PR-author-vs-YAML
// relationship; ValidateRequestAccess does. Splitting them keeps a clean unit
// test seam between schema-shape failures (decoder-domain) and trust failures
// (state-machine domain).
func DecodeRequestAccessYAML(raw []byte) (RequestAccessFile, error) {
	if len(raw) == 0 {
		return RequestAccessFile{}, fmt.Errorf("%w: payload is empty",
			ErrRequestAccessSchemaInvalid)
	}

	var wire requestAccessYAML
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&wire); err != nil {
		return RequestAccessFile{}, fmt.Errorf(
			"%w: yaml decode failed: %v", ErrRequestAccessSchemaInvalid, err)
	}

	// Reject trailing documents: a contributor could attempt to smuggle a
	// second document past the first via `---` separators.
	var probe map[string]any
	if err := dec.Decode(&probe); err == nil {
		return RequestAccessFile{}, fmt.Errorf(
			"%w: multi-document YAML payloads are not accepted",
			ErrRequestAccessSchemaInvalid)
	}

	// Required fields: every field is required; the YAML schema has no
	// optional keys at v1.
	if wire.SchemaVersion == nil {
		return RequestAccessFile{}, fmt.Errorf(
			"%w: schema_version is required", ErrRequestAccessSchemaInvalid)
	}
	if wire.GitHubHandle == nil {
		return RequestAccessFile{}, fmt.Errorf(
			"%w: github_handle is required", ErrRequestAccessSchemaInvalid)
	}
	if wire.AgePubkey == nil {
		return RequestAccessFile{}, fmt.Errorf(
			"%w: age_pubkey is required", ErrRequestAccessSchemaInvalid)
	}
	if wire.Justification == nil {
		return RequestAccessFile{}, fmt.Errorf(
			"%w: justification is required", ErrRequestAccessSchemaInvalid)
	}
	if wire.RequestedAt == nil {
		return RequestAccessFile{}, fmt.Errorf(
			"%w: requested_at is required", ErrRequestAccessSchemaInvalid)
	}

	file := RequestAccessFile{
		SchemaVersion: *wire.SchemaVersion,
		GitHubHandle:  *wire.GitHubHandle,
		AgePubkey:     *wire.AgePubkey,
		Justification: *wire.Justification,
		RequestedAt:   *wire.RequestedAt,
	}

	// Per-field validation that does not depend on PRMetadata; cross-field
	// trust checks live in ValidateRequestAccess so the two layers stay
	// independent.
	if err := validateSchemaFields(file); err != nil {
		return RequestAccessFile{}, err
	}
	return file, nil
}

// ValidateRequestAccess enforces every constraint required to safely absorb a
// `requests/<handle>.yaml` payload into a rotation: per-field schema
// validation AND the PR-author-vs-YAML state machine that defends against
// impersonation, force-push races, fork-ownership transfer, draft state,
// closed / merged state, deleted / renamed accounts, bot identities, and
// commit-author divergence.
//
// The function is pure; it has no side effects, takes no I/O ports, reads no
// clock or randomness, and returns the first failure encountered (fail-closed;
// callers MUST NOT continue past any non-nil error). ctx is accepted as the
// first parameter for cancellation propagation and future-proofing even though
// no I/O is performed today.
//
// The schema validation half is also run on DecodeRequestAccessYAML for early
// rejection of payloads that never reach this function; that is intentional —
// the strict-decoder lane is the YAML-shape boundary, this function adds the
// cross-field trust assertions. A payload that bypassed the decoder (e.g.,
// constructed in-memory by a future caller) is still defended.
//
//nolint:cyclop // the state-machine enumeration is intentionally a flat, auditable chain
func ValidateRequestAccess(ctx context.Context, file RequestAccessFile, pr PRMetadata) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("request-access validation cancelled: %w", err)
	}

	// Schema half — every payload, regardless of whether it came through the
	// strict decoder, MUST satisfy the per-field constraints.
	if err := validateSchemaFields(file); err != nil {
		return err
	}

	// PR-author state machine — fail-closed across every documented mode.
	// Order matters: PR state validation precedes identity match so an
	// already-merged or draft PR fails with the state-specific sentinel
	// before any identity comparison occurs.
	if pr.State != "open" {
		return fmt.Errorf("%w: observed PR state %q (want open)",
			ErrRequestAccessPRStateInvalid, pr.State)
	}
	if pr.IsDraft {
		return fmt.Errorf("%w: PR is a draft", ErrRequestAccessPRStateInvalid)
	}
	if pr.IsMerged {
		return fmt.Errorf("%w: PR is already merged",
			ErrRequestAccessPRStateInvalid)
	}

	// Bot / Organization PR-author absorption is structurally refused.
	if pr.AuthorType != "" && pr.AuthorType != "User" {
		return fmt.Errorf(
			"%w: PR opener is a %q account (only human User accounts may be absorbed)",
			ErrRequestAccessIdentityMismatch, pr.AuthorType)
	}

	// Deleted-account / anonymous-author refusal. The "ghost" placeholder is a
	// documented GitHub-API canonical string for deleted accounts.
	authorLogin := strings.ToLower(pr.AuthorLogin)
	if authorLogin == "" || authorLogin == "ghost" {
		return fmt.Errorf(
			"%w: PR author login is empty or the GitHub deleted-account placeholder",
			ErrRequestAccessIdentityMismatch)
	}

	// Byte-equal PR-author-vs-YAML compare after lowercase normalisation. The
	// YAML side is gate-refused at schema if it is not already lowercase
	// ASCII, so this is purely the PR-side normalisation (GitHub SDK echoes
	// case-preserved logins).
	if file.GitHubHandle != authorLogin {
		return fmt.Errorf(
			"%w: YAML github_handle %q does not match PR author login %q",
			ErrRequestAccessIdentityMismatch, file.GitHubHandle, authorLogin)
	}

	// Fork-ownership integrity. The head-repo owner login MUST match the
	// PR-author login (the fork is the contributor's own fork); a mismatch
	// indicates a transfer between author-PR-open and admin-fetch.
	headOwner := strings.ToLower(pr.HeadRepoOwnerLogin)
	if headOwner != "" && headOwner != authorLogin {
		return fmt.Errorf(
			"%w: head.repo.owner.login %q differs from PR author %q",
			ErrRequestAccessForkOwnershipChanged, headOwner, authorLogin)
	}

	// Commit-author divergence trip-wire. Every commit on the PR MUST have an
	// author login byte-equal (lowercase-normalised) to the PR opener; any
	// divergence is treated as an impersonation attempt and refused with the
	// divergent commit SHA named for operator forensics.
	for _, c := range pr.Commits {
		got := strings.ToLower(c.AuthorLogin)
		if got != authorLogin {
			return fmt.Errorf(
				"%w: commit %q author login %q differs from PR opener %q",
				ErrRequestAccessCommitAuthorDivergence, c.SHA, got, authorLogin)
		}
	}

	// Commit-body forge trip-wire. The byreis-sig: token is reserved for
	// byreis-authored signed commits; a contributor-authored commit body
	// containing those bytes (case-insensitive) is treated as a forge attempt
	// and refused with the offending commit SHA named for operator forensics.
	// Runs AFTER the divergence loop so the more-specific divergence error
	// wins when both conditions hold simultaneously.
	for _, c := range pr.Commits {
		if strings.Contains(strings.ToLower(c.Body), "byreis-sig:") {
			return fmt.Errorf(
				"%w: commit %q body contains the reserved byreis-sig: token",
				ErrRequestAccessCommitBodyForgery, c.SHA)
		}
	}

	return nil
}

// validateSchemaFields applies every per-field rule to a RequestAccessFile
// regardless of decoder provenance. Used by both DecodeRequestAccessYAML and
// ValidateRequestAccess so a payload constructed in-memory is defended even
// when the decoder lane is bypassed.
func validateSchemaFields(file RequestAccessFile) error {
	if !requestAccessSchemaVersionRE.MatchString(file.SchemaVersion) {
		return fmt.Errorf("%w: schema_version %q does not match %s",
			ErrRequestAccessSchemaInvalid, file.SchemaVersion,
			requestAccessSchemaVersionRE)
	}
	if !isCanonicalGitHubLogin(file.GitHubHandle) {
		return fmt.Errorf(
			"%w: github_handle %q does not match GitHub login alphabet "+
				"(ASCII alphanumeric or hyphen, 1-39 chars, no leading / trailing / double hyphens; lowercase)",
			ErrRequestAccessSchemaInvalid, file.GitHubHandle)
	}
	if !isASCIIPrintable(file.GitHubHandle) {
		return fmt.Errorf(
			"%w: github_handle %q contains non-ASCII bytes",
			ErrRequestAccessSchemaInvalid, file.GitHubHandle)
	}
	if file.AgePubkey == "" {
		return fmt.Errorf("%w: age_pubkey is empty", ErrRequestAccessSchemaInvalid)
	}
	if _, err := age.ParseX25519Recipient(file.AgePubkey); err != nil {
		return fmt.Errorf(
			"%w: age_pubkey is not a canonical age recipient: %v",
			ErrRequestAccessSchemaInvalid, err)
	}
	if len(file.Justification) > maxJustificationBytes {
		return fmt.Errorf(
			"%w: justification length %d bytes exceeds cap %d",
			ErrRequestAccessSchemaInvalid, len(file.Justification), maxJustificationBytes)
	}
	if !utf8.ValidString(file.Justification) {
		return fmt.Errorf("%w: justification is not valid UTF-8",
			ErrRequestAccessSchemaInvalid)
	}
	if file.RequestedAt == "" {
		return fmt.Errorf("%w: requested_at is empty",
			ErrRequestAccessSchemaInvalid)
	}
	if _, err := time.Parse(time.RFC3339, file.RequestedAt); err != nil {
		return fmt.Errorf(
			"%w: requested_at %q does not parse as RFC3339: %v",
			ErrRequestAccessSchemaInvalid, file.RequestedAt, err)
	}
	return nil
}

// isCanonicalGitHubLogin returns true iff s matches GitHub's canonical login
// alphabet exactly: 1–39 ASCII lowercase alphanumeric or hyphen characters,
// first and last chars are alphanumeric, no two consecutive hyphens. RE2 has
// no look-ahead, so the hyphen-position rules are checked structurally.
func isCanonicalGitHubLogin(s string) bool {
	if !githubLoginCharRE.MatchString(s) {
		return false
	}
	if s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '-' && s[i+1] == '-' {
			return false
		}
	}
	return true
}

// isASCIIPrintable returns true iff every byte of s is in [0x21, 0x7E] —
// pure ASCII non-space printable. The handle regex already rejects non-ASCII
// bytes structurally, but the explicit byte check defends against any future
// regex change that might inadvertently let multibyte sequences through.
func isASCIIPrintable(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x21 || b > 0x7E {
			return false
		}
	}
	return true
}
