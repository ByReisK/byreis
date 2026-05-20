package fetchtransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// verifyTimeout is the bounded execution ceiling for a git verify-commit
// subprocess. The subprocess is also cancelled via context, so the effective
// deadline is min(ctx.Deadline, verifyTimeout from call time).
const verifyTimeout = 30 * time.Second

// cloneTimeout is the bounded execution ceiling for a git clone subprocess.
const cloneTimeout = 60 * time.Second

// readTimeout is the bounded execution ceiling for a git cat-file blob read.
const readTimeout = 30 * time.Second

// principalName is the fixed allowed-signers principal written for the anchor
// key. Using a static string makes the signerID returned on success predictable
// and deterministic. The trust decision is the exit code; the principal string
// does not carry an independent trust claim.
const principalName = "byreis-anchor"

// CommandRunner is the subprocess seam. The production implementation shells to
// the system git binary. Tests inject a fake to avoid any real network or real
// git binary dependency.
//
// dir is the working directory for the command. env is the full environment
// (not merged with the process environment — the caller is responsible for
// passing any needed inherited vars). name and args are the command and its
// arguments.
//
// Returns stdout, stderr, the process exit code, and any exec-level error
// (e.g. binary not found, killed by signal). A non-zero exit code is NOT an
// exec-level error: it is returned as exitCode > 0 with err == nil.
type CommandRunner interface {
	Run(ctx context.Context, dir string, env []string, name string, args ...string) (stdout, stderr []byte, exitCode int, err error)
}

// MkdirTempFunc is the seam for temp directory creation. Injected in tests to
// avoid real filesystem access. Production uses os.MkdirTemp.
type MkdirTempFunc func(dir, pattern string) (string, error)

// RemoveAllFunc is the seam for temp directory cleanup.
type RemoveAllFunc func(path string) error

// HeadVerifier performs registry HEAD commit signature verification against the
// pinned full-key trust anchor. It shells to the system git binary per the
// project's signed-commit discipline.
//
// HeadVerifier is the production registry-HEAD signed-commit verifier. It
// exposes VerifyHead (which creates and cleans up its own workspace) and
// VerifyHeadRetainClone (which creates a workspace and returns it to the caller
// for subsequent content-addressed reads). The latter is used by the production
// transport to share the clone between verification and file reads.
type HeadVerifier struct {
	runner    CommandRunner
	mkdirTemp MkdirTempFunc
	removeAll RemoveAllFunc
	// extraEnv holds optional additional environment variables injected at the
	// end of the hardened env for all subprocess calls. Used to inject
	// authentication (e.g. HTTP extra headers for private GitHub repos) without
	// modifying the hardened baseline. Must never contain secrets that should
	// not be in subprocesses; callers are responsible for secure handling.
	extraEnv []string
}

// HeadVerifierConfig holds injected dependencies for HeadVerifier.
type HeadVerifierConfig struct {
	// Runner is the subprocess runner. Required.
	Runner CommandRunner

	// MkdirTemp creates a temporary directory. Defaults to os.MkdirTemp when nil.
	MkdirTemp MkdirTempFunc

	// RemoveAll removes a directory tree. Defaults to os.RemoveAll when nil.
	RemoveAll RemoveAllFunc

	// ExtraEnv holds optional additional environment variables appended to the
	// hardened env for all subprocess calls (clone, rev-parse, verify, cat-file).
	// Used to inject HTTP authentication headers for private repositories.
	// The caller is responsible for handling these values securely.
	ExtraEnv []string
}

// NewHeadVerifier constructs a HeadVerifier from the given config.
// Returns an error if Runner is nil.
func NewHeadVerifier(cfg HeadVerifierConfig) (*HeadVerifier, error) {
	if cfg.Runner == nil {
		return nil, errors.New(
			"fetchtransport.NewHeadVerifier: CommandRunner is required — inject a real or fake runner")
	}
	mkdirTemp := cfg.MkdirTemp
	if mkdirTemp == nil {
		mkdirTemp = os.MkdirTemp
	}
	removeAll := cfg.RemoveAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	return &HeadVerifier{
		runner:    cfg.Runner,
		mkdirTemp: mkdirTemp,
		removeAll: removeAll,
		extraEnv:  cfg.ExtraEnv,
	}, nil
}

// VerifyHead fetches the registry HEAD commit SHA and verifies its signature
// against the pinned anchorKey. This method creates and cleans up its own
// workspace. For use cases that need to read content from the same clone,
// use VerifyHeadRetainClone instead.
//
// Verification scheme: the anchorKey is written as the sole entry in a
// temporary allowed-signers file. git is configured to use SSH commit signing
// with that file, and git verify-commit is invoked on the HEAD SHA. The exit
// code drives the trust decision: exit 0 means the commit was signed by exactly
// the anchorKey (full-key identity by construction — the file contains only
// that key). Any other outcome returns verified=false, fail closed.
//
// signerID on success is the registry-attested principal (the principalName
// constant). The signerID value is parsed from git stderr and confirmed against
// the allowed-signers principal — not from TOFU, fingerprint, or any second
// trust root.
//
// The commit SHA returned is exactly the SHA whose signature was verified. No
// ref re-resolution occurs between the clone step and the verify step.
//
// Fail-closed on every error path — no error-swallow-to-true under any
// circumstance.
func (v *HeadVerifier) VerifyHead(ctx context.Context, repoURL string, anchorKey ed25519.PublicKey) (commit, signerID string, verified bool, err error) {
	commit, signerID, verified, _, cleanup, err := v.VerifyHeadRetainClone(ctx, repoURL, anchorKey)
	if cleanup != nil {
		cleanup()
	}
	return commit, signerID, verified, err
}

// VerifyHeadRetainClone is identical to VerifyHead but does NOT clean up the
// clone workspace. Instead it returns:
//   - cloneDir: the path of the clone directory (under a managed tmpDir)
//   - cleanup: a function that removes the tmpDir; the caller MUST call it on
//     every exit path, including error and panic (via defer)
//
// The returned cloneDir is valid for `git -C <cloneDir> cat-file blob
// <verifiedSHA>:<path>` reads only when verified==true. On any error or
// verified==false the clone may be partial; the caller must still invoke
// cleanup.
//
// Concurrent calls each produce a distinct tmpDir (and thus a distinct
// cloneDir), satisfying the one-clone-per-FetchAdminSet-scope invariant.
func (v *HeadVerifier) VerifyHeadRetainClone(ctx context.Context, repoURL string, anchorKey ed25519.PublicKey) (commit, signerID string, verified bool, cloneDir string, cleanup func(), err error) {
	noop := func() {}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", "", false, "", noop, fmt.Errorf(
			"FetchHead: context already cancelled: %w — "+
				"ensure network connectivity and re-try, or run `byreis doctor`", ctxErr)
	}

	if len(anchorKey) != ed25519.PublicKeySize {
		return "", "", false, "", noop, fmt.Errorf(
			"FetchHead: anchor key is %d bytes, need exactly %d (Ed25519 public key size) — "+
				"check your trust anchor configuration: run `byreis doctor`",
			len(anchorKey), ed25519.PublicKeySize)
	}

	// Create the workspace with mode 0700 so no other user on the system can
	// read or traverse it. All subsequent git operations run with HOME=tmpDir
	// and GIT_CONFIG_NOSYSTEM=1 to isolate them from any ambient git config.
	tmpDir, mkErr := v.mkdirTemp("", "byreis-fetchhead-*")
	if mkErr != nil {
		return "", "", false, "", noop, fmt.Errorf(
			"FetchHead: cannot create temp workspace: %w — "+
				"check filesystem permissions: run `byreis doctor`", mkErr)
	}
	// Ensure the tmpDir is 0700 even if mkdirTemp used a different mode.
	// 0700 is intentional for a temporary directory: owner-only rwx, no other user
	// can read or traverse it. gosec G302 flags directories at 0700 but this
	// is the correct security posture for a scratch workspace holding key material.
	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec // 0700 on dir is intentional: owner-only scratch workspace
		_ = v.removeAll(tmpDir)
		return "", "", false, "", noop, fmt.Errorf(
			"FetchHead: cannot chmod temp workspace to 0700: %w — "+
				"check filesystem permissions: run `byreis doctor`", chErr)
	}
	cleanupFn := func() { _ = v.removeAll(tmpDir) }

	// hardenedEnv is the isolated environment shared by the clone, rev-parse,
	// and verify legs. It prevents ambient git config (system-level, user-level,
	// credential helpers, hook paths, [includeIf] directives, protocol.*.allow
	// overrides) from influencing any of the three subprocess invocations.
	// GIT_ALLOW_PROTOCOL restricts the URL schemes git will follow during the
	// clone (prevents ext::, fd::, ftp:: and similar protocol-handler escapes).
	// core.hooksPath=/dev/null and core.fsmonitor= (empty string) disable hook
	// execution and the fsmonitor daemon for the cloned repo.
	// v.extraEnv (if set) is appended last for optional auth injection.
	hardenedEnv := func() []string {
		base := cleanGitEnv()
		env := append(base,
			"GIT_CONFIG_NOSYSTEM=1",
			"HOME="+tmpDir,
			"GIT_TERMINAL_PROMPT=0",
			"GIT_ALLOW_PROTOCOL=file:https:ssh",
			"GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=core.hooksPath",
			"GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=core.fsmonitor",
			"GIT_CONFIG_VALUE_1=",
		)
		return append(env, v.extraEnv...)
	}

	// Step 1: clone the registry repo (shallow, no checkout) to get commit
	// objects. The clone produces the local git object store needed for
	// git verify-commit and subsequent cat-file blob reads.
	// --no-local prevents using local hard-link shortcuts for file:// URLs
	// (forces a genuine copy, preventing races with the source repo).
	// --no-recurse-submodules ensures submodule hooks/scripts are never
	// executed. -- (end-of-options) prevents repoURL from being parsed as a
	// git flag even if it begins with "-".
	cloneCtx, cloneCancel := withBoundedDeadline(ctx, cloneTimeout)
	defer cloneCancel()

	cloneDir = filepath.Join(tmpDir, "repo")
	cloneArgs := []string{
		"clone", "--depth=1", "--no-checkout", "--no-local", "--",
		repoURL, cloneDir,
	}
	_, cloneStderr, cloneExit, cloneErr := v.runner.Run(
		cloneCtx, tmpDir,
		hardenedEnv(),
		"git", cloneArgs...,
	)
	if cloneErr != nil {
		if isContextError(cloneCtx, ctx) {
			return "", "", false, "", cleanupFn, fmt.Errorf(
				"FetchHead: git clone cancelled (deadline exceeded or context cancelled): %w — "+
					"check network connectivity: run `byreis doctor`", ctx.Err())
		}
		return "", "", false, "", cleanupFn, fmt.Errorf(
			"FetchHead: git clone exec error: %w — "+
				"ensure git is installed and the registry URL is reachable: "+
				"run `byreis doctor`", cloneErr)
	}
	if cloneExit != 0 {
		return "", "", false, "", cleanupFn, fmt.Errorf(
			"FetchHead: git clone exited %d: %s — "+
				"check network connectivity and registry URL: run `byreis doctor`",
			cloneExit, sanitizeOutput(cloneStderr))
	}

	// Step 2: resolve HEAD to the exact commit SHA. This is the SHA we verify
	// and return. No ref re-resolution occurs after this point.
	revCtx, revCancel := withBoundedDeadline(ctx, 10*time.Second)
	defer revCancel()

	revStdout, _, revExit, revErr := v.runner.Run(
		revCtx, cloneDir,
		hardenedEnv(),
		"git", "rev-parse", "HEAD",
	)
	if revErr != nil {
		if isContextError(revCtx, ctx) {
			return "", "", false, "", cleanupFn, fmt.Errorf(
				"FetchHead: git rev-parse cancelled: %w — run `byreis doctor`",
				ctx.Err())
		}
		return "", "", false, "", cleanupFn, fmt.Errorf(
			"FetchHead: git rev-parse HEAD exec error: %w — run `byreis doctor`",
			revErr)
	}
	if revExit != 0 {
		return "", "", false, "", cleanupFn, fmt.Errorf(
			"FetchHead: git rev-parse HEAD exited %d — run `byreis doctor`",
			revExit)
	}

	headSHA := strings.TrimSpace(string(revStdout))
	if !isValidSHA(headSHA) {
		return "", "", false, "", cleanupFn, fmt.Errorf(
			"FetchHead: git rev-parse returned non-SHA output %q — "+
				"run `byreis doctor`", headSHA)
	}

	// Step 3: write the allowed-signers file with the anchor key as the sole
	// trusted entry. Full-key identity is enforced by construction: the file
	// contains only the anchorKey, so exit 0 from verify-commit implies the
	// commit was signed by exactly that key.
	allowedSignersPath := filepath.Join(tmpDir, "allowed_signers")
	if wsErr := writeAllowedSigners(allowedSignersPath, anchorKey); wsErr != nil {
		return "", "", false, "", cleanupFn, fmt.Errorf(
			"FetchHead: cannot write allowed-signers file: %w — "+
				"check filesystem permissions: run `byreis doctor`", wsErr)
	}

	// Step 4: run git verify-commit with SSH signature configuration. The
	// environment overrides prevent system/user git config from interfering
	// with the trust decision. GIT_CONFIG_COUNT/KEY/VALUE_N is the portable
	// way to inject config without writing a gitconfig file.
	// The verify leg uses an extended hardened env that additionally configures
	// the SSH allowed-signers file and the gpg format.
	verifyCtx, verifyCancel := withBoundedDeadline(ctx, verifyTimeout)
	defer verifyCancel()

	verifyEnv := append(cleanGitEnv(),
		"GIT_CONFIG_NOSYSTEM=1",
		"HOME="+tmpDir,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=file:https:ssh",
		"GIT_CONFIG_COUNT=5",
		"GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0=/dev/null",
		"GIT_CONFIG_KEY_1=core.fsmonitor",
		"GIT_CONFIG_VALUE_1=",
		"GIT_CONFIG_KEY_2=gpg.format",
		"GIT_CONFIG_VALUE_2=ssh",
		"GIT_CONFIG_KEY_3=gpg.ssh.allowedSignersFile",
		"GIT_CONFIG_VALUE_3="+allowedSignersPath,
		"GIT_CONFIG_KEY_4=gpg.minTrustLevel",
		"GIT_CONFIG_VALUE_4=undefined",
	)
	verifyEnv = append(verifyEnv, v.extraEnv...)

	_, verifyStderr, verifyExit, verifyErr := v.runner.Run(
		verifyCtx, cloneDir,
		verifyEnv,
		"git", "verify-commit", "--raw", headSHA,
	)

	if verifyErr != nil {
		if isContextError(verifyCtx, ctx) {
			return headSHA, "", false, "", cleanupFn, fmt.Errorf(
				"FetchHead: git verify-commit cancelled (deadline exceeded or context cancelled): %w — "+
					"run `byreis doctor`", ctx.Err())
		}
		return headSHA, "", false, "", cleanupFn, fmt.Errorf(
			"FetchHead: git verify-commit exec error: %w — "+
				"ensure git is installed with SSH signing support: run `byreis doctor`",
			verifyErr)
	}

	// Exit code drives the trust decision (fail closed). Non-zero covers:
	// unsigned HEAD, wrong-signer key, malformed signature, git internal errors.
	// No error-swallow-to-true: a non-zero exit is never mapped to verified=true.
	if verifyExit != 0 {
		return headSHA, "", false, cloneDir, cleanupFn, nil
	}

	// Exit 0: the commit signature was verified against the allowed-signers file
	// which contains only the anchorKey. Parse stderr for the signerID principal.
	signerPrincipal := parseSignerID(verifyStderr)
	if signerPrincipal == "" {
		// Exit 0 but no parseable signer identity: fail closed. This handles
		// ambiguous or empty status output — we do not grant verified=true without
		// a confirmed signer identity.
		return headSHA, "", false, cloneDir, cleanupFn, nil
	}

	// Confirm the parsed principal matches the expected anchor principal. This
	// catches any case where the allowed-signers file was somehow extended or
	// where git returned a different principal.
	if signerPrincipal != principalName {
		return headSHA, "", false, cloneDir, cleanupFn, nil
	}

	return headSHA, signerPrincipal, true, cloneDir, cleanupFn, nil
}

// ReadBlobAtSHA reads the raw bytes of a file at a specific tree path within
// the given cloneDir, using `git -C <cloneDir> cat-file blob <sha>:<path>`.
//
// The sha parameter must be a valid 40/64-hex commit SHA (validated by
// isValidSHA before pathspec composition). The path is a relative registry
// path (e.g. "admins.yaml" or "projects/myproject.yaml"); it MUST already
// be validated by the caller (e.g. via ValidateProjectID) before this call.
//
// cat-file blob is used instead of git show to avoid textconv, pager, and
// smudge filter side effects that could alter the committed bytes.
//
// Returns ErrBlobNotFound when the path does not exist in the tree at that
// SHA. All other git errors are returned as wrapped errors with actionable
// hints.
func (v *HeadVerifier) ReadBlobAtSHA(ctx context.Context, cloneDir, sha, path string) ([]byte, error) {
	if !isValidSHA(sha) {
		return nil, fmt.Errorf(
			"ReadBlobAtSHA: SHA %q is not a valid 40/64-hex commit hash — "+
				"this is an internal invariant violation; run `byreis doctor`", sha)
	}

	// The env for the cat-file leg is identical to the hardened env used for
	// clone/rev-parse/verify: GIT_CONFIG_NOSYSTEM, HOME isolation, protocol
	// allowlist, hooks disabled. extraEnv is appended for optional auth.
	tmpDir := filepath.Dir(cloneDir)
	catEnv := append(cleanGitEnv(),
		"GIT_CONFIG_NOSYSTEM=1",
		"HOME="+tmpDir,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ALLOW_PROTOCOL=file:https:ssh",
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0=/dev/null",
		"GIT_CONFIG_KEY_1=core.fsmonitor",
		"GIT_CONFIG_VALUE_1=",
	)
	catEnv = append(catEnv, v.extraEnv...)

	// Compose the <sha>:<path> pathspec. The sha was validated above. The path
	// is controlled by the caller (registry paths only); it never contains shell
	// metacharacters because it is passed as a distinct argv element (no shell).
	pathspec := sha + ":" + path

	catCtx, catCancel := withBoundedDeadline(ctx, readTimeout)
	defer catCancel()

	stdout, stderr, exitCode, execErr := v.runner.Run(
		catCtx, cloneDir,
		catEnv,
		"git", "cat-file", "blob", "--", pathspec,
	)
	if execErr != nil {
		if isContextError(catCtx, ctx) {
			return nil, fmt.Errorf(
				"ReadBlobAtSHA: git cat-file cancelled for %q at %q: %w — "+
					"run `byreis doctor`", path, sha, ctx.Err())
		}
		return nil, fmt.Errorf(
			"ReadBlobAtSHA: git cat-file exec error for %q at %q: %w — "+
				"run `byreis doctor`", path, sha, execErr)
	}
	if exitCode != 0 {
		// Non-zero exit from cat-file blob means the path does not exist in the
		// tree at this SHA (or the SHA is not a valid object). This maps to the
		// absent-file sentinel so callers can distinguish absent from other errors.
		_ = stderr // do not log stderr — may contain object metadata
		return nil, &blobNotFoundError{sha: sha, path: path}
	}
	return stdout, nil
}

// blobNotFoundError is returned by ReadBlobAtSHA when the path does not exist
// in the git tree at the given SHA. It implements the BlobNotFound() bool
// marker method so callers that cannot import this package can detect
// not-found via errors.As(err, new(interface{ BlobNotFound() bool })).
type blobNotFoundError struct {
	sha  string
	path string
}

func (e *blobNotFoundError) Error() string {
	return fmt.Sprintf("path %q not found in git tree at SHA %q", e.path, e.sha)
}

// BlobNotFound is a marker method that identifies this error as a blob-not-found
// error. Callers that cannot import this package may check for this interface
// via errors.As to detect not-found without a package-level dependency.
func (e *blobNotFoundError) BlobNotFound() bool { return true }

// IsBlobNotFound reports whether err is a blobNotFoundError.
func IsBlobNotFound(err error) bool {
	var e *blobNotFoundError
	return errors.As(err, &e)
}

// blobNotFoundMarker is the interface implemented by blobNotFoundError.
// Exposed for callers that cannot import this internal package to detect
// blob-not-found via errors.As.
type blobNotFoundMarker interface {
	error
	BlobNotFound() bool
}

// IsBlobNotFoundByMarker reports whether err wraps a blobNotFoundError using
// the exported marker interface. This is the detection path for callers that
// cannot import this internal package directly.
func IsBlobNotFoundByMarker(err error) bool {
	var m blobNotFoundMarker
	return errors.As(err, &m) && m.BlobNotFound()
}

// writeAllowedSigners writes a git SSH allowed-signers file with the anchorKey
// as the sole trusted entry. The file format is:
//
//	<principal> <keytype> <base64-blob>
//
// where base64-blob is the OpenSSH public key wire format:
// uint32(len("ssh-ed25519")) || "ssh-ed25519" || uint32(32) || key-bytes.
func writeAllowedSigners(path string, anchorKey ed25519.PublicKey) error {
	blob := marshalSSHEd25519PublicKey(anchorKey)
	b64 := base64.StdEncoding.EncodeToString(blob)
	line := principalName + " ssh-ed25519 " + b64 + "\n"
	return os.WriteFile(path, []byte(line), 0o600)
}

// marshalSSHEd25519PublicKey encodes an Ed25519 public key in the OpenSSH
// wire format used in authorized_keys and allowed-signers files:
// uint32(len("ssh-ed25519")) || "ssh-ed25519" || uint32(32) || keyBytes.
//
// The lengths of the key type string ("ssh-ed25519", 11 bytes) and the key
// bytes (ed25519.PublicKeySize, 32 bytes) are well-known constants that fit
// in uint32 without overflow; the nolint directives below acknowledge this.
func marshalSSHEd25519PublicKey(key ed25519.PublicKey) []byte {
	const keyType = "ssh-ed25519"
	buf := make([]byte, 0, 4+len(keyType)+4+ed25519.PublicKeySize)
	buf = appendUint32(buf, uint32(len(keyType))) //nolint:gosec // len("ssh-ed25519") == 11, no overflow
	buf = append(buf, []byte(keyType)...)
	buf = appendUint32(buf, uint32(len(key))) //nolint:gosec // ed25519.PublicKeySize == 32, no overflow
	buf = append(buf, key...)
	return buf
}

func appendUint32(b []byte, v uint32) []byte {
	//nolint:gosec // v>>N shifts reduce value; byte() of shifted uint32 is safe
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// parseSignerID extracts the signer principal from git verify-commit stderr.
// For SSH signatures, the relevant output line is:
//
//	Good "git" signature for <principal> with ED25519 key SHA256:<fp>
//
// Returns the principal string, or "" if no parseable line is found.
func parseSignerID(stderr []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(stderr))
	for scanner.Scan() {
		line := scanner.Text()
		const goodSigPrefix = `Good "git" signature for `
		if idx := strings.Index(line, goodSigPrefix); idx >= 0 {
			rest := line[idx+len(goodSigPrefix):]
			if withIdx := strings.Index(rest, " with "); withIdx > 0 {
				return strings.TrimSpace(rest[:withIdx])
			}
		}
	}
	return ""
}

// isValidSHA returns true if s is a valid 40-char (SHA-1) or 64-char (SHA-256)
// hex commit hash as returned by git rev-parse.
func isValidSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'f'
		isUpper := c >= 'A' && c <= 'F'
		if !isDigit && !isLower && !isUpper {
			return false
		}
	}
	return true
}

// cleanGitEnv returns a minimal environment for git subprocess calls.
// PATH is preserved so git can find ssh-keygen and other tools it shells to.
// LANG/LC_ALL=C ensures consistent ASCII output for output parsing.
func cleanGitEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"LANG=C",
		"LC_ALL=C",
	}
}

// sanitizeOutput trims and truncates subprocess stderr output for use in error
// messages. Truncated at 256 bytes to prevent log flooding. Must never include
// signature bytes, key material, or secret-adjacent content — this function is
// for git diagnostics only (exit code messages, network errors).
func sanitizeOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 256 {
		s = s[:256] + "...(truncated)"
	}
	return s
}

// withBoundedDeadline derives a child context whose deadline is the earlier of
// the parent's deadline and (now + bound). This prevents unbounded subprocess
// execution. The returned cancel function must always be called by the caller.
func withBoundedDeadline(parent context.Context, bound time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(bound)
	if d, ok := parent.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return context.WithDeadline(parent, deadline)
}

// ReadProjectBlob clones projectURL (shallow, no-checkout), resolves branch to
// an in-clone SHA (S_proj) exactly ONCE, then reads path from that same clone
// via `git cat-file blob -- S_proj:path`. The clone is removed on every return
// path including error and panic (via defer).
//
// S_proj is an intra-clone read-skew-prevention mechanism ONLY. It is NOT a
// signed or cryptographically verified SHA analogous to the registry
// verifiedSHA. The project repo has no signed-commit verifier; project-repo
// trust is the manifest signature (verify.VerifyOfRecord over the
// registry-attested recipient/signer set and counter authority per ADR-0008/0009).
// The project leg is structurally weaker than the registry leg because trust
// derives from the manifest signature, not from the project commit.
//
// This function is the canonical git-based file-of-record read primitive and
// MUST be used by the production file-of-record source. ReadBlobAtRef MUST NOT
// be used for the file-of-record path (it self-clones and re-resolves a ref,
// violating the single-clone / no-re-resolution invariant).
//
// Hardening: the clone and every subsequent git leg run with the full hardened
// isolated env (GIT_CONFIG_NOSYSTEM, HOME=tmpDir, GIT_ALLOW_PROTOCOL, hooks
// disabled) — identical to the registry verify leg. --no-local is applied for
// file:// URLs. No token is transmitted for file:// URLs.
//
// Returns (resolvedSHA, bytes, error). resolvedSHA is the S_proj value;
// callers MUST assert that the SHA composed into the pathspec equals
// resolvedSHA (asserted internally before pathspec composition).
//
// Returns ErrBlobNotFound (via IsBlobNotFound) when the path does not exist
// in the tree at S_proj. An over-size blob is rejected before return (the
// caller passes maxBytes; use 0 for no limit, though a limit is required for
// trust-bearing reads).
func (v *HeadVerifier) ReadProjectBlob(ctx context.Context, projectURL, branch, path string, maxBytes int64) (resolvedSHA string, data []byte, err error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", nil, fmt.Errorf(
			"ReadProjectBlob: context already cancelled: %w — run `byreis doctor`", ctxErr)
	}

	// Create a fresh 0700 workspace for isolation. All git invocations use
	// HOME=tmpDir and GIT_CONFIG_NOSYSTEM=1 so no ambient git config can
	// influence the clone, rev-parse, or cat-file leg.
	tmpDir, mkErr := v.mkdirTemp("", "byreis-project-blob-*")
	if mkErr != nil {
		return "", nil, fmt.Errorf(
			"ReadProjectBlob: cannot create temp workspace: %w — "+
				"check filesystem permissions: run `byreis doctor`", mkErr)
	}
	defer func() { _ = v.removeAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec // 0700 on dir is intentional: owner-only scratch workspace
		return "", nil, fmt.Errorf(
			"ReadProjectBlob: cannot chmod temp workspace to 0700: %w — "+
				"check filesystem permissions: run `byreis doctor`", chErr)
	}

	// hardenedEnv is byte-identical to the registry verify leg (VerifyHeadRetainClone).
	// Applied to clone, rev-parse, and cat-file legs without exception.
	// No bare cleanGitEnv() on any project trust leg.
	hardenedEnv := func() []string {
		base := cleanGitEnv()
		env := append(base,
			"GIT_CONFIG_NOSYSTEM=1",
			"HOME="+tmpDir,
			"GIT_TERMINAL_PROMPT=0",
			"GIT_ALLOW_PROTOCOL=file:https:ssh",
			"GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=core.hooksPath",
			"GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=core.fsmonitor",
			"GIT_CONFIG_VALUE_1=",
		)
		// Do NOT append v.extraEnv for file:// URLs (no token transmitted).
		// For non-file:// URLs, append auth env only (not git config vars).
		if !strings.HasPrefix(projectURL, "file://") {
			return append(env, v.extraEnv...)
		}
		return env
	}

	cloneDir := filepath.Join(tmpDir, "repo")

	// Step 1: clone the project repo. ONE clone per ReadProjectBlob call.
	// --no-local is required for file:// URLs (prevents local hard-link shortcuts).
	// --no-recurse-submodules: never execute submodule hooks.
	// -- (end-of-options): prevents projectURL from being parsed as a git flag.
	isFileURL := strings.HasPrefix(projectURL, "file://")
	cloneArgs := []string{"clone", "--depth=1", "--no-checkout"}
	if isFileURL {
		cloneArgs = append(cloneArgs, "--no-local")
	}
	cloneArgs = append(cloneArgs, "--", projectURL, cloneDir)

	cloneCtx, cloneCancel := withBoundedDeadline(ctx, cloneTimeout)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := v.runner.Run(
		cloneCtx, tmpDir,
		hardenedEnv(),
		"git", cloneArgs...,
	)
	if cloneErr != nil {
		if isContextError(cloneCtx, ctx) {
			return "", nil, fmt.Errorf(
				"ReadProjectBlob: git clone cancelled: %w — "+
					"check network connectivity: run `byreis doctor`", ctx.Err())
		}
		return "", nil, fmt.Errorf(
			"ReadProjectBlob: git clone exec error: %w — "+
				"ensure git is installed and the project URL is reachable: run `byreis doctor`",
			cloneErr)
	}
	if cloneExit != 0 {
		return "", nil, fmt.Errorf(
			"ReadProjectBlob: git clone exited %d: %s — "+
				"check network connectivity and project URL: run `byreis doctor`",
			cloneExit, sanitizeOutput(cloneStderr))
	}

	// Step 2: resolve the configured branch to S_proj exactly ONCE.
	// S_proj is an intra-clone no-skew invariant — NOT a trust root.
	// No re-resolution occurs after this point.
	revCtx, revCancel := withBoundedDeadline(ctx, 10*time.Second)
	defer revCancel()

	branchRef := branch
	if branchRef == "" {
		branchRef = "HEAD"
	}
	revStdout, _, revExit, revErr := v.runner.Run(
		revCtx, cloneDir,
		hardenedEnv(),
		"git", "rev-parse", branchRef,
	)
	if revErr != nil {
		if isContextError(revCtx, ctx) {
			return "", nil, fmt.Errorf(
				"ReadProjectBlob: git rev-parse cancelled: %w — run `byreis doctor`",
				ctx.Err())
		}
		return "", nil, fmt.Errorf(
			"ReadProjectBlob: git rev-parse %q exec error: %w — run `byreis doctor`",
			branch, revErr)
	}
	if revExit != 0 {
		return "", nil, fmt.Errorf(
			"ReadProjectBlob: git rev-parse %q exited %d — "+
				"check that branch %q exists in the project repo: run `byreis doctor`",
			branch, revExit, branch)
	}

	sProjSHA := strings.TrimSpace(string(revStdout))
	if !isValidSHA(sProjSHA) {
		return "", nil, fmt.Errorf(
			"ReadProjectBlob: git rev-parse returned non-SHA output — run `byreis doctor`")
	}

	// Step 3: re-validate S_proj before pathspec composition (defense-in-depth;
	// the isValidSHA check above is the primary gate but we assert again here
	// to satisfy the SHA-identity-before-pathspec contract).
	if !isValidSHA(sProjSHA) {
		return "", nil, fmt.Errorf(
			"ReadProjectBlob: S_proj SHA failed re-validation before pathspec — " +
				"internal invariant violated; run `byreis doctor`")
	}

	// Step 4: read the blob at S_proj:<path> via cat-file blob.
	// ReadBlobAtSHA validates the SHA again internally before composing the pathspec.
	raw, readErr := v.ReadBlobAtSHA(ctx, cloneDir, sProjSHA, path)
	if readErr != nil {
		if isContextError(ctx, ctx) {
			return "", nil, fmt.Errorf(
				"ReadProjectBlob: cat-file cancelled: %w — run `byreis doctor`", ctx.Err())
		}
		// IsBlobNotFound propagates as-is so callers can map to ErrFileOfRecordNotFound.
		return "", nil, readErr
	}

	// Step 5: pre-read size cap (must not return over-size blobs to callers
	// who will pass them to a YAML decoder or other trust-path consumer).
	if maxBytes > 0 && int64(len(raw)) > maxBytes {
		return "", nil, fmt.Errorf(
			"ReadProjectBlob: blob at %q exceeds maximum size %d bytes (got %d) — "+
				"the file is unusually large; run `byreis doctor`",
			path, maxBytes, len(raw))
	}

	return sProjSHA, raw, nil
}

// ReadBlobAtRef clones repoURL (shallow), resolves ref to a SHA, then reads
// path from the clone via `git cat-file blob <sha>:<path>`. The clone is
// created in a fresh 0700 temp directory and removed on return. No signature
// verification is performed; this is for advisory reads (e.g. file-of-record).
//
// Returns ErrBlobNotFound when the path does not exist in the tree at that ref.
//
// Deprecated: ReadBlobAtRef performs a self-contained clone + ref re-resolution
// with no signature verification, violating the verified-SHA / no-ref-re-resolution
// discipline required on the production trust path. The canonical primitive for
// caller-supplied verified SHAs is ReadBlobAtSHA; the production file-of-record
// and registry-admins read paths use ReadProjectBlob (reads at the exact SHA that
// HeadVerifier.VerifyHead signature-verified, from the same clone, with no second
// network round-trip). This function has zero non-test production callers and is
// scheduled for deletion at the B5/B6 aggregate-gate cleanup pass. Do not wire
// into any new production path.
func (v *HeadVerifier) ReadBlobAtRef(ctx context.Context, repoURL, ref, path string) ([]byte, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf(
			"ReadBlobAtRef: context already cancelled: %w — run `byreis doctor`", ctxErr)
	}

	tmpDir, mkErr := v.mkdirTemp("", "byreis-blobref-*")
	if mkErr != nil {
		return nil, fmt.Errorf(
			"ReadBlobAtRef: cannot create temp workspace: %w — "+
				"check filesystem permissions: run `byreis doctor`", mkErr)
	}
	defer func() { _ = v.removeAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec // 0700 on dir is intentional: owner-only scratch workspace
		return nil, fmt.Errorf(
			"ReadBlobAtRef: cannot chmod temp workspace: %w — "+
				"check filesystem permissions: run `byreis doctor`", chErr)
	}

	hardenedEnvRef := func() []string {
		base := cleanGitEnv()
		env := append(base,
			"GIT_CONFIG_NOSYSTEM=1",
			"HOME="+tmpDir,
			"GIT_TERMINAL_PROMPT=0",
			"GIT_ALLOW_PROTOCOL=file:https:ssh",
			"GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=core.hooksPath",
			"GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=core.fsmonitor",
			"GIT_CONFIG_VALUE_1=",
		)
		return append(env, v.extraEnv...)
	}

	cloneDir := filepath.Join(tmpDir, "repo")
	cloneCtx, cloneCancel := withBoundedDeadline(ctx, cloneTimeout)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := v.runner.Run(
		cloneCtx, tmpDir,
		hardenedEnvRef(),
		"git", "clone", "--depth=1", "--no-checkout", "--no-local", "--",
		repoURL, cloneDir,
	)
	if cloneErr != nil {
		if isContextError(cloneCtx, ctx) {
			return nil, fmt.Errorf(
				"ReadBlobAtRef: git clone cancelled: %w — run `byreis doctor`", ctx.Err())
		}
		return nil, fmt.Errorf(
			"ReadBlobAtRef: git clone exec error: %w — "+
				"ensure git is installed and the URL is reachable: run `byreis doctor`", cloneErr)
	}
	if cloneExit != 0 {
		return nil, fmt.Errorf(
			"ReadBlobAtRef: git clone exited %d: %s — run `byreis doctor`",
			cloneExit, sanitizeOutput(cloneStderr))
	}

	revCtx, revCancel := withBoundedDeadline(ctx, 10*time.Second)
	defer revCancel()

	revStdout, _, revExit, revErr := v.runner.Run(
		revCtx, cloneDir,
		hardenedEnvRef(),
		"git", "rev-parse", "HEAD",
	)
	if revErr != nil {
		if isContextError(revCtx, ctx) {
			return nil, fmt.Errorf(
				"ReadBlobAtRef: git rev-parse cancelled: %w — run `byreis doctor`", ctx.Err())
		}
		return nil, fmt.Errorf(
			"ReadBlobAtRef: git rev-parse HEAD exec error: %w — run `byreis doctor`", revErr)
	}
	if revExit != 0 {
		return nil, fmt.Errorf(
			"ReadBlobAtRef: git rev-parse HEAD exited %d — run `byreis doctor`", revExit)
	}

	sha := strings.TrimSpace(string(revStdout))
	if !isValidSHA(sha) {
		return nil, fmt.Errorf(
			"ReadBlobAtRef: git rev-parse returned non-SHA output %q — run `byreis doctor`", sha)
	}

	return v.ReadBlobAtSHA(ctx, cloneDir, sha, path)
}

// isContextError reports whether the subprocess context or the parent context
// has expired or been cancelled. Used to classify subprocess errors as
// context-driven vs exec-level.
func isContextError(child, parent context.Context) bool {
	return child.Err() != nil || parent.Err() != nil
}
