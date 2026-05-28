// Package signerprobe implements the usecase.SignerProbe port for the registry
// signer discovery flow used by the init use-case.
//
// The adapter clones the registry repo shallowly, reads the raw HEAD commit
// object, parses the embedded OpenSSH signature to extract the committer's
// public key, and returns it as a usecase.ProbedSigner.  This is deliberately
// distinct from VerifyHead: that path requires a key you already trust;
// signerprobe runs before the trust anchor exists and discovers the key so the
// operator can inspect and accept it.
//
// Security posture:
//   - Nothing is trusted on the discovery path: the extracted key is surfaced
//     to the caller (the init use-case) for explicit operator acceptance only.
//   - The clone is ephemeral (temp-dir, removed on every return path).
//   - Auth is injected as GIT_CONFIG extra-header env vars, never as argv or
//     visible in process listings.
//   - Timeouts are bounded per operation; context cancellation is honoured.
//
// Placement: internal/adapter (outward layer).  Core packages never import it.
package signerprobe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ByReisK/byreis/internal/core/usecase"
)

// cloneTimeout is the maximum wall-clock time allowed for the shallow clone.
const cloneTimeout = 60 * time.Second

// catFileTimeout is the maximum wall-clock time allowed for git cat-file.
const catFileTimeout = 15 * time.Second

// CommandRunner is the subprocess seam.  The production implementation uses
// the system git binary.  Tests inject a fake.
//
// Semantics: a non-zero exit code is returned as exitCode > 0 with err == nil.
// An exec-level error (binary not found, killed by signal) is returned as
// err != nil with exitCode 0.
type CommandRunner interface {
	Run(ctx context.Context, dir string, env []string, name string, args ...string) (stdout, stderr []byte, exitCode int, err error)
}

// MkdirTempFunc is the seam for temporary directory creation.
type MkdirTempFunc func(dir, pattern string) (string, error)

// RemoveAllFunc is the seam for directory removal.
type RemoveAllFunc func(path string) error

// Config holds the injected dependencies for Probe.
type Config struct {
	// Runner executes git subprocesses.  Required.
	Runner CommandRunner

	// MkdirTemp creates a temporary directory.  Defaults to os.MkdirTemp.
	MkdirTemp MkdirTempFunc

	// RemoveAll removes a directory tree.  Defaults to os.RemoveAll.
	RemoveAll RemoveAllFunc

	// ExtraEnv holds optional environment variables appended to the hardened
	// baseline for all subprocess calls.  Used to inject HTTP authentication
	// headers for private repositories (e.g. "GIT_CONFIG_KEY_N=…").
	ExtraEnv []string
}

// Probe implements usecase.SignerProbe by cloning the registry repo and
// extracting the commit signer's raw Ed25519 public key from the HEAD commit's
// embedded OpenSSH signature.
type Probe struct {
	runner    CommandRunner
	mkdirTemp MkdirTempFunc
	removeAll RemoveAllFunc
	extraEnv  []string
}

// New constructs a Probe.  Returns an error when Runner is nil.
func New(cfg Config) (*Probe, error) {
	if cfg.Runner == nil {
		return nil, errors.New(
			"signerprobe.New: CommandRunner is required — inject a real or fake runner")
	}
	mkdirTemp := cfg.MkdirTemp
	if mkdirTemp == nil {
		mkdirTemp = os.MkdirTemp
	}
	removeAll := cfg.RemoveAll
	if removeAll == nil {
		removeAll = os.RemoveAll
	}
	return &Probe{
		runner:    cfg.Runner,
		mkdirTemp: mkdirTemp,
		removeAll: removeAll,
		extraEnv:  cfg.ExtraEnv,
	}, nil
}

// RegistrySigner implements usecase.SignerProbe.  It clones the registry repo,
// reads the raw HEAD commit object, parses the embedded OpenSSH signature, and
// returns the signer's raw Ed25519 public key together with its sha256
// fingerprint.
//
// On any failure the clone is removed and a wrapped error is returned; the
// caller (init use-case) surfaces a usecase.ErrRegistryVerifyFailed to the
// operator.  Nothing is written to disk beyond the ephemeral temp directory.
func (p *Probe) RegistrySigner(ctx context.Context, registryURL string) (usecase.ProbedSigner, error) {
	if err := ctx.Err(); err != nil {
		return usecase.ProbedSigner{}, fmt.Errorf("signerprobe: cancelled: %w", err)
	}
	if registryURL == "" {
		return usecase.ProbedSigner{}, fmt.Errorf(
			"signerprobe: registryURL is required — set BYREIS_REGISTRY")
	}

	tmpDir, err := p.mkdirTemp("", "byreis-signerprobe-*")
	if err != nil {
		return usecase.ProbedSigner{}, fmt.Errorf(
			"signerprobe: cannot create temp directory: %w — "+
				"check filesystem permissions; run `byreis doctor`", err)
	}
	cleanup := func() { _ = p.removeAll(tmpDir) }
	defer cleanup()

	cloneDir := tmpDir + "/repo"

	// Step 1: shallow clone (no-checkout minimises network transfer).
	cloneCtx, cloneCancel := withBoundedDeadline(ctx, cloneTimeout)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := p.runner.Run(
		cloneCtx, tmpDir,
		p.hardenedEnv(tmpDir),
		"git", "clone", "--depth=1", "--no-checkout", "--no-local", "--",
		registryURL, cloneDir,
	)
	if cloneErr != nil {
		if isContextErr(cloneCtx, ctx) {
			return usecase.ProbedSigner{}, fmt.Errorf(
				"signerprobe: git clone cancelled (deadline or context): %w — "+
					"check network connectivity; run `byreis doctor`", ctx.Err())
		}
		return usecase.ProbedSigner{}, fmt.Errorf(
			"signerprobe: git clone exec error: %w — "+
				"ensure git is installed and the registry URL is reachable; "+
				"run `byreis doctor`", cloneErr)
	}
	if cloneExit != 0 {
		return usecase.ProbedSigner{}, fmt.Errorf(
			"signerprobe: git clone exited %d: %s — "+
				"ensure the registry URL is reachable and (if private) that "+
				"BYREIS_GITHUB_TOKEN is set; run `byreis doctor`",
			cloneExit, sanitize(cloneStderr))
	}

	// Step 2: read the raw HEAD commit object.
	catCtx, catCancel := withBoundedDeadline(ctx, catFileTimeout)
	defer catCancel()

	rawCommit, _, catExit, catErr := p.runner.Run(
		catCtx, cloneDir,
		p.hardenedEnv(tmpDir),
		"git", "cat-file", "commit", "HEAD",
	)
	if catErr != nil {
		if isContextErr(catCtx, ctx) {
			return usecase.ProbedSigner{}, fmt.Errorf(
				"signerprobe: git cat-file cancelled: %w — run `byreis doctor`", ctx.Err())
		}
		return usecase.ProbedSigner{}, fmt.Errorf(
			"signerprobe: git cat-file exec error: %w — run `byreis doctor`", catErr)
	}
	if catExit != 0 {
		return usecase.ProbedSigner{}, fmt.Errorf(
			"signerprobe: git cat-file exited %d — "+
				"ensure the registry HEAD commit exists; run `byreis doctor`", catExit)
	}

	// Step 3: extract the OpenSSH signature block from the commit object.
	sigBlock, err := extractGPGSigBlock(rawCommit)
	if err != nil {
		return usecase.ProbedSigner{}, fmt.Errorf(
			"signerprobe: no SSH signature in HEAD commit — "+
				"the registry HEAD commit must be signed with an Ed25519 SSH key; "+
				"run `byreis doctor`: %w", err)
	}

	// Step 4: parse the OpenSSH signature to extract the raw Ed25519 public key.
	rawKey, err := extractEd25519KeyFromOpenSSHSig(sigBlock)
	if err != nil {
		return usecase.ProbedSigner{}, fmt.Errorf(
			"signerprobe: extracting Ed25519 key from SSH signature: %w — "+
				"only Ed25519 SSH commit signatures are supported; "+
				"re-generate the registry signing key with `ssh-keygen -t ed25519`", err)
	}

	fingerprint := computeFingerprint(rawKey)
	return usecase.ProbedSigner{
		Key:         rawKey,
		Fingerprint: fingerprint,
	}, nil
}

// ─── environment helpers ──────────────────────────────────────────────────────

// hardenedEnv returns the isolated environment used for all git subprocesses.
// It prevents ambient system/user git config from influencing any operation.
func (p *Probe) hardenedEnv(tmpDir string) []string {
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
	if len(p.extraEnv) == 0 {
		return env
	}
	// When authentication env vars are present they override GIT_CONFIG_COUNT.
	// The caller builds a self-contained GIT_CONFIG_COUNT/KEY/VALUE block that
	// supersedes the baseline block above.
	return append(env, p.extraEnv...)
}

// cleanGitEnv returns a minimal environment: PATH (for git to find its helpers)
// plus LANG/LC_ALL=C for predictable ASCII output.
func cleanGitEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"LANG=C",
		"LC_ALL=C",
	}
}

// ─── commit parsing ───────────────────────────────────────────────────────────

// extractGPGSigBlock finds and returns the raw bytes of the gpgsig header value
// from a raw git commit object.  The gpgsig header is a folded multi-line value:
// the first line begins with "gpgsig " and continuation lines begin with " "
// (a single space).
//
// Returns an error when no gpgsig header is found or the block is empty.
func extractGPGSigBlock(rawCommit []byte) ([]byte, error) {
	lines := bytes.Split(rawCommit, []byte("\n"))

	var sigLines [][]byte
	inSig := false

	for _, line := range lines {
		if !inSig {
			if bytes.HasPrefix(line, []byte("gpgsig ")) {
				// First line: strip the "gpgsig " prefix.
				sigLines = append(sigLines, bytes.TrimPrefix(line, []byte("gpgsig ")))
				inSig = true
				continue
			}
			// The empty line separates headers from the commit message body.
			if len(line) == 0 {
				break
			}
			continue
		}
		// Continuation lines begin with a single space.
		if len(line) > 0 && line[0] == ' ' {
			sigLines = append(sigLines, line[1:])
			continue
		}
		// Non-continuation line: the gpgsig block has ended.
		break
	}

	if len(sigLines) == 0 {
		return nil, errors.New("no gpgsig header found in commit object")
	}

	block := bytes.Join(sigLines, []byte("\n"))
	block = bytes.TrimSpace(block)
	if len(block) == 0 {
		return nil, errors.New("gpgsig block is empty")
	}
	return block, nil
}

// opensshSigMagic is the fixed preamble for OpenSSH signature files.
const opensshSigMagic = "SSHSIG"

// extractEd25519KeyFromOpenSSHSig parses an OpenSSH armored signature block
// and returns the raw 32-byte Ed25519 public key embedded in it.
//
// OpenSSH signature wire format (RFC / openssh-portable sshsig.c):
//
//	"SSHSIG" (6 bytes, no NUL)
//	uint32  version        (currently 0x00000001)
//	string  publickey      (length-prefixed SSH wire format of the signing key)
//	string  namespace      (e.g. "git")
//	string  reserved       (empty)
//	string  hash_algorithm (e.g. "sha512")
//	string  signature      (SSH signature blob)
//
// The publickey field is itself a length-prefixed SSH wire-format key:
//
//	string  key_type  (e.g. "ssh-ed25519")
//	string  key_data  (32 bytes for Ed25519)
func extractEd25519KeyFromOpenSSHSig(armored []byte) (ed25519.PublicKey, error) {
	// Strip PEM-like armor.
	raw, err := decodeOpenSSHSigArmor(armored)
	if err != nil {
		return nil, fmt.Errorf("decoding OpenSSH signature armor: %w", err)
	}

	// Verify the SSHSIG magic preamble.
	if len(raw) < len(opensshSigMagic) {
		return nil, errors.New("OpenSSH signature too short to contain magic preamble")
	}
	if string(raw[:len(opensshSigMagic)]) != opensshSigMagic {
		return nil, fmt.Errorf(
			"OpenSSH signature does not start with %q — not an SSH signature", opensshSigMagic)
	}
	buf := raw[len(opensshSigMagic):]

	// Skip version (uint32).
	if len(buf) < 4 {
		return nil, errors.New("OpenSSH signature truncated before version field")
	}
	buf = buf[4:]

	// Read the publickey string (length-prefixed).
	pubKeyBlob, _, err := readSSHString(buf)
	if err != nil {
		return nil, fmt.Errorf("reading public key field from OpenSSH signature: %w", err)
	}

	// Parse the SSH public key wire format to extract the key type and key data.
	keyType, rest, err := readSSHString(pubKeyBlob)
	if err != nil {
		return nil, fmt.Errorf("reading key type from SSH public key: %w", err)
	}
	if string(keyType) != "ssh-ed25519" {
		return nil, fmt.Errorf(
			"unsupported key type %q — only Ed25519 SSH commit signatures are supported; "+
				"re-generate the registry signing key with `ssh-keygen -t ed25519`",
			string(keyType))
	}

	keyData, _, err := readSSHString(rest)
	if err != nil {
		return nil, fmt.Errorf("reading key data from SSH public key: %w", err)
	}
	if len(keyData) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"Ed25519 public key is %d bytes, expected %d — corrupt SSH signature",
			len(keyData), ed25519.PublicKeySize)
	}

	result := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(result, keyData)
	return result, nil
}

// decodeOpenSSHSigArmor strips the BEGIN/END SSH SIGNATURE armor and returns
// the raw base64-decoded bytes.  The format is:
//
//	-----BEGIN SSH SIGNATURE-----
//	<base64 lines>
//	-----END SSH SIGNATURE-----
func decodeOpenSSHSigArmor(armored []byte) ([]byte, error) {
	const beginMarker = "-----BEGIN SSH SIGNATURE-----"
	const endMarker = "-----END SSH SIGNATURE-----"

	s := strings.TrimSpace(string(armored))

	beginIdx := strings.Index(s, beginMarker)
	if beginIdx < 0 {
		return nil, errors.New("BEGIN SSH SIGNATURE marker not found")
	}
	afterBegin := s[beginIdx+len(beginMarker):]

	endIdx := strings.Index(afterBegin, endMarker)
	if endIdx < 0 {
		return nil, errors.New("END SSH SIGNATURE marker not found")
	}
	b64Body := strings.TrimSpace(afterBegin[:endIdx])
	// Remove any whitespace (including newlines) from the base64 body.
	b64Body = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, b64Body)

	decoded, err := base64.StdEncoding.DecodeString(b64Body)
	if err != nil {
		return nil, fmt.Errorf("base64-decoding SSH signature body: %w", err)
	}
	return decoded, nil
}

// readSSHString reads a length-prefixed string from buf (uint32 big-endian
// length followed by that many bytes) and returns the string data and the
// remaining buffer.
func readSSHString(buf []byte) (data, rest []byte, err error) {
	if len(buf) < 4 {
		return nil, nil, errors.New("buffer too short for SSH string length field")
	}
	length := binary.BigEndian.Uint32(buf[:4])
	buf = buf[4:]
	if len(buf) < int(length) { //nolint:gosec // length is a parsed uint32 from a network blob; the comparison is against a slice length (int), which is always non-negative and bounded by addressable memory
		return nil, nil, fmt.Errorf(
			"buffer too short: need %d bytes for SSH string, have %d", length, len(buf))
	}
	return buf[:length], buf[length:], nil
}

// ─── fingerprint ─────────────────────────────────────────────────────────────

// computeFingerprint returns the hex-encoded sha256 of key.  This matches the
// derivation in usecase.fingerprintOf so pinned and probed fingerprints compare
// correctly.
func computeFingerprint(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

// ─── misc helpers ─────────────────────────────────────────────────────────────

// sanitize trims and truncates subprocess stderr for use in error messages.
func sanitize(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 256 {
		s = s[:256] + "...(truncated)"
	}
	return s
}

// withBoundedDeadline derives a child context whose deadline is the earlier of
// the parent's deadline and (now + bound).  The returned cancel must be called.
func withBoundedDeadline(parent context.Context, bound time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(bound)
	if d, ok := parent.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return context.WithDeadline(parent, deadline)
}

// isContextErr reports whether the error from a bounded-deadline context is due
// to context expiry (either the inner deadline or the outer context).
func isContextErr(inner, outer context.Context) bool {
	return inner.Err() != nil || outer.Err() != nil
}

// Compile-time assertion that Probe satisfies the usecase.SignerProbe port.
var _ usecase.SignerProbe = (*Probe)(nil)
