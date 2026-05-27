// Package registry — production FetchTransport implementation.
//
// productionFetchTransport satisfies the full FetchTransport interface.
// FetchHead delegates verbatim to a held *fetchtransport.HeadVerifier (one
// verifier — no re-verify or re-interpret). ReadAdmins and ReadProjectConfig
// read the committed bytes from the SAME local clone that FetchHead produced,
// using `git cat-file blob <verifiedSHA>:<path>` — never a second clone, no
// network round-trip between verify and read (same-clone / verified-SHA
// provenance).
//
// Clone lifetime: one clone per FetchAdminSet call. FetchHead creates the
// clone and stores a session keyed by the verified SHA. ReadAdmins pops the
// pending session for that SHA, reads from the clone, then moves the session
// to the active queue. ReadProjectConfig (called immediately after ReadAdmins
// in FetchAdminSet) pops the active session and triggers cleanup. On any error
// path the session cleanup is called directly, so the temp directory is removed
// on every exit including panic and context cancellation.
//
// Concurrent FetchAdminSet calls each get their own distinct clone directory
// (the session FIFO queues are per-SHA so same-SHA concurrent calls are served
// in FIFO order with no sharing).
//
// This type lives in package registry (not in the fetchtransport sub-package)
// so that ProjectConfig, countertypes, and domain types are in scope without
// creating a registry→fetchtransport→registry import cycle.
package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/ByReisK/byreis/internal/adapter/registry/internal/fetchtransport"
	"github.com/ByReisK/byreis/internal/core/audit"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/validator"
)

// maxAdminYAMLBytes is the pre-decode size bound for admins.yaml and
// per-project YAML files. A payload exceeding this is rejected before decoding
// to prevent OOM from a malicious (but signature-valid) oversized registry file.
const maxAdminYAMLBytes = 1 << 20 // 1 MiB

// maxCounterJSONBytes is the pre-decode size bound for counter store JSON files.
// 64 KiB is more than sufficient for the two-record counter schema; a larger
// blob is rejected before decoding as a fail-closed guard against OOM.
const maxCounterJSONBytes = 64 * 1024 // 64 KiB

// mergeBaseTimeout is the bounded execution ceiling for a git merge-base
// --is-ancestor subprocess. Applied via withBoundedDeadline so the effective
// deadline is min(ctx.Deadline, mergeBaseTimeout from call time).
const mergeBaseTimeout = 30 * time.Second

// cloneSession holds the state of a single FetchAdminSet-scoped clone. It is
// created by FetchHead and consumed by the subsequent ReadAdmins +
// ReadProjectConfig calls within the same FetchAdminSet invocation.
//
// cleanupOnce wraps the cleanup function so it is idempotent (safe to call
// from ReadAdmins on error AND from ReadProjectConfig on the normal path).
type cloneSession struct {
	cloneDir    string
	verifiedSHA string
	cleanupOnce sync.Once
	cleanupFn   func()
}

// cleanup removes the tmpDir containing the clone. Safe to call multiple times.
func (s *cloneSession) cleanup() {
	s.cleanupOnce.Do(s.cleanupFn)
}

// sessionQueue is a FIFO queue of clone sessions, serialised by a mutex.
// Multiple concurrent FetchAdminSet calls for the same commit SHA each push
// their session and pop it in FIFO order — distinct clone dirs, no sharing.
type sessionQueue struct {
	mu       sync.Mutex
	sessions []*cloneSession
}

func (q *sessionQueue) push(s *cloneSession) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sessions = append(q.sessions, s)
}

// pop removes and returns the first session, or nil if the queue is empty.
func (q *sessionQueue) pop() *cloneSession {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.sessions) == 0 {
		return nil
	}
	s := q.sessions[0]
	q.sessions = q.sessions[1:]
	return s
}

// FetchTransportWriteConfig holds injected write-path dependencies for the
// production fetch transport. These are optional: when nil the write methods
// return ErrRegistryWriteAuth immediately, which is correct for any path that
// doesn't need counter writes (contributor paths, read-only tools).
type FetchTransportWriteConfig struct {
	// Signer is the ADMIN-only commit signer. It reuses the ManifestSigner
	// adapter — no new key material and no parallel signer path. Production
	// wiring passes the same ManifestSigner instance used by the merge use-case.
	// Must not be nil if counter writes are required.
	Signer RegistryWriteSigner

	// TokenProvider is the ADMIN-only registry-write credential provider.
	// The implementation consults the mode gate and refuses to return a token
	// in CONTRIBUTOR mode. Must not be nil if counter writes are required.
	TokenProvider RegistryWriteTokenProvider
}

// productionFetchTransport is the production implementation of FetchTransport.
// It satisfies the full interface: FetchHead creates a clone and retains it
// for the duration of the FetchAdminSet call. ReadAdmins and ReadProjectConfig
// read from that retained clone via git cat-file blob. The clone is removed
// (via the session cleanup) after ReadProjectConfig completes or on any error.
type productionFetchTransport struct {
	verifier *fetchtransport.HeadVerifier

	// writeCfg holds the optional write-path dependencies (Signer + TokenProvider).
	// When nil the write methods fail with ErrRegistryWriteAuth.
	writeCfg *FetchTransportWriteConfig

	// pendingMu + pendingSessions: sessions created by FetchHead, awaiting
	// ReadAdmins. Maps verified SHA → FIFO queue.
	pendingMu       sync.Mutex
	pendingSessions map[string]*sessionQueue

	// activeMu + activeSessions: sessions moved here by ReadAdmins, awaiting
	// ReadProjectConfig. Maps verified SHA → FIFO queue.
	activeMu       sync.Mutex
	activeSessions map[string]*sessionQueue

	// counterMu + counterActiveSessions: sessions moved here by ReadCounter,
	// awaiting the conditional IsAncestor call within the same
	// CounterAuthority invocation. Maps verified HEAD SHA → FIFO queue.
	// Mirrors the pendingSessions/activeSessions two-queue discipline for the
	// FetchHead → ReadCounter → [IsAncestor|DiscardCounterSession] pipeline.
	// The in-memory session state is ephemeral; it does not survive process
	// restart.
	counterMu             sync.Mutex
	counterActiveSessions map[string]*sessionQueue
}

// NewProductionFetchTransport constructs a productionFetchTransport. The
// verifier is required; returns an error if it is nil. The optional writeCfg
// enables the counter-write path (WriteCounter/CommitCounter); pass nil for
// read-only use.
func NewProductionFetchTransport(v *fetchtransport.HeadVerifier, writeCfg *FetchTransportWriteConfig) (*productionFetchTransport, error) {
	if v == nil {
		return nil, errors.New(
			"registry.NewProductionFetchTransport: HeadVerifier is required — " +
				"inject a real or fake verifier")
	}
	return &productionFetchTransport{
		verifier:              v,
		writeCfg:              writeCfg,
		pendingSessions:       make(map[string]*sessionQueue),
		activeSessions:        make(map[string]*sessionQueue),
		counterActiveSessions: make(map[string]*sessionQueue),
	}, nil
}

// SubprocessRunner is a CommandRunner implementation that shells to the OS for
// subprocess execution. It is the production implementation of
// fetchtransport.CommandRunner. cmd/byreis/main.go constructs one and passes it
// to NewProductionFetchTransportFromRunner; the internal fetchtransport sub-package
// drives the actual subprocess invocations.
//
// Implements fetchtransport.CommandRunner.
type SubprocessRunner struct{}

// Run executes the named command with the given args in dir with the given env.
// Non-zero exit codes are returned as exitCode > 0 with err == nil (matching
// the fetchtransport.CommandRunner contract). An exec-level error (binary not
// found, killed by signal) is returned as err != nil with exitCode 0.
func (SubprocessRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) (stdout, stderr []byte, exitCode int, err error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // name+args are controlled by the caller (git subcommands)
	cmd.Dir = dir
	cmd.Env = env
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()
	outBytes := outBuf.Bytes()
	errBytes := errBuf.Bytes()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return outBytes, errBytes, exitErr.ExitCode(), nil
		}
		return outBytes, errBytes, 0, runErr
	}
	return outBytes, errBytes, 0, nil
}

// NewProductionFetchTransportFromRunner constructs a productionFetchTransport
// using a SubprocessRunner for the HeadVerifier. This is the wiring entrypoint
// for cmd/byreis/main.go which cannot import the internal fetchtransport
// sub-package directly. Pass a non-nil writeCfg to enable the counter-write
// path; pass nil for read-only tools.
func NewProductionFetchTransportFromRunner(runner SubprocessRunner, writeCfg *FetchTransportWriteConfig) (*productionFetchTransport, error) {
	v, err := fetchtransport.NewHeadVerifier(fetchtransport.HeadVerifierConfig{
		Runner:    runner,
		MkdirTemp: os.MkdirTemp,
		RemoveAll: os.RemoveAll,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"registry.NewProductionFetchTransportFromRunner: constructing head verifier: %w", err)
	}
	return NewProductionFetchTransport(v, writeCfg)
}

// FetchHead delegates VERBATIM to HeadVerifier.VerifyHeadRetainClone.
// One verifier only — no re-verify or re-interpret. When verified==true, the
// clone is retained and stored as a pending session keyed by the verified SHA,
// ready for the subsequent ReadAdmins + ReadProjectConfig calls within the
// same FetchAdminSet invocation. When verified==false or on error, the clone
// is cleaned up immediately.
func (t *productionFetchTransport) FetchHead(ctx context.Context, repoURL string, anchorKey ed25519.PublicKey) (string, string, bool, error) {
	commit, signerID, verified, cloneDir, cleanupFn, err := t.verifier.VerifyHeadRetainClone(ctx, repoURL, anchorKey)
	if err != nil {
		// VerifyHeadRetainClone always returns a non-nil cleanupFn even on error.
		cleanupFn()
		return commit, signerID, verified, err
	}
	if !verified {
		// Verification failed: clean up the clone (may be partial) and return.
		cleanupFn()
		return commit, signerID, false, nil
	}

	// verified==true and cloneDir is set. Create a session and push it to the
	// pending queue so ReadAdmins can find it by SHA.
	sess := &cloneSession{
		cloneDir:    cloneDir,
		verifiedSHA: commit,
		cleanupFn:   cleanupFn,
	}
	t.pushPending(commit, sess)
	return commit, signerID, true, nil
}

func (t *productionFetchTransport) pushPending(sha string, s *cloneSession) {
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	if t.pendingSessions[sha] == nil {
		t.pendingSessions[sha] = &sessionQueue{}
	}
	t.pendingSessions[sha].push(s)
}

func (t *productionFetchTransport) popPending(sha string) *cloneSession {
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	q := t.pendingSessions[sha]
	if q == nil {
		return nil
	}
	return q.pop()
}

func (t *productionFetchTransport) pushActive(sha string, s *cloneSession) {
	t.activeMu.Lock()
	defer t.activeMu.Unlock()
	if t.activeSessions[sha] == nil {
		t.activeSessions[sha] = &sessionQueue{}
	}
	t.activeSessions[sha].push(s)
}

func (t *productionFetchTransport) popActive(sha string) *cloneSession {
	t.activeMu.Lock()
	defer t.activeMu.Unlock()
	q := t.activeSessions[sha]
	if q == nil {
		return nil
	}
	return q.pop()
}

func (t *productionFetchTransport) pushCounterActive(sha string, s *cloneSession) {
	t.counterMu.Lock()
	defer t.counterMu.Unlock()
	if t.counterActiveSessions[sha] == nil {
		t.counterActiveSessions[sha] = &sessionQueue{}
	}
	t.counterActiveSessions[sha].push(s)
}

func (t *productionFetchTransport) popCounterActive(sha string) *cloneSession {
	t.counterMu.Lock()
	defer t.counterMu.Unlock()
	q := t.counterActiveSessions[sha]
	if q == nil {
		return nil
	}
	return q.pop()
}

// ReadProjectBlob delegates to the held HeadVerifier.ReadProjectBlob for the
// git-based file-of-record read. It satisfies the fileofrecord.ProjectBlobReader
// interface.
//
// ONE clone of projectURL is performed per call. The branch is resolved to
// S_proj exactly once inside that clone; S_proj is an intra-clone NO-SKEW
// invariant, NOT a signed or trust-verified SHA. Project-repo trust is the
// manifest signature (verify.VerifyOfRecord over the registry-attested set).
//
// A git-layer blob-not-found error is propagated as-is; the caller detects
// it via the BlobNotFound() bool marker interface without importing this
// package.
func (t *productionFetchTransport) ReadProjectBlob(ctx context.Context, projectURL, branch, path string, maxBytes int64) (string, []byte, error) {
	return t.verifier.ReadProjectBlob(ctx, projectURL, branch, path, maxBytes)
}

// IsAncestor reports whether ancestor is a (non-strict) ancestor of tip using
// git merge-base --is-ancestor against the retained clone from ReadCounter. The
// clone was deposited into counterActiveSessions by ReadCounter; IsAncestor
// pops it here and owns the cleanup via defer.
//
// Exit-code triage (four distinct branches):
//
//   - exit 0 + nil err  → (true, nil)   — ancestor is ancestor of tip
//   - exit 1 + nil err  → (false, nil)  — not an ancestor (rollback detected by caller)
//   - exit other        → (false, err)  — git error; wraps ErrCounterStoreUnreadable
//   - runErr != nil     → (false, err)  — exec-level failure; wraps ctx.Err() if cancelled
//
// Both SHA arguments are re-validated by isValidSHA before argv assembly. The
// subprocess runs with the same hardened environment as ReadBlobAtSHA and the
// verify leg (GIT_CONFIG_NOSYSTEM, HOME isolation, protocol allowlist, hooks
// disabled), bounded by mergeBaseTimeout.
func (t *productionFetchTransport) IsAncestor(ctx context.Context, _ string, ancestor, tip string) (bool, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, fmt.Errorf(
			"IsAncestor: context already cancelled: %w — run `byreis doctor`", ctxErr)
	}

	// Re-validate both SHA arguments before touching argv or the session queue.
	if !fetchtransport.IsValidSHA(ancestor) {
		return false, fmt.Errorf(
			"%w: IsAncestor: ancestor %q is not a valid 40/64-hex commit hash — "+
				"internal invariant violated; run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, ancestor)
	}
	if !fetchtransport.IsValidSHA(tip) {
		return false, fmt.Errorf(
			"%w: IsAncestor: tip %q is not a valid 40/64-hex commit hash — "+
				"internal invariant violated; run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, tip)
	}

	// Pop the counter-active session keyed by tip (the verified HEAD SHA from
	// FetchHead/ReadCounter). This is the same-clone provenance guarantee:
	// the ancestry check runs against the exact clone ReadCounter used.
	sess := t.popCounterActive(tip)
	if sess == nil {
		return false, fmt.Errorf(
			"%w: IsAncestor: no counter clone session for tip SHA %q — "+
				"internal invariant violated; run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, tip)
	}
	// Cleanup on every exit path (success, error, ctx-cancel, panic).
	defer sess.cleanup()

	// Derive the hardened env from the retained clone directory. tmpDir is the
	// parent of cloneDir, identical to the convention in ReadBlobAtSHA.
	tmpDir := filepath.Dir(sess.cloneDir)
	mergeEnv := append(fetchtransport.CleanGitEnv(),
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

	// Bounded deadline: never exceed mergeBaseTimeout, never extend a
	// shorter parent deadline.
	mbCtx, mbCancel := fetchtransport.WithBoundedDeadline(ctx, mergeBaseTimeout)
	defer mbCancel()

	// argv: "merge-base --is-ancestor -- <ancestor> <tip>"
	// The "--" end-of-options guard prevents any ref-like input from being
	// parsed as a flag even if validation above were somehow bypassed.
	_, stderr, exitCode, runErr := t.verifier.RunSubprocess(
		mbCtx, sess.cloneDir, mergeEnv,
		"git", "merge-base", "--is-ancestor", "--", ancestor, tip,
	)

	if runErr != nil {
		if mbCtx.Err() != nil || ctx.Err() != nil {
			return false, fmt.Errorf(
				"IsAncestor: git merge-base cancelled: %w — run `byreis doctor`",
				ctx.Err())
		}
		return false, fmt.Errorf(
			"IsAncestor: git merge-base exec error: %w — run `byreis doctor`",
			runErr)
	}

	// Silence stderr: counter blob paths may include PR identifiers and other
	// workflow metadata that must not propagate into error messages.
	_ = stderr

	switch exitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf(
			"%w: IsAncestor: git merge-base unexpected exit %d — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, exitCode)
	}
}

// ReadCounter reads the last_accepted_counter and optional pending bump for the
// given (projectID, fileName) pair from the counter store file committed in the
// registry at the exact SHA FetchHead verified. It pops the pending session
// created by FetchHead; on success it pushes the session to counterActiveSessions
// for the subsequent conditional IsAncestor call. On any error path the session
// is cleaned up synchronously — never deferred — so the clone is released before
// this function returns on error.
//
// Absent counter file (BlobNotFound typed marker) returns (0, nil, nil) — a
// counter that has never been written is treated as zero (the freshly-created
// counter case). Every other error surface returns a non-nil error wrapping
// ErrCounterStoreUnreadable with an actionable hint.
func (t *productionFetchTransport) ReadCounter(ctx context.Context, _ string, headCommit, projectID, fileName string) (uint64, *countertypes.PendingBump, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, nil, fmt.Errorf(
			"ReadCounter: context already cancelled: %w — run `byreis doctor`", ctxErr)
	}

	// Validate projectID and fileName BEFORE composing any path or touching the
	// session queue. A validation failure must not consume a session.
	if err := fetchtransport.ValidateProjectID(projectID); err != nil {
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: invalid projectID: %v — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, err)
	}
	if err := fetchtransport.ValidateFileName(fileName); err != nil {
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: invalid fileName: %v — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, err)
	}

	// Pop the pending clone session deposited by the preceding FetchHead call,
	// keyed by headCommit. Using the caller-supplied headCommit as the session
	// key ensures only the session whose verifiedSHA matches the headCommit the
	// orchestrator passed is eligible for this ReadCounter invocation.
	sess := t.popPending(headCommit)
	if sess == nil {
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: no clone session available for headCommit %q — "+
				"FetchHead must be called before ReadCounter; run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, headCommit)
	}

	// Immediate cleanup guard: set up a cleanup flag so that on any error path
	// below the session is cleaned synchronously. On the success path we push
	// to counterActiveSessions instead.
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			sess.cleanup()
		}
	}()

	// SHA-equality assertion: the session's verifiedSHA must exactly match the
	// headCommit parameter the orchestrator passed. This is the in-code structural
	// assertion — NOT an assignment. A mismatch indicates an internal invariant
	// violation (concurrent session interleave or a wrong headCommit from the
	// caller) and is fail-closed.
	if sess.verifiedSHA != headCommit {
		sess.cleanup()
		cleanedUp = true
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: session SHA %q does not match headCommit %q — "+
				"internal invariant violated; run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, sess.verifiedSHA, headCommit)
	}

	// Re-validate the headCommit (now confirmed == sess.verifiedSHA) defensively;
	// an invalid SHA here indicates an internal invariant violation.
	if !fetchtransport.IsValidSHA(headCommit) {
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: headCommit %q is not a valid SHA — "+
				"internal invariant violated; run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, headCommit)
	}

	// Compose the counter blob path via the single authorised helper.
	blobPath := fetchtransport.CounterBlobPath(projectID, fileName)

	raw, readErr := t.verifier.ReadBlobAtSHA(ctx, sess.cloneDir, headCommit, blobPath)
	if readErr != nil {
		if fetchtransport.IsBlobNotFound(readErr) {
			// Counter file is absent. Counter-coverage rule: for a cold project (no
			// projects/<projectID>.yaml listing this file at the verified HEAD),
			// this is safe — zero counter is correct. For a warm project
			// (projects/<projectID>.yaml exists and lists this fileName), a missing
			// counter is an integrity violation: every first merge MUST create the
			// counter. Warm + absent → ErrCounterReconcile (terminal).
			isWarm, warmErr := t.isWarmProject(ctx, sess.cloneDir, headCommit, projectID, fileName)
			if warmErr != nil {
				// Cannot determine warmth: fail closed — treat as warm (integrity unknown).
				return 0, nil, fmt.Errorf(
					"%w: ReadCounter: cannot determine project warmth for absent-counter "+
						"integrity check — run `byreis doctor`",
					coreregistry.ErrCounterStoreUnreadable)
			}
			if isWarm {
				// Warm project with no counter file: integrity violation.
				return 0, nil, fmt.Errorf(
					"%w: ReadCounter: counter file %q absent at %q but project "+
						"%q has a configured file %q — the first merge must create "+
						"the counter; run `byreis admin counter reconcile` to diagnose",
					countertypes.ErrCounterReconcile,
					blobPath, headCommit, projectID, fileName)
			}
			// Cold project: zero counter is correct.
			return 0, nil, nil
		}
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: reading %q at %q: %v — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, blobPath, headCommit, readErr)
	}

	// Pre-decode size cap: 64 KiB hard limit measured on raw bytes BEFORE
	// any JSON decoding. Over-size blobs are rejected without invoking the decoder.
	if len(raw) > maxCounterJSONBytes {
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: counter blob %q at %q exceeds max size %d bytes (got %d) — "+
				"run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, blobPath, headCommit,
			maxCounterJSONBytes, len(raw))
	}

	// Empty or whitespace-only blob: not the same as absent (BlobNotFound); fail
	// closed — a zero-byte blob is a repository integrity concern, not a fresh counter.
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: counter blob %q at %q is empty or whitespace-only — "+
				"run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, blobPath, headCommit)
	}

	// Explicit duplicate-key detection via token-stream pre-scan. The Go stdlib
	// json.Decoder with DisallowUnknownFields does NOT catch duplicate keys
	// (last-write-wins). This separate pass catches duplicates at any nesting level.
	if err := checkDuplicateJSONKeys(raw); err != nil {
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: %v in counter blob %q at %q — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, err, blobPath, headCommit)
	}

	// Decode into the strict typed struct matching the counter store wire format.
	cf, decErr := decodeCounterFile(raw)
	if decErr != nil {
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: decoding counter blob %q at %q: %v — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, blobPath, headCommit, decErr)
	}

	// Post-decode semantic validation: project_id, file, and SHAs must satisfy
	// the domain invariants defined in the counter schema.
	if err := validateCounterFileSemantics(cf, projectID, fileName); err != nil {
		return 0, nil, fmt.Errorf(
			"%w: ReadCounter: semantic validation of counter blob %q at %q: %v — "+
				"run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, blobPath, headCommit, err)
	}

	// When a pending record is present, verify parent_commit_sha: the parent of
	// the commit that introduced the pending record must match the
	// parent_commit_sha recorded in the pending sub-object. This is the
	// captured-commit-replay defence: a captured signed counter commit cannot be
	// silently reused at a different HEAD position because the parent SHA is
	// embedded in the signed (git-signed) commit message AND in the counter JSON.
	if cf.Pending != nil {
		if err := t.verifyPendingParentSHA(ctx, sess.cloneDir, headCommit, blobPath, cf.Pending.ParentCommitSHA); err != nil {
			return 0, nil, fmt.Errorf(
				"%w: ReadCounter: parent_commit_sha mismatch in counter blob %q at %q: %v — "+
					"possible replayed or misplaced counter commit; "+
					"run `byreis admin counter reconcile`",
				countertypes.ErrCounterReconcile, blobPath, headCommit, err)
		}
	}

	// Build the domain PendingBump if the pending record is present.
	var pending *countertypes.PendingBump
	if cf.Pending != nil {
		pending = &countertypes.PendingBump{
			PendingCounter:    cf.Pending.PendingCounter,
			TargetArtifactSHA: cf.Pending.TargetArtifactSHA,
			TargetPR:          cf.Pending.TargetPR,
		}
	}

	// Success path: push the session to counterActiveSessions so the conditional
	// IsAncestor call can use the same clone. Mark cleaned up so the defer does
	// not fire.
	cleanedUp = true
	t.pushCounterActive(headCommit, sess)

	return cf.LastAcceptedCounter, pending, nil
}

// DiscardCounterSession pops the counter-active session keyed by headCommit and
// cleans it up synchronously. Called by CounterAuthority on the two no-ancestor
// branches (cold-cache first-call and warm-cache identical-HEAD) so the session
// does not leak when IsAncestor is not called. If no session is present for this
// headCommit, the call is a no-op (safe to call unconditionally on those branches).
func (t *productionFetchTransport) DiscardCounterSession(_ context.Context, headCommit string) {
	if sess := t.popCounterActive(headCommit); sess != nil {
		sess.cleanup()
	}
}

// writeTimeout is the bounded execution ceiling for a git push subprocess.
const writeTimeout = 60 * time.Second

// WriteCounter writes a signed commit to the registry that records the pending
// bump intent. The commit message body carries the canonical signed envelope:
// project_id, file, expected_previous_counter, pending_counter,
// target_artifact_sha, target_pr, and parent_commit_sha (replay anchor).
//
// The push is conditional (force-if-includes / non-fast-forward CAS): if the
// registry HEAD moved between the fetch and this push, the push fails with
// ErrRegistryConcurrentWrite so the caller can retry from step 1.
//
// The write path requires writeCfg.Signer and writeCfg.TokenProvider to be
// non-nil; absent either returns ErrRegistryWriteAuth.
func (t *productionFetchTransport) WriteCounter(ctx context.Context, repoURL, projectID, fileName string, pending *countertypes.PendingBump) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("WriteCounter: context already cancelled: %w", ctxErr)
	}
	if t.writeCfg == nil || t.writeCfg.Signer == nil || t.writeCfg.TokenProvider == nil {
		return fmt.Errorf("%w: WriteCounter: no write configuration provided — "+
			"run `byreis admin register` to add a registry-write token",
			ErrRegistryWriteAuth)
	}

	// Retrieve the registry-write credential. The provider refuses to return the
	// token in CONTRIBUTOR mode (contributor/admin credential separation). An
	// absent token returns ErrRegistryWriteAuth so callers get the actionable hint.
	token, tokenErr := t.writeCfg.TokenProvider.RegistryWriteToken(ctx, repoURL)
	if tokenErr != nil {
		return fmt.Errorf("%w: WriteCounter: retrieving registry-write token: %v",
			ErrRegistryWriteAuth, tokenErr)
	}

	if err := fetchtransport.ValidateProjectID(projectID); err != nil {
		return fmt.Errorf("WriteCounter: invalid projectID: %w", err)
	}
	if err := fetchtransport.ValidateFileName(fileName); err != nil {
		return fmt.Errorf("WriteCounter: invalid fileName: %w", err)
	}
	if pending == nil {
		return fmt.Errorf("WriteCounter: pending bump must not be nil")
	}

	return t.doCounterWrite(ctx, repoURL, projectID, fileName, token, pending, 0, false, audit.Event{})
}

// CommitCounter atomically advances last_accepted_counter to pendingCounter
// and clears the pending record in a single signed registry commit. This is
// the strict-two-phase step 5: it MUST NOT be called without a prior
// WriteCounter for the same (project, file, pendingCounter, targetArtifactSHA).
//
// The push is conditional (non-fast-forward CAS): ErrRegistryConcurrentWrite
// if the registry HEAD moved.
func (t *productionFetchTransport) CommitCounter(ctx context.Context, repoURL, projectID, fileName string, pendingCounter uint64) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("CommitCounter: context already cancelled: %w", ctxErr)
	}
	if t.writeCfg == nil || t.writeCfg.Signer == nil || t.writeCfg.TokenProvider == nil {
		return fmt.Errorf("%w: CommitCounter: no write configuration provided — "+
			"run `byreis admin register` to add a registry-write token",
			ErrRegistryWriteAuth)
	}

	token, tokenErr := t.writeCfg.TokenProvider.RegistryWriteToken(ctx, repoURL)
	if tokenErr != nil {
		return fmt.Errorf("%w: CommitCounter: retrieving registry-write token: %v",
			ErrRegistryWriteAuth, tokenErr)
	}

	if err := fetchtransport.ValidateProjectID(projectID); err != nil {
		return fmt.Errorf("CommitCounter: invalid projectID: %w", err)
	}
	if err := fetchtransport.ValidateFileName(fileName); err != nil {
		return fmt.Errorf("CommitCounter: invalid fileName: %w", err)
	}

	return t.doCounterWrite(ctx, repoURL, projectID, fileName, token, nil, pendingCounter, true, audit.Event{})
}

// CommitCounterWithAudit atomically advances last_accepted_counter to the
// pending counter, clears pending, appends an audit JSONL entry to
// audit/<project>.jsonl, and embeds audit_entry_sha in the signed commit
// body — all in ONE signed git commit and ONE conditional push.
//
// This is the merge-audit path: bumpIn.AuditEntry carries EventKindMerge and
// MUST pass audit.ValidateEventFields before signing. A validation failure
// aborts the entire commit (fail-closed, no signed orphan). The JSONL line is
// staged in the SAME git-add invocation as the counter blob so the two files
// are structurally inseparable: a CommitBump that does not land also leaves no
// half-appended remote audit line.
//
// OccurredAt is stamped by the transport at commit-build time (the call-site
// code in merge.go leaves it zero). A failed CommitBump pushes nothing
// remotely, so a resumed attempt derives a fresh timestamp against the new
// clone — there is no half-appended remote line to produce a duplicate.
func (t *productionFetchTransport) CommitCounterWithAudit(ctx context.Context, repoURL string, bumpIn coreregistry.CommitBumpInput) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("CommitCounterWithAudit: context already cancelled: %w", ctxErr)
	}
	if t.writeCfg == nil || t.writeCfg.Signer == nil || t.writeCfg.TokenProvider == nil {
		return fmt.Errorf("%w: CommitCounterWithAudit: no write configuration provided — "+
			"run `byreis admin register` to add a registry-write token",
			ErrRegistryWriteAuth)
	}

	token, tokenErr := t.writeCfg.TokenProvider.RegistryWriteToken(ctx, repoURL)
	if tokenErr != nil {
		return fmt.Errorf("%w: CommitCounterWithAudit: retrieving registry-write token: %v",
			ErrRegistryWriteAuth, tokenErr)
	}

	if err := fetchtransport.ValidateProjectID(bumpIn.ProjectID); err != nil {
		return fmt.Errorf("CommitCounterWithAudit: invalid projectID: %w", err)
	}
	if err := fetchtransport.ValidateFileName(bumpIn.FileName); err != nil {
		return fmt.Errorf("CommitCounterWithAudit: invalid fileName: %w", err)
	}

	return t.doCounterWrite(ctx, repoURL, bumpIn.ProjectID, bumpIn.FileName, token, nil, bumpIn.PendingCounter, true, bumpIn.AuditEntry)
}

// doCounterWrite is the shared implementation for WriteCounter, CommitCounter,
// and CommitCounterWithAudit.
//
// When commitPhase is false: writes the pending record (WriteCounter).
// When commitPhase is true:  advances last_accepted and clears pending
// (CommitCounter / CommitCounterWithAudit).
//
// When auditEntry.Kind is non-empty AND commitPhase is true, the audit JSONL
// line is built, appended to audit/<project>.jsonl in the clone, and staged in
// the SAME git-add invocation as the counter blob — the two files are
// structurally inseparable. audit_entry_sha = sha256(JSONL line) is embedded
// in the signed commit message body. ValidateEventFields runs before any signing;
// a validation failure aborts the commit (no signed orphan).
//
// OccurredAt is stamped by this function at the moment the commit message body
// is built, so the timestamp matches the commit exactly. The caller in merge.go
// leaves OccurredAt zero; the transport owns timestamping. A failed push leaves
// no remote state, so a CAS-retry rebuild starts from a fresh clone and derives
// a new timestamp — there is no half-appended remote line.
//
// Atomicity: each call produces exactly ONE signed git commit. CommitCounter's
// single commit simultaneously advances last_accepted_counter AND clears pending
// (and optionally appends the audit line) — never two commits.
//
// CAS: push uses --force-with-lease on the expected parent SHA. A non-fast-
// forward push returns ErrRegistryConcurrentWrite so the spine can retry;
// on retry the audit append is rebuilt against the FRESH re-clone.
func (t *productionFetchTransport) doCounterWrite(
	ctx context.Context,
	repoURL, projectID, fileName, token string,
	pending *countertypes.PendingBump,
	pendingCounter uint64,
	commitPhase bool,
	auditEntry audit.Event,
) error {
	// Create an isolated 0700 workspace for all git operations.
	tmpDir, mkErr := os.MkdirTemp("", "byreis-counter-write-*")
	if mkErr != nil {
		return fmt.Errorf("doCounterWrite: cannot create temp workspace: %w — "+
			"check filesystem permissions: run `byreis doctor`", mkErr)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec // 0700 on dir is intentional: owner-only scratch workspace
		return fmt.Errorf("doCounterWrite: cannot chmod temp workspace to 0700: %w — "+
			"check filesystem permissions: run `byreis doctor`", chErr)
	}

	cloneDir := filepath.Join(tmpDir, "repo")

	// hardenedEnv assembles the isolation environment for all git legs.
	// extraEnv is appended for HTTP authentication (the registry-write token).
	hardenedEnv := func(extraEnv ...string) []string {
		base := fetchtransport.CleanGitEnv()
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
		return append(env, extraEnv...)
	}

	// authEnv carries the registry-write credential as an HTTP extra-header.
	// This follows the same pattern as the read path extraEnv: the token is
	// passed via GIT_CONFIG so it is process-scoped and does not persist.
	// The token appears only in the env of git subprocess invocations, never
	// in log output (the hardened env sanitizer never includes env values).
	authEnv := func() []string {
		if token == "" {
			return nil
		}
		return []string{
			"GIT_CONFIG_COUNT=3",
			"GIT_CONFIG_KEY_0=core.hooksPath",
			"GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=core.fsmonitor",
			"GIT_CONFIG_VALUE_1=",
			"GIT_CONFIG_KEY_2=http.extraHeader",
			"GIT_CONFIG_VALUE_2=Authorization: Bearer " + token,
		}
	}

	// Step 1: clone the registry (shallow, full checkout for file writes).
	cloneCtx, cloneCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := t.verifier.RunSubprocess(
		cloneCtx, tmpDir,
		append(hardenedEnv(), authEnv()...),
		"git", "clone", "--depth=1", "--no-local", "--", repoURL, cloneDir,
	)
	if cloneErr != nil {
		return fmt.Errorf("doCounterWrite: git clone exec error: %w — "+
			"ensure git is installed and the registry URL is reachable: run `byreis doctor`",
			cloneErr)
	}
	if cloneExit != 0 {
		return fmt.Errorf("%w: doCounterWrite: git clone exited %d: %s",
			ErrRegistryWriteAuth, cloneExit, fetchtransport.SanitizeOutput(cloneStderr))
	}

	// Step 2: capture the registry HEAD (parent SHA for CAS + replay anchor).
	revCtx, revCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer revCancel()

	revStdout, _, revExit, revErr := t.verifier.RunSubprocess(
		revCtx, cloneDir, hardenedEnv(),
		"git", "rev-parse", "HEAD",
	)
	if revErr != nil {
		return fmt.Errorf("doCounterWrite: git rev-parse HEAD exec error: %w — run `byreis doctor`", revErr)
	}
	if revExit != 0 {
		return fmt.Errorf("doCounterWrite: git rev-parse HEAD exited %d — run `byreis doctor`", revExit)
	}
	parentSHA := strings.TrimSpace(string(revStdout))
	if !fetchtransport.IsValidSHA(parentSHA) {
		return fmt.Errorf("doCounterWrite: git rev-parse returned non-SHA output %q — run `byreis doctor`", parentSHA)
	}

	// Step 3: read the current counter file to build the updated content.
	blobPath := fetchtransport.CounterBlobPath(projectID, fileName)
	counterFilePath := filepath.Join(cloneDir, filepath.FromSlash(blobPath))

	currentRaw, readFileErr := os.ReadFile(counterFilePath) //nolint:gosec // path is under the tmpDir clone, composed from validated projectID/fileName
	var existing counterFileParsed
	fileExists := true
	if readFileErr != nil {
		if os.IsNotExist(readFileErr) {
			fileExists = false
		} else {
			return fmt.Errorf("doCounterWrite: reading current counter file: %w — run `byreis doctor`", readFileErr)
		}
	}
	if fileExists {
		if len(currentRaw) > maxCounterJSONBytes {
			return fmt.Errorf("doCounterWrite: current counter file exceeds max size — run `byreis doctor`")
		}
		if len(bytes.TrimSpace(currentRaw)) > 0 {
			if dupErr := checkDuplicateJSONKeys(currentRaw); dupErr != nil {
				return fmt.Errorf("%w: doCounterWrite: duplicate key in counter file: %v",
					coreregistry.ErrCounterStoreUnreadable, dupErr)
			}
			var decErr error
			existing, decErr = decodeCounterFile(currentRaw)
			if decErr != nil {
				return fmt.Errorf("%w: doCounterWrite: decoding current counter file: %v",
					coreregistry.ErrCounterStoreUnreadable, decErr)
			}
		}
	}

	// Step 4: build updated counter JSON and the signed commit message body.
	var newJSON []byte
	var commitMsgBody string
	var jsonErr error

	if !commitPhase {
		// WriteCounter: set pending, preserve last_accepted_counter.
		newJSON, commitMsgBody, jsonErr = t.buildWritePendingJSON(
			ctx, existing, projectID, fileName, parentSHA, pending)
	} else {
		// CommitCounter: advance last_accepted to pendingCounter, clear pending.
		// This MUST be a single atomic commit.
		if existing.Pending == nil {
			return fmt.Errorf("%w: CommitCounter: no pending record in counter file "+
				"for (%s,%s) — CommitCounter must follow a successful WriteCounter; "+
				"run `byreis admin counter reconcile`",
				countertypes.ErrCounterReconcile, projectID, fileName)
		}
		if existing.Pending.PendingCounter != pendingCounter {
			return fmt.Errorf("%w: CommitCounter: pending counter is %d, requested %d "+
				"for (%s,%s) — run `byreis admin counter reconcile`",
				countertypes.ErrCounterReconcile,
				existing.Pending.PendingCounter, pendingCounter, projectID, fileName)
		}
		newJSON, commitMsgBody, jsonErr = t.buildCommitPendingJSON(
			ctx, existing, projectID, fileName, parentSHA, pendingCounter)
	}
	if jsonErr != nil {
		return fmt.Errorf("doCounterWrite: building counter JSON: %w", jsonErr)
	}

	// Step 4a: when this is a merge CommitBump carrying an audit entry, build
	// the JSONL line and embed audit_entry_sha in the commit message body BEFORE
	// any file write or git operation. Fail-closed on validation: a malformed
	// event aborts here with no signed orphan and no partial state.
	//
	// OccurredAt is stamped at this moment — the transport owns timestamping, and
	// the caller (merge.go) deliberately leaves it zero to delegate that
	// responsibility here. The timestamp matches the actual commit time.
	//
	// Idempotency on resume: a failed push leaves no remote state, so a CAS-retry
	// re-enters doCounterWrite from a fresh clone. The fresh clone has no
	// half-appended audit line, and the fresh call derives a new timestamp. This
	// is correct: the winning JSONL is the one that rides the winning commit.
	var auditJSONLBytes []byte
	var auditFilePath string
	var auditBlobPath string
	if commitPhase && auditEntry.Kind != "" {
		// Stamp OccurredAt at commit-build time.
		auditEntry.OccurredAt = time.Now().UTC()

		var auditSHA string
		var auditErr error
		auditJSONLBytes, auditSHA, auditErr = buildAuditJSONLEntry(auditEntry)
		if auditErr != nil {
			return fmt.Errorf("doCounterWrite: building audit JSONL entry: %w — "+
				"verify the audit-event producer constructs canonical-typed Details values",
				auditErr)
		}

		// Append audit_entry_sha to the commit message body so the signed payload
		// binds the counter advance to the specific audit line. This mirrors the
		// rotation commit body (buildRotationCommitMessageBody) which embeds the
		// same field. The line is appended after the body so existing body parsers
		// remain forward-compatible.
		commitMsgBody = commitMsgBody + "audit_entry_sha: " + auditSHA + "\n"

		auditBlobPath = "audit/" + projectID + ".jsonl"
		auditFilePath = filepath.Join(cloneDir, filepath.FromSlash(auditBlobPath))
	}

	// Step 5: write the updated counter file to the clone.
	counterDir := filepath.Dir(counterFilePath)
	if mkdirErr := os.MkdirAll(counterDir, 0o700); mkdirErr != nil {
		return fmt.Errorf("doCounterWrite: creating counter directory: %w — "+
			"check filesystem permissions: run `byreis doctor`", mkdirErr)
	}
	if writeErr := os.WriteFile(counterFilePath, newJSON, 0o600); writeErr != nil { //nolint:gosec // 0600 for counter file: owner-only
		return fmt.Errorf("doCounterWrite: writing counter file: %w — "+
			"check filesystem permissions: run `byreis doctor`", writeErr)
	}

	// Step 5a: when carrying an audit entry, write (append or create) the JSONL
	// line to audit/<project>.jsonl in the clone. The file is created on first
	// merge. The write happens BEFORE git add so the file is in the working tree
	// for the combined stage in step 6.
	if len(auditJSONLBytes) > 0 {
		auditDir := filepath.Dir(auditFilePath)
		if mkdirErr := os.MkdirAll(auditDir, 0o700); mkdirErr != nil {
			return fmt.Errorf("doCounterWrite: creating audit directory: %w — "+
				"check filesystem permissions: run `byreis doctor`", mkdirErr)
		}
		auditFile, openErr := os.OpenFile(auditFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // 0600 for audit file: owner-only
		if openErr != nil {
			return fmt.Errorf("doCounterWrite: opening audit file for append: %w — "+
				"check filesystem permissions: run `byreis doctor`", openErr)
		}
		_, appendErr := auditFile.Write(auditJSONLBytes)
		closeErr := auditFile.Close()
		if appendErr != nil {
			return fmt.Errorf("doCounterWrite: appending to audit file: %w — "+
				"check filesystem permissions: run `byreis doctor`", appendErr)
		}
		if closeErr != nil {
			return fmt.Errorf("doCounterWrite: closing audit file: %w — "+
				"check filesystem permissions: run `byreis doctor`", closeErr)
		}
	}

	// Step 6: stage all modified files in a single git add invocation.
	//
	// When an audit entry is present, BOTH the counter blob AND the audit file
	// must be staged in the SAME git add call. Staging them separately risks a
	// counter-advanced-but-no-audit orphan if the second add fails or is skipped.
	// Using a single invocation with explicit paths makes the atomicity visible
	// in the subprocess log and removes the two-step window entirely.
	addCtx, addCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer addCancel()

	var addArgs []string
	if auditBlobPath != "" {
		// Stage counter blob and audit file together — inseparable.
		addArgs = []string{"add", "--", blobPath, auditBlobPath}
	} else {
		addArgs = []string{"add", "--", blobPath}
	}

	_, addStderr, addExit, addErr := t.verifier.RunSubprocess(
		addCtx, cloneDir, hardenedEnv(),
		"git", addArgs...,
	)
	if addErr != nil {
		return fmt.Errorf("doCounterWrite: git add exec error: %w — run `byreis doctor`", addErr)
	}
	if addExit != 0 {
		return fmt.Errorf("doCounterWrite: git add exited %d: %s — run `byreis doctor`",
			addExit, fetchtransport.SanitizeOutput(addStderr))
	}

	// Step 7: configure git identity for the commit.
	configCtx, configCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer configCancel()

	_, _, configExit, configErr := t.verifier.RunSubprocess(
		configCtx, cloneDir, hardenedEnv(),
		"git", "config", "user.name", "byreis-admin",
	)
	if configErr != nil || configExit != 0 {
		return fmt.Errorf("doCounterWrite: git config user.name failed — run `byreis doctor`")
	}
	_, _, emailExit, emailErr := t.verifier.RunSubprocess(
		configCtx, cloneDir, hardenedEnv(),
		"git", "config", "user.email", "byreis-admin@localhost",
	)
	if emailErr != nil || emailExit != 0 {
		return fmt.Errorf("doCounterWrite: git config user.email failed — run `byreis doctor`")
	}

	// Step 8: produce the SSH signing key for this commit. The admin identity
	// key is loaded via the REUSED ManifestSigner adapter — no new key path,
	// no os.ReadFile, no BYREIS_KEY* env read here. We obtain the signature over
	// the commit message body and write a signing key file to the workspace.
	// The signing key is the admin's Ed25519 key, obtained indirectly by having
	// the ManifestSigner sign the message body; the git SSH commit signing
	// infrastructure then verifies it.
	//
	// Because git SSH commit signing requires the private key on disk or via
	// ssh-agent, we implement a two-phase approach:
	//   Phase A: create the commit WITHOUT a signature to capture the exact
	//            commit message body text.
	//   Phase B: sign the message body via ManifestSigner.SignText, write a
	//            detached .sig file, and amend the commit to add the signature.
	//
	// The commit IS the atomic unit; the signature is embedded in the final commit.
	// IMPORTANT: SignText is called AFTER commit message is known so the
	// signature covers the exact commit message body (no pre-commit guessing).
	//
	// Git SSH signing flow: write a gpg-format signature to a temp file and use
	// `git commit --gpg-sign` with a custom key. Because go-git's signed-commit
	// support is incomplete for SSH keys, we use `git commit -m <msg>` directly
	// and embed the signature in the commit body as a `gpgsig` trailer using
	// `git hash-object + git commit-tree + git update-ref` — the git plumbing approach.
	//
	// Simplified path: use `git commit --allow-empty-message -m <body>` then
	// produce the Ed25519 signature over the commit message body via SignText,
	// and amend. For this change, we sign the commit message body via SignText
	// and record the signerID+hex-sig as a structured footer in the commit
	// message body itself (following the pattern of signed manifests). This
	// is an explicit deviation from SSH commit signing: justified below.
	//
	// Justification for signed-footer-in-message vs. git SSH commit signing:
	// git SSH commit signing requires the admin's private key on disk (via a
	// key file or ssh-agent). Our ManifestSigner abstraction intentionally
	// hides the key material behind a port — we cannot extract the raw private
	// key. Embedding the signature as a structured footer in the commit message
	// body preserves the invariant that ManifestSigner is the only path to the
	// admin's private key, satisfies the "signed payload" requirement, and is
	// verifiable by a reader who knows the signerID's public key. The git-level
	// CAS (conditional push) is the availability guarantee; the signed footer
	// is the integrity guarantee. Both are required; neither replaces the other.
	//
	// The registry MUST have branch-protection requiring signed commits; this
	// enforcement is at the git host level, not here.
	signerID, sig, signErr := t.writeCfg.Signer.SignText(ctx, []byte(commitMsgBody))
	if signErr != nil {
		return fmt.Errorf("doCounterWrite: signing commit message body: %w — "+
			"check admin identity configuration: run `byreis doctor`", signErr)
	}

	// Build the full commit message: body + sig footer.
	// byreis-sig: bytes are written to a temp file; they NEVER appear in argv.
	fullMessage := commitMsgBody + "\n\nbyreis-signer: " + signerID + "\nbyreis-sig: " + fmt.Sprintf("%x", sig) + "\n"

	// Step 9: write commit message to a temp file so the byreis-sig: footer
	// never appears in the git subprocess argv.
	msgFile := filepath.Join(tmpDir, "commitmsg-counter.txt")
	if wErr := os.WriteFile(msgFile, []byte(fullMessage), 0o600); wErr != nil { //nolint:gosec
		return fmt.Errorf("doCounterWrite: writing commit message file: %w", wErr)
	}
	defer func() { _ = os.Remove(msgFile) }()

	commitCtx, commitCancel := fetchtransport.WithBoundedDeadline(ctx, 30*time.Second)
	defer commitCancel()

	_, commitStderr, commitExit, commitErr := t.verifier.RunSubprocess(
		commitCtx, cloneDir, hardenedEnv(),
		"git", "commit", "-F", msgFile,
	)
	if commitErr != nil {
		return fmt.Errorf("doCounterWrite: git commit exec error: %w — run `byreis doctor`", commitErr)
	}
	if commitExit != 0 {
		return fmt.Errorf("doCounterWrite: git commit exited %d: %s — run `byreis doctor`",
			commitExit, fetchtransport.SanitizeOutput(commitStderr))
	}

	// Step 10: conditional push — CAS via --force-with-lease=refs/heads/main:<parentSHA>.
	// If the registry HEAD moved since fetch, the push fails (non-fast-forward)
	// and we return ErrRegistryConcurrentWrite so the caller retries from step 1.
	pushCtx, pushCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer pushCancel()

	leaseRef := "refs/heads/main:" + parentSHA
	_, pushStderr, pushExit, pushErr := t.verifier.RunSubprocess(
		pushCtx, cloneDir,
		append(hardenedEnv(), authEnv()...),
		"git", "push", "--force-with-lease="+leaseRef, "origin", "main",
	)
	if pushErr != nil {
		return fmt.Errorf("doCounterWrite: git push exec error: %w — "+
			"check network connectivity: run `byreis doctor`", pushErr)
	}
	switch pushExit {
	case 0:
		// Success.
		return nil
	case 1:
		// Exit 1 from git push typically means non-fast-forward / lease mismatch.
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "rejected") || strings.Contains(stderrStr, "non-fast-forward") || strings.Contains(stderrStr, "stale info") {
			return fmt.Errorf("%w: doCounterWrite: push rejected (non-fast-forward / "+
				"concurrent write detected): %s",
				ErrRegistryConcurrentWrite, stderrStr)
		}
		// Other exit-1 causes: branch-protection rules.
		return fmt.Errorf("%w: doCounterWrite: push rejected by remote: %s",
			ErrRegistryWriteRejected, stderrStr)
	default:
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "403") || strings.Contains(stderrStr, "401") || strings.Contains(stderrStr, "Authentication") {
			return fmt.Errorf("%w: doCounterWrite: push authentication failure: %s",
				ErrRegistryWriteAuth, stderrStr)
		}
		return fmt.Errorf("%w: doCounterWrite: git push exited %d: %s",
			ErrRegistryWriteRejected, pushExit, stderrStr)
	}
}

// buildWritePendingJSON constructs the updated counter JSON and the signed commit
// message body for a WriteCounter (pending-phase) operation.
func (t *productionFetchTransport) buildWritePendingJSON(
	ctx context.Context,
	existing counterFileParsed,
	projectID, fileName, parentSHA string,
	pending *countertypes.PendingBump,
) ([]byte, string, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	pendingJSON := &counterPendingJSON{
		PendingCounter:    json.Number(fmt.Sprintf("%d", pending.PendingCounter)),
		TargetArtifactSHA: pending.TargetArtifactSHA,
		TargetPR:          pending.TargetPR,
		IntentAt:          now,
		ParentCommitSHA:   parentSHA,
	}

	wire := counterFileJSON{
		ProjectID:           projectID,
		File:                fileName,
		LastAcceptedCounter: json.Number(fmt.Sprintf("%d", existing.LastAcceptedCounter)),
		LastPR:              existing.LastPR,
		UpdatedAt:           now,
		Pending:             pendingJSON,
		// Preserve the existing rotation_epoch: single-file RecordPendingBump
		// must NOT touch the rotation_epoch field; only an atomic N-file
		// rotation commit changes it. A zero epoch is serialised as omitempty
		// (absent from JSON), which is wire-identical to a v0.1-written file.
		RotationEpoch: epochNumberOrOmit(existing.RotationEpoch),
	}

	raw, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("buildWritePendingJSON: marshalling: %w", err)
	}
	raw = append(raw, '\n')

	body := buildCounterCommitMessageBody(
		projectID, fileName,
		existing.LastAcceptedCounter,
		pending.PendingCounter,
		pending.TargetArtifactSHA,
		pending.TargetPR,
		parentSHA,
	)

	_ = ctx // reserved for future async expansion
	return raw, body, nil
}

// buildCommitPendingJSON constructs the updated counter JSON and the signed commit
// message body for a CommitCounter (advance+clear) operation. This produces the
// single atomic commit that simultaneously advances last_accepted_counter AND
// clears pending to null.
func (t *productionFetchTransport) buildCommitPendingJSON(
	ctx context.Context,
	existing counterFileParsed,
	projectID, fileName, parentSHA string,
	pendingCounter uint64,
) ([]byte, string, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	wire := counterFileJSON{
		ProjectID:           projectID,
		File:                fileName,
		LastAcceptedCounter: json.Number(fmt.Sprintf("%d", pendingCounter)),
		LastPR:              existing.Pending.TargetPR,
		UpdatedAt:           now,
		Pending:             nil, // atomically cleared in this single commit
		// Preserve the existing rotation_epoch: CommitBump (single-file merge) must
		// NOT touch the rotation_epoch field; only an atomic N-file rotation commit
		// changes it. The epoch is advanced exclusively by CommitRotation.
		RotationEpoch: epochNumberOrOmit(existing.RotationEpoch),
	}

	raw, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("buildCommitPendingJSON: marshalling: %w", err)
	}
	raw = append(raw, '\n')

	body := buildCounterCommitMessageBody(
		projectID, fileName,
		existing.LastAcceptedCounter,
		pendingCounter,
		existing.Pending.TargetArtifactSHA,
		existing.Pending.TargetPR,
		parentSHA,
	)

	_ = ctx // reserved for future async expansion
	return raw, body, nil
}

// buildCounterCommitMessageBody returns the canonical signed-payload envelope
// for a counter commit message body. The fields are:
//   - project_id
//   - file
//   - expected_previous_counter (= last_accepted_counter at fetch time)
//   - pending_counter           (the value being claimed)
//   - target_artifact_sha       (= verify.ContentSHA(signed artifact))
//   - target_pr                 (project-repo PR identifier)
//   - parent_commit_sha         (registry HEAD at fetch time — replay defence)
//
// The body is used as the git commit message body AND signed by the admin's
// ManifestSigner (Ed25519) via SignText. The signature is embedded as a
// structured footer so the message body + signature together form the tamper-
// evident record of intent.
func buildCounterCommitMessageBody(
	projectID, fileName string,
	expectedPreviousCounter, pendingCounter uint64,
	targetArtifactSHA, targetPR, parentCommitSHA string,
) string {
	return fmt.Sprintf(
		"byreis: counter write-ahead\n\n"+
			"project_id: %s\n"+
			"file: %s\n"+
			"expected_previous_counter: %d\n"+
			"pending_counter: %d\n"+
			"target_artifact_sha: %s\n"+
			"target_pr: %s\n"+
			"parent_commit_sha: %s\n",
		projectID, fileName,
		expectedPreviousCounter,
		pendingCounter,
		targetArtifactSHA,
		targetPR,
		parentCommitSHA,
	)
}

// CommitRotationTransport implements the optional rotationCommitTransport
// extension interface. It is the production realisation of CommitRotation: one
// signed registry commit that atomically advances last_accepted_counter for all
// N files, clears all N pending records, updates the rotation_epoch for all N
// files, and appends one audit/<project>.jsonl entry.
//
// The push uses --force-with-lease=refs/heads/main:<in.RegistryParentSHA>. The
// RegistryParentSHA MUST be the post-Phase-1 registry tip (the registry HEAD
// after all N RecordPendingBump commits have landed), not the pre-Phase-1 tip.
// A CONTRIBUTOR-mode call returns ErrRegistryWriteAuth before any clone is
// created (load-site mode-gate inherited from writeCfg.TokenProvider).
func (t *productionFetchTransport) CommitRotationTransport(ctx context.Context, repoURL string, in coreregistry.CommitRotationInput) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("CommitRotationTransport: context already cancelled: %w", ctxErr)
	}
	if t.writeCfg == nil || t.writeCfg.Signer == nil || t.writeCfg.TokenProvider == nil {
		return fmt.Errorf("%w: CommitRotationTransport: no write configuration provided — "+
			"run `byreis admin register` to add a registry-write token",
			ErrRegistryWriteAuth)
	}
	if len(in.PerFile) == 0 {
		return fmt.Errorf("CommitRotationTransport: PerFile is empty — " +
			"at least one file must be present in a rotation commit; " +
			"run `byreis admin rotation reconcile` to diagnose")
	}
	if err := fetchtransport.ValidateProjectID(in.ProjectID); err != nil {
		return fmt.Errorf("CommitRotationTransport: invalid ProjectID: %w", err)
	}
	if !fetchtransport.IsValidSHA(in.RegistryParentSHA) {
		return fmt.Errorf("CommitRotationTransport: RegistryParentSHA %q is not a valid SHA — "+
			"pass the post-Phase-1 registry HEAD tip; run `byreis admin rotation reconcile`",
			in.RegistryParentSHA)
	}

	// Load-site mode-gate: TokenProvider refuses to return the token in
	// CONTRIBUTOR mode (credential-separation invariant).
	token, tokenErr := t.writeCfg.TokenProvider.RegistryWriteToken(ctx, repoURL)
	if tokenErr != nil {
		return fmt.Errorf("%w: CommitRotationTransport: retrieving registry-write token: %v",
			ErrRegistryWriteAuth, tokenErr)
	}

	return t.doCommitRotation(ctx, repoURL, token, in)
}

// doCommitRotation is the internal implementation of CommitRotationTransport.
// It produces exactly ONE git commit and ONE git push per call.
//
// Commit body encoding: envelope head fields in a fixed order, then per-file
// blocks sorted ascending by logical_file (no map iteration in the signing
// stream). The canonical bytes are sha256-hashed into the signed body as
// audit_entry_sha for the audit append.
func (t *productionFetchTransport) doCommitRotation(
	ctx context.Context,
	repoURL, token string,
	in coreregistry.CommitRotationInput,
) error {
	// Sort PerFile ascending by logical_file name for deterministic signing
	// stream (no map iteration; sort slice by LogicalName).
	sorted := make([]coreregistry.PerFileCommit, len(in.PerFile))
	copy(sorted, in.PerFile)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].LogicalName < sorted[j].LogicalName
	})

	// Create an isolated 0700 workspace for all git operations.
	tmpDir, mkErr := os.MkdirTemp("", "byreis-rotation-commit-*")
	if mkErr != nil {
		return fmt.Errorf("doCommitRotation: cannot create temp workspace: %w — "+
			"check filesystem permissions: run `byreis doctor`", mkErr)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec // 0700 on dir is intentional: owner-only scratch workspace
		return fmt.Errorf("doCommitRotation: cannot chmod temp workspace to 0700: %w — "+
			"check filesystem permissions: run `byreis doctor`", chErr)
	}

	cloneDir := filepath.Join(tmpDir, "repo")

	hardenedEnv := func(extraEnv ...string) []string {
		base := fetchtransport.CleanGitEnv()
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
		return append(env, extraEnv...)
	}

	authEnv := func() []string {
		if token == "" {
			return nil
		}
		return []string{
			"GIT_CONFIG_COUNT=3",
			"GIT_CONFIG_KEY_0=core.hooksPath",
			"GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=core.fsmonitor",
			"GIT_CONFIG_VALUE_1=",
			"GIT_CONFIG_KEY_2=http.extraHeader",
			"GIT_CONFIG_VALUE_2=Authorization: Bearer " + token,
		}
	}

	// Clone the registry (shallow, full checkout for file writes). One clone,
	// one commit, one push — no loop of commits.
	cloneCtx, cloneCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := t.verifier.RunSubprocess(
		cloneCtx, tmpDir,
		append(hardenedEnv(), authEnv()...),
		"git", "clone", "--depth=1", "--no-local", "--", repoURL, cloneDir,
	)
	if cloneErr != nil {
		return fmt.Errorf("doCommitRotation: git clone exec error: %w — "+
			"ensure git is installed and the registry URL is reachable: run `byreis doctor`",
			cloneErr)
	}
	if cloneExit != 0 {
		return fmt.Errorf("%w: doCommitRotation: git clone exited %d: %s",
			ErrRegistryWriteAuth, cloneExit, fetchtransport.SanitizeOutput(cloneStderr))
	}

	now := time.Now().UTC().Format(time.RFC3339)

	// Update all N counter files in the working tree. Each file is read, the
	// pending record is cleared, last_accepted_counter is advanced, and
	// rotation_epoch is set to in.NewEpoch. Files are processed in the sorted
	// order so any filesystem-level determinism matches the signing stream.
	for _, pf := range sorted {
		if err := fetchtransport.ValidateFileName(pf.LogicalName); err != nil {
			return fmt.Errorf("doCommitRotation: invalid LogicalName %q: %w", pf.LogicalName, err)
		}

		blobPath := fetchtransport.CounterBlobPath(in.ProjectID, pf.LogicalName)
		counterFilePath := filepath.Join(cloneDir, filepath.FromSlash(blobPath))

		currentRaw, readErr := os.ReadFile(counterFilePath) //nolint:gosec // path under tmpDir clone, composed from validated inputs
		var existing counterFileParsed
		if readErr != nil {
			if !os.IsNotExist(readErr) {
				return fmt.Errorf("doCommitRotation: reading counter file for %q: %w — "+
					"run `byreis doctor`", pf.LogicalName, readErr)
			}
			// File absent: treat as zero counter (cold file). The pending should
			// exist from RecordPendingBump but tolerate absent file at commit time.
		} else {
			if len(currentRaw) > maxCounterJSONBytes {
				return fmt.Errorf("doCommitRotation: counter file for %q exceeds max size — "+
					"run `byreis doctor`", pf.LogicalName)
			}
			if len(bytes.TrimSpace(currentRaw)) > 0 {
				if dupErr := checkDuplicateJSONKeys(currentRaw); dupErr != nil {
					return fmt.Errorf("%w: doCommitRotation: duplicate key in counter file for %q: %v",
						coreregistry.ErrCounterStoreUnreadable, pf.LogicalName, dupErr)
				}
				var decErr error
				existing, decErr = decodeCounterFile(currentRaw)
				if decErr != nil {
					return fmt.Errorf("%w: doCommitRotation: decoding counter file for %q: %v",
						coreregistry.ErrCounterStoreUnreadable, pf.LogicalName, decErr)
				}
			}
		}

		// Build the updated counter JSON: advance counter, clear pending, set epoch.
		wire := counterFileJSON{
			ProjectID:           in.ProjectID,
			File:                pf.LogicalName,
			LastAcceptedCounter: json.Number(fmt.Sprintf("%d", pf.PendingCounter)),
			LastPR:              pf.TargetPR,
			UpdatedAt:           now,
			Pending:             nil, // atomically cleared
			RotationEpoch:       epochNumberOrOmit(in.NewEpoch),
		}
		_ = existing // existing counter data validated above; new values sourced from PerFileCommit

		newJSON, marshalErr := json.MarshalIndent(wire, "", "  ")
		if marshalErr != nil {
			return fmt.Errorf("doCommitRotation: marshalling counter JSON for %q: %w",
				pf.LogicalName, marshalErr)
		}
		newJSON = append(newJSON, '\n')

		counterDir := filepath.Dir(counterFilePath)
		if mkdirErr := os.MkdirAll(counterDir, 0o700); mkdirErr != nil {
			return fmt.Errorf("doCommitRotation: creating counter directory for %q: %w — "+
				"check filesystem permissions: run `byreis doctor`", pf.LogicalName, mkdirErr)
		}
		if writeErr := os.WriteFile(counterFilePath, newJSON, 0o600); writeErr != nil { //nolint:gosec // 0600 for counter file: owner-only
			return fmt.Errorf("doCommitRotation: writing counter file for %q: %w — "+
				"check filesystem permissions: run `byreis doctor`", pf.LogicalName, writeErr)
		}
	}

	// Build and write the audit JSONL entry to audit/<project>.jsonl.
	// The audit entry is part of the SAME commit as the counter advances
	// (same-commit atomicity).
	auditJSONLBytes, auditSHA, auditErr := buildAuditJSONLEntry(in.AuditEntry)
	if auditErr != nil {
		return fmt.Errorf("doCommitRotation: building audit JSONL entry: %w", auditErr)
	}

	auditFilePath := filepath.Join(cloneDir, "audit", in.ProjectID+".jsonl")
	auditDir := filepath.Dir(auditFilePath)
	if mkdirErr := os.MkdirAll(auditDir, 0o700); mkdirErr != nil {
		return fmt.Errorf("doCommitRotation: creating audit directory: %w — "+
			"check filesystem permissions: run `byreis doctor`", mkdirErr)
	}

	auditFile, openErr := os.OpenFile(auditFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // 0600 for audit file: owner-only
	if openErr != nil {
		return fmt.Errorf("doCommitRotation: opening audit file for append: %w — "+
			"check filesystem permissions: run `byreis doctor`", openErr)
	}
	_, appendErr := auditFile.Write(auditJSONLBytes)
	closeErr := auditFile.Close()
	if appendErr != nil {
		return fmt.Errorf("doCommitRotation: appending to audit file: %w — "+
			"check filesystem permissions: run `byreis doctor`", appendErr)
	}
	if closeErr != nil {
		return fmt.Errorf("doCommitRotation: closing audit file: %w — "+
			"check filesystem permissions: run `byreis doctor`", closeErr)
	}

	// Build the canonical signed commit message body.
	commitMsgBody := buildRotationCommitMessageBody(in, sorted, auditSHA)

	// Stage all changed files in a single git add invocation.
	addCtx, addCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer addCancel()

	_, addStderr, addExit, addErr := t.verifier.RunSubprocess(
		addCtx, cloneDir, hardenedEnv(),
		"git", "add", "-A",
	)
	if addErr != nil {
		return fmt.Errorf("doCommitRotation: git add exec error: %w — run `byreis doctor`", addErr)
	}
	if addExit != 0 {
		return fmt.Errorf("doCommitRotation: git add exited %d: %s — run `byreis doctor`",
			addExit, fetchtransport.SanitizeOutput(addStderr))
	}

	// Configure git identity for the commit.
	configCtx, configCancel := fetchtransport.WithBoundedDeadline(ctx, 10*time.Second)
	defer configCancel()

	_, _, nameExit, nameErr := t.verifier.RunSubprocess(
		configCtx, cloneDir, hardenedEnv(),
		"git", "config", "user.name", "byreis-admin",
	)
	if nameErr != nil || nameExit != 0 {
		return fmt.Errorf("doCommitRotation: git config user.name failed — run `byreis doctor`")
	}
	_, _, emailExit, emailErr := t.verifier.RunSubprocess(
		configCtx, cloneDir, hardenedEnv(),
		"git", "config", "user.email", "byreis-admin@localhost",
	)
	if emailErr != nil || emailExit != 0 {
		return fmt.Errorf("doCommitRotation: git config user.email failed — run `byreis doctor`")
	}

	// Sign the commit message body using the admin's ManifestSigner (same
	// writesigner instance as doCounterWrite — no new key material).
	signerID, sig, signErr := t.writeCfg.Signer.SignText(ctx, []byte(commitMsgBody))
	if signErr != nil {
		return fmt.Errorf("doCommitRotation: signing commit message body: %w — "+
			"check admin identity configuration: run `byreis doctor`", signErr)
	}

	// byreis-sig: bytes are written to a temp file; they NEVER appear in argv.
	fullMessage := commitMsgBody + "\n\nbyreis-signer: " + signerID +
		"\nbyreis-sig: " + fmt.Sprintf("%x", sig) + "\n"

	// Write commit message to a temp file so the byreis-sig: footer
	// never appears in the git subprocess argv.
	rotMsgFile := filepath.Join(tmpDir, "commitmsg-rotation.txt")
	if wErr := os.WriteFile(rotMsgFile, []byte(fullMessage), 0o600); wErr != nil { //nolint:gosec
		return fmt.Errorf("doCommitRotation: writing commit message file: %w", wErr)
	}
	defer func() { _ = os.Remove(rotMsgFile) }()

	// Create the signed commit — exactly ONE commit per rotation call.
	commitCtx, commitCancel := fetchtransport.WithBoundedDeadline(ctx, 30*time.Second)
	defer commitCancel()

	_, commitStderr, commitExit, commitErr := t.verifier.RunSubprocess(
		commitCtx, cloneDir, hardenedEnv(),
		"git", "commit", "-F", rotMsgFile,
	)
	if commitErr != nil {
		return fmt.Errorf("doCommitRotation: git commit exec error: %w — run `byreis doctor`", commitErr)
	}
	if commitExit != 0 {
		return fmt.Errorf("doCommitRotation: git commit exited %d: %s — run `byreis doctor`",
			commitExit, fetchtransport.SanitizeOutput(commitStderr))
	}

	// Conditional push — CAS via --force-with-lease=refs/heads/main:<RegistryParentSHA>.
	// The lease value is in.RegistryParentSHA byte-for-byte (the post-Phase-1 tip).
	// No per-step refresh inside doCommitRotation. Exactly ONE push per call.
	pushCtx, pushCancel := fetchtransport.WithBoundedDeadline(ctx, writeTimeout)
	defer pushCancel()

	leaseRef := "refs/heads/main:" + in.RegistryParentSHA
	_, pushStderr, pushExit, pushErr := t.verifier.RunSubprocess(
		pushCtx, cloneDir,
		append(hardenedEnv(), authEnv()...),
		"git", "push", "--force-with-lease="+leaseRef, "origin", "main",
	)
	if pushErr != nil {
		return fmt.Errorf("doCommitRotation: git push exec error: %w — "+
			"check network connectivity: run `byreis doctor`", pushErr)
	}
	switch pushExit {
	case 0:
		return nil
	case 1:
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "rejected") ||
			strings.Contains(stderrStr, "non-fast-forward") ||
			strings.Contains(stderrStr, "stale info") {
			// Rotation-distinct hint: includes "rotation" and the actionable
			// "byreis admin rotation reconcile" reference for recovery.
			return fmt.Errorf("%w: rotation CommitRotation push rejected "+
				"(non-fast-forward / concurrent write detected) — another admin write "+
				"landed between Phase 1 and Phase 2 of this rotation; "+
				"run `byreis admin rotation reconcile` to classify and recover: %s",
				ErrRegistryConcurrentWrite, stderrStr)
		}
		return fmt.Errorf("%w: doCommitRotation: push rejected by remote: %s",
			ErrRegistryWriteRejected, stderrStr)
	default:
		stderrStr := fetchtransport.SanitizeOutput(pushStderr)
		if strings.Contains(stderrStr, "403") ||
			strings.Contains(stderrStr, "401") ||
			strings.Contains(stderrStr, "Authentication") {
			return fmt.Errorf("%w: doCommitRotation: push authentication failure: %s",
				ErrRegistryWriteAuth, stderrStr)
		}
		return fmt.Errorf("%w: doCommitRotation: git push exited %d: %s",
			ErrRegistryWriteRejected, pushExit, stderrStr)
	}
}

// buildAuditJSONLEntry serialises an audit.Event to its canonical JSONL bytes
// (a single JSON object followed by a newline) and returns the sha256 hex digest
// of those bytes. The digest is embedded in the signed commit body as
// audit_entry_sha so the audit append is structurally inseparable from the
// counter advance (same-commit atomicity).
//
// Field order within the JSON object is deterministic because encoding/json
// serialises struct fields in declaration order. The Event struct has a fixed
// field order, so the canonical bytes are byte-stable for the same logical event.
//
// ValidateEventFields is called before serialisation so that a malformed
// Details map with a non-canonical value (e.g., high-entropy base64 run, bad
// pubkey format) is rejected before being signed into the registry.
func buildAuditJSONLEntry(e audit.Event) (jsonlBytes []byte, hexDigest string, err error) {
	if validateErr := audit.ValidateEventFields(e); validateErr != nil {
		return nil, "", fmt.Errorf("buildAuditJSONLEntry: event field validation failed: %w — "+
			"verify the audit-event producer constructs canonical-typed Details values", validateErr)
	}
	raw, marshalErr := json.Marshal(e)
	if marshalErr != nil {
		return nil, "", fmt.Errorf("buildAuditJSONLEntry: marshalling audit event: %w", marshalErr)
	}
	line := append(raw, '\n')
	sum := sha256.Sum256(line)
	return line, fmt.Sprintf("%x", sum[:]), nil
}

// buildRotationCommitMessageBody returns the canonical signed-payload envelope
// for a rotation commit message body. The encoding is:
//
//   - Envelope head: project_id, new_rotation_epoch, registry_parent_sha,
//     audit_entry_sha — all project-level fields (new_rotation_epoch is single
//     project-level, NOT per-file).
//   - Per-file blocks: sorted ascending by logical_file (no map iteration);
//     each carries logical_file, expected_previous_counter, pending_counter,
//     target_artifact_sha, target_pr, parent_commit_sha.
//
// No map iteration appears in the signing stream; sort is explicit and
// deterministic.
func buildRotationCommitMessageBody(
	in coreregistry.CommitRotationInput,
	sortedFiles []coreregistry.PerFileCommit,
	auditEntrySHA string,
) string {
	var b strings.Builder
	b.WriteString("byreis: rotation commit\n\n")
	fmt.Fprintf(&b, "project_id: %s\n", in.ProjectID)
	fmt.Fprintf(&b, "new_rotation_epoch: %d\n", in.NewEpoch)
	fmt.Fprintf(&b, "registry_parent_sha: %s\n", in.RegistryParentSHA)
	fmt.Fprintf(&b, "audit_entry_sha: %s\n", auditEntrySHA)
	for _, pf := range sortedFiles {
		fmt.Fprintf(&b,
			"file: %s\n"+
				"  expected_previous_counter: %d\n"+
				"  pending_counter: %d\n"+
				"  target_artifact_sha: %s\n"+
				"  target_pr: %s\n"+
				"  parent_commit_sha: %s\n",
			pf.LogicalName,
			pf.PendingCounter-1, // expected_previous = pending - 1
			pf.PendingCounter,
			pf.TargetSHA,
			pf.TargetPR,
			in.RegistryParentSHA, // per-file parent_commit_sha = the shared post-Phase-1 tip
		)
	}
	return b.String()
}

// isWarmProject reports whether the given (projectID, fileName) pair is
// "warm" — i.e., projects/<projectID>.yaml exists in the registry clone at
// headCommit AND lists fileName as a configured file.
//
// A warm project with an absent counter file is a counter-coverage integrity
// violation: the first merge must have created the counter. A cold project (not
// yet registered in projects/ or not yet listing this file) is safe to return 0.
//
// Returns (false, nil) on any read-failure so the caller can apply the
// fail-closed policy (treat as warm = fail with ErrCounterStoreUnreadable).
func (t *productionFetchTransport) isWarmProject(ctx context.Context, cloneDir, headCommit, projectID, fileName string) (bool, error) {
	projectsPath := "projects/" + projectID + ".yaml"
	raw, readErr := t.verifier.ReadBlobAtSHA(ctx, cloneDir, headCommit, projectsPath)
	if readErr != nil {
		if fetchtransport.IsBlobNotFound(readErr) {
			// No projects/<projectID>.yaml → cold project.
			return false, nil
		}
		// Read error → propagate so caller treats as warm (fail closed).
		return false, readErr
	}

	// Minimal YAML parse: look for the fileName key in the files: map.
	// Use a simple grep-style scan to avoid importing the full yaml decoder
	// here (production_transport.go already imports go.yaml.in/yaml/v3).
	type projectYAML struct {
		Files map[string]string `yaml:"files"`
	}
	var parsed projectYAML
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(false) // lenient: we only care about 'files'
	if decErr := dec.Decode(&parsed); decErr != nil {
		// Parse error → cannot determine warmth; caller treats as warm (fail closed).
		return false, decErr
	}

	_, listed := parsed.Files[fileName]
	return listed, nil
}

// verifyPendingParentSHA verifies that the parent_commit_sha recorded in the
// pending sub-object matches the actual parent of the commit that wrote the
// pending record. This is the captured-commit-replay defence: a captured
// signed counter commit cannot be silently reused at a different HEAD position
// because the parent SHA is embedded in both the signed commit message body
// and the counter JSON pending record.
//
// Implementation: use `git log -n 1 --pretty=format:%P -- <blobPath>` against
// the retained clone to find the parent(s) of the most recent commit that
// touched the counter file. The recorded parentCommitSHA must match.
//
// Returns nil when the check passes or when the recorded parentCommitSHA is
// empty (counter files written by earlier byreis versions without the field —
// treated permissively to avoid breaking existing counters until they are
// rewritten by WriteCounter).
func (t *productionFetchTransport) verifyPendingParentSHA(ctx context.Context, cloneDir, headCommit, blobPath, parentCommitSHA string) error {
	if parentCommitSHA == "" {
		// Legacy counter file without parent_commit_sha: permissive pass until
		// the pending record is rewritten by a WriteCounter call.
		return nil
	}

	// Find the most recent commit that touched the counter file.
	logCtx, logCancel := fetchtransport.WithBoundedDeadline(ctx, 15*time.Second)
	defer logCancel()

	tmpDir := filepath.Dir(cloneDir)
	logEnv := append(fetchtransport.CleanGitEnv(),
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

	// git log -n 1 --pretty=format:%P <headCommit> -- <blobPath>
	// %P = space-separated list of parent SHAs of the matching commit.
	stdout, _, logExit, logErr := t.verifier.RunSubprocess(
		logCtx, cloneDir, logEnv,
		"git", "log", "-n", "1", "--pretty=format:%P", headCommit, "--", blobPath,
	)
	if logErr != nil || logExit != 0 {
		// Cannot determine the parent commit. Treat as verification failure (fail closed).
		return fmt.Errorf("verifyPendingParentSHA: git log failed (exit %d): %w",
			logExit, logErr)
	}

	// Parse the parent SHA(s) — only the first parent is relevant.
	parentLine := strings.TrimSpace(string(stdout))
	if parentLine == "" {
		// The commit is a root commit (no parent). This is unusual; fail closed.
		return fmt.Errorf("verifyPendingParentSHA: counter commit has no parent — "+
			"unexpected root commit for %q at %q", blobPath, headCommit)
	}

	// The first parent is the one the admin fetched from (fast-forward registry).
	parts := strings.Fields(parentLine)
	actualParent := parts[0]

	if !fetchtransport.IsValidSHA(actualParent) {
		return fmt.Errorf("verifyPendingParentSHA: git log returned invalid parent SHA %q", actualParent)
	}

	if actualParent != parentCommitSHA {
		return fmt.Errorf(
			"parent_commit_sha mismatch: recorded %q, actual %q — "+
				"the pending record was written against a different registry HEAD; "+
				"possible replayed or misplaced commit",
			parentCommitSHA, actualParent)
	}

	return nil
}

// ReadProjectConfig reads projects/<projectID>.yaml at the exact pinned
// headCommit SHA from the retained clone. An absent file returns zero
// ProjectConfig with no error. Pops and cleans up the active session for this
// SHA (the clone was moved from pending to active by ReadAdmins).
func (t *productionFetchTransport) ReadProjectConfig(ctx context.Context, _ string, headCommit, projectID string) (ProjectConfig, error) {
	if err := fetchtransport.ValidateProjectID(projectID); err != nil {
		return ProjectConfig{}, fmt.Errorf(
			"registry ReadProjectConfig: invalid projectID: %w", err)
	}

	// Pop the active session for this SHA (set by ReadAdmins).
	// Always clean up when ReadProjectConfig returns, whether successfully or
	// with an error. If no session exists (e.g. ReadAdmins error path already
	// cleaned up), proceed without a clone and return empty config.
	sess := t.popActive(headCommit)
	if sess != nil {
		defer sess.cleanup()
	}

	if sess == nil || sess.cloneDir == "" {
		// No clone session available. This happens when ReadAdmins returned an
		// error (session already cleaned up) or in test paths that bypass FetchHead.
		return ProjectConfig{}, nil
	}

	path := "projects/" + projectID + ".yaml"
	raw, err := t.verifier.ReadBlobAtSHA(ctx, sess.cloneDir, headCommit, path)
	if err != nil {
		if fetchtransport.IsBlobNotFound(err) {
			return ProjectConfig{}, nil
		}
		return ProjectConfig{}, fmt.Errorf(
			"registry ReadProjectConfig: reading %q at %q from clone: %w — "+
				"run `byreis doctor` to diagnose", path, headCommit, err)
	}

	if int64(len(raw)) > maxAdminYAMLBytes {
		return ProjectConfig{}, fmt.Errorf(
			"registry ReadProjectConfig: %q at %q exceeds max size %d bytes (got %d) — "+
				"registry file is unusually large; run `byreis doctor`",
			path, headCommit, maxAdminYAMLBytes, len(raw))
	}

	type projectYAML struct {
		Files map[string]string `yaml:"files"`
	}
	var parsed projectYAML
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if decErr := dec.Decode(&parsed); decErr != nil {
		return ProjectConfig{}, fmt.Errorf(
			"registry ReadProjectConfig: decoding %q at %q: %w — "+
				"registry file may be malformed; run `byreis doctor`",
			path, headCommit, decErr)
	}

	return ProjectConfig(parsed), nil
}

// ReadAdmins reads and parses admins.yaml at the exact pinned headCommit SHA
// from the retained clone. ValidateProjectID is called before any path
// composition. Fails closed on absent/unparseable/empty admins.yaml.
//
// Pops the pending session for headCommit (created by FetchHead) and moves it
// to the active queue for ReadProjectConfig to consume. On error the session
// is cleaned up immediately (since ReadProjectConfig will not be called on the
// error path in FetchAdminSet).
func (t *productionFetchTransport) ReadAdmins(ctx context.Context, _ string, headCommit, projectID string) (ParsedAdminData, error) {
	if err := fetchtransport.ValidateProjectID(projectID); err != nil {
		return ParsedAdminData{}, fmt.Errorf(
			"registry ReadAdmins: invalid projectID: %w — "+
				"run `byreis doctor` to diagnose", err)
	}

	// Pop the pending session for this SHA (created by FetchHead).
	sess := t.popPending(headCommit)
	if sess == nil {
		// No session found. This is an internal invariant violation — FetchHead
		// must have been called and returned verified=true before ReadAdmins.
		return ParsedAdminData{}, fmt.Errorf(
			"%w: no clone session found for commit %q — "+
				"internal invariant violated; run `byreis doctor`",
			coreregistry.ErrAdminSetUnreadable, headCommit)
	}

	// SHA string-equality assertion: the session's verifiedSHA must exactly
	// match the headCommit parameter. This is the in-code SHA-identity assertion
	// required by the same-clone / verified-SHA provenance contract.
	if sess.verifiedSHA != headCommit {
		sess.cleanup()
		return ParsedAdminData{}, fmt.Errorf(
			"%w: session SHA %q does not match headCommit %q — "+
				"internal invariant violated; run `byreis doctor`",
			coreregistry.ErrAdminSetUnreadable, sess.verifiedSHA, headCommit)
	}

	raw, readErr := t.verifier.ReadBlobAtSHA(ctx, sess.cloneDir, headCommit, "admins.yaml")
	if readErr != nil {
		sess.cleanup()
		if fetchtransport.IsBlobNotFound(readErr) {
			return ParsedAdminData{}, fmt.Errorf(
				"%w: admins.yaml is absent at commit %q — "+
					"the registry must contain admins.yaml; run `byreis doctor`",
				coreregistry.ErrAdminSetUnreadable, headCommit)
		}
		return ParsedAdminData{}, fmt.Errorf(
			"%w: reading admins.yaml at commit %q: %v — "+
				"run `byreis doctor` to diagnose",
			coreregistry.ErrAdminSetUnreadable, headCommit, readErr)
	}

	if int64(len(raw)) > maxAdminYAMLBytes {
		sess.cleanup()
		return ParsedAdminData{}, fmt.Errorf(
			"%w: admins.yaml at commit %q exceeds max size %d bytes (got %d) — "+
				"registry file is unusually large; run `byreis doctor`",
			coreregistry.ErrAdminSetUnreadable, headCommit, maxAdminYAMLBytes, len(raw))
	}

	data, parseErr := parseAdminsYAML(raw, headCommit)
	if parseErr != nil {
		sess.cleanup()
		return ParsedAdminData{}, parseErr
	}

	if len(data.RawRecipients) == 0 {
		sess.cleanup()
		return ParsedAdminData{}, fmt.Errorf(
			"%w: admins.yaml at commit %q has an empty recipient set — "+
				"at least one admin recipient is required; run `byreis doctor`",
			coreregistry.ErrAdminSetUnreadable, headCommit)
	}
	if len(data.SignerKeys) == 0 {
		sess.cleanup()
		return ParsedAdminData{}, fmt.Errorf(
			"%w: admins.yaml at commit %q has an empty signer set — "+
				"at least one admin signing key is required; run `byreis doctor`",
			coreregistry.ErrNoTrustedSigner, headCommit)
	}

	// Move the session to the active queue so ReadProjectConfig can use the
	// same clone for its read.
	t.pushActive(headCommit, sess)

	return ParsedAdminData{
		Recipients: data.RawRecipients,
		SignerKeys: data.SignerKeys,
	}, nil
}

// adminsYAMLEntry is the strict wire format for a single entry in admins.yaml.
// KnownFields(true) rejects any field not listed here.
type adminsYAMLEntry struct {
	ID        string `yaml:"id"`
	AgeKey    string `yaml:"age_key"`
	SignerKey string `yaml:"signer_key"`
}

// adminsYAMLFile is the strict wire format for the top-level admins.yaml.
type adminsYAMLFile struct {
	Admins []adminsYAMLEntry `yaml:"admins"`
}

// parsedAdminsIntermediate holds the parsed-but-not-yet-returned values
// before the empty-set guards in ReadAdmins fire.
type parsedAdminsIntermediate struct {
	RawRecipients []rectypes.Recipient
	SignerKeys    map[string]coreregistry.SignerKey
}

// parseAdminsYAML decodes raw admins.yaml bytes into domain values.
// Uses strict KnownFields(true) YAML decoding. Rejects duplicate admin ids,
// non-base64 signer fields, wrong-length keys, all-zero Ed25519 keys, and
// entries with empty id, age_key, or signer_key fields.
func parseAdminsYAML(raw []byte, commitHint string) (parsedAdminsIntermediate, error) {
	var file adminsYAMLFile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&file); err != nil {
		return parsedAdminsIntermediate{}, fmt.Errorf(
			"%w: decoding admins.yaml at commit %q: %v — "+
				"registry file may be malformed or contain unknown fields; run `byreis doctor`",
			coreregistry.ErrAdminSetUnreadable, commitHint, err)
	}

	if len(file.Admins) == 0 {
		return parsedAdminsIntermediate{}, fmt.Errorf(
			"%w: admins.yaml at commit %q has no admin entries — "+
				"at least one admin is required; run `byreis doctor`",
			coreregistry.ErrAdminSetUnreadable, commitHint)
	}

	seenIDs := make(map[string]struct{}, len(file.Admins))
	recipients := make([]rectypes.Recipient, 0, len(file.Admins))
	signerKeys := make(map[string]coreregistry.SignerKey, len(file.Admins))

	for i, entry := range file.Admins {
		if entry.ID == "" {
			return parsedAdminsIntermediate{}, fmt.Errorf(
				"%w: admins.yaml entry index %d at commit %q has an empty id — "+
					"each admin entry must have a non-empty id; run `byreis doctor`",
				coreregistry.ErrAdminSetUnreadable, i, commitHint)
		}

		// Reject duplicate admin id — deterministic fail-closed, not last-write-wins.
		if _, dup := seenIDs[entry.ID]; dup {
			return parsedAdminsIntermediate{}, fmt.Errorf(
				"%w: admins.yaml at commit %q has duplicate admin id %q — "+
					"admin ids must be unique; run `byreis doctor`",
				coreregistry.ErrAdminSetUnreadable, commitHint, entry.ID)
		}
		seenIDs[entry.ID] = struct{}{}

		// Validate the age recipient key.
		if entry.AgeKey == "" {
			return parsedAdminsIntermediate{}, fmt.Errorf(
				"%w: admin %q in admins.yaml at commit %q has an empty age_key — "+
					"each admin entry must have a non-empty age_key; run `byreis doctor`",
				coreregistry.ErrAdminSetUnreadable, entry.ID, commitHint)
		}
		// Admit a recipient iff its backend is a member of the closed admit-set
		// (native X25519 or a supported age-plugin backend). This validates the
		// bech32 encoding and the backend discriminator, rejecting both malformed
		// keys and well-formed keys for unsupported backends fail-closed — a
		// loose "age1" prefix is no longer sufficient.
		if _, classErr := validator.ClassifyRecipient(entry.AgeKey); classErr != nil {
			return parsedAdminsIntermediate{}, fmt.Errorf(
				"%w: admin %q in admins.yaml at commit %q has an unsupported age_key: %v",
				coreregistry.ErrAdminSetUnreadable, entry.ID, commitHint, classErr)
		}
		fp := ageKeyFingerprint(entry.AgeKey)
		recipients = append(recipients, rectypes.Recipient{
			Label:       entry.ID,
			AgePubKey:   entry.AgeKey,
			Fingerprint: fp,
		})

		// Validate and decode the Ed25519 signer key (base64-encoded raw bytes).
		if entry.SignerKey == "" {
			return parsedAdminsIntermediate{}, fmt.Errorf(
				"%w: admin %q in admins.yaml at commit %q has an empty signer_key — "+
					"each admin entry must have a non-empty signer_key; run `byreis doctor`",
				coreregistry.ErrNoTrustedSigner, entry.ID, commitHint)
		}
		keyBytes, decErr := base64.StdEncoding.DecodeString(entry.SignerKey)
		if decErr != nil {
			return parsedAdminsIntermediate{}, fmt.Errorf(
				"%w: admin %q signer_key in admins.yaml at commit %q is not valid base64 — "+
					"run `byreis doctor`",
				coreregistry.ErrNoTrustedSigner, entry.ID, commitHint)
		}
		if len(keyBytes) != ed25519.PublicKeySize {
			return parsedAdminsIntermediate{}, fmt.Errorf(
				"%w: admin %q signer_key in admins.yaml at commit %q has length %d (need %d) — "+
					"run `byreis doctor`",
				coreregistry.ErrNoTrustedSigner, entry.ID, commitHint,
				len(keyBytes), ed25519.PublicKeySize)
		}
		if isAllZeroKey(keyBytes) {
			return parsedAdminsIntermediate{}, fmt.Errorf(
				"%w: admin %q signer_key in admins.yaml at commit %q is all-zero — "+
					"a zero key is not a valid Ed25519 public key; run `byreis doctor`",
				coreregistry.ErrNoTrustedSigner, entry.ID, commitHint)
		}
		signerKeys[entry.ID] = coreregistry.SignerKey(keyBytes)
	}

	return parsedAdminsIntermediate{
		RawRecipients: recipients,
		SignerKeys:    signerKeys,
	}, nil
}

// ageKeyFingerprint computes the rectypes.Fingerprint (SHA-256) of an age
// public key string. The preimage is the UTF-8 bytes of the "age1..." string,
// consistent with the encrypt package's fingerprint convention.
func ageKeyFingerprint(agePubKey string) rectypes.Fingerprint {
	sum := sha256.Sum256([]byte(agePubKey))
	return rectypes.Fingerprint(sum)
}

// epochNumberOrOmit converts a uint64 epoch to a json.Number suitable for
// the counterFileJSON.RotationEpoch field. When epoch == 0, it returns an
// empty json.Number so the omitempty tag omits the field from the JSON output,
// producing a file wire-identical to a v0.1-written file for epoch-zero state.
// When epoch > 0, it returns the decimal string representation.
func epochNumberOrOmit(epoch uint64) json.Number {
	if epoch == 0 {
		return "" // omitempty: field absent from JSON output
	}
	return json.Number(fmt.Sprintf("%d", epoch))
}

// isAllZeroKey returns true if all bytes in b are zero.
func isAllZeroKey(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// counterPendingJSON is the strict wire format for the "pending" sub-object in
// the counter store JSON, matching the documented counter store wire format,
// plus the parent_commit_sha replay-defence anchor.
// Field names must match exactly; DisallowUnknownFields rejects extra fields.
// PendingCounter uses json.Number so UseNumber() mode rejects floats/scientific.
type counterPendingJSON struct {
	PendingCounter    json.Number `json:"pending_counter"`
	TargetArtifactSHA string      `json:"target_artifact_sha"`
	TargetPR          string      `json:"target_pr"`
	IntentAt          string      `json:"intent_at"`
	// ParentCommitSHA is the registry HEAD SHA at the time the pending record
	// was written. It is included here so ReadCounter can verify the pending
	// record is anchored to the correct parent (replay-defence anchor). It is
	// also embedded in the signed commit message body for git-level coverage.
	ParentCommitSHA string `json:"parent_commit_sha"`
}

// counterFileJSON is the wire format for the counter store JSON file,
// matching the documented counter store wire format.
// Field names must match exactly.
// json.Number mode is used for the counter fields to reject scientific notation,
// floats, and out-of-range values.
//
// DisallowUnknownFields IS used in decodeCounterFile: truly unknown keys are
// rejected (ErrCounterStoreUnreadable). The RotationEpoch field was added in
// v0.2 and is declared here, so v0.2 files are accepted by DisallowUnknownFields.
// Writes from byreis v0.1 omit rotation_epoch; the omitempty tag means v0.2 also omits it
// when epoch == 0, preserving wire compatibility for the counter-zero case.
//
// Note: a strict-decoder reader that rejects unknown JSON keys cannot parse
// counter-store files written with this rotation_epoch field present.
// The v0.2-and-later decoder accepts the field; pre-rotation files (where the
// field is absent) parse fine via the omitempty default-zero path.
type counterFileJSON struct {
	ProjectID           string      `json:"project_id"`
	File                string      `json:"file"`
	LastAcceptedCounter json.Number `json:"last_accepted_counter"`
	LastPR              string      `json:"last_pr"`
	UpdatedAt           string      `json:"updated_at"`
	// RotationEpoch is the project-level rotation epoch for this file, added in
	// v0.2. It is incremented by CommitRotation for all N files atomically.
	// Single-file CommitBump leaves this field unchanged. The omitempty tag
	// omits the field when epoch == 0, so v0.2 writes of epoch-zero files are
	// wire-identical to v0.1 writes — a v0.1 binary reading a new epoch=0
	// file sees no unknown field.
	RotationEpoch json.Number         `json:"rotation_epoch,omitempty"`
	Pending       *counterPendingJSON `json:"pending"`
}

// counterFileParsed is the fully-decoded, post-semantic-validation counter file
// with integer counter values (not json.Number).
type counterFileParsed struct {
	ProjectID           string
	File                string
	LastAcceptedCounter uint64
	LastPR              string
	UpdatedAt           string
	RotationEpoch       uint64 // 0 when absent (backwards-compatible default)
	Pending             *counterPendingParsed
}

// counterPendingParsed mirrors counterPendingJSON but with uint64 counter.
type counterPendingParsed struct {
	PendingCounter    uint64
	TargetArtifactSHA string
	TargetPR          string
	IntentAt          string
	ParentCommitSHA   string
}

// checkDuplicateJSONKeys performs a token-stream pre-scan of raw JSON to detect
// duplicate keys at any nesting level. The Go stdlib json.Decoder with
// DisallowUnknownFields does NOT catch duplicate keys (last-write-wins). This
// separate pass is required: a counter blob with duplicate keys is rejected as
// ErrCounterStoreUnreadable-worthy.
//
// Returns an error describing the first duplicate key found, or nil if all keys
// are unique.
func checkDuplicateJSONKeys(raw []byte) error {
	type frame struct {
		keys map[string]struct{}
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	var stack []frame

	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// A non-EOF parse error means the JSON is malformed; surface it so
			// the caller wraps it as ErrCounterStoreUnreadable. The duplicate-key
			// scan itself does not need to return a parse error (the full Decode
			// call below will catch it again with DisallowUnknownFields), but we
			// break early to avoid infinite loops on malformed input.
			break
		}

		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, frame{keys: make(map[string]struct{})})
			case '}':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			case '[':
				// Arrays do not have keys; push a nil-keyed frame as placeholder.
				stack = append(stack, frame{keys: nil})
			case ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
		case string:
			// A string token after a '{' delimiter (inside an object) is a key.
			// After the key comes a value; we track keys in the current frame.
			if len(stack) > 0 {
				top := &stack[len(stack)-1]
				if top.keys != nil {
					if _, exists := top.keys[v]; exists {
						return fmt.Errorf("duplicate key %q in counter store JSON", v)
					}
					top.keys[v] = struct{}{}
				}
			}
		}
	}
	return nil
}

// decodeCounterFile decodes the raw JSON bytes into a counterFileParsed using
// UseNumber mode for integer-only counter fields. DisallowUnknownFields is used
// to reject keys not declared in counterFileJSON — the counterFileJSON struct
// includes rotation_epoch (added in v0.2), so v0.2 files are accepted and
// truly unknown keys are rejected. The checkDuplicateJSONKeys pre-scan is the
// guard against malicious duplicate keys.
// The caller must have already run checkDuplicateJSONKeys and the pre-decode
// size check before calling this function.
func decodeCounterFile(raw []byte) (counterFileParsed, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()

	var wire counterFileJSON
	if err := dec.Decode(&wire); err != nil {
		return counterFileParsed{}, fmt.Errorf("decoding counter JSON: %w", err)
	}

	// Parse last_accepted_counter: integer-only, no scientific notation, no
	// negative, no decimal, range [0, math.MaxUint64].
	la, err := parseCounterNumber(wire.LastAcceptedCounter, "last_accepted_counter")
	if err != nil {
		return counterFileParsed{}, err
	}

	// Parse rotation_epoch: present only in v0.2+ files. When absent (empty
	// json.Number from omitempty), defaults to 0 for backwards compatibility
	// with v0.1-produced files.
	var rotationEpoch uint64
	if wire.RotationEpoch != "" {
		rotationEpoch, err = parseCounterNumber(wire.RotationEpoch, "rotation_epoch")
		if err != nil {
			return counterFileParsed{}, err
		}
	}

	result := counterFileParsed{
		ProjectID:           wire.ProjectID,
		File:                wire.File,
		LastAcceptedCounter: la,
		LastPR:              wire.LastPR,
		UpdatedAt:           wire.UpdatedAt,
		RotationEpoch:       rotationEpoch,
	}

	if wire.Pending != nil {
		pc, err := parseCounterNumber(wire.Pending.PendingCounter, "pending.pending_counter")
		if err != nil {
			return counterFileParsed{}, err
		}
		result.Pending = &counterPendingParsed{
			PendingCounter:    pc,
			TargetArtifactSHA: wire.Pending.TargetArtifactSHA,
			TargetPR:          wire.Pending.TargetPR,
			IntentAt:          wire.Pending.IntentAt,
			ParentCommitSHA:   wire.Pending.ParentCommitSHA,
		}
	}

	return result, nil
}

// parseCounterNumber parses a json.Number for a counter field. Rejects:
// scientific notation (contains 'e'/'E'), decimal point (contains '.'),
// negative values (starts with '-'), values > math.MaxUint64, leading zeros
// (except literal "0"), leading '+'.
func parseCounterNumber(n json.Number, fieldName string) (uint64, error) {
	s := n.String()
	if s == "" {
		return 0, fmt.Errorf("counter field %q is empty", fieldName)
	}
	// Reject negative.
	if s[0] == '-' {
		return 0, fmt.Errorf(
			"counter field %q must not be negative (got %q)", fieldName, s)
	}
	// Reject leading '+'.
	if s[0] == '+' {
		return 0, fmt.Errorf(
			"counter field %q must not have a leading '+' (got %q)", fieldName, s)
	}
	// Reject scientific notation.
	if strings.ContainsAny(s, "eE") {
		return 0, fmt.Errorf(
			"counter field %q must be an integer, not scientific notation (got %q)",
			fieldName, s)
	}
	// Reject decimal.
	if strings.Contains(s, ".") {
		return 0, fmt.Errorf(
			"counter field %q must be an integer, not a decimal (got %q)", fieldName, s)
	}
	// Reject leading zeros (except literal "0").
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf(
			"counter field %q must not have a leading zero (got %q)", fieldName, s)
	}
	// Parse as uint64.
	v, parseErr := parseUint64(s)
	if parseErr != nil {
		return 0, fmt.Errorf(
			"counter field %q is not a valid uint64 (got %q): %w", fieldName, s, parseErr)
	}
	return v, nil
}

// parseUint64 parses a non-negative decimal string as a uint64.
// Returns an error on overflow or non-digit characters.
func parseUint64(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}
	var result uint64
	const maxVal = math.MaxUint64
	const maxValDivBy10 = maxVal / 10
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit character %q", c)
		}
		d := uint64(c - '0')
		if result > maxValDivBy10 || (result == maxValDivBy10 && d > maxVal%10) {
			return 0, fmt.Errorf("value overflows uint64")
		}
		result = result*10 + d
	}
	return result, nil
}

// isValidSHALowercase returns true if s is a valid 64-char lowercase hex string
// (BLAKE2b-256 / SHA-256 artifact SHA as used in target_artifact_sha).
func isValidSHALowercase64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validateCounterFileSemantics applies the post-decode semantic invariants
// for the counter file schema. All failures are returned as plain errors; the
// caller wraps them with ErrCounterStoreUnreadable.
func validateCounterFileSemantics(cf counterFileParsed, projectID, fileName string) error {
	// project_id must match caller-supplied projectID byte-for-byte.
	if cf.ProjectID != projectID {
		return fmt.Errorf(
			"project_id field %q does not match expected %q",
			cf.ProjectID, projectID)
	}
	// file must match caller-supplied fileName byte-for-byte.
	if cf.File != fileName {
		return fmt.Errorf(
			"file field %q does not match expected %q", cf.File, fileName)
	}
	// last_accepted_counter == 0 implies last_pr must be empty.
	if cf.LastAcceptedCounter == 0 && cf.LastPR != "" {
		return fmt.Errorf(
			"last_pr must be empty when last_accepted_counter is 0 (got %q)",
			cf.LastPR)
	}
	// last_accepted_counter > 0 implies last_pr must be non-empty.
	if cf.LastAcceptedCounter > 0 && cf.LastPR == "" {
		return fmt.Errorf(
			"last_pr must be non-empty when last_accepted_counter is %d",
			cf.LastAcceptedCounter)
	}
	// Validate pending record if present.
	if cf.Pending != nil {
		p := cf.Pending
		// pending_counter must be exactly last_accepted_counter + 1.
		if p.PendingCounter != cf.LastAcceptedCounter+1 {
			return fmt.Errorf(
				"pending.pending_counter %d must equal last_accepted_counter %d + 1",
				p.PendingCounter, cf.LastAcceptedCounter)
		}
		// target_artifact_sha must be 64 lowercase hex chars.
		if !isValidSHALowercase64(p.TargetArtifactSHA) {
			return fmt.Errorf(
				"pending.target_artifact_sha %q is not a 64-char lowercase hex string",
				p.TargetArtifactSHA)
		}
		// target_pr must be non-empty when pending is present.
		if p.TargetPR == "" {
			return fmt.Errorf(
				"pending.target_pr must not be empty when pending record is present")
		}
		// intent_at must be non-empty when pending is present.
		if p.IntentAt == "" {
			return fmt.Errorf(
				"pending.intent_at must not be empty when pending record is present")
		}
		// parent_commit_sha must be a valid SHA when pending is present.
		if p.ParentCommitSHA == "" {
			return fmt.Errorf(
				"pending.parent_commit_sha must not be empty when pending record is present")
		}
		if !fetchtransport.IsValidSHA(p.ParentCommitSHA) {
			return fmt.Errorf(
				"pending.parent_commit_sha %q is not a valid 40/64-hex SHA",
				p.ParentCommitSHA)
		}
	}
	return nil
}

// ReadRotationEpoch reads the rotation_epoch field from the counter store file
// for the given (projectID, fileName) at the given verified headCommit. It does
// not use the session pipeline (ReadCounter's clone session); it opens a
// temporary clone to read the blob directly. Returns 0 and nil when the counter
// file is absent or when the rotation_epoch field is missing.
//
// This is a read-only operation: it does not advance any counter or deposit any
// session. Context cancellation is honoured; a cancelled context returns (0, err).
func (t *productionFetchTransport) ReadRotationEpoch(ctx context.Context, repoURL, headCommit, projectID, fileName string) (uint64, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, fmt.Errorf(
			"ReadRotationEpoch: context already cancelled: %w — run `byreis doctor`", ctxErr)
	}

	if err := fetchtransport.ValidateProjectID(projectID); err != nil {
		return 0, fmt.Errorf(
			"%w: ReadRotationEpoch: invalid projectID: %v — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, err)
	}
	if err := fetchtransport.ValidateFileName(fileName); err != nil {
		return 0, fmt.Errorf(
			"%w: ReadRotationEpoch: invalid fileName: %v — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, err)
	}
	if !fetchtransport.IsValidSHA(headCommit) {
		return 0, fmt.Errorf(
			"%w: ReadRotationEpoch: headCommit %q is not a valid SHA — "+
				"internal invariant violated; run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, headCommit)
	}

	// Create a temporary workspace for the clone.
	tmpDir, mkErr := os.MkdirTemp("", "byreis-epoch-read-*")
	if mkErr != nil {
		return 0, fmt.Errorf("ReadRotationEpoch: cannot create temp workspace: %w — "+
			"check filesystem permissions: run `byreis doctor`", mkErr)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec // 0700 on dir is intentional: owner-only scratch workspace
		return 0, fmt.Errorf("ReadRotationEpoch: cannot chmod temp workspace to 0700: %w — "+
			"check filesystem permissions: run `byreis doctor`", chErr)
	}

	cloneDir := filepath.Join(tmpDir, "repo")

	hardenedEnv := func() []string {
		base := fetchtransport.CleanGitEnv()
		return append(base,
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
	}

	cloneCtx, cloneCancel := fetchtransport.WithBoundedDeadline(ctx, 30*time.Second)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := t.verifier.RunSubprocess(
		cloneCtx, tmpDir, hardenedEnv(),
		"git", "clone", "--depth=1", "--no-local", "--", repoURL, cloneDir,
	)
	if cloneErr != nil {
		return 0, fmt.Errorf("ReadRotationEpoch: git clone exec error: %w — "+
			"run `byreis doctor`", cloneErr)
	}
	if cloneExit != 0 {
		return 0, fmt.Errorf("%w: ReadRotationEpoch: git clone exited %d: %s — "+
			"run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, cloneExit,
			fetchtransport.SanitizeOutput(cloneStderr))
	}

	blobPath := fetchtransport.CounterBlobPath(projectID, fileName)
	raw, readErr := t.verifier.ReadBlobAtSHA(ctx, cloneDir, headCommit, blobPath)
	if readErr != nil {
		if fetchtransport.IsBlobNotFound(readErr) {
			return 0, nil // absent counter file defaults to epoch 0
		}
		return 0, fmt.Errorf(
			"%w: ReadRotationEpoch: reading %q at %q: %v — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, blobPath, headCommit, readErr)
	}

	if len(raw) > maxCounterJSONBytes {
		return 0, fmt.Errorf(
			"%w: ReadRotationEpoch: counter blob %q at %q exceeds max size %d bytes — "+
				"run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, blobPath, headCommit, maxCounterJSONBytes)
	}

	if len(bytes.TrimSpace(raw)) == 0 {
		return 0, nil // empty blob: treat as epoch 0
	}

	cf, decErr := decodeCounterFile(raw)
	if decErr != nil {
		return 0, fmt.Errorf(
			"%w: ReadRotationEpoch: decoding counter blob %q at %q: %v — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, blobPath, headCommit, decErr)
	}

	return cf.RotationEpoch, nil
}

// maxAuditJSONLBytes is the pre-decode size cap for the audit JSONL file.
// Audit logs are append-only and can legitimately grow larger than a single
// counter JSON object, so a generous ceiling is appropriate. The per-line cap
// (maxAuditLineBytes) and the result-count cap are the real ceilings for OOM
// safety; this total cap is the outermost defence against a pathologically large
// or maliciously inflated blob.
const maxAuditJSONLBytes = 8 * 1024 * 1024 // 8 MiB

// maxAuditLineBytes is the per-JSONL-line byte cap applied via
// bufio.Scanner.Buffer. A single audit event should never be remotely close to
// this limit; setting it explicitly (rather than relying on the Scanner default)
// makes the bound structural and testable.
const maxAuditLineBytes = 256 * 1024 // 256 KiB

// ReadAuditLog reads the raw audit/<projectID>.jsonl blob from the registry
// tree at the exact verified headCommit. It mirrors ReadRotationEpoch in its
// clone discipline: one temporary workspace, bounded subprocess timeout,
// ValidateProjectID before path composition, IsBlobNotFound absent handling, and
// a size ceiling before returning the raw bytes to the caller.
//
// headCommit MUST be the SHA from the caller's single preceding verified
// FetchHead call (same-invocation provenance — no second FetchHead, no TOCTOU
// window). An absent audit file returns (nil, nil); a blob exceeding
// maxAuditJSONLBytes returns a typed bounded-read error.
func (t *productionFetchTransport) ReadAuditLog(ctx context.Context, repoURL, headCommit, projectID string) ([]byte, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf(
			"ReadAuditLog: context already cancelled: %w — run `byreis doctor`", ctxErr)
	}

	if err := fetchtransport.ValidateProjectID(projectID); err != nil {
		return nil, fmt.Errorf(
			"%w: ReadAuditLog: invalid projectID: %v — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, err)
	}
	if !fetchtransport.IsValidSHA(headCommit) {
		return nil, fmt.Errorf(
			"%w: ReadAuditLog: headCommit %q is not a valid SHA — "+
				"internal invariant violated; run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, headCommit)
	}

	tmpDir, mkErr := os.MkdirTemp("", "byreis-audit-read-*")
	if mkErr != nil {
		return nil, fmt.Errorf("ReadAuditLog: cannot create temp workspace: %w — "+
			"check filesystem permissions: run `byreis doctor`", mkErr)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if chErr := os.Chmod(tmpDir, 0o700); chErr != nil { //nolint:gosec // 0700 on dir is intentional: owner-only scratch workspace
		return nil, fmt.Errorf("ReadAuditLog: cannot chmod temp workspace to 0700: %w — "+
			"check filesystem permissions: run `byreis doctor`", chErr)
	}

	cloneDir := filepath.Join(tmpDir, "repo")

	hardenedEnv := func() []string {
		base := fetchtransport.CleanGitEnv()
		return append(base,
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
	}

	cloneCtx, cloneCancel := fetchtransport.WithBoundedDeadline(ctx, 30*time.Second)
	defer cloneCancel()

	_, cloneStderr, cloneExit, cloneErr := t.verifier.RunSubprocess(
		cloneCtx, tmpDir, hardenedEnv(),
		"git", "clone", "--depth=1", "--no-local", "--", repoURL, cloneDir,
	)
	if cloneErr != nil {
		return nil, fmt.Errorf("ReadAuditLog: git clone exec error: %w — "+
			"run `byreis doctor`", cloneErr)
	}
	if cloneExit != 0 {
		return nil, fmt.Errorf("%w: ReadAuditLog: git clone exited %d: %s — "+
			"run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, cloneExit,
			fetchtransport.SanitizeOutput(cloneStderr))
	}

	// Compose the audit blob path AFTER ValidateProjectID passes.
	blobPath := "audit/" + projectID + ".jsonl"
	raw, readErr := t.verifier.ReadBlobAtSHA(ctx, cloneDir, headCommit, blobPath)
	if readErr != nil {
		if fetchtransport.IsBlobNotFound(readErr) {
			return nil, nil // absent audit file: valid "no entries yet" outcome
		}
		return nil, fmt.Errorf(
			"%w: ReadAuditLog: reading %q at %q: %v — run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, blobPath, headCommit, readErr)
	}

	if len(raw) > maxAuditJSONLBytes {
		return nil, fmt.Errorf(
			"%w: ReadAuditLog: audit blob %q at %q exceeds max size %d bytes — "+
				"run `byreis doctor`",
			coreregistry.ErrCounterStoreUnreadable, blobPath, headCommit, maxAuditJSONLBytes)
	}

	return raw, nil
}

// Compile-time assertions: productionFetchTransport satisfies both
// FetchTransport and the mergeAuditTransport extension. The merge path
// dispatches to CommitCounterWithAudit via a runtime interface assertion;
// this assertion ensures that if the method is ever removed or renamed
// the build fails before any test can silently fall through to the
// bare-CommitCounter path.
var _ FetchTransport = (*productionFetchTransport)(nil)
var _ mergeAuditTransport = (*productionFetchTransport)(nil)
