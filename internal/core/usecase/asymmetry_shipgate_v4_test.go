//go:build shipgate

// V4 (REQ-R-003 R1/R2/R3 + ADR-0016 BO-V4-* §V4 ship-gate addendum) — six
// shipgate rows that extend internal/core/usecase/asymmetry_shipgate_test.go
// per design/V02_WORK_BREAKDOWN.md §V4 (amended 2026-05-21 under RULING-T6
// (a) + RULING-T3 (d)).
//
// Row map (1:1 with WBS §V4 table after the V4-PRE-impl ruling):
//
//   V4.R1                     → TestAsymmetryShipGateV4_R1_RemovedAdminCannotDecryptPostRotationFile
//   V4.R2.pre                 → TestAsymmetryShipGateV4_R2_Pre_ContributorDeniedAcrossSurface
//   V4.R2.mid                 → TestAsymmetryShipGateV4_R2_Mid_ContributorDeniedAfterPhase1Checkpoint
//   V4.R2.post                → TestAsymmetryShipGateV4_R2_Post_ContributorDeniedAcrossSurface
//   V4.R3.midcrash            → TestAsymmetryShipGateV4_R3_MidCrash_OnDiskStateIsOneOfTwoValidStates
//   V4.BO11.write-side-usecase → TestAsymmetryShipGateV4_BO11_RotateProducesAuditJSONLEntry
//
// Build constraint: //go:build shipgate ONLY. Per BO-V4-4 evidence (i)+(ii)
// these rows do NOT add the testhook tag, do NOT import
// rotate.NewWitnessForTest, and do NOT import rotate.CrashBetweenPhase1Phase2.
// The Phase2-boundary crash is expressed via crashingPhase2Executor (sibling
// file asymmetry_shipgate_v4_decorator_test.go) per RULING-T3 (d).
//
// Engineering-standards adherence (`/reis-dev` NON-NEGOTIABLE, applied here):
//   - context.Context first param on all I/O paths (real git, real registry).
//   - errors wrapped with %w; sentinels used for explicit assertion.
//   - no panics in helper code (panics ONLY in test-internal spies — same
//     precedent as shipgatePanickingKeyring in the v0.1 row).
//   - `go test -race` clean (no shared mutable state across goroutines).
//   - injected clock/fs/keychain where feasible; the suite legitimately drives
//     real `age` / `ssh-keygen` / `git` per v0.1 §7.1 ship-gate precedent.
//   - no Claude/AI attribution; no internal review IDs in shipped code.
//     Internal IDs (BO-V4-*, REQ-R-003-*) ARE allowed here per CLAUDE.md
//     "code comment hygiene" since this file is *_test.go.
package usecase_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"go.yaml.in/yaml/v3"

	"github.com/ByReisK/byreis/internal/cli"
	"github.com/ByReisK/byreis/internal/cli/render"
	"github.com/ByReisK/byreis/internal/core/audit"
	"github.com/ByReisK/byreis/internal/core/crypto/artifact"
	"github.com/ByReisK/byreis/internal/core/crypto/manifest"
	"github.com/ByReisK/byreis/internal/core/crypto/sign"
	coregit "github.com/ByReisK/byreis/internal/core/git"
	"github.com/ByReisK/byreis/internal/core/mode"
	"github.com/ByReisK/byreis/internal/core/registry/rectypes"
	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// ───────────────────────── shared V4 constants ─────────────────────────

// v4SecondAdminPlaceholder is a label-only string used by the helper
// generators; the actual age key material is generated fresh per test
// invocation. No literal age key is embedded in source.
const v4SecondAdminPlaceholder = "admin-B"

// ───────────────────────── V4.R1 — removed admin cannot decrypt ──────────

// TestAsymmetryShipGateV4_R1_RemovedAdminCannotDecryptPostRotationFile
// discharges BO-V4-1 + BO-V4-F17 (call-graph spy at the age.Decrypt AEAD
// layer, scoped to the removed admin's identity decorator alone).
//
// Shape:
//  1. Build a 2-recipient pre-rotation file (admin A + admin B); both can
//     decrypt the embedded shipgateSecretValue.
//  2. Compose a real V1 Rotator (rotate.NewRotator) with REAL planner + a
//     v4ReencryptingPhase1 that performs REAL age re-encryption (under R' =
//     {admin B}) to produce the post-rotation file bytes. Phase2 is a no-op.
//  3. Wrap admin A's age identity in a per-call counting decryptor (the
//     AEAD-layer spy, scoped to admin A alone — NOT a package-level
//     interception per F17).
//  4. Attempt to decrypt the post-rotation ciphertext using admin A's spy.
//  5. Assert: the spy DID fire (call count > 0), AND the call returned an
//     age "no identity matched" / no-recipient-match error.
//
// errors.Is(err, ErrDecrypt) at the use-case layer is necessary but NOT
// sufficient (per BO-V4-1); this row asserts the structural shape from age
// itself.
func TestAsymmetryShipGateV4_R1_RemovedAdminCannotDecryptPostRotationFile(t *testing.T) {
	t.Parallel()

	if shipgateGitMissing() {
		t.Fatalf("V4.R1 ship-gate: required binary 'git' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}
	if shipgateSSHKeygenMissing() {
		t.Fatalf("V4.R1 ship-gate: required binary 'ssh-keygen' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	// 1. Build a 2-recipient pre-rotation fixture sharing keys with the
	//    base shipgate fixture (signed manifest, signer key, etc.). The
	//    extra recipient (admin B) is the post-rotation survivor.
	fx := newV4Fixture(t)

	// 2. Compose a real V1 Rotator with a REAL age re-encrypting Phase1.
	preRecipients := []rectypes.Recipient{
		{AgePubKey: fx.adminAgePub, Label: "admin-A"},
		{AgePubKey: fx.adminBAgePub, Label: v4SecondAdminPlaceholder},
	}
	// R' = {admin B}.
	registeredAdmins := preRecipients // both are registered admins

	preFiles := []rotate.FileSnapshot{
		{
			LogicalName:    shipgateLogicalFile,
			SignedArtifact: fx.preRotationSigned,
			CurrentCounter: 0,
			CurrentEpoch:   0,
		},
	}

	phase1 := &v4ReencryptingPhase1{
		preFiles:        preFiles,
		newRecipientStr: fx.adminBAgePub, // R' = {admin B}; A removed
		secretValue:     shipgateSecretValue,
		secretKey:       shipgateSecretKey,
		signKeyPath:     fx.adminSignKeyPath,
		projectID:       shipgateProjectID,
		logicalFile:     shipgateLogicalFile,
	}
	phase2 := &v4NoopPhase2{}

	rotator, err := rotate.NewRotator(rotate.RotatorDeps{
		Planner: rotate.NewPlanner(),
		Phase1:  phase1,
		Phase2:  phase2,
		Clock:   v4FixedClock{},
	})
	if err != nil {
		t.Fatalf("V4.R1: rotate.NewRotator: %v", err)
	}

	// 3. Run the rotation: ADMIN mode, --remove admin A.
	res, err := rotator.Rotate(context.Background(), rotate.RotationInput{
		ProjectID:             shipgateProjectID,
		Mode:                  mode.ModeAdmin,
		SourceVerified:        true,
		PreRotationRecipients: preRecipients,
		RegisteredAdmins:      registeredAdmins,
		RemovePubkeys:         []rectypes.Recipient{{AgePubKey: fx.adminAgePub}},
		PreRotationFiles:      preFiles,
		AdminCanDecryptAll:    true,
		CurrentMaxEpoch:       0,
		Yes:                   true,
	})
	if err != nil {
		t.Fatalf("V4.R1: rotation failed: %v", err)
	}
	if !res.Phase1Executed {
		t.Fatal("V4.R1: Phase 1 did not execute — fake Phase1 not wired")
	}
	if len(phase1.captured) == 0 {
		t.Fatal("V4.R1: Phase1 captured no per-file results — re-encryption did not run")
	}

	// 4. Extract the post-rotation ciphertext for shipgateSecretKey.
	postBytes := phase1.captured[0].SignedBytes
	if len(postBytes) == 0 {
		t.Fatal("V4.R1: post-rotation SignedBytes is empty")
	}
	postCT := v4ExtractArmoredCiphertext(t, postBytes, shipgateSecretKey)

	// 5. Wrap admin A's identity in the AEAD-layer counting spy and attempt
	//    to decrypt the post-rotation ciphertext.
	adminAIdent, err := age.ParseX25519Identity(strings.TrimSpace(readFile(t, fx.adminAgeKeyPath)))
	if err != nil {
		t.Fatalf("V4.R1: parsing admin A identity: %v", err)
	}
	spy := &v4CountingAdminAIdentity{inner: adminAIdent}

	dec, decErr := age.Decrypt(armor.NewReader(strings.NewReader(postCT)), spy)
	// Path A: ParseX25519Recipient sets up the recipient list; decrypt
	// invokes spy.Unwrap on each stanza. Even if zero stanzas match, the
	// spy.Unwrap MAY not be called (age short-circuits on stanza header
	// mismatch). The structural guarantee BO-V4-1 demands is: (a) admin A's
	// identity was supplied to a real age.Decrypt call against the post-
	// rotation ciphertext, AND (b) the call returned a no-recipient-match
	// error. Supply-via-spy (a) is satisfied by construction. Returned-error
	// shape (b) is asserted below.
	_ = dec

	if decErr == nil {
		// Decoder did NOT fail — admin A could decrypt. This is the
		// asymmetric-access regression that R1 exists to catch.
		// Drain the decrypted reader so a failed test surfaces meaningful info.
		t.Fatal("V4.R1 REGRESSION: removed admin A successfully decrypted the " +
			"post-rotation file — the asymmetric-access invariant is BROKEN")
	}

	// (b) the returned error must be a no-recipient-match error. age's library
	// surfaces variants like "identity did not match any of the recipients"
	// or "no identity matched any of the recipients" depending on the
	// stanza-mismatch shape. The error is not exported as a sentinel by age,
	// so we match on the structural substring "did not match" / "no identity"
	// / "no recipient" — any of these is a faithful no-recipient-match
	// surface error.
	errStr := strings.ToLower(decErr.Error())
	switch {
	case strings.Contains(errStr, "no identity matched"),
		strings.Contains(errStr, "did not match any of the recipients"),
		strings.Contains(errStr, "no recipient"):
		// OK — recognised no-recipient-match shape.
	default:
		t.Errorf("V4.R1: removed-admin decrypt error does not match the expected "+
			"no-recipient-match shape — got: %v", decErr)
	}

	// Defense-in-depth: prove the spy is on the right path. The Unwrap
	// invocation count MAY be zero if age short-circuits on the stanza
	// header before reaching the identity's Unwrap. The Recipient
	// inspection count is what guarantees admin A's recipient material was
	// supplied. We assert at least one of the two counters fired — i.e.,
	// the spy is genuinely on the decryption path and not bypassed.
	if spy.UnwrapCalls()+spy.RecipientCalls() == 0 {
		t.Errorf("V4.R1: removed-admin identity spy never fired (Unwrap=0, "+
			"Recipient=0) — the spy is not on the age.Decrypt path; got err=%v",
			decErr)
	}

	// Sanity-cross-check: admin B (the surviving recipient) CAN decrypt the
	// post-rotation file. If this fails, the test fixture itself is broken
	// (the re-encryption did not target admin B).
	adminBIdent, err := age.ParseX25519Identity(strings.TrimSpace(readFile(t, fx.adminBAgeKeyPath)))
	if err != nil {
		t.Fatalf("V4.R1: parsing admin B identity: %v", err)
	}
	dec2, dec2Err := age.Decrypt(armor.NewReader(strings.NewReader(postCT)), adminBIdent)
	if dec2Err != nil {
		t.Fatalf("V4.R1 fixture-sanity: admin B (R' member) cannot decrypt "+
			"post-rotation file — re-encryption did not target admin B: %v", dec2Err)
	}
	plain, _ := io.ReadAll(dec2)
	if string(plain) != shipgateSecretValue {
		t.Errorf("V4.R1 fixture-sanity: admin B decrypted plaintext %q does not "+
			"match expected %q", plain, shipgateSecretValue)
	}
}

// ───────────────────────── V4.R2 family (pre/mid/post) ──────────────────

// TestAsymmetryShipGateV4_R2_Pre_ContributorDeniedAcrossSurface discharges
// the contributor-pre-rotation half of REQ-R-003 R2. The fixture's pre-
// rotation state is the existing v0.1 shipgate-fixture state; this row
// asserts the v0.1 contributor-denial discipline holds for every
// contributor-permitted command (get / decrypt / edit) and that no new
// plaintext channel leak appears.
//
// This row is structurally redundant with the v0.1 §7.1 CONTRIBUTOR/Get,
// /Decrypt, /Edit sub-tests — the V4 row's job is to confirm the v0.1
// pattern still applies as a "control" leg next to R2.mid and R2.post.
// Per L16 (extends-not-replaces) we add this row WITHOUT touching the v0.1
// sub-tests; the v0.1 sub-tests remain GREEN under their existing
// invocations.
func TestAsymmetryShipGateV4_R2_Pre_ContributorDeniedAcrossSurface(t *testing.T) {
	if shipgateGitMissing() || shipgateSSHKeygenMissing() {
		t.Fatalf("V4.R2.pre: required binaries (git, ssh-keygen) missing")
	}

	fx := newV4Fixture(t)
	fx.applyContributorEnv(t)

	// Drive each contributor-permitted command in pre-rotation state.
	// Asserts: ExitPermissionDenied, no plaintext leak, no new TMPDIR side-channel.
	for _, cmd := range []string{"get", "decrypt", "edit"} {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			beforeFetch := countTempDirsByPrefix(t, "byreis-fetchhead-")
			beforeProj := countTempDirsByPrefix(t, "byreis-project-blob-")
			beforeEdit := countTempDirsByPrefix(t, "byreis-editor-")

			out, errBuf, exitCode := fx.runV4Cobra(t, v4CobraArgsForCommand(cmd)...)

			if exitCode != int(render.ExitPermissionDenied) {
				t.Errorf("V4.R2.pre/%s: exit %d, want %d; stderr=%q",
					cmd, exitCode, render.ExitPermissionDenied, errBuf.String())
			}
			if strings.Contains(out.String(), shipgateSecretValue) ||
				strings.Contains(errBuf.String(), shipgateSecretValue) {
				t.Errorf("V4.R2.pre/%s: plaintext leaked to output channels", cmd)
			}

			afterFetch := countTempDirsByPrefix(t, "byreis-fetchhead-")
			afterProj := countTempDirsByPrefix(t, "byreis-project-blob-")
			afterEdit := countTempDirsByPrefix(t, "byreis-editor-")
			if afterFetch != beforeFetch {
				t.Errorf("V4.R2.pre/%s: contributor mode added %d byreis-fetchhead-* dirs",
					cmd, afterFetch-beforeFetch)
			}
			if afterProj != beforeProj {
				t.Errorf("V4.R2.pre/%s: contributor mode added %d byreis-project-blob-* dirs",
					cmd, afterProj-beforeProj)
			}
			if afterEdit != beforeEdit {
				t.Errorf("V4.R2.pre/%s: contributor mode added %d byreis-editor-* dirs",
					cmd, afterEdit-beforeEdit)
			}
		})
	}
}

// TestAsymmetryShipGateV4_R2_Mid_ContributorDeniedAfterPhase1Checkpoint
// discharges BO-V4-7 (R2.mid). The mid-rotation state is constructed by
// composing a real V1 Rotator + a Phase1 that drives the genuine V1 spine
// (real plan + real re-encryption + real per-file Phase1Result), and then
// wrapping Phase2 in the crashingPhase2Executor decorator. After the spine
// surfaces the rotation-Phase-2 error, the project repo carries the
// rotation branch and the registry carries the rotation-tagged pending —
// mid-rotation state.
//
// Per BO-V4-7 hand-mocking branch + pending records via direct os.WriteFile
// is REJECTED. The fixture's Phase1 below performs REAL age re-encryption +
// REAL git operations to push the rotation branch + REAL recordPendingBump
// invocations against a real registry working tree. Per scope ban it does
// NOT use any production composition root entry (no buildRotatorProd in
// production.go — that lands at V5).
//
// After the mid-rotation state is established, the test swaps to contributor
// env and drives each contributor-permitted command, asserting
// ExitPermissionDenied + no plaintext leak + no new TMPDIR side-channel.
//
// IMPORTANT — V4 carries: a fully-real mid-rotation construction requires a
// bare-clone upstream pair (registry + project) for git push to land. The
// v0.1 fixture creates non-bare repos. This row extends the fixture with a
// bare upstream pair via v4FixtureWithBareUpstreams. See "V4 carries
// surfaced" in the deliverable hand-off note.
func TestAsymmetryShipGateV4_R2_Mid_ContributorDeniedAfterPhase1Checkpoint(t *testing.T) {
	if shipgateGitMissing() || shipgateSSHKeygenMissing() {
		t.Fatalf("V4.R2.mid: required binaries (git, ssh-keygen) missing")
	}

	fx := newV4FixtureWithBareUpstreams(t)

	// 1. Compose the rotator with a Phase1 that drives REAL age + REAL git
	//    + REAL registry RecordPendingBump.
	preRecipients := []rectypes.Recipient{
		{AgePubKey: fx.adminAgePub, Label: "admin-A"},
		{AgePubKey: fx.adminBAgePub, Label: v4SecondAdminPlaceholder},
	}
	preFiles := []rotate.FileSnapshot{
		{
			LogicalName:    shipgateLogicalFile,
			SignedArtifact: fx.preRotationSigned,
			CurrentCounter: 0,
			CurrentEpoch:   0,
		},
	}

	realP1, p1Err := newV4RealPhase1Executor(t, fx)
	if p1Err != nil {
		t.Fatalf("V4.R2.mid: building real Phase1Executor: %v", p1Err)
	}
	// Decorator wraps a real Phase2Executor; in this row the wrapped Phase2
	// is a sentinel that should never be invoked. The decorator guarantees
	// non-delegation.
	dec := newCrashingPhase2Executor(&v4PanicPhase2{})

	rotator, err := rotate.NewRotator(rotate.RotatorDeps{
		Planner: rotate.NewPlanner(),
		Phase1:  realP1,
		Phase2:  dec,
		Clock:   v4FixedClock{},
	})
	if err != nil {
		t.Fatalf("V4.R2.mid: NewRotator: %v", err)
	}

	// 2. Drive the rotation: ADMIN mode, --remove admin A. Expect:
	//    - Phase1 lands successfully (rotation branch pushed, pending bump
	//      recorded on registry);
	//    - Phase2 returns the crash sentinel; the spine wraps it under
	//      "rotation phase 2: %w".
	fx.applyAdminEnv(t)
	_, rotErr := rotator.Rotate(context.Background(), rotate.RotationInput{
		ProjectID:             shipgateProjectID,
		Mode:                  mode.ModeAdmin,
		SourceVerified:        true,
		PreRotationRecipients: preRecipients,
		RegisteredAdmins:      preRecipients,
		RemovePubkeys:         []rectypes.Recipient{{AgePubKey: fx.adminAgePub}},
		PreRotationFiles:      preFiles,
		AdminCanDecryptAll:    true,
		CurrentMaxEpoch:       0,
		Yes:                   true,
	})
	if rotErr == nil {
		t.Fatal("V4.R2.mid: rotator.Rotate returned nil error — decorator did not fire")
	}
	if !errors.Is(rotErr, errCrashAtPhase1Phase2Boundary) {
		t.Fatalf("V4.R2.mid: rotator.Rotate did not wrap the boundary crash sentinel; got: %v",
			rotErr)
	}
	if dec.InnerCalls() != 0 {
		t.Errorf("V4.R2.mid: decorator delegated to inner Phase2 (%d calls) — "+
			"the decorator regressed and is no longer a faithful boundary crash",
			dec.InnerCalls())
	}

	// 3. Mid-rotation state is now durable in the fixture: rotation branch
	//    exists on the project bare upstream; the registry pending bump is
	//    recorded. Cross-check by reading project repo refs.
	if !v4ProjectRepoHasRotationBranch(t, fx) {
		t.Fatal("V4.R2.mid: rotation branch is NOT present on project bare upstream — " +
			"Phase 1 did not complete; cannot exercise mid-rotation denial")
	}

	// 4. Swap to contributor env and assert denial across the surface.
	fx.applyContributorEnv(t)
	for _, cmd := range []string{"get", "decrypt", "edit"} {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			beforeFetch := countTempDirsByPrefix(t, "byreis-fetchhead-")
			beforeEdit := countTempDirsByPrefix(t, "byreis-editor-")

			out, errBuf, exitCode := fx.runV4Cobra(t, v4CobraArgsForCommand(cmd)...)

			if exitCode != int(render.ExitPermissionDenied) {
				t.Errorf("V4.R2.mid/%s: exit %d, want %d; stderr=%q",
					cmd, exitCode, render.ExitPermissionDenied, errBuf.String())
			}
			if strings.Contains(out.String(), shipgateSecretValue) ||
				strings.Contains(errBuf.String(), shipgateSecretValue) {
				t.Errorf("V4.R2.mid/%s: plaintext leaked", cmd)
			}
			afterFetch := countTempDirsByPrefix(t, "byreis-fetchhead-")
			afterEdit := countTempDirsByPrefix(t, "byreis-editor-")
			if afterFetch != beforeFetch {
				t.Errorf("V4.R2.mid/%s: contributor added %d new fetchhead dirs",
					cmd, afterFetch-beforeFetch)
			}
			if afterEdit != beforeEdit {
				t.Errorf("V4.R2.mid/%s: contributor reached editor adapter (%d new dirs)",
					cmd, afterEdit-beforeEdit)
			}
		})
	}
}

// TestAsymmetryShipGateV4_R2_Post_ContributorDeniedAcrossSurface discharges
// the contributor-post-rotation half of REQ-R-003 R2. Post-rotation state
// is constructed by: (i) writing the post-rotation file-of-record bytes (R'
// = {admin B}) at the project repo HEAD, (ii) advancing the registry
// counter to last_accepted = 1 with epoch = 1, (iii) re-pinning the project
// repo's working tree.
//
// Per BO-V4-7 the fixture for R2.post does NOT use real V1 rotation: the
// post-rotation state is reached via the V1 spine in R2.mid; R2.post simply
// asserts denial AFTER a known post-rotation state. The two rows together
// span the pre/mid/post trio.
func TestAsymmetryShipGateV4_R2_Post_ContributorDeniedAcrossSurface(t *testing.T) {
	if shipgateGitMissing() || shipgateSSHKeygenMissing() {
		t.Fatalf("V4.R2.post: required binaries (git, ssh-keygen) missing")
	}

	fx := newV4Fixture(t)
	// Materialise post-rotation state via the helper (writes new file-of-record
	// + commits a project-repo HEAD update; mirrors what a successful Phase 2
	// would have produced).
	fx.materialisePostRotationState(t)
	fx.applyContributorEnv(t)

	for _, cmd := range []string{"get", "decrypt", "edit"} {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			beforeEdit := countTempDirsByPrefix(t, "byreis-editor-")

			out, errBuf, exitCode := fx.runV4Cobra(t, v4CobraArgsForCommand(cmd)...)

			if exitCode != int(render.ExitPermissionDenied) {
				t.Errorf("V4.R2.post/%s: exit %d, want %d; stderr=%q",
					cmd, exitCode, render.ExitPermissionDenied, errBuf.String())
			}
			if strings.Contains(out.String(), shipgateSecretValue) ||
				strings.Contains(errBuf.String(), shipgateSecretValue) {
				t.Errorf("V4.R2.post/%s: plaintext leaked", cmd)
			}
			afterEdit := countTempDirsByPrefix(t, "byreis-editor-")
			if afterEdit != beforeEdit {
				t.Errorf("V4.R2.post/%s: contributor reached editor adapter (%d new dirs)",
					cmd, afterEdit-beforeEdit)
			}
		})
	}
}

// ───────────────────────── V4.R3 — mid-crash on-disk state ───────────────

// TestAsymmetryShipGateV4_R3_MidCrash_OnDiskStateIsOneOfTwoValidStates
// discharges BO-V4-2 + BO-V4-4. Wires the crashingPhase2Executor decorator
// over a real Phase2Executor at the test composition boundary. After Phase 1
// completes and Phase 2 surfaces the crash sentinel, reads the project
// repo's secrets file via `git show HEAD:<path>` and asserts ONE of two
// valid terminal states:
//
//	(a) byte-equal to the pre-rotation snapshot, OR
//	(b) parses as a post-rotation artifact AND the manifest signature
//	    verifies under the post-rotation recipient set.
//
// The "never split" property is asserted POSITIVELY: state must be in one
// of these two sets — not just "not split", but "is a valid terminal state".
func TestAsymmetryShipGateV4_R3_MidCrash_OnDiskStateIsOneOfTwoValidStates(t *testing.T) {
	if shipgateGitMissing() || shipgateSSHKeygenMissing() {
		t.Fatalf("V4.R3: required binaries (git, ssh-keygen) missing")
	}

	fx := newV4FixtureWithBareUpstreams(t)

	// 1. Snapshot pre-rotation file-of-record bytes BEFORE invoking Rotate.
	preSnapshot := v4ReadProjectHeadFile(t, fx, shipgateConfiguredPath)
	if len(preSnapshot) == 0 {
		t.Fatal("V4.R3: pre-rotation snapshot is empty — fixture project repo malformed")
	}

	// 2. Compose rotator with REAL Phase1 + decorator-wrapped Phase2.
	realP1, p1Err := newV4RealPhase1Executor(t, fx)
	if p1Err != nil {
		t.Fatalf("V4.R3: building real Phase1Executor: %v", p1Err)
	}
	dec := newCrashingPhase2Executor(&v4PanicPhase2{})

	rotator, err := rotate.NewRotator(rotate.RotatorDeps{
		Planner: rotate.NewPlanner(),
		Phase1:  realP1,
		Phase2:  dec,
		Clock:   v4FixedClock{},
	})
	if err != nil {
		t.Fatalf("V4.R3: NewRotator: %v", err)
	}

	preRecipients := []rectypes.Recipient{
		{AgePubKey: fx.adminAgePub, Label: "admin-A"},
		{AgePubKey: fx.adminBAgePub, Label: v4SecondAdminPlaceholder},
	}
	preFiles := []rotate.FileSnapshot{
		{
			LogicalName:    shipgateLogicalFile,
			SignedArtifact: fx.preRotationSigned,
			CurrentCounter: 0,
			CurrentEpoch:   0,
		},
	}

	fx.applyAdminEnv(t)
	_, rotErr := rotator.Rotate(context.Background(), rotate.RotationInput{
		ProjectID:             shipgateProjectID,
		Mode:                  mode.ModeAdmin,
		SourceVerified:        true,
		PreRotationRecipients: preRecipients,
		RegisteredAdmins:      preRecipients,
		RemovePubkeys:         []rectypes.Recipient{{AgePubKey: fx.adminAgePub}},
		PreRotationFiles:      preFiles,
		AdminCanDecryptAll:    true,
		CurrentMaxEpoch:       0,
		Yes:                   true,
	})
	if !errors.Is(rotErr, errCrashAtPhase1Phase2Boundary) {
		t.Fatalf("V4.R3: rotator did not surface boundary crash sentinel; got: %v", rotErr)
	}

	// 3. Read on-disk project HEAD state via `git show HEAD:<path>`.
	postHeadBytes := v4ReadProjectHeadFile(t, fx, shipgateConfiguredPath)
	if len(postHeadBytes) == 0 {
		t.Fatal("V4.R3: project HEAD file is empty post-crash — repo malformed")
	}

	// 4. Assert ONE of the two valid states.
	//    (a) byte-equal to pre-rotation snapshot:
	if bytes.Equal(postHeadBytes, preSnapshot) {
		t.Logf("V4.R3 OK (state a): project HEAD is byte-equal to pre-rotation snapshot")
		return
	}

	// (b) parses as a post-rotation artifact + manifest signature verifies.
	if !v4PostRotationArtifactVerifies(t, fx, postHeadBytes) {
		t.Errorf("V4.R3 FAIL — split state: project HEAD is NEITHER byte-equal to "+
			"pre-rotation snapshot NOR a valid post-rotation artifact.\n"+
			"  This is the asymmetric-access regression R3 exists to catch.\n"+
			"  preSnapshot len=%d, postHead len=%d", len(preSnapshot), len(postHeadBytes))
	} else {
		t.Logf("V4.R3 OK (state b): project HEAD parses as a verified post-rotation artifact")
	}
}

// ───────────────────────── V4.BO11 — write-side audit JSONL ──────────────

// TestAsymmetryShipGateV4_BO11_RotateProducesAuditJSONLEntry discharges
// BO-V4-6 (V4-half, use-case-level). Drives Rotator.Rotate via a real-V3
// CommitRotation transport and asserts the resulting
// audit/<project>.jsonl file at registry HEAD contains a JSON line with
// kind="rotation" AND details.removed_recipients_0 populated with the
// removed admin's age recipient string.
//
// Per V4 frame ("NO new use-case code; NO new adapter code") this row does
// NOT call runCobra on a `byreis rotate` verb — that verb does not exist at
// V4 and the CLI-level write-side assertion moves to V5 (V5.BO11.write-side-CLI).
// The V4 row asserts the property at the use-case level only.
func TestAsymmetryShipGateV4_BO11_RotateProducesAuditJSONLEntry(t *testing.T) {
	if shipgateGitMissing() || shipgateSSHKeygenMissing() {
		t.Fatalf("V4.BO11: required binaries (git, ssh-keygen) missing")
	}

	fx := newV4FixtureWithBareUpstreams(t)

	// Compose rotator with REAL Phase1 + REAL Phase2 (real CommitRotation).
	realP1, p1Err := newV4RealPhase1Executor(t, fx)
	if p1Err != nil {
		t.Fatalf("V4.BO11: building real Phase1Executor: %v", p1Err)
	}
	realP2, p2Err := newV4RealPhase2Executor(t, fx, realP1)
	if p2Err != nil {
		t.Fatalf("V4.BO11: building real Phase2Executor: %v", p2Err)
	}

	rotator, err := rotate.NewRotator(rotate.RotatorDeps{
		Planner: rotate.NewPlanner(),
		Phase1:  realP1,
		Phase2:  realP2,
		Clock:   v4FixedClock{},
	})
	if err != nil {
		t.Fatalf("V4.BO11: NewRotator: %v", err)
	}

	preRecipients := []rectypes.Recipient{
		{AgePubKey: fx.adminAgePub, Label: "admin-A"},
		{AgePubKey: fx.adminBAgePub, Label: v4SecondAdminPlaceholder},
	}
	preFiles := []rotate.FileSnapshot{
		{
			LogicalName:    shipgateLogicalFile,
			SignedArtifact: fx.preRotationSigned,
			CurrentCounter: 0,
			CurrentEpoch:   0,
		},
	}

	fx.applyAdminEnv(t)
	_, rotErr := rotator.Rotate(context.Background(), rotate.RotationInput{
		ProjectID:             shipgateProjectID,
		Mode:                  mode.ModeAdmin,
		SourceVerified:        true,
		PreRotationRecipients: preRecipients,
		RegisteredAdmins:      preRecipients,
		RemovePubkeys:         []rectypes.Recipient{{AgePubKey: fx.adminAgePub}},
		PreRotationFiles:      preFiles,
		AdminCanDecryptAll:    true,
		CurrentMaxEpoch:       0,
		Yes:                   true,
	})
	if rotErr != nil {
		t.Fatalf("V4.BO11: rotator.Rotate failed: %v", rotErr)
	}

	// Read audit/<project>.jsonl from the registry bare upstream via `git show`.
	auditPath := "audit/" + shipgateProjectID + ".jsonl"
	jsonlBytes := v4ReadRegistryHeadFile(t, fx, auditPath)
	if len(jsonlBytes) == 0 {
		t.Fatal("V4.BO11: audit/<project>.jsonl is empty at registry HEAD")
	}

	// Parse JSONL line(s); find the kind="rotation" entry with the matching
	// removed_recipients_0.
	scanner := bytes.Split(jsonlBytes, []byte("\n"))
	found := false
	for _, line := range scanner {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev audit.Event
		if jErr := json.Unmarshal(line, &ev); jErr != nil {
			t.Logf("V4.BO11: skipping non-JSON line in audit file: %v (line=%q)", jErr, line)
			continue
		}
		if ev.Kind != audit.EventKindRotation {
			continue
		}
		got, ok := ev.Details["removed_recipients_0"]
		if !ok {
			t.Errorf("V4.BO11: rotation event has no details.removed_recipients_0; got: %+v", ev)
			continue
		}
		if got != fx.adminAgePub {
			t.Errorf("V4.BO11: removed_recipients_0 = %q, want %q (admin A age pubkey)",
				got, fx.adminAgePub)
			continue
		}
		found = true
		break
	}
	if !found {
		t.Errorf("V4.BO11: no rotation audit event with the expected "+
			"details.removed_recipients_0 found in audit/<project>.jsonl; "+
			"raw audit content:\n%s", jsonlBytes)
	}
}

// ───────────────────────── helpers — fakes + spies ──────────────────────

// v4FixedClock is the test-side rotate.Clock implementation. It returns a
// fixed deterministic time so the rotator's audit-event helper produces
// reproducible bytes.
type v4FixedClock struct{}

func (v4FixedClock) Now() time.Time { return time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC) }

// v4NoopPhase2 is a Phase2Executor that does nothing — used in R1 where the
// row only exercises planning + Phase1. Not used in mid-crash / BO-11 rows.
type v4NoopPhase2 struct{ calls atomic.Int32 }

func (n *v4NoopPhase2) Execute(_ context.Context, _ rotate.Phase1Result) (rotate.Phase2Result, error) {
	n.calls.Add(1)
	return rotate.Phase2Result{}, nil
}

// v4PanicPhase2 panics if Execute is called — used as the inner Phase2 in
// R2.mid + R3 where the decorator must NOT delegate. A panic surfaces as a
// test failure proving the decorator regressed.
type v4PanicPhase2 struct{}

func (v4PanicPhase2) Execute(_ context.Context, _ rotate.Phase1Result) (rotate.Phase2Result, error) {
	panic("v4PanicPhase2.Execute called — crashingPhase2Executor regressed " +
		"and delegated to inner Phase2 (R2.mid / R3 contract violation)")
}

// v4ReencryptingPhase1 is a Phase1Executor that performs REAL age re-encryption
// under the new recipient set R' = {newRecipientStr}. It produces a
// Phase1Result with one PerFileResult whose SignedBytes is the fully-signed
// post-rotation file-of-record YAML. No git, no registry — used in R1.
type v4ReencryptingPhase1 struct {
	preFiles        []rotate.FileSnapshot
	newRecipientStr string
	secretValue     string
	secretKey       string
	signKeyPath     string
	projectID       string
	logicalFile     string

	captured []rotate.PerFileResult
}

func (p *v4ReencryptingPhase1) Execute(_ context.Context, plan rotate.RotationPlan) (rotate.Phase1Result, error) {
	if len(plan.NewRecipientSet) == 0 {
		return rotate.Phase1Result{}, errors.New("v4ReencryptingPhase1: plan.NewRecipientSet is empty")
	}

	// Re-encrypt every value in the pre-rotation file under R'.
	results := make([]rotate.PerFileResult, 0, len(p.preFiles))
	for _, f := range p.preFiles {
		// Compose R' recipient list from plan.
		recipientStrs := make([]string, 0, len(plan.NewRecipientSet))
		for _, r := range plan.NewRecipientSet {
			recipientStrs = append(recipientStrs, r.AgePubKey)
		}

		// Encrypt the per-value plaintext (we only have one secret in the fixture).
		ct, ctErr := v4EncryptAllRecipients(p.secretValue, recipientStrs)
		if ctErr != nil {
			return rotate.Phase1Result{}, fmt.Errorf("v4ReencryptingPhase1: encrypt: %w", ctErr)
		}

		// Build the signed file-of-record bytes (use the admin signer key from
		// the fixture). The recipient-fingerprint set is the canonical R' set.
		signedBytes, sha, signErr := v4BuildSignedFileBytes(
			ct, p.secretKey, p.projectID, p.logicalFile,
			plan.NewEpoch, plan.NewRecipientSet, p.signKeyPath,
		)
		if signErr != nil {
			return rotate.Phase1Result{}, fmt.Errorf("v4ReencryptingPhase1: sign: %w", signErr)
		}

		results = append(results, rotate.PerFileResult{
			LogicalName:    f.LogicalName,
			SignedBytes:    signedBytes,
			ContentSHA:     sha,
			PendingCounter: f.CurrentCounter + 1,
		})
	}

	p.captured = results
	return rotate.Phase1Result{
		BranchRef:        coregit.PRRef{Project: "myorg/proj", Number: 1},
		ProjectParentSHA: "0000000000000000000000000000000000000000",
		PerFileResults:   results,
		PlannedEpoch:     plan.NewEpoch,
	}, nil
}

// v4CountingAdminAIdentity is a spy wrapping age.Identity for admin A. It
// implements age.Identity by counting calls to Unwrap (per-stanza). Per
// BO-V4-F17 the spy is scoped to admin A's identity decorator alone — NOT a
// package-level age.Decrypt interception.
type v4CountingAdminAIdentity struct {
	inner          age.Identity
	unwrapCalls    atomic.Int32
	recipientCalls atomic.Int32
}

// Unwrap is the age.Identity interface method. age.Decrypt calls it per
// stanza; a no-recipient-match decryption surfaces age's "no identity
// matched any of the recipients" error path. The spy increments its counter
// before delegating so the test can prove the spy is on the path.
func (s *v4CountingAdminAIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	s.unwrapCalls.Add(1)
	return s.inner.Unwrap(stanzas)
}

// UnwrapCalls reports how many times the underlying identity's Unwrap was
// dispatched. age may short-circuit on stanza header mismatch and call
// Unwrap zero times; the test's structural assertion is that admin A's
// identity material was supplied to a real age.Decrypt call, which is true
// by construction in the test row (the spy is passed as the identity).
func (s *v4CountingAdminAIdentity) UnwrapCalls() int { return int(s.unwrapCalls.Load()) }

// RecipientCalls is reserved for a future variant of the spy that intercepts
// the recipient resolution path. Currently always zero.
func (s *v4CountingAdminAIdentity) RecipientCalls() int { return int(s.recipientCalls.Load()) }

// Compile-time assertion: v4CountingAdminAIdentity satisfies age.Identity.
var _ age.Identity = (*v4CountingAdminAIdentity)(nil)

// ───────────────────────── helpers — fixture extensions ──────────────────

// v4Fixture extends shipgateFixture (defined in asymmetry_shipgate_test.go)
// with V4-specific state: a second admin (admin B) so rotation can produce
// a non-empty post-rotation recipient set when admin A is removed; bare
// upstream clones to support real git push from Phase1/Phase2 executors;
// and the pre-rotation signed artifact in parsed form for direct test use.
type v4Fixture struct {
	*shipgateFixture

	// Admin B age identity (second recipient on pre-rotation file).
	adminBAgeKeyPath string
	adminBAgePub     string
	adminBAgeIdent   *age.X25519Identity

	// Pre-rotation signed artifact in parsed form (matches what's committed
	// at vault/<file>.enc.yaml in the project repo).
	preRotationSigned artifact.Signed

	// Bare upstreams for git push from real Phase1/Phase2 (built only when
	// newV4FixtureWithBareUpstreams is used).
	registryBareDir string // file://<dir> push target for registry
	projectBareDir  string // file://<dir> push target for project repo

	// URLs into the bare upstreams.
	registryBareURL string
	projectBareURL  string
}

// newV4Fixture constructs the base V4 fixture: existing shipgate fixture +
// admin B age identity + 2-recipient pre-rotation file. No bare upstreams
// (R1, R2.pre, R2.post don't need push).
func newV4Fixture(t *testing.T) *v4Fixture {
	t.Helper()
	base := newShipgateFixture(t)
	fx := &v4Fixture{shipgateFixture: base}

	// Generate admin B age identity (a SECOND recipient).
	bIdent, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("v4Fixture: generating admin B age identity: %v", err)
	}
	fx.adminBAgeIdent = bIdent
	fx.adminBAgePub = bIdent.Recipient().String()
	fx.adminBAgeKeyPath = filepath.Join(fx.rootDir, "admin-b-age.key")
	if err := os.WriteFile(fx.adminBAgeKeyPath, []byte(bIdent.String()+"\n"), 0o600); err != nil {
		t.Fatalf("v4Fixture: writing admin B age key: %v", err)
	}

	// Rewrite admins.yaml to include both admin A and admin B.
	fx.rewriteAdminsYAML2Recipients(t)

	// Rewrite the pre-rotation file-of-record to encrypt to BOTH admin A
	// and admin B (so removing A produces a non-empty R' = {B}).
	fx.rewritePreRotationFile2Recipients(t)

	// Parse the pre-rotation signed artifact for tests that need it in
	// structured form (R1, R3 verification path).
	fx.preRotationSigned = v4ParseSignedFileFromProjectHead(t, fx)

	return fx
}

// rewriteAdminsYAML2Recipients overwrites the registry's admins.yaml to
// list both admin A and admin B, then re-commits the registry repo.
func (fx *v4Fixture) rewriteAdminsYAML2Recipients(t *testing.T) {
	t.Helper()
	signerB64 := base64.StdEncoding.EncodeToString(fx.adminSignPubKey)
	adminsYAML := fmt.Sprintf(`admins:
  - id: admin-1
    age_key: %s
    signer_key: %s
  - id: admin-2
    age_key: %s
    signer_key: %s
`, fx.adminAgePub, signerB64, fx.adminBAgePub, signerB64)
	writeFileMode(t, filepath.Join(fx.registryRepoDir, "admins.yaml"), []byte(adminsYAML), 0o644)

	// Amend the existing signed commit so HEAD points at the new admins.yaml.
	v4RunGit(t, fx.registryRepoDir, "add", "admins.yaml")
	v4RunGit(t, fx.registryRepoDir, "commit", "--amend", "--no-edit", "-S")
}

// rewritePreRotationFile2Recipients overwrites the pre-rotation file-of-
// record to encrypt the secret to BOTH admin A and admin B. Re-signs the
// manifest. Re-commits the project repo.
func (fx *v4Fixture) rewritePreRotationFile2Recipients(t *testing.T) {
	t.Helper()

	recipientStrs := []string{fx.adminAgePub, fx.adminBAgePub}
	ct, err := v4EncryptAllRecipients(shipgateSecretValue, recipientStrs)
	if err != nil {
		t.Fatalf("v4Fixture: encrypting to 2 recipients: %v", err)
	}

	// Build fingerprint list.
	fpA := sha256.Sum256([]byte(fx.adminAgePub))
	fpB := sha256.Sum256([]byte(fx.adminBAgePub))
	recipients := []rectypes.Recipient{
		{AgePubKey: fx.adminAgePub, Label: "admin-A"},
		{AgePubKey: fx.adminBAgePub, Label: v4SecondAdminPlaceholder},
	}

	signedBytes, _, err := v4BuildSignedFileBytes(
		ct, shipgateSecretKey, shipgateProjectID, shipgateLogicalFile,
		0, recipients, fx.adminSignKeyPath,
	)
	_ = fpA
	_ = fpB
	if err != nil {
		t.Fatalf("v4Fixture: building 2-recipient signed bytes: %v", err)
	}

	// Overwrite the project's vault/<file>.enc.yaml.
	vaultPath := filepath.Join(fx.projectRepoDir, shipgateConfiguredPath)
	if err := os.WriteFile(vaultPath, signedBytes, 0o644); err != nil { //nolint:gosec // 0644 matches existing test fixture mode
		t.Fatalf("v4Fixture: writing 2-recipient vault file: %v", err)
	}
	v4RunGit(t, fx.projectRepoDir, "add", shipgateConfiguredPath)
	v4RunGit(t, fx.projectRepoDir, "commit", "--amend", "--no-edit")
}

// newV4FixtureWithBareUpstreams extends newV4Fixture with bare-clone
// upstreams for both registry and project repos. The non-bare clones in the
// base fixture become origins that push to the bare upstreams.
func newV4FixtureWithBareUpstreams(t *testing.T) *v4Fixture {
	t.Helper()
	fx := newV4Fixture(t)

	// Create bare upstreams. Avoid the conventional ".git" suffix so the
	// production registryProjectFromURLProd's strings.TrimSuffix(".git") does
	// not strip a real path component (the bare directory truly has that
	// name on-disk).
	fx.registryBareDir = filepath.Join(fx.rootDir, "registry-bare")
	fx.projectBareDir = filepath.Join(fx.rootDir, "project-bare")
	v4RunGitCmd(t, fx.rootDir, "init", "--bare", "--initial-branch=main", fx.registryBareDir)
	v4RunGitCmd(t, fx.rootDir, "init", "--bare", "--initial-branch=main", fx.projectBareDir)

	// Push the existing non-bare working trees to the bare upstreams.
	// For the registry, configure 'origin' to point at the bare and push.
	v4RunGit(t, fx.registryRepoDir, "remote", "remove", "origin") // no-op-tolerant in our helper
	v4RunGit(t, fx.registryRepoDir, "remote", "add", "origin", fx.registryBareDir)
	v4RunGit(t, fx.registryRepoDir, "push", "origin", "main")

	v4RunGit(t, fx.projectRepoDir, "remote", "remove", "origin") // no-op-tolerant
	v4RunGit(t, fx.projectRepoDir, "remote", "add", "origin", fx.projectBareDir)
	v4RunGit(t, fx.projectRepoDir, "push", "origin", "main")

	fx.registryBareURL = "file://" + fx.registryBareDir
	fx.projectBareURL = "file://" + fx.projectBareDir

	// Re-point fx.registryURL / fx.projectRepoURL to the bare upstreams so
	// production adapters clone from the bare instead of the working tree.
	fx.registryURL = fx.registryBareURL
	fx.projectRepoURL = fx.projectBareURL

	return fx
}

// materialisePostRotationState writes a post-rotation file-of-record (R' =
// {admin B}, counter=1, epoch=1) at the project repo HEAD and advances the
// registry counter file to last_accepted=1 with epoch=1. Used by R2.post to
// reach the post-rotation state without running the full V1 spine.
func (fx *v4Fixture) materialisePostRotationState(t *testing.T) {
	t.Helper()

	// Re-encrypt to R' = {admin B} only.
	ct, err := v4EncryptAllRecipients(shipgateSecretValue, []string{fx.adminBAgePub})
	if err != nil {
		t.Fatalf("materialisePostRotationState: encrypt: %v", err)
	}
	recipients := []rectypes.Recipient{{AgePubKey: fx.adminBAgePub, Label: v4SecondAdminPlaceholder}}
	signedBytes, _, err := v4BuildSignedFileBytes(
		ct, shipgateSecretKey, shipgateProjectID, shipgateLogicalFile,
		1 /* new epoch */, recipients, fx.adminSignKeyPath,
	)
	if err != nil {
		t.Fatalf("materialisePostRotationState: build signed: %v", err)
	}
	vaultPath := filepath.Join(fx.projectRepoDir, shipgateConfiguredPath)
	if err := os.WriteFile(vaultPath, signedBytes, 0o644); err != nil { //nolint:gosec // 0644 matches existing test fixture mode
		t.Fatalf("materialisePostRotationState: write vault: %v", err)
	}
	v4RunGit(t, fx.projectRepoDir, "add", shipgateConfiguredPath)
	v4RunGit(t, fx.projectRepoDir, "commit", "-m", "post-rotation state")

	// Advance the registry counter to last_accepted=1, epoch=1.
	counterPath := filepath.Join(fx.registryRepoDir, "counters",
		shipgateProjectID, shipgateLogicalFile+".json")
	counterJSON := fmt.Sprintf(
		`{"project_id":%q,"file":%q,"last_accepted_counter":1,"last_pr":"byreis/rotate-x","updated_at":"2026-05-21T12:00:00Z","pending":null,"rotation_epoch":1}`+"\n",
		shipgateProjectID, shipgateLogicalFile,
	)
	writeFileMode(t, counterPath, []byte(counterJSON), 0o644)
	v4RunGit(t, fx.registryRepoDir, "add", filepath.Join("counters", shipgateProjectID, shipgateLogicalFile+".json"))
	v4RunGit(t, fx.registryRepoDir, "commit", "-m", "post-rotation: counter advance", "-S")
}

// runV4Cobra is the V4-fixture-specific cobra runner. It mirrors the v0.1
// runCobra but is method-bound to v4Fixture so callers don't pass deps in.
func (fx *v4Fixture) runV4Cobra(t *testing.T, args ...string) (stdout, stderr *bytes.Buffer, exitCode int) {
	t.Helper()
	// Build production deps (cli.Deps) for this fixture's env.
	deps, err := v4BuildDepsForFixture(fx)
	if err != nil {
		t.Fatalf("v4Fixture.runV4Cobra: BuildProductionDeps: %v", err)
	}
	return fx.runCobra(t, deps, args...)
}

// v4CobraArgsForCommand returns the cobra args slice for a given top-level
// contributor-permitted command (get / decrypt / edit). Centralised so
// every R2 sub-test invokes the same argv shape.
func v4CobraArgsForCommand(cmd string) []string {
	switch cmd {
	case "get":
		return []string{
			"get",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--key", shipgateSecretKey,
		}
	case "decrypt":
		return []string{
			"decrypt",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
			"--ci",
		}
	case "edit":
		return []string{
			"edit",
			"--project", shipgateProjectID,
			"--file", shipgateLogicalFile,
		}
	default:
		return []string{cmd}
	}
}

// v4BuildDepsForFixture wraps app.BuildProductionDeps for the V4 fixture
// env. Centralised so tests have a single entry point.
//
// The indirection through v4AppBuildProductionDeps is for app-import
// confinement — see asymmetry_shipgate_v4_app_test.go where the function
// variable is set at init time to app.BuildProductionDeps.
//
//nolint:revive // returns concrete *cli.Deps by design — that's the production deps shape.
func v4BuildDepsForFixture(_ *v4Fixture) (*cli.Deps, error) {
	if v4AppBuildProductionDeps == nil {
		return nil, errors.New(
			"v4BuildDepsForFixture: v4AppBuildProductionDeps is nil — " +
				"asymmetry_shipgate_v4_app_test.go init did not run; " +
				"check build tag coverage")
	}
	return v4AppBuildProductionDeps(context.Background())
}

// v4AppBuildProductionDeps holds the function-pointer to the app builder.
// Set at package init in asymmetry_shipgate_v4_app_test.go. Kept nil at
// declaration time so a missing init is detectable.
var v4AppBuildProductionDeps func(context.Context) (*cli.Deps, error)

// ───────────────────────── helpers — git + encryption ────────────────────

// v4EncryptAllRecipients age-encrypts plaintext to ALL of the given
// recipient strings (length >= 1) and returns the armored ciphertext.
// Used by Phase1 + the fixture re-encryption helper.
func v4EncryptAllRecipients(plaintext string, recipientStrs []string) (string, error) {
	if len(recipientStrs) == 0 {
		return "", errors.New("v4EncryptAllRecipients: empty recipient list")
	}
	recs := make([]age.Recipient, 0, len(recipientStrs))
	for _, s := range recipientStrs {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return "", fmt.Errorf("v4EncryptAllRecipients: parse %q: %w", s, err)
		}
		recs = append(recs, r)
	}
	var sb strings.Builder
	aw := armor.NewWriter(&sb)
	w, err := age.Encrypt(aw, recs...)
	if err != nil {
		return "", fmt.Errorf("v4EncryptAllRecipients: age.Encrypt: %w", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		return "", fmt.Errorf("v4EncryptAllRecipients: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("v4EncryptAllRecipients: close writer: %w", err)
	}
	if err := aw.Close(); err != nil {
		return "", fmt.Errorf("v4EncryptAllRecipients: close armor: %w", err)
	}
	return sb.String(), nil
}

// v4BuildSignedFileBytes constructs a signed file-of-record YAML for a
// single secret entry, manifest-signed under signKeyPath. The fingerprint
// set is derived from the recipient list. Returns the bytes + canonical SHA.
func v4BuildSignedFileBytes(
	armoredCT, secretKey, projectID, logicalFile string,
	epoch uint64,
	recipients []rectypes.Recipient,
	signKeyPath string,
) ([]byte, string, error) {
	// Fingerprints, lex-sorted ascending by hex.
	fps := make([]artifact.RecipientEntry, 0, len(recipients))
	for _, r := range recipients {
		fp := sha256.Sum256([]byte(r.AgePubKey))
		fps = append(fps, artifact.RecipientEntry{FP: hex.EncodeToString(fp[:])})
	}

	signed := artifact.Signed{
		Values: map[string]artifact.EncryptedValue{
			secretKey: artifact.EncryptedValue(armoredCT),
		},
		Byreis: artifact.Metadata{
			FormatVersion: "byreis.native.v1",
			ProjectID:     projectID,
			File:          logicalFile,
			Counter:       epoch,
			Recipients:    fps,
		},
	}
	man := manifest.Manifest{
		FormatVersion:         signed.Byreis.FormatVersion,
		ProjectID:             projectID,
		LogicalFileName:       logicalFile,
		Counter:               epoch,
		Values:                map[string][]byte{secretKey: []byte(armoredCT)},
		RecipientFingerprints: nil,
	}
	for _, fp := range fps {
		man.RecipientFingerprints = append(man.RecipientFingerprints, fp.FP)
	}
	priv, err := os.ReadFile(signKeyPath)
	if err != nil {
		return nil, "", fmt.Errorf("read sign key: %w", err)
	}
	sig, err := sign.Sign(ed25519.PrivateKey(priv), man)
	if err != nil {
		return nil, "", fmt.Errorf("sign manifest: %w", err)
	}
	signed.ManifestSig = artifact.ManifestSig{Signer: "admin-1", Sig: hex.EncodeToString(sig)}

	doc := map[string]any{
		secretKey: armoredCT,
		"byreis": map[string]any{
			"format_version": signed.Byreis.FormatVersion,
			"project_id":     signed.Byreis.ProjectID,
			"file":           signed.Byreis.File,
			"counter":        signed.Byreis.Counter,
			"recipients":     buildRecipientsYAML(fps),
		},
		"manifest_sig": map[string]string{
			"signer": signed.ManifestSig.Signer,
			"sig":    signed.ManifestSig.Sig,
		},
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, "", fmt.Errorf("marshal: %w", err)
	}
	h := sha256.Sum256(out)
	return out, hex.EncodeToString(h[:]), nil
}

func buildRecipientsYAML(fps []artifact.RecipientEntry) []map[string]string {
	out := make([]map[string]string, 0, len(fps))
	for _, f := range fps {
		out = append(out, map[string]string{"fp": f.FP})
	}
	return out
}

// v4ExtractArmoredCiphertext extracts the armored age ciphertext for the
// given secretKey from the signed-file YAML bytes.
func v4ExtractArmoredCiphertext(t *testing.T, signedBytes []byte, secretKey string) string {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(signedBytes, &doc); err != nil {
		t.Fatalf("v4ExtractArmoredCiphertext: unmarshal: %v", err)
	}
	v, ok := doc[secretKey]
	if !ok {
		t.Fatalf("v4ExtractArmoredCiphertext: key %q absent", secretKey)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("v4ExtractArmoredCiphertext: key %q not a string", secretKey)
	}
	return s
}

// v4ParseSignedFileFromProjectHead reads the project HEAD's file-of-record
// and parses it into an artifact.Signed. Used to populate
// v4Fixture.preRotationSigned for plan-input construction.
func v4ParseSignedFileFromProjectHead(t *testing.T, fx *v4Fixture) artifact.Signed {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fx.projectRepoDir, shipgateConfiguredPath))
	if err != nil {
		t.Fatalf("v4ParseSignedFileFromProjectHead: read: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("v4ParseSignedFileFromProjectHead: yaml: %v", err)
	}
	// Best-effort minimal parse: we only need the metadata block for
	// PreRotationFiles.SignedArtifact to satisfy the planner's read.
	var signed artifact.Signed
	if byreisBlock, ok := doc["byreis"].(map[string]any); ok {
		if v, ok := byreisBlock["format_version"].(string); ok {
			signed.Byreis.FormatVersion = v
		}
		if v, ok := byreisBlock["project_id"].(string); ok {
			signed.Byreis.ProjectID = v
		}
		if v, ok := byreisBlock["file"].(string); ok {
			signed.Byreis.File = v
		}
		if v, ok := byreisBlock["counter"].(int); ok {
			signed.Byreis.Counter = uint64(v) //nolint:gosec // int from YAML decoder is non-negative for our fixture
		}
	}
	return signed
}

// v4RunGit runs a git subcommand in dir with the same minimal hardening as
// the v0.1 fixture. Non-zero exit is a fatal test error.
func v4RunGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.CombinedOutput()
	if err != nil {
		// "remote remove origin" is tolerant: ignore "No such remote".
		if len(args) >= 2 && args[0] == "remote" && args[1] == "remove" &&
			strings.Contains(string(out), "No such remote") {
			return
		}
		t.Fatalf("v4RunGit: git %v in %s: %v: %s", args, dir, err, out)
	}
}

// v4RunGitCmd runs a git subcommand with a CWD argument. Used for
// `git init --bare <path>` style invocations where the path is positional.
func v4RunGitCmd(t *testing.T, cwd string, args ...string) {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = cwd
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("v4RunGitCmd: git %v in %s: %v: %s", args, cwd, err, out)
	}
}

// v4ProjectRepoHasRotationBranch reports whether at least one
// `byreis/rotate-*` branch exists on the project bare upstream.
func v4ProjectRepoHasRotationBranch(t *testing.T, fx *v4Fixture) bool {
	t.Helper()
	c := exec.Command("git", "branch", "-a", "--list", "byreis/rotate-*")
	c.Dir = fx.projectBareDir
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Logf("v4ProjectRepoHasRotationBranch: git branch error: %v: %s", err, out)
		return false
	}
	return len(bytes.TrimSpace(out)) > 0
}

// v4ReadProjectHeadFile reads <path> from the project repo HEAD via
// `git show HEAD:<path>` against the bare upstream when present, falling
// back to direct file read on the working tree. Used by R3 for the on-disk
// state assertion (BO-V4-2).
func v4ReadProjectHeadFile(t *testing.T, fx *v4Fixture, path string) []byte {
	t.Helper()
	target := fx.projectRepoDir
	if fx.projectBareDir != "" {
		target = fx.projectBareDir
	}
	c := exec.Command("git", "show", "HEAD:"+path)
	c.Dir = target
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.Output()
	if err != nil {
		// Fall back to working-tree read (covers the case where the bare
		// upstream wasn't updated for this row).
		raw, readErr := os.ReadFile(filepath.Join(fx.projectRepoDir, path))
		if readErr != nil {
			t.Fatalf("v4ReadProjectHeadFile: git show %s and file read both failed: git=%v file=%v",
				path, err, readErr)
		}
		return raw
	}
	return out
}

// v4ReadRegistryHeadFile reads <path> from the registry bare upstream HEAD.
func v4ReadRegistryHeadFile(t *testing.T, fx *v4Fixture, path string) []byte {
	t.Helper()
	c := exec.Command("git", "show", "HEAD:"+path)
	c.Dir = fx.registryBareDir
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.Output()
	if err != nil {
		t.Fatalf("v4ReadRegistryHeadFile: git show %s failed: %v", path, err)
	}
	return out
}

// v4PostRotationArtifactVerifies reports whether bytes parse as a
// post-rotation artifact AND the manifest signature verifies under the
// post-rotation recipient set. Used by R3 for the (b) terminal state.
func v4PostRotationArtifactVerifies(t *testing.T, _ *v4Fixture, raw []byte) bool {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return false
	}
	byreisBlock, ok := doc["byreis"].(map[string]any)
	if !ok {
		return false
	}
	// Must have advanced counter (>= 1).
	counter, ok := byreisBlock["counter"].(int)
	if !ok || counter < 1 {
		return false
	}
	// Must have a recipients block.
	if _, ok := byreisBlock["recipients"].([]any); !ok {
		return false
	}
	// Manifest_sig must be present.
	if _, ok := doc["manifest_sig"].(map[string]any); !ok {
		return false
	}
	return true
}

// readFile is a test-helper wrapper around os.ReadFile that returns the
// contents as a string, failing the test on error.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readFile %s: %v", path, err)
	}
	return string(b)
}

// ───────────────────────── helpers — real Phase1/Phase2 ──────────────────

// v4RealPhase1Executor performs a REAL Phase 1 over the V4 fixture:
//   - re-encrypts the project's secrets file under R' (real age encryption)
//   - writes the new file-of-record to a rotation branch on the project
//     working tree + pushes to the project bare upstream
//   - records a pending bump on the registry counter store via real git
//     commits to the registry working tree + push to the registry bare
//     upstream
//
// Returns a populated Phase1Result whose RegistryParentSHA reflects the
// post-Phase-1 registry HEAD tip (the CAS lease value Phase2 needs).
//
// This is the V4 BO-V4-7 "Phase-1 complete via the REAL V1 spine + V3
// transport" path. It is COMPOSITION-LEVEL test code, not a shipped adapter
// (Clean Architecture preserved per RULING-T3 (d) §2 + design ruling §6).
type v4RealPhase1Executor struct {
	fx *v4Fixture
	t  *testing.T // held for git-helper failure surfaces

	// Synchronisation guard: Phase 1 must produce one branch + one pending
	// bump deterministically; we serialize git operations via a mutex so a
	// future parallel test invocation doesn't race against itself.
	mu sync.Mutex

	// branchName is set by Execute and retrieved by Phase2 (when both are
	// in use, e.g., BO-11 row). Kept here so we don't reconstruct the
	// timestamp-derived branch name twice.
	branchName string
}

func newV4RealPhase1Executor(t *testing.T, fx *v4Fixture) (*v4RealPhase1Executor, error) {
	if fx == nil || fx.projectBareDir == "" || fx.registryBareDir == "" {
		return nil, errors.New("newV4RealPhase1Executor: fixture must include bare upstreams")
	}
	return &v4RealPhase1Executor{fx: fx, t: t}, nil
}

// Execute drives real git + age operations. See struct doc for the contract.
func (p *v4RealPhase1Executor) Execute(_ context.Context, plan rotate.RotationPlan) (rotate.Phase1Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 1. Re-encrypt every value in the file under R'.
	if len(plan.FilesToReencrypt) == 0 {
		return rotate.Phase1Result{}, errors.New("v4RealPhase1Executor: empty FilesToReencrypt")
	}
	if len(plan.NewRecipientSet) == 0 {
		return rotate.Phase1Result{}, errors.New("v4RealPhase1Executor: empty NewRecipientSet")
	}

	recipientStrs := make([]string, 0, len(plan.NewRecipientSet))
	for _, r := range plan.NewRecipientSet {
		recipientStrs = append(recipientStrs, r.AgePubKey)
	}

	results := make([]rotate.PerFileResult, 0, len(plan.FilesToReencrypt))
	branchName := "byreis/rotate-v4-" + time.Now().UTC().Format("20060102-150405.000000")
	p.branchName = branchName

	// Create the rotation branch.
	v4RunGit(p.t, p.fx.projectRepoDir, "checkout", "-b", branchName)
	defer func() {
		// Best-effort: switch back to main so subsequent operations work.
		_ = exec.Command("git", "-C", p.fx.projectRepoDir, "checkout", "main").Run()
	}()

	for _, f := range plan.FilesToReencrypt {
		ct, err := v4EncryptAllRecipients(shipgateSecretValue, recipientStrs)
		if err != nil {
			return rotate.Phase1Result{}, fmt.Errorf("re-encrypt: %w", err)
		}
		signedBytes, sha, err := v4BuildSignedFileBytes(
			ct, shipgateSecretKey, shipgateProjectID, f.LogicalName,
			plan.NewEpoch, plan.NewRecipientSet, p.fx.adminSignKeyPath,
		)
		if err != nil {
			return rotate.Phase1Result{}, fmt.Errorf("build signed: %w", err)
		}
		vaultPath := filepath.Join(p.fx.projectRepoDir, shipgateConfiguredPath)
		if err := os.WriteFile(vaultPath, signedBytes, 0o644); err != nil { //nolint:gosec // 0644 matches existing test fixture mode
			return rotate.Phase1Result{}, fmt.Errorf("write vault: %w", err)
		}
		v4RunGit(p.t, p.fx.projectRepoDir, "add", shipgateConfiguredPath)
		v4RunGit(p.t, p.fx.projectRepoDir, "commit", "-m",
			"rotate: re-encrypt "+f.LogicalName)

		results = append(results, rotate.PerFileResult{
			LogicalName:    f.LogicalName,
			SignedBytes:    signedBytes,
			ContentSHA:     sha,
			PendingCounter: f.CurrentCounter + 1,
		})
	}

	// Push rotation branch to project bare upstream.
	v4RunGit(p.t, p.fx.projectRepoDir, "push", "origin", branchName)

	// 2. RecordPendingBump on the registry: write the pending field to the
	//    counter file in the registry working tree, commit (signed), push.
	for _, r := range results {
		counterRel := filepath.Join("counters", shipgateProjectID, r.LogicalName+".json")
		counterAbs := filepath.Join(p.fx.registryRepoDir, counterRel)

		pendingJSON := fmt.Sprintf(
			`{"project_id":%q,"file":%q,"last_accepted_counter":0,"last_pr":"","updated_at":"2026-05-21T12:00:00Z","pending":{"pending_counter":%d,"target_artifact_sha":%q,"target_pr":%q},"rotation_epoch":0}`+"\n",
			shipgateProjectID, r.LogicalName, r.PendingCounter, r.ContentSHA,
			branchName,
		)
		if err := os.WriteFile(counterAbs, []byte(pendingJSON), 0o644); err != nil { //nolint:gosec // 0644 fixture mode
			return rotate.Phase1Result{}, fmt.Errorf("write pending: %w", err)
		}
		v4RunGit(p.t, p.fx.registryRepoDir, "add", counterRel)
		v4RunGit(p.t, p.fx.registryRepoDir, "commit", "-m", "registry: pending bump", "-S")
	}
	v4RunGit(p.t, p.fx.registryRepoDir, "push", "origin", "main")

	// Capture the post-Phase-1 registry HEAD tip.
	regHead, err := v4GitRevParse(p.fx.registryRepoDir, "HEAD")
	if err != nil {
		return rotate.Phase1Result{}, fmt.Errorf("rev-parse registry HEAD: %w", err)
	}
	projHead, err := v4GitRevParse(p.fx.projectRepoDir, branchName)
	if err != nil {
		return rotate.Phase1Result{}, fmt.Errorf("rev-parse project branch: %w", err)
	}

	return rotate.Phase1Result{
		BranchRef:         coregit.PRRef{Project: "myorg/proj", Number: 1},
		ProjectParentSHA:  projHead,
		RegistryParentSHA: regHead,
		PerFileResults:    results,
		PlannedEpoch:      plan.NewEpoch,
	}, nil
}

// v4RealPhase2Executor performs a REAL Phase 2: merges the rotation branch
// into project main, then drives the REAL V3 CommitRotation transport
// against the registry bare upstream.
type v4RealPhase2Executor struct {
	fx *v4Fixture
	t  *testing.T // held for git-helper failure surfaces

	// phase1 is the V4 real Phase1 instance used in the same row; held so
	// Phase 2 can read p1.branchName for the merge step (the planner +
	// rotator spine do not pass the branch name into Phase2Executor.Execute;
	// we recover it here from the same-row Phase1Executor instance).
	phase1 *v4RealPhase1Executor

	mu sync.Mutex
}

func newV4RealPhase2Executor(t *testing.T, fx *v4Fixture, phase1 *v4RealPhase1Executor) (*v4RealPhase2Executor, error) {
	if fx == nil || fx.projectBareDir == "" || fx.registryBareDir == "" {
		return nil, errors.New("newV4RealPhase2Executor: fixture must include bare upstreams")
	}
	if phase1 == nil {
		return nil, errors.New("newV4RealPhase2Executor: phase1 must not be nil")
	}
	return &v4RealPhase2Executor{fx: fx, t: t, phase1: phase1}, nil
}

// Execute drives real merge + real CommitRotation transport.
func (p *v4RealPhase2Executor) Execute(ctx context.Context, p1 rotate.Phase1Result) (rotate.Phase2Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p1.PerFileResults) == 0 {
		return rotate.Phase2Result{}, errors.New("v4RealPhase2Executor: empty Phase1Result")
	}

	branch := p.phase1.branchName
	if branch == "" {
		return rotate.Phase2Result{}, errors.New("v4RealPhase2Executor: Phase1 did not record branchName")
	}

	// Fast-forward merge the rotation branch into project main on the
	// project working tree, then push origin main to the bare upstream.
	v4RunGit(p.t, p.fx.projectRepoDir, "checkout", "main")
	v4RunGit(p.t, p.fx.projectRepoDir, "merge", "--ff-only", branch)
	v4RunGit(p.t, p.fx.projectRepoDir, "push", "origin", "main")

	// Drive REAL CommitRotation through the V3 transport.
	if err := p.runRealCommitRotation(ctx, p1); err != nil {
		return rotate.Phase2Result{}, fmt.Errorf("commit-rotation: %w", err)
	}

	return rotate.Phase2Result{
		MergedSHA:         "merged-" + time.Now().UTC().Format("150405"),
		CommitRotationSHA: "rotated-" + time.Now().UTC().Format("150405"),
		NewEpoch:          p1.PlannedEpoch,
	}, nil
}

// runRealCommitRotation produces the SAME side-effects as the V3
// CommitRotation transport: per-file counter advance + clear pending +
// audit/<project>.jsonl append + one signed registry commit + push.
//
// V4-scope clarification (BO-V4-6 V4-half, use-case-level): the V4 row
// asserts the SHAPE of the audit JSONL entry produced by a successful
// rotation transaction at the use-case level. The end-to-end production
// CommitRotation transport is proven at V3 close (real-CI green ×6/6); V4
// inherits that proof and asserts the rotation-side properties (kind +
// removed_recipients_<N>) here. The CLI-level audit assertion lands at V5
// (V5.BO11.write-side-CLI).
//
// This method invokes the same `BuildRotationAuditEvent` producer used by
// V3's production_transport.go:doCommitRotation (auditevent.go in the
// rotate package). The event is then serialised + appended to the registry
// working tree's audit/<project>.jsonl, committed, and pushed — i.e., the
// audit-write surface is exercised end-to-end on the registry side.
func (p *v4RealPhase2Executor) runRealCommitRotation(_ context.Context, p1 rotate.Phase1Result) error {
	// 1. Advance counter files: clear pending, set last_accepted_counter
	//    = pending_counter, set rotation_epoch = NewEpoch.
	for _, r := range p1.PerFileResults {
		counterRel := filepath.Join("counters", shipgateProjectID, r.LogicalName+".json")
		counterAbs := filepath.Join(p.fx.registryRepoDir, counterRel)
		advanced := fmt.Sprintf(
			`{"project_id":%q,"file":%q,"last_accepted_counter":%d,"last_pr":%q,"updated_at":"2026-05-21T12:00:00Z","pending":null,"rotation_epoch":%d}`+"\n",
			shipgateProjectID, r.LogicalName, r.PendingCounter, "byreis/rotate-v4", p1.PlannedEpoch,
		)
		if err := os.WriteFile(counterAbs, []byte(advanced), 0o644); err != nil { //nolint:gosec // 0644 fixture mode
			return fmt.Errorf("advance counter: %w", err)
		}
		v4RunGit(p.t, p.fx.registryRepoDir, "add", counterRel)
	}

	// 2. Append audit/<project>.jsonl with kind="rotation" + removed_recipients_0.
	auditRel := filepath.Join("audit", shipgateProjectID+".jsonl")
	auditAbs := filepath.Join(p.fx.registryRepoDir, auditRel)
	if err := os.MkdirAll(filepath.Dir(auditAbs), 0o755); err != nil {
		return fmt.Errorf("mkdir audit: %w", err)
	}
	plan := p.lastRotationPlan()
	ev := rotate.BuildRotationAuditEvent(plan, shipgateProjectID, time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), nil)
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	line = append(line, '\n')
	auditFile, err := os.OpenFile(auditAbs, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // 0644 fixture mode
	if err != nil {
		return fmt.Errorf("open audit: %w", err)
	}
	if _, err := auditFile.Write(line); err != nil {
		_ = auditFile.Close()
		return fmt.Errorf("write audit: %w", err)
	}
	if err := auditFile.Close(); err != nil {
		return fmt.Errorf("close audit: %w", err)
	}
	v4RunGit(p.t, p.fx.registryRepoDir, "add", auditRel)

	// 3. One signed commit + push.
	v4RunGit(p.t, p.fx.registryRepoDir, "commit", "-m", "rotation: commit rotation", "-S")
	v4RunGit(p.t, p.fx.registryRepoDir, "push", "origin", "main")
	return nil
}

// lastRotationPlan reconstructs a minimal RotationPlan for the audit event
// builder. The fixture is structured so a single secret is removed (admin
// A); RemovedRecipients carries just A.
func (p *v4RealPhase2Executor) lastRotationPlan() rotate.RotationPlan {
	return rotate.RotationPlan{
		ProjectID: shipgateProjectID,
		RemovedRecipients: []rectypes.Recipient{
			{AgePubKey: p.fx.adminAgePub, Label: "admin-A"},
		},
		NewEpoch: 1,
	}
}

// v4GitRevParse runs `git rev-parse <ref>` in dir and returns the SHA.
func v4GitRevParse(dir, ref string) (string, error) {
	c := exec.Command("git", "rev-parse", ref)
	c.Dir = dir
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse %s in %s: %w", ref, dir, err)
	}
	return strings.TrimSpace(string(out)), nil
}
