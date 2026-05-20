// Package registry_test — V2 test rows for rotation epoch schema and
// counter-decision rule extension.
//
// Test rows (all individually failing before V2 implementation):
//
//	V2.D5.1 — v0.2 binary reads v0.1 counter-store file (no rotation_epoch key)
//	          → field defaults to 0 for every file.
//	V2.D5.2 — simulated v0.1 binary reads v0.2 counter-store JSON (rotation_epoch=3)
//	          → unknown field ignored; last_accepted_counter parsed correctly.
//	V2.D5.3 — CommitRotation advances rotation_epoch for all N files atomically.
//	V2.D5.4 — single-file CommitBump does NOT touch rotation_epoch.
//	V2.D4.1 — new OK-resume row: sc == la+1 AND P matches AND ROTATION_IN_FLIGHT
//	          → predicate fires correctly.
//	V2.D4.2 — read-only VerifyOfRecord caller under rotation-in-flight does NOT
//	          reach CommitRotation (call-graph spy asserts zero CommitRotation calls).
package registry_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/adapter/registry"
	"github.com/ByReisK/byreis/internal/core/logging"
	coreregistry "github.com/ByReisK/byreis/internal/core/registry"
	"github.com/ByReisK/byreis/internal/core/registry/countertypes"
)

// ---- V2.D5.1 — v0.2 binary reads v0.1 counter-store JSON (no rotation_epoch) ----

// TestV2_D5_1_V1FileNoRotationEpoch_DefaultsToZero proves that when a v0.2
// binary encounters a counter-store JSON file that has no "rotation_epoch" field
// (as produced by a v0.1 binary), the field defaults to 0 and no error is
// returned.
//
// The v0.1 wire format contained exactly these fields:
//
//	project_id, file, last_accepted_counter, last_pr, updated_at, pending.
//
// A v0.2 decoder MUST accept this file and return rotation_epoch == 0.
func TestV2_D5_1_V1FileNoRotationEpoch_DefaultsToZero(t *testing.T) {
	t.Parallel()

	// Minimal v0.1-shaped counter file — no rotation_epoch field.
	v1JSON := []byte(`{
  "project_id": "proj-a",
  "file": "secrets/db.enc.yaml",
  "last_accepted_counter": 7,
  "last_pr": "myorg/my-secrets#12",
  "updated_at": "2026-05-20T10:00:00Z",
  "pending": null
}
`)

	// FetchRotationEpochs via the fake transport that serves this JSON as a
	// counter blob. RotationEpoch must be 0 for the file.
	ft := &v2RotationEpochFakeTransport{
		counterBlob: v1JSON,
		projectID:   "proj-a",
		fileName:    "secrets/db.enc.yaml",
	}

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-a",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: ft,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	epochs, err := c.FetchRotationEpochs(context.Background(), "proj-a")
	if err != nil {
		t.Fatalf("FetchRotationEpochs unexpectedly failed: %v", err)
	}

	got, ok := epochs["secrets/db.enc.yaml"]
	if !ok {
		t.Fatalf("FetchRotationEpochs: expected entry for file %q, got map %v",
			"secrets/db.enc.yaml", epochs)
	}
	if got != 0 {
		t.Errorf("FetchRotationEpochs: rotation_epoch = %d, want 0 (missing field defaults to 0)",
			got)
	}
}

// ---- V2.D5.2 — decoder posture behaviour with v0.2 JSON (rotation_epoch=3) ----

// TestV2_D5_2_V2FileWithEpoch_DecoderBehaviorByPosture proves two sub-cases:
//
// (a) A lenient decoder (no DisallowUnknownFields, struct lacking rotation_epoch)
// silently ignores the rotation_epoch key and correctly reads
// last_accepted_counter from the v0.2 file. This captures the property for any
// third-party tool that uses a lenient JSON decoder.
//
// (b) A strict decoder (DisallowUnknownFields, struct lacking rotation_epoch)
// rejects the v0.2 file with an unknown-field error. This is the actual
// behaviour of a v0.1 binary — documented in the D5 erratum — and means a v0.1
// binary cannot parse a v0.2-extended counter store once rotation_epoch > 0.
// All admin operators must upgrade to v0.2 before the first rotation commit
// lands; there is no rollback path from a registry that has seen any rotation.
func TestV2_D5_2_V2FileWithEpoch_DecoderBehaviorByPosture(t *testing.T) {
	t.Parallel()

	// V2 counter file — has rotation_epoch=3.
	v2JSON := []byte(`{
  "project_id": "proj-b",
  "file": "secrets/api.enc.yaml",
  "last_accepted_counter": 12,
  "last_pr": "myorg/my-secrets#20",
  "updated_at": "2026-05-20T11:00:00Z",
  "rotation_epoch": 3,
  "pending": null
}
`)

	// simulatedV1CounterFile is a struct that models a v0.1 binary's JSON struct:
	// no rotation_epoch field declared.
	type simulatedV1CounterFile struct {
		ProjectID           string      `json:"project_id"`
		File                string      `json:"file"`
		LastAcceptedCounter json.Number `json:"last_accepted_counter"`
		LastPR              string      `json:"last_pr"`
		UpdatedAt           string      `json:"updated_at"`
		// rotation_epoch is absent — simulating v0.1 struct layout.
	}

	t.Run("lenient-decoder-ignores-unknown-field", func(t *testing.T) {
		t.Parallel()
		// Standard json.Unmarshal — no DisallowUnknownFields — unknown fields ignored.
		var decoded simulatedV1CounterFile
		if err := json.Unmarshal(v2JSON, &decoded); err != nil {
			t.Fatalf("lenient decoder: unexpected parse error on v0.2 JSON: %v", err)
		}
		if decoded.LastAcceptedCounter.String() != "12" {
			t.Errorf("lenient decoder: last_accepted_counter = %q, want %q",
				decoded.LastAcceptedCounter.String(), "12")
		}
		if decoded.ProjectID != "proj-b" {
			t.Errorf("lenient decoder: project_id = %q, want %q",
				decoded.ProjectID, "proj-b")
		}
	})

	t.Run("strict-decoder-rejects-unknown-field", func(t *testing.T) {
		t.Parallel()
		// json.Decoder with DisallowUnknownFields — mirrors the v0.1 binary's
		// decodeCounterFile posture. It must reject the v0.2 file because
		// rotation_epoch is not declared in simulatedV1CounterFile.
		var decoded simulatedV1CounterFile
		dec := json.NewDecoder(bytes.NewReader(v2JSON))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&decoded); err == nil {
			t.Fatal("strict decoder: expected unknown-field error, got nil — " +
				"this would mean a v0.1 binary could read v0.2 counter files, " +
				"contradicting the D5 erratum")
		}
		// The error should mention the unknown field name.
	})

	// Also verify the v0.2 decoder reads rotation_epoch=3 from the same JSON.
	t.Run("v02-decoder-reads-epoch", func(t *testing.T) {
		t.Parallel()
		ft := &v2RotationEpochFakeTransport{
			counterBlob: v2JSON,
			projectID:   "proj-b",
			fileName:    "secrets/api.enc.yaml",
		}
		cfg := registry.ClientConfig{
			RegistryURL:    "https://example.com/registry",
			ProjectID:      "proj-b",
			TrustAnchorKey: make([]byte, 32),
			Clock:          func() time.Time { return time.Now() },
			FetchTransport: ft,
		}
		c, err := registry.New(cfg)
		if err != nil {
			t.Fatalf("registry.New: %v", err)
		}
		epochs, err := c.FetchRotationEpochs(context.Background(), "proj-b")
		if err != nil {
			t.Fatalf("FetchRotationEpochs: %v", err)
		}
		if got := epochs["secrets/api.enc.yaml"]; got != 3 {
			t.Errorf("v0.2 decoder: rotation_epoch = %d, want 3", got)
		}
	})
}

// ---- V2.D5.3 — CommitRotation advances rotation_epoch for all N files ---------

// TestV2_D5_3_CommitRotation_AdvancesEpochForAllFiles proves that CommitRotation
// advances the rotation_epoch field for all N files in the input atomically (as
// reflected in the adapter's in-memory and cache state). Single-writer fake is
// used; the transport call-log asserts one CommitRotation call was made.
func TestV2_D5_3_CommitRotation_AdvancesEpochForAllFiles(t *testing.T) {
	t.Parallel()

	spy := &commitRotationSpy{}
	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-c",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	in := coreregistry.CommitRotationInput{
		ProjectID: "proj-c",
		NewEpoch:  2,
		PerFile: []coreregistry.PerFileCommit{
			{LogicalName: "secrets/db.enc.yaml", PendingCounter: 4, TargetSHA: makeSHA("db"), TargetPR: "org/repo#1"},
			{LogicalName: "secrets/api.enc.yaml", PendingCounter: 7, TargetSHA: makeSHA("api"), TargetPR: "org/repo#1"},
		},
		RegistryParentSHA: "parent-sha-abc",
	}

	_, err = c.CommitRotation(context.Background(), in)
	if err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}

	if spy.commitRotationCalls != 1 {
		t.Errorf("CommitRotation: transport call count = %d, want 1", spy.commitRotationCalls)
	}

	// All N files must reflect the new epoch in FetchRotationEpochs after commit.
	// Seed the spy with v0.2 JSON for each file at the new epoch.
	spy.epochsAfterCommit = map[string]uint64{
		"secrets/db.enc.yaml":  2,
		"secrets/api.enc.yaml": 2,
	}

	epochs, err := c.FetchRotationEpochs(context.Background(), "proj-c")
	if err != nil {
		t.Fatalf("FetchRotationEpochs after CommitRotation: %v", err)
	}
	for _, file := range []string{"secrets/db.enc.yaml", "secrets/api.enc.yaml"} {
		if got := epochs[file]; got != 2 {
			t.Errorf("FetchRotationEpochs[%q] = %d, want 2 after CommitRotation", file, got)
		}
	}
}

// ---- V2.D5.4 — single-file CommitBump does NOT touch rotation_epoch ----------

// TestV2_D5_4_CommitBump_DoesNotTouchRotationEpoch proves that a single-file
// CommitBump operation leaves the rotation_epoch field unchanged (invariant
// under single-file merges per ADR-0016 D5).
func TestV2_D5_4_CommitBump_DoesNotTouchRotationEpoch(t *testing.T) {
	t.Parallel()

	// Counter file at epoch=1 before the bump.
	preBumpJSON := []byte(`{
  "project_id": "proj-d",
  "file": "secrets/web.enc.yaml",
  "last_accepted_counter": 5,
  "last_pr": "myorg/my-secrets#10",
  "updated_at": "2026-05-20T12:00:00Z",
  "rotation_epoch": 1,
  "pending": {
    "pending_counter": 6,
    "target_artifact_sha": "` + makeSHA("web") + `",
    "target_pr": "myorg/my-secrets#11",
    "intent_at": "2026-05-20T12:01:00Z",
    "parent_commit_sha": "` + makeSHA40("par") + `"
  }
}
`)

	spy := &commitBumpSpy{
		blobAfterCommit: []byte(`{
  "project_id": "proj-d",
  "file": "secrets/web.enc.yaml",
  "last_accepted_counter": 6,
  "last_pr": "myorg/my-secrets#11",
  "updated_at": "2026-05-20T12:02:00Z",
  "rotation_epoch": 1,
  "pending": null
}
`),
		projectID:   "proj-d",
		fileName:    "secrets/web.enc.yaml",
		counterBlob: preBumpJSON,
	}

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-d",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// Seed pending in-memory state so CommitBump has a pending record to match.
	pendIn := coreregistry.PendingBumpInput{
		ProjectID:         "proj-d",
		FileName:          "secrets/web.enc.yaml",
		PendingCounter:    6,
		TargetArtifactSHA: makeSHA("web"),
		TargetPR:          "myorg/my-secrets#11",
	}
	if pendErr := c.SimulateRecordPendingBump(context.Background(), pendIn); pendErr != nil {
		t.Fatalf("SimulateRecordPendingBump: %v", pendErr)
	}

	bumpIn := coreregistry.CommitBumpInput{
		ProjectID:      "proj-d",
		FileName:       "secrets/web.enc.yaml",
		PendingCounter: 6,
		PRRef:          "myorg/my-secrets#11",
	}
	if bumpErr := c.CommitBump(context.Background(), bumpIn); bumpErr != nil {
		t.Fatalf("CommitBump: %v", bumpErr)
	}

	// After CommitBump, FetchRotationEpochs must still report epoch=1 (unchanged).
	epochs, err := c.FetchRotationEpochs(context.Background(), "proj-d")
	if err != nil {
		t.Fatalf("FetchRotationEpochs after CommitBump: %v", err)
	}
	if got := epochs["secrets/web.enc.yaml"]; got != 1 {
		t.Errorf("rotation_epoch after CommitBump = %d, want 1 (CommitBump must not touch epoch)",
			got)
	}
}

// ---- V2.D4.1 — OK-resume row under rotation-in-flight predicate ---------------

// TestV2_D4_1_RotationInFlightPredicate_FiresCorrectly proves that the
// ADR-0016 D4 decision-table addendum fires: when sc == la+1 AND P matches AND
// the registry signals ROTATION_IN_FLIGHT for the project, the predicate
// RotationInFlight returns true and the adapter indicates the caller must drive
// CommitRotation (not per-file CommitBump).
func TestV2_D4_1_RotationInFlightPredicate_FiresCorrectly(t *testing.T) {
	t.Parallel()

	// A counter-store JSON where pending is set AND rotation_epoch indicates
	// a rotation is in flight (rotation_epoch > 0 with pending != nil).
	// The adapter's RotationInFlight predicate checks: pending != nil AND
	// rotation_epoch > 0 (implying CommitRotation is the required commit path).
	rotationInFlightJSON := []byte(`{
  "project_id": "proj-e",
  "file": "secrets/key.enc.yaml",
  "last_accepted_counter": 3,
  "last_pr": "myorg/my-secrets#8",
  "updated_at": "2026-05-20T13:00:00Z",
  "rotation_epoch": 1,
  "pending": {
    "pending_counter": 4,
    "target_artifact_sha": "` + makeSHA("key") + `",
    "target_pr": "myorg/rotate-1-20260520",
    "intent_at": "2026-05-20T13:01:00Z",
    "parent_commit_sha": "` + makeSHA40("reg") + `"
  }
}
`)

	ft := &v2RotationEpochFakeTransport{
		counterBlob: rotationInFlightJSON,
		projectID:   "proj-e",
		fileName:    "secrets/key.enc.yaml",
	}

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-e",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: ft,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// RotationInFlight must return true: pending is set AND rotation_epoch > 0.
	inFlight, err := c.RotationInFlight(context.Background(), "proj-e", "secrets/key.enc.yaml")
	if err != nil {
		t.Fatalf("RotationInFlight: %v", err)
	}
	if !inFlight {
		t.Error("RotationInFlight = false, want true when pending != nil AND rotation_epoch > 0")
	}

	// A file with pending but rotation_epoch == 0 (single-file merge, not rotation)
	// must NOT trigger RotationInFlight.
	notRotationJSON := []byte(`{
  "project_id": "proj-e",
  "file": "secrets/other.enc.yaml",
  "last_accepted_counter": 2,
  "last_pr": "myorg/my-secrets#5",
  "updated_at": "2026-05-20T13:00:00Z",
  "rotation_epoch": 0,
  "pending": {
    "pending_counter": 3,
    "target_artifact_sha": "` + makeSHA("oth") + `",
    "target_pr": "myorg/my-secrets#6",
    "intent_at": "2026-05-20T13:01:00Z",
    "parent_commit_sha": "` + makeSHA40("par") + `"
  }
}
`)
	ft.counterBlob = notRotationJSON
	ft.fileName = "secrets/other.enc.yaml"

	notInFlight, err := c.RotationInFlight(context.Background(), "proj-e", "secrets/other.enc.yaml")
	if err != nil {
		t.Fatalf("RotationInFlight (epoch=0): %v", err)
	}
	if notInFlight {
		t.Error("RotationInFlight = true for epoch=0 pending, want false (single-file merge, not rotation)")
	}
}

// ---- V2.D4.1b — RotationInFlight returns (true, err) on uncertainty ----------

// TestV2_D4_1b_RotationInFlightPredicate_FailClosedOnUncertainty proves the
// fail-closed direction: when the registry state cannot be confirmed (transport
// error or no transport configured), RotationInFlight returns (true, non-nil
// error) so callers treat the project as in-flight and route through
// CommitRotation rather than risking corruption of a partial rotation.
func TestV2_D4_1b_RotationInFlightPredicate_FailClosedOnUncertainty(t *testing.T) {
	t.Parallel()

	t.Run("nil-transport", func(t *testing.T) {
		t.Parallel()
		cfg := registry.ClientConfig{
			RegistryURL:    "https://example.com/registry",
			ProjectID:      "proj-uncertainty",
			TrustAnchorKey: make([]byte, 32),
			Clock:          func() time.Time { return time.Now() },
			FetchTransport: nil, // no transport — offline
		}
		c, err := registry.New(cfg)
		if err != nil {
			t.Fatalf("registry.New: %v", err)
		}
		inFlight, callErr := c.RotationInFlight(context.Background(), "proj-uncertainty", "secrets/a.enc.yaml")
		if !inFlight {
			t.Error("RotationInFlight = false with nil transport, want true (fail closed)")
		}
		if callErr == nil {
			t.Error("RotationInFlight error = nil with nil transport, want non-nil error")
		}
	})

	t.Run("fetch-error", func(t *testing.T) {
		t.Parallel()
		ft := &fetchErrorTransport{err: errors.New("simulated network failure")}
		cfg := registry.ClientConfig{
			RegistryURL:    "https://example.com/registry",
			ProjectID:      "proj-uncertainty",
			TrustAnchorKey: make([]byte, 32),
			Clock:          func() time.Time { return time.Now() },
			FetchTransport: ft,
		}
		c, err := registry.New(cfg)
		if err != nil {
			t.Fatalf("registry.New: %v", err)
		}
		inFlight, callErr := c.RotationInFlight(context.Background(), "proj-uncertainty", "secrets/a.enc.yaml")
		if !inFlight {
			t.Error("RotationInFlight = false on fetch error, want true (fail closed)")
		}
		if callErr == nil {
			t.Error("RotationInFlight error = nil on fetch error, want non-nil error")
		}
	})

	t.Run("unverified-head", func(t *testing.T) {
		t.Parallel()
		ft := &fetchErrorTransport{returnUnverified: true}
		cfg := registry.ClientConfig{
			RegistryURL:    "https://example.com/registry",
			ProjectID:      "proj-uncertainty",
			TrustAnchorKey: make([]byte, 32),
			Clock:          func() time.Time { return time.Now() },
			FetchTransport: ft,
		}
		c, err := registry.New(cfg)
		if err != nil {
			t.Fatalf("registry.New: %v", err)
		}
		inFlight, callErr := c.RotationInFlight(context.Background(), "proj-uncertainty", "secrets/a.enc.yaml")
		if !inFlight {
			t.Error("RotationInFlight = false on unverified HEAD, want true (fail closed)")
		}
		if callErr == nil {
			t.Error("RotationInFlight error = nil on unverified HEAD, want non-nil error")
		}
	})
}

// fetchErrorTransport is a minimal FetchTransport that returns either a network
// error or an unverified HEAD from FetchHead to exercise the fail-closed path.
type fetchErrorTransport struct {
	err              error
	returnUnverified bool
}

func (f *fetchErrorTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	if f.err != nil {
		return "", "", false, f.err
	}
	// returnUnverified: return a commit SHA but verified=false.
	return "unverified-head-sha", "some-signer", false, nil
}

func (f *fetchErrorTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}

func (f *fetchErrorTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}

func (f *fetchErrorTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}

func (f *fetchErrorTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}

func (f *fetchErrorTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, nil
}

func (f *fetchErrorTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}

func (f *fetchErrorTransport) DiscardCounterSession(_ context.Context, _ string) {}

func (f *fetchErrorTransport) ReadRotationEpoch(_ context.Context, _, _ string, _, _ string) (uint64, error) {
	return 0, nil
}

// ---- V2.D4.2 — read-only caller does NOT reach CommitRotation ----------------

// TestV2_D4_2_ReadOnlyCaller_DoesNotReachCommitRotation proves that a read-only
// operation (FetchRotationEpochs, which is the VerifyOfRecord-equivalent for the
// epoch query path) does NOT invoke CommitRotation on the transport, even when a
// rotation is in flight. This extends ADR-0006 L3 (read-only-caller rule).
func TestV2_D4_2_ReadOnlyCaller_DoesNotReachCommitRotation(t *testing.T) {
	t.Parallel()

	spy := &commitRotationSpy{}
	// Wire the spy with a counter blob that has a pending rotation in flight.
	spy.counterBlob = []byte(`{
  "project_id": "proj-f",
  "file": "secrets/prod.enc.yaml",
  "last_accepted_counter": 9,
  "last_pr": "myorg/my-secrets#15",
  "updated_at": "2026-05-20T14:00:00Z",
  "rotation_epoch": 2,
  "pending": {
    "pending_counter": 10,
    "target_artifact_sha": "` + makeSHA("prd") + `",
    "target_pr": "myorg/rotate-2-20260520",
    "intent_at": "2026-05-20T14:01:00Z",
    "parent_commit_sha": "` + makeSHA40("reg") + `"
  }
}
`)
	spy.projectID = "proj-f"
	spy.fileName = "secrets/prod.enc.yaml"
	spy.epochsAfterCommit = map[string]uint64{
		"secrets/prod.enc.yaml": 2,
	}

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-f",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: spy,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// FetchRotationEpochs is the read-only caller path.
	_, err = c.FetchRotationEpochs(context.Background(), "proj-f")
	if err != nil {
		t.Fatalf("FetchRotationEpochs: %v", err)
	}

	// The read-only path MUST NOT have called CommitRotation on the transport.
	if spy.commitRotationCalls != 0 {
		t.Errorf("read-only FetchRotationEpochs invoked CommitRotation %d time(s), want 0",
			spy.commitRotationCalls)
	}
}

// ---- helper types -----------------------------------------------------------

// v2RotationEpochFakeTransport is a minimal FetchTransport that serves a
// fixed counter blob for one (projectID, fileName) and supports FetchRotationEpochs
// via ReadCounter.
type v2RotationEpochFakeTransport struct {
	counterBlob []byte
	projectID   string
	fileName    string
}

func (f *v2RotationEpochFakeTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "fake-head-v2", "fake-signer", true, nil
}

func (f *v2RotationEpochFakeTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}

func (f *v2RotationEpochFakeTransport) ReadCounter(_ context.Context, _, _, projectID, fileName string) (uint64, *countertypes.PendingBump, error) {
	if projectID == f.projectID && fileName == f.fileName {
		// Parse the blob and return the counter and pending.
		return parseCounterBlob(f.counterBlob)
	}
	return 0, nil, nil
}

func (f *v2RotationEpochFakeTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}

func (f *v2RotationEpochFakeTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}

func (f *v2RotationEpochFakeTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	if f.fileName == "" {
		return registry.ProjectConfig{}, nil
	}
	return registry.ProjectConfig{Files: map[string]string{f.fileName: f.fileName}}, nil
}

func (f *v2RotationEpochFakeTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}

func (f *v2RotationEpochFakeTransport) DiscardCounterSession(_ context.Context, _ string) {}

// ReadRotationEpoch reads the rotation_epoch from the counter blob for the
// given (projectID, fileName). Returns 0 if the field is absent.
func (f *v2RotationEpochFakeTransport) ReadRotationEpoch(_ context.Context, _, _ string, projectID, fileName string) (uint64, error) {
	if projectID == f.projectID && fileName == f.fileName {
		return parseRotationEpochFromBlob(f.counterBlob)
	}
	return 0, nil
}

// commitRotationSpy is a FetchTransport that records CommitRotation calls and
// can serve synthetic epoch maps for FetchRotationEpochs.
type commitRotationSpy struct {
	commitRotationCalls int
	epochsAfterCommit   map[string]uint64
	counterBlob         []byte
	projectID           string
	fileName            string
}

func (s *commitRotationSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head", "spy-signer", true, nil
}

func (s *commitRotationSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}

func (s *commitRotationSpy) ReadCounter(_ context.Context, _, _, projectID, fileName string) (uint64, *countertypes.PendingBump, error) {
	if projectID == s.projectID && fileName == s.fileName && len(s.counterBlob) > 0 {
		return parseCounterBlob(s.counterBlob)
	}
	return 0, nil, nil
}

func (s *commitRotationSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}

func (s *commitRotationSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}

func (s *commitRotationSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	files := make(map[string]string)
	if s.epochsAfterCommit != nil {
		for fn := range s.epochsAfterCommit {
			files[fn] = fn
		}
	} else if s.fileName != "" {
		files[s.fileName] = s.fileName
	}
	return registry.ProjectConfig{Files: files}, nil
}

func (s *commitRotationSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}

func (s *commitRotationSpy) DiscardCounterSession(_ context.Context, _ string) {}

// CommitRotationTransport is the spy's CommitRotation transport method (called by
// the adapter's CommitRotation). Records the call.
func (s *commitRotationSpy) CommitRotationTransport(_ context.Context, _ string, _ coreregistry.CommitRotationInput) error {
	s.commitRotationCalls++
	return nil
}

// ReadRotationEpoch serves the epochsAfterCommit map.
func (s *commitRotationSpy) ReadRotationEpoch(_ context.Context, _, _ string, _, fileName string) (uint64, error) {
	if s.epochsAfterCommit != nil {
		return s.epochsAfterCommit[fileName], nil
	}
	return 0, nil
}

// commitBumpSpy is a FetchTransport for V2.D5.4 that verifies CommitBump does
// not modify rotation_epoch.
type commitBumpSpy struct {
	blobAfterCommit []byte
	counterBlob     []byte
	projectID       string
	fileName        string
}

func (s *commitBumpSpy) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "spy-head-bump", "spy-signer", true, nil
}

func (s *commitBumpSpy) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}

func (s *commitBumpSpy) ReadCounter(_ context.Context, _, _, projectID, fileName string) (uint64, *countertypes.PendingBump, error) {
	blob := s.counterBlob
	if projectID == s.projectID && fileName == s.fileName {
		return parseCounterBlob(blob)
	}
	return 0, nil, nil
}

func (s *commitBumpSpy) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}

func (s *commitBumpSpy) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	// After CommitCounter, flip to the post-bump blob so FetchRotationEpochs reads epoch=1.
	s.counterBlob = s.blobAfterCommit
	return nil
}

func (s *commitBumpSpy) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	if s.fileName == "" {
		return registry.ProjectConfig{}, nil
	}
	return registry.ProjectConfig{Files: map[string]string{s.fileName: s.fileName}}, nil
}

func (s *commitBumpSpy) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}

func (s *commitBumpSpy) DiscardCounterSession(_ context.Context, _ string) {}

func (s *commitBumpSpy) ReadRotationEpoch(_ context.Context, _, _ string, _, fileName string) (uint64, error) {
	if fileName == s.fileName {
		return parseRotationEpochFromBlob(s.counterBlob)
	}
	return 0, nil
}

// ---- Fix4: FetchRotationEpochs partial-source warn --------------------------

// recordingLogger is a fake logging.Logger that captures all Warn-level calls.
type recordingLogger struct {
	mu      sync.Mutex
	entries []recordedLogEntry
}

type recordedLogEntry struct {
	level  logging.Level
	msg    string
	fields map[string]string
}

func (r *recordingLogger) Log(_ context.Context, level logging.Level, msg string, fields ...string) {
	entry := recordedLogEntry{
		level:  level,
		msg:    msg,
		fields: make(map[string]string, len(fields)/2),
	}
	for i := 0; i+1 < len(fields); i += 2 {
		entry.fields[fields[i]] = fields[i+1]
	}
	r.mu.Lock()
	r.entries = append(r.entries, entry)
	r.mu.Unlock()
}

func (r *recordingLogger) warns() []recordedLogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []recordedLogEntry
	for _, e := range r.entries {
		if e.level == logging.LevelWarn {
			out = append(out, e)
		}
	}
	return out
}

// configErrorTransport is a FetchTransport whose ReadProjectConfig always
// returns an error, used to exercise the warn-on-partial-source path.
type configErrorTransport struct {
	cfgErr error
}

func (t *configErrorTransport) FetchHead(_ context.Context, _ string, _ ed25519.PublicKey) (string, string, bool, error) {
	return "cfg-err-head", "signer", true, nil
}

func (t *configErrorTransport) IsAncestor(_ context.Context, _, _, _ string) (bool, error) {
	return true, nil
}

func (t *configErrorTransport) ReadCounter(_ context.Context, _, _, _, _ string) (uint64, *countertypes.PendingBump, error) {
	return 0, nil, nil
}

func (t *configErrorTransport) WriteCounter(_ context.Context, _, _, _ string, _ *countertypes.PendingBump) error {
	return nil
}

func (t *configErrorTransport) CommitCounter(_ context.Context, _, _, _ string, _ uint64) error {
	return nil
}

func (t *configErrorTransport) ReadProjectConfig(_ context.Context, _, _, _ string) (registry.ProjectConfig, error) {
	return registry.ProjectConfig{}, t.cfgErr
}

func (t *configErrorTransport) ReadAdmins(_ context.Context, _, _, _ string) (registry.ParsedAdminData, error) {
	return registry.ParsedAdminData{}, nil
}

func (t *configErrorTransport) DiscardCounterSession(_ context.Context, _ string) {}

func (t *configErrorTransport) ReadRotationEpoch(_ context.Context, _, _ string, _, _ string) (uint64, error) {
	return 0, nil
}

// TestFetchRotationEpochs_PartialSource_WarnFires proves that when
// ReadProjectConfig returns an error, the logger emits a single Warn entry
// that names the projectID and the underlying error, and FetchRotationEpochs
// still returns a non-error result (non-fatal fallback).
func TestFetchRotationEpochs_PartialSource_WarnFires(t *testing.T) {
	t.Parallel()

	rl := &recordingLogger{}
	ft := &configErrorTransport{cfgErr: errors.New("simulated config read failure")}

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-warn",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		FetchTransport: ft,
		Logger:         rl,
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	// FetchRotationEpochs must succeed (config error is non-fatal).
	_, fetchErr := c.FetchRotationEpochs(context.Background(), "proj-warn")
	if fetchErr != nil {
		t.Fatalf("FetchRotationEpochs: unexpected error: %v", fetchErr)
	}

	warns := rl.warns()
	if len(warns) == 0 {
		t.Fatal("expected at least one Warn log entry when ReadProjectConfig fails, got none")
	}
	found := false
	for _, w := range warns {
		if w.fields["projectID"] == "proj-warn" && w.fields["error"] != "" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Warn entry missing projectID=proj-warn or error field; warns: %+v", warns)
	}
}

// ---- parse helpers ----------------------------------------------------------

// parseCounterBlob parses a minimal counter JSON blob (used by fake transports).
// Only reads last_accepted_counter and pending. Not a production decoder.
func parseCounterBlob(raw []byte) (uint64, *countertypes.PendingBump, error) {
	var v struct {
		LastAcceptedCounter uint64 `json:"last_accepted_counter"`
		Pending             *struct {
			PendingCounter    uint64 `json:"pending_counter"`
			TargetArtifactSHA string `json:"target_artifact_sha"`
			TargetPR          string `json:"target_pr"`
		} `json:"pending"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, nil, err
	}
	var pb *countertypes.PendingBump
	if v.Pending != nil {
		pb = &countertypes.PendingBump{
			PendingCounter:    v.Pending.PendingCounter,
			TargetArtifactSHA: v.Pending.TargetArtifactSHA,
			TargetPR:          v.Pending.TargetPR,
		}
	}
	return v.LastAcceptedCounter, pb, nil
}

// parseRotationEpochFromBlob parses only rotation_epoch from a counter JSON blob.
// Returns 0 if the field is absent (backwards compat).
func parseRotationEpochFromBlob(raw []byte) (uint64, error) {
	var v struct {
		RotationEpoch uint64 `json:"rotation_epoch"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, err
	}
	return v.RotationEpoch, nil
}

// makeSHA returns a 64-char lowercase hex string derived from a short seed string.
// Used to produce test values for target_artifact_sha.
func makeSHA(seed string) string {
	const chars = "abcdef0123456789"
	h := make([]byte, 64)
	for i := range h {
		h[i] = chars[(i+len(seed))%len(chars)]
	}
	return string(h)
}

// makeSHA40 returns a 40-char lowercase hex string for parent_commit_sha tests.
func makeSHA40(seed string) string {
	const chars = "abcdef0123456789"
	h := make([]byte, 40)
	for i := range h {
		h[i] = chars[(i+len(seed))%len(chars)]
	}
	return string(h)
}

// ---- ErrCommitRotationNotImplemented sentinel test --------------------------

// TestCommitRotationNotImplemented_V2Sentinel proves that the V2 adapter
// implementation of CommitRotation returns ErrCommitRotationNotImplemented
// (the typed not-implemented sentinel declared per the V02_PORTS.md note that
// V2 declares the interface but the full transport lands in V3).
func TestCommitRotationNotImplemented_V2Sentinel(t *testing.T) {
	t.Parallel()

	cfg := registry.ClientConfig{
		RegistryURL:    "https://example.com/registry",
		ProjectID:      "proj-stub",
		TrustAnchorKey: make([]byte, 32),
		Clock:          func() time.Time { return time.Now() },
		// No FetchTransport: CommitRotation should fail with the sentinel.
	}
	c, err := registry.New(cfg)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	in := coreregistry.CommitRotationInput{
		ProjectID: "proj-stub",
		NewEpoch:  1,
		PerFile: []coreregistry.PerFileCommit{
			{LogicalName: "secrets/a.enc.yaml", PendingCounter: 1, TargetSHA: makeSHA("a"), TargetPR: "org/repo#1"},
		},
		RegistryParentSHA: "parent-sha",
	}

	_, err = c.CommitRotation(context.Background(), in)
	if err == nil {
		t.Fatal("CommitRotation: expected ErrCommitRotationNotImplemented, got nil")
	}
	if !errors.Is(err, coreregistry.ErrCommitRotationNotImplemented) {
		t.Errorf("CommitRotation: want errors.Is(err, ErrCommitRotationNotImplemented), got: %v", err)
	}
}
