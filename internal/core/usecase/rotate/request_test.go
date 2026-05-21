package rotate_test

// V6.1 request-access validation domain core — table-driven negatives + positive.
//
// Row IDs (audit-trail anchors permitted in _test.go ONLY):
//   - V6.D11.schema.* — 9 PR-author-vs-YAML failure modes (T-V6-1, T-V6-2,
//     T-V6-3, T-V6-4, T-V6-5, T-V6-8, T-V6-9 + F39) + 1 happy-path row.
//   - V6.SCHEMA.* — 8 strict-decoder negative rows (T-V6-6, T-V6-12,
//     BO-V6-CRYPTO-5).
//   - V6.HANDLE.ascii — handle ASCII-only property table (T-V6-3).
//   - V6.JUST.bytes — justification byte-length boundary (T-V6-12).
//
// Discharges: BO-V6-CRYPTO-3 (admin-side BO-3 enumeration) and BO-V6-CRYPTO-5
// (strict-decoder discipline). Adapter-side PR fetching is V6.2; this file
// exercises the pure validation contract via fake-built `RequestAccessFile` +
// `PRMetadata` values, with no real network, fs, or github SDK contact.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ByReisK/byreis/internal/core/usecase/rotate"
)

// validHandle returns a canonical lowercase ASCII GitHub-login handle. Tests
// override fields to flip a single attribute at a time.
const validHandle = "alice"

// validPubkey is a syntactically-correct age recipient (62 chars: "age1" +
// 58 bech32). The validator parses via age.ParseX25519Recipient which accepts
// well-formed encodings even for test-fixture pubkeys.
const validPubkey = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

// validSchemaVersion is the canonical v1 schema_version string. Pinned per
// the ADR-0016 D11 regex `^byreis\.request_access\.v[0-9]+$`.
const validSchemaVersion = "byreis.request_access.v1"

// validHappyPath builds a RequestAccessFile + PRMetadata pair whose
// ValidateRequestAccess invocation MUST return nil. All negative rows mutate
// one attribute at a time off this baseline so the failing axis is unambiguous.
func validHappyPath() (rotate.RequestAccessFile, rotate.PRMetadata) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	yamlFile := rotate.RequestAccessFile{
		SchemaVersion: validSchemaVersion,
		GitHubHandle:  validHandle,
		AgePubkey:     validPubkey,
		Justification: "please grant access for the prod ops on-call",
		RequestedAt:   now.Format(time.RFC3339),
	}
	prMeta := rotate.PRMetadata{
		AuthorLogin:        validHandle,
		State:              "open",
		IsDraft:            false,
		IsMerged:           false,
		HeadSHA:            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		HeadRepoOwnerLogin: validHandle,
		AuthorType:         "User",
		Commits: []rotate.CommitInfo{
			{SHA: "abc111", AuthorLogin: validHandle, Body: "feat: request access"},
			{SHA: "def222", AuthorLogin: validHandle, Body: "chore: tidy request payload"},
		},
	}
	return yamlFile, prMeta
}

// TestValidateRequestAccess_HappyPath — V6.D11.schema.happy-path. All
// constraints satisfied; ValidateRequestAccess returns nil. Establishes the
// non-empty baseline so each negative row's failure is unambiguous.
func TestValidateRequestAccess_HappyPath(t *testing.T) {
	t.Parallel()

	yamlFile, prMeta := validHappyPath()
	err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta)
	if err != nil {
		t.Fatalf("ValidateRequestAccess(happy path) error = %v, want nil", err)
	}
}

// TestValidateRequestAccess_StateMatrix exercises the 9-mode + 1-happy
// PR-author-vs-YAML state machine (T-V6-1..9 + F39).
func TestValidateRequestAccess_StateMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		// rowID — audit-trail tag tying back to ADR-0016 §D11 E1-V6 erratum
		// point 2. T-V6 IDs and F-finding IDs map to each row.
		rowID   string
		mutate  func(*rotate.RequestAccessFile, *rotate.PRMetadata)
		wantErr error
	}{
		{
			// T-V6-1 / E1-V6 mode 1 / mode 4: YAML handle "alice" but PR author
			// is "evil". Byte-equal compare refuses.
			rowID: "V6.D11.schema.handle-vs-author-mismatch",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.AuthorLogin = "evil"
			},
			wantErr: rotate.ErrRequestAccessIdentityMismatch,
		},
		{
			// E1-V6 mode 5: deleted GitHub account placeholder "ghost".
			rowID: "V6.D11.schema.deleted-account-ghost",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.AuthorLogin = "ghost"
			},
			wantErr: rotate.ErrRequestAccessIdentityMismatch,
		},
		{
			// E1-V6 mode 5: empty author login (anonymous / renamed).
			rowID: "V6.D11.schema.empty-author-login",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.AuthorLogin = ""
			},
			wantErr: rotate.ErrRequestAccessIdentityMismatch,
		},
		{
			// E1-V6 mode 9 / T-V6-1: bot identity refused.
			rowID: "V6.D11.schema.bot-identity",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.AuthorType = "Bot"
			},
			wantErr: rotate.ErrRequestAccessIdentityMismatch,
		},
		{
			// E1-V6 mode 7: draft PR is structurally not finalised.
			rowID: "V6.D11.schema.draft-pr",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.IsDraft = true
			},
			wantErr: rotate.ErrRequestAccessPRStateInvalid,
		},
		{
			// E1-V6 mode 8: closed PR refused regardless of merged_at.
			rowID: "V6.D11.schema.closed-pr",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.State = "closed"
			},
			wantErr: rotate.ErrRequestAccessPRStateInvalid,
		},
		{
			// E1-V6 mode 8: merged PR refused — already absorbed.
			rowID: "V6.D11.schema.merged-pr",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.IsMerged = true
			},
			wantErr: rotate.ErrRequestAccessPRStateInvalid,
		},
		{
			// T-V6-2: commit-author divergence — any commit whose author.login
			// differs from PR opener is refused (login-level trip-wire).
			rowID: "V6.D11.schema.commit-author-divergence",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.Commits = []rotate.CommitInfo{
					{SHA: "abc111", AuthorLogin: validHandle, Body: "feat: request access"},
					{SHA: "def222", AuthorLogin: "mallory", Body: "feat: request access"},
				}
			},
			wantErr: rotate.ErrRequestAccessCommitAuthorDivergence,
		},
		{
			// T-V6-NEW-2 / F42: a request-access commit body carries the
			// reserved byreis-sig: footer token. The trip-wire refuses on
			// case-insensitive match — contributor-authored commit bodies must
			// never contain bytes resembling byreis's signed-commit footer.
			rowID: "V6.D11.schema.byreis-sig-lowercase-refused",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.Commits = []rotate.CommitInfo{
					{
						SHA:         "abc111",
						AuthorLogin: validHandle,
						Body:        "feat: open access request\n\nbyreis-sig: AAA=\n",
					},
				}
			},
			wantErr: rotate.ErrRequestAccessCommitBodyForgery,
		},
		{
			// T-V6-NEW-2 / F42 — case-insensitivity axis. Mixed-case forge
			// attempts must refuse identically to the lowercase form.
			rowID: "V6.D11.schema.BYREIS-SIG-mixed-case-refused",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.Commits = []rotate.CommitInfo{
					{
						SHA:         "abc111",
						AuthorLogin: validHandle,
						Body:        "feat\n\nBYREIS-Sig: anything",
					},
				}
			},
			wantErr: rotate.ErrRequestAccessCommitBodyForgery,
		},
		{
			// T-V6-NEW-2 / F42 — clean-body passes (positive control). A normal
			// commit body containing no byreis-sig: token passes the new
			// trip-wire (and the rest of the validation chain).
			rowID: "V6.D11.schema.clean-body-passes",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.Commits = []rotate.CommitInfo{
					{
						SHA:         "abc111",
						AuthorLogin: validHandle,
						Body:        "feat: open access request\n\nplease grant access; thanks.",
					},
				}
			},
			wantErr: nil,
		},
		{
			// F39: fork-PR ownership drift. yamlHandle == authorLogin == "alice"
			// but fork owner observed at execute differs.
			rowID: "V6.D11.schema.fork-ownership-mismatch",
			mutate: func(_ *rotate.RequestAccessFile, pr *rotate.PRMetadata) {
				pr.HeadRepoOwnerLogin = "evil-fork-owner"
			},
			wantErr: rotate.ErrRequestAccessForkOwnershipChanged,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.rowID, func(t *testing.T) {
			t.Parallel()

			yamlFile, prMeta := validHappyPath()
			tc.mutate(&yamlFile, &prMeta)
			err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("row %q: ValidateRequestAccess err = %v, want nil", tc.rowID, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("row %q: ValidateRequestAccess err = %v, want errors.Is(_, %v)", tc.rowID, err, tc.wantErr)
			}
		})
	}
}

// TestValidateRequestAccess_HandleASCII fuzzes the github_handle field with
// every documented confusable. T-V6-3 demands ASCII-only + lowercase
// normalisation + canonical GitHub login regex.
func TestValidateRequestAccess_HandleASCII(t *testing.T) {
	t.Parallel()

	cases := []struct {
		// V6.HANDLE.ascii.* — every row asserts ErrRequestAccessSchemaInvalid
		// because the handle violates the canonical regex. The author-login
		// match is irrelevant: schema validation precedes BO-3 compare.
		rowID string
		// handle is the YAML's github_handle. The PR author login is set to the
		// same string so any acceptance would imply the schema gate failed open.
		handle string
	}{
		// Confusable fixtures are built from Go unicode escape sequences so
		// the source file itself does not carry visually-deceptive bytes
		// (gosec G116 Trojan Source guard).
		{rowID: "V6.HANDLE.ascii.cyrillic-confusable", handle: "alic\u0435"},
		{rowID: "V6.HANDLE.ascii.zero-width-joiner", handle: "ali\u200dce"},
		{rowID: "V6.HANDLE.ascii.bidi-override", handle: "ali\u202ece"},
		{rowID: "V6.HANDLE.ascii.uppercase", handle: "Alice"}, // not lowercase-normalised input
		{rowID: "V6.HANDLE.ascii.length-40", handle: strings.Repeat("a", 40)},
		{rowID: "V6.HANDLE.ascii.leading-hyphen", handle: "-alice"},
		{rowID: "V6.HANDLE.ascii.trailing-hyphen", handle: "alice-"},
		{rowID: "V6.HANDLE.ascii.double-hyphen", handle: "ali--ce"},
		{rowID: "V6.HANDLE.ascii.empty", handle: ""},
		{rowID: "V6.HANDLE.ascii.underscore", handle: "ali_ce"},
		{rowID: "V6.HANDLE.ascii.dot", handle: "ali.ce"},
		{rowID: "V6.HANDLE.ascii.slash", handle: "ali/ce"},
		{rowID: "V6.HANDLE.ascii.null-byte", handle: "ali\x00ce"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.rowID, func(t *testing.T) {
			t.Parallel()

			yamlFile, prMeta := validHappyPath()
			yamlFile.GitHubHandle = tc.handle
			prMeta.AuthorLogin = tc.handle
			prMeta.HeadRepoOwnerLogin = tc.handle
			err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta)
			if !errors.Is(err, rotate.ErrRequestAccessSchemaInvalid) {
				t.Fatalf("row %q: err = %v, want errors.Is(_, ErrRequestAccessSchemaInvalid)", tc.rowID, err)
			}
		})
	}
}

// TestValidateRequestAccess_HandleASCIIAccepts proves the validator accepts a
// minimal ASCII-conformant handle without leading/trailing/double hyphens.
// This protects against an over-broad refusal in TestValidateRequestAccess_HandleASCII.
func TestValidateRequestAccess_HandleASCIIAccepts(t *testing.T) {
	t.Parallel()

	cases := []string{
		"a",                     // length-1 single alphanumeric
		"alice",                 // canonical
		"alice-bob",             // single hyphen interior
		"alice1",                // alphanumeric
		"1alice",                // leading digit allowed
		strings.Repeat("a", 39), // length-39 boundary
	}
	for _, h := range cases {
		h := h
		t.Run("V6.HANDLE.accept/"+h, func(t *testing.T) {
			t.Parallel()
			yamlFile, prMeta := validHappyPath()
			yamlFile.GitHubHandle = h
			prMeta.AuthorLogin = h
			prMeta.HeadRepoOwnerLogin = h
			for i := range prMeta.Commits {
				prMeta.Commits[i].AuthorLogin = h
			}
			if err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta); err != nil {
				t.Fatalf("handle %q: unexpected error %v", h, err)
			}
		})
	}
}

// TestValidateRequestAccess_JustificationBytes pins T-V6-12: justification
// length is BYTES not runes. 1000 ASCII bytes accept; 1001 refuse; 1000 ASCII
// plus 1 multibyte refuse; 333 three-byte UTF-8 characters (= 999 bytes)
// accept; 334 three-byte chars (= 1002 bytes) refuse.
func TestValidateRequestAccess_JustificationBytes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		rowID   string
		just    string
		wantErr bool
	}{
		{rowID: "V6.JUST.bytes.1000-ascii-accept", just: strings.Repeat("a", 1000), wantErr: false},
		{rowID: "V6.JUST.bytes.1001-ascii-refuse", just: strings.Repeat("a", 1001), wantErr: true},
		{
			// 1000 ASCII + 1 byte of UTF-8 = 1001 bytes (the single multibyte
			// char does not split, so the count must exceed 1000).
			rowID:   "V6.JUST.bytes.1000-ascii-plus-multibyte-refuse",
			just:    strings.Repeat("a", 1000) + "é", // é is 2 bytes; total 1002
			wantErr: true,
		},
		{
			// 333 × 3-byte UTF-8 chars = 999 bytes → accept.
			rowID:   "V6.JUST.bytes.utf8-999-accept",
			just:    strings.Repeat("中", 333),
			wantErr: false,
		},
		{
			// 334 × 3-byte UTF-8 chars = 1002 bytes → refuse.
			rowID:   "V6.JUST.bytes.utf8-1002-refuse",
			just:    strings.Repeat("中", 334),
			wantErr: true,
		},
		{
			// Non-UTF-8 sequence is rejected (T-V6-6 requires UTF-8 valid).
			rowID:   "V6.JUST.bytes.non-utf8",
			just:    string([]byte{0xff, 0xfe, 0xfd}),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.rowID, func(t *testing.T) {
			t.Parallel()

			yamlFile, prMeta := validHappyPath()
			yamlFile.Justification = tc.just
			err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta)
			if tc.wantErr {
				if !errors.Is(err, rotate.ErrRequestAccessSchemaInvalid) {
					t.Fatalf("row %q: err = %v, want errors.Is(_, ErrRequestAccessSchemaInvalid)", tc.rowID, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("row %q: unexpected error %v", tc.rowID, err)
			}
		})
	}
}

// TestValidateRequestAccess_SchemaVersion exercises the schema_version regex
// `^byreis\.request_access\.v[0-9]+$`. ADR-0016 D11 step 3.
func TestValidateRequestAccess_SchemaVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		rowID   string
		version string
		wantErr bool
	}{
		{rowID: "V6.SCHEMA.version.v1-accept", version: "byreis.request_access.v1", wantErr: false},
		{rowID: "V6.SCHEMA.version.v2-accept", version: "byreis.request_access.v2", wantErr: false},
		{rowID: "V6.SCHEMA.version.v100-accept", version: "byreis.request_access.v100", wantErr: false},
		{rowID: "V6.SCHEMA.version.empty-refuse", version: "", wantErr: true},
		{rowID: "V6.SCHEMA.version.v0-vs-v1-different-prefix", version: "byreis.access.v1", wantErr: true},
		{rowID: "V6.SCHEMA.version.no-version-suffix", version: "byreis.request_access", wantErr: true},
		{rowID: "V6.SCHEMA.version.letter-suffix", version: "byreis.request_access.va", wantErr: true},
		{rowID: "V6.SCHEMA.version.injection", version: "byreis.request_access.v1; rm -rf /", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.rowID, func(t *testing.T) {
			t.Parallel()
			yamlFile, prMeta := validHappyPath()
			yamlFile.SchemaVersion = tc.version
			err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta)
			if tc.wantErr {
				if !errors.Is(err, rotate.ErrRequestAccessSchemaInvalid) {
					t.Fatalf("row %q: err = %v, want errors.Is(_, ErrRequestAccessSchemaInvalid)", tc.rowID, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("row %q: unexpected error %v", tc.rowID, err)
			}
		})
	}
}

// TestValidateRequestAccess_AgePubkey exercises BO-V6-CRYPTO-5 — the
// age_pubkey field MUST parse via age.ParseX25519Recipient; base64 / raw bytes
// / malformed strings are refused.
func TestValidateRequestAccess_AgePubkey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		rowID   string
		pk      string
		wantErr bool
	}{
		{rowID: "V6.SCHEMA.pubkey.canonical-accept", pk: validPubkey, wantErr: false},
		{rowID: "V6.SCHEMA.pubkey.empty", pk: "", wantErr: true},
		{rowID: "V6.SCHEMA.pubkey.base64", pk: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEABCD", wantErr: true},
		{rowID: "V6.SCHEMA.pubkey.malformed-prefix", pk: "ssh-ed25519 AAAA", wantErr: true},
		{rowID: "V6.SCHEMA.pubkey.truncated", pk: "age1abc", wantErr: true},
		{rowID: "V6.SCHEMA.pubkey.uppercase", pk: strings.ToUpper(validPubkey), wantErr: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.rowID, func(t *testing.T) {
			t.Parallel()
			yamlFile, prMeta := validHappyPath()
			yamlFile.AgePubkey = tc.pk
			err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta)
			if tc.wantErr {
				if !errors.Is(err, rotate.ErrRequestAccessSchemaInvalid) {
					t.Fatalf("row %q: err = %v, want errors.Is(_, ErrRequestAccessSchemaInvalid)", tc.rowID, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("row %q: unexpected error %v", tc.rowID, err)
			}
		})
	}
}

// TestValidateRequestAccess_RequestedAt exercises RFC3339 parsing for
// requested_at. Schema requires RFC3339; any other format refused.
func TestValidateRequestAccess_RequestedAt(t *testing.T) {
	t.Parallel()

	cases := []struct {
		rowID   string
		ts      string
		wantErr bool
	}{
		{rowID: "V6.SCHEMA.requested-at.rfc3339-utc", ts: "2026-05-21T12:00:00Z", wantErr: false},
		{rowID: "V6.SCHEMA.requested-at.rfc3339-offset", ts: "2026-05-21T12:00:00-07:00", wantErr: false},
		{rowID: "V6.SCHEMA.requested-at.empty", ts: "", wantErr: true},
		{rowID: "V6.SCHEMA.requested-at.date-only", ts: "2026-05-21", wantErr: true},
		{rowID: "V6.SCHEMA.requested-at.unix-epoch", ts: "1747824000", wantErr: true},
		{rowID: "V6.SCHEMA.requested-at.malformed", ts: "yesterday afternoon", wantErr: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.rowID, func(t *testing.T) {
			t.Parallel()
			yamlFile, prMeta := validHappyPath()
			yamlFile.RequestedAt = tc.ts
			err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta)
			if tc.wantErr {
				if !errors.Is(err, rotate.ErrRequestAccessSchemaInvalid) {
					t.Fatalf("row %q: err = %v, want errors.Is(_, ErrRequestAccessSchemaInvalid)", tc.rowID, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("row %q: unexpected error %v", tc.rowID, err)
			}
		})
	}
}

// TestValidateRequestAccess_LowercaseNormalisation pins T-V6-3's lowercase
// normalisation contract: a YAML handle whose chars don't match the canonical
// lowercase form refuses with schema-invalid (the YAML handle MUST already be
// lowercase; uppercase is a YAML defect).
func TestValidateRequestAccess_LowercaseNormalisation(t *testing.T) {
	t.Parallel()

	yamlFile, prMeta := validHappyPath()
	yamlFile.GitHubHandle = "ALICE" // schema regex requires lowercase
	prMeta.AuthorLogin = "alice"
	if err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta); !errors.Is(err, rotate.ErrRequestAccessSchemaInvalid) {
		t.Fatalf("uppercase YAML handle must refuse with schema-invalid, got %v", err)
	}
}

// TestDecodeRequestAccessYAML exercises BO-V6-CRYPTO-5 + T-V6-6: strict-decoder
// discipline. Unknown fields, duplicate keys, malformed YAML, and missing
// required fields refuse with ErrRequestAccessSchemaInvalid.
func TestDecodeRequestAccessYAML(t *testing.T) {
	t.Parallel()

	good := []byte("" +
		"schema_version: byreis.request_access.v1\n" +
		"github_handle: alice\n" +
		"age_pubkey: " + validPubkey + "\n" +
		"justification: please grant access\n" +
		"requested_at: 2026-05-21T12:00:00Z\n")

	cases := []struct {
		// Each row covers one strict-decoder failure mode from T-V6-6.
		rowID   string
		yaml    []byte
		wantErr bool
	}{
		{rowID: "V6.SCHEMA.decode.happy-path", yaml: good, wantErr: false},
		{
			rowID: "V6.SCHEMA.decode.unknown-field",
			yaml: []byte("" +
				"schema_version: byreis.request_access.v1\n" +
				"github_handle: alice\n" +
				"age_pubkey: " + validPubkey + "\n" +
				"justification: x\n" +
				"requested_at: 2026-05-21T12:00:00Z\n" +
				"is_admin: true\n"), // smuggled field — must refuse
			wantErr: true,
		},
		{
			rowID: "V6.SCHEMA.decode.duplicate-key",
			yaml: []byte("" +
				"schema_version: byreis.request_access.v1\n" +
				"github_handle: alice\n" +
				"github_handle: bob\n" + // duplicate
				"age_pubkey: " + validPubkey + "\n" +
				"justification: x\n" +
				"requested_at: 2026-05-21T12:00:00Z\n"),
			wantErr: true,
		},
		{
			rowID:   "V6.SCHEMA.decode.malformed",
			yaml:    []byte("schema_version: byreis.request_access.v1\ngithub_handle: \"unterminated"),
			wantErr: true,
		},
		{
			rowID:   "V6.SCHEMA.decode.missing-required-handle",
			yaml:    []byte("schema_version: byreis.request_access.v1\nage_pubkey: " + validPubkey + "\njustification: x\nrequested_at: 2026-05-21T12:00:00Z\n"),
			wantErr: true,
		},
		{
			rowID:   "V6.SCHEMA.decode.missing-required-pubkey",
			yaml:    []byte("schema_version: byreis.request_access.v1\ngithub_handle: alice\njustification: x\nrequested_at: 2026-05-21T12:00:00Z\n"),
			wantErr: true,
		},
		{
			rowID:   "V6.SCHEMA.decode.missing-schema-version",
			yaml:    []byte("github_handle: alice\nage_pubkey: " + validPubkey + "\njustification: x\nrequested_at: 2026-05-21T12:00:00Z\n"),
			wantErr: true,
		},
		{
			rowID:   "V6.SCHEMA.decode.empty",
			yaml:    []byte(""),
			wantErr: true,
		},
		{
			rowID:   "V6.SCHEMA.decode.oversize-justification",
			yaml:    []byte("schema_version: byreis.request_access.v1\ngithub_handle: alice\nage_pubkey: " + validPubkey + "\njustification: " + strings.Repeat("a", 1001) + "\nrequested_at: 2026-05-21T12:00:00Z\n"),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.rowID, func(t *testing.T) {
			t.Parallel()
			_, err := rotate.DecodeRequestAccessYAML(tc.yaml)
			if tc.wantErr {
				if !errors.Is(err, rotate.ErrRequestAccessSchemaInvalid) {
					t.Fatalf("row %q: err = %v, want errors.Is(_, ErrRequestAccessSchemaInvalid)", tc.rowID, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("row %q: unexpected error %v", tc.rowID, err)
			}
		})
	}
}

// TestValidateRequestAccess_PRStateOpenNonDraftAccepts proves the happy-state
// PR shape. Verifies the matrix-pin row from V02_V6_ACK_THREAT_MODELER §5.
func TestValidateRequestAccess_PRStateOpenNonDraftAccepts(t *testing.T) {
	t.Parallel()
	yamlFile, prMeta := validHappyPath()
	// Explicitly assert the canonical accepted state shape.
	prMeta.State = "open"
	prMeta.IsDraft = false
	prMeta.IsMerged = false
	prMeta.AuthorType = "User"
	if err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

// TestValidateRequestAccess_PRAuthorLowercaseNormalised proves byte-equal
// compare is lowercase-normalised on both sides (T-V6-3 + E1-V6 mode 4).
// YAML side is gate-refused at schema (lowercase-only), so this row pins the
// PR-side normalisation: PR author "Alice" against YAML "alice" must accept,
// because GitHub logins are case-insensitive (the canonical login is what the
// PR side returns; admin's runtime fetch may surface any-case the SDK echoes).
func TestValidateRequestAccess_PRAuthorLowercaseNormalised(t *testing.T) {
	t.Parallel()
	yamlFile, prMeta := validHappyPath()
	prMeta.AuthorLogin = "ALICE"
	prMeta.HeadRepoOwnerLogin = "ALICE"
	if err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta); err != nil {
		t.Fatalf("PR author case-normalisation refused match: %v", err)
	}
}

// TestValidateRequestAccess_PRAuthorMustMatchHandle ensures we always match
// the PR-author against the handle, even when the YAML's schema-valid handle
// has no mismatch with any other field.
func TestValidateRequestAccess_PRAuthorMustMatchHandle(t *testing.T) {
	t.Parallel()
	yamlFile, prMeta := validHappyPath()
	yamlFile.GitHubHandle = "alice"
	prMeta.AuthorLogin = "bob"
	prMeta.HeadRepoOwnerLogin = "bob"
	if err := rotate.ValidateRequestAccess(context.Background(), yamlFile, prMeta); !errors.Is(err, rotate.ErrRequestAccessIdentityMismatch) {
		t.Fatalf("err = %v, want errors.Is(_, ErrRequestAccessIdentityMismatch)", err)
	}
}
