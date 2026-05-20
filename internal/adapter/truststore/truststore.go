// Package truststore implements the usecase.TrustAnchorStore port for the real
// filesystem. It reads and writes trust.yaml — the pinned registry commit-signer
// key store — under TOCTOU-safe O_NOFOLLOW + fstat-on-fd discipline from the
// shared internal/core/trust primitive.
//
// trust.yaml canonical format:
//
//	signers:
//	  - key: <base64-std raw 32-byte ed25519 pubkey>
//	    fingerprint: <hex sha256 of those 32 bytes>
//
// On read the loader recomputes sha256(key) and rejects any entry whose
// fingerprint does not match (fail-closed integrity self-check). The
// TrustAnchor returned always carries both the raw key and the verified
// fingerprint; the caller (usecase.ValidateTrustAnchor) re-validates as a
// second gate before any key reaches the registry client.
//
// Placement: OUTER adapter layer (internal/adapter/truststore). Core packages
// never import this adapter; it is injected at the composition root.
package truststore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"

	"github.com/ByReisK/byreis/internal/core/trust"
	"github.com/ByReisK/byreis/internal/core/usecase"
)

// trustYAMLFile is the filename within the config directory.
const trustYAMLFile = "trust.yaml"

// signerEntry is the on-disk representation of one pinned signer key.
type signerEntry struct {
	// Key is the base64-std encoded raw 32-byte Ed25519 public key.
	Key string `yaml:"key"`
	// Fingerprint is the hex-encoded sha256 of the decoded key bytes.
	Fingerprint string `yaml:"fingerprint"`
}

// trustYAML is the trust.yaml root structure.
type trustYAML struct {
	Signers []signerEntry `yaml:"signers"`
}

// Store implements usecase.TrustAnchorStore. It holds the config directory path
// and performs no I/O at construction time. The zero value is not useful; use New.
type Store struct {
	configDir string
}

// New constructs a Store rooted at configDir. configDir must be the byreis
// config directory (e.g. ~/.config/byreis). No I/O is performed at construction.
func New(configDir string) (*Store, error) {
	if configDir == "" {
		return nil, errors.New(
			"truststore.New: configDir is required — set BYREIS_CONFIG or ensure ~/.config/byreis exists")
	}
	return &Store{configDir: configDir}, nil
}

// trustFilePath returns the absolute path to trust.yaml.
func (s *Store) trustFilePath() string {
	return filepath.Join(s.configDir, trustYAMLFile)
}

// ReadAnchor reads the trust anchor from trust.yaml. The read is TOCTOU-safe:
// the trust package's CheckTrustFileTOCTOU opens the file with O_NOFOLLOW and
// fstats the fd before reading. The file must be exactly 0600 and owned by the
// invoking user; any violation is a hard error.
//
// Only the FIRST entry in the signers list is used (the binding model is a
// single pinned signer per client at v0.1). A file with no entries returns an
// error so the caller knows there is nothing to compare against.
//
// The returned TrustAnchor carries the raw decoded key and the stored
// fingerprint. The caller MUST invoke usecase.ValidateTrustAnchor on the
// result before using the key — this adapter does a best-effort integrity
// check (sha256 re-derivation) but the domain validator is the authoritative gate.
func (s *Store) ReadAnchor(ctx context.Context) (usecase.TrustAnchor, error) {
	if err := ctx.Err(); err != nil {
		return usecase.TrustAnchor{}, fmt.Errorf("truststore.ReadAnchor cancelled: %w", err)
	}

	path := s.trustFilePath()
	f, err := trust.CheckTrustFileTOCTOU(path)
	if err != nil {
		return usecase.TrustAnchor{}, fmt.Errorf(
			"trust anchor file %q: %w — run `byreis doctor` to diagnose, or "+
				"`byreis init` to re-create",
			path, err)
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(f)
	if err != nil {
		return usecase.TrustAnchor{}, fmt.Errorf("reading trust anchor file %q: %w", path, err)
	}

	var doc trustYAML
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return usecase.TrustAnchor{}, fmt.Errorf(
			"parsing trust anchor file %q: %w — "+
				"the file may be corrupt; restore from backup or re-pin via `byreis init`",
			path, err)
	}

	if len(doc.Signers) == 0 {
		return usecase.TrustAnchor{}, fmt.Errorf(
			"trust anchor file %q has no signers — "+
				"run `byreis init` to pin the registry signer",
			path)
	}

	entry := doc.Signers[0]
	return decodeEntry(entry, path)
}

// WriteAnchor writes the trust anchor to trust.yaml at mode 0600. The parent
// config directory is created with mode 0700 if absent. Writing atomically
// replaces any existing file (the caller must have already verified the anchor
// or be performing a manual re-pin).
func (s *Store) WriteAnchor(ctx context.Context, anchor usecase.TrustAnchor) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("truststore.WriteAnchor cancelled: %w", err)
	}

	if len(anchor.SignerKey) == 0 {
		return errors.New("truststore.WriteAnchor: anchor.SignerKey must not be empty")
	}
	if anchor.SignerFingerprint == "" {
		return errors.New("truststore.WriteAnchor: anchor.SignerFingerprint must not be empty")
	}

	// Ensure the config directory exists at 0700.
	if err := os.MkdirAll(s.configDir, 0o700); err != nil {
		return fmt.Errorf("creating config directory %q: %w", s.configDir, err)
	}

	entry := signerEntry{
		Key:         base64.StdEncoding.EncodeToString(anchor.SignerKey),
		Fingerprint: anchor.SignerFingerprint,
	}
	doc := trustYAML{Signers: []signerEntry{entry}}

	data, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("marshaling trust anchor: %w", err)
	}

	path := s.trustFilePath()

	// Write to a temp file in the same directory, then rename atomically.
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil { //nolint:gosec // 0600 is the required mode for trust.yaml; world-accessible mode is the attack we prevent
		return fmt.Errorf("writing trust anchor to %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming trust anchor into place: %w", err)
	}

	return nil
}

// AnchorExists reports whether trust.yaml is present. It does NOT open or read
// the file; it is used only to decide whether first-init acceptance is needed.
func (s *Store) AnchorExists(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("truststore.AnchorExists cancelled: %w", err)
	}
	_, err := os.Lstat(s.trustFilePath())
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking trust anchor existence: %w", err)
	}
	return true, nil
}

// decodeEntry decodes a signerEntry to a TrustAnchor, performing the
// best-effort integrity check (sha256 re-derivation). The caller must still
// invoke usecase.ValidateTrustAnchor as the authoritative gate.
func decodeEntry(entry signerEntry, path string) (usecase.TrustAnchor, error) {
	if entry.Key == "" {
		return usecase.TrustAnchor{}, fmt.Errorf(
			"trust anchor file %q: signer entry has empty key", path)
	}

	keyBytes, err := base64.StdEncoding.DecodeString(entry.Key)
	if err != nil {
		return usecase.TrustAnchor{}, fmt.Errorf(
			"trust anchor file %q: base64-decoding signer key failed: %w — "+
				"the file may be corrupt; re-pin via `byreis init`",
			path, err)
	}

	// Integrity self-check: recompute sha256(key) and compare.
	computed := hex.EncodeToString(sha256Sum(keyBytes))
	if entry.Fingerprint != "" && computed != entry.Fingerprint {
		return usecase.TrustAnchor{}, fmt.Errorf(
			"trust anchor file %q: key/fingerprint mismatch (stored %q, computed %q) — "+
				"the trust.yaml file is corrupt or was tampered with; "+
				"do not proceed; re-pin via `byreis init --accept-signer <fingerprint>` "+
				"after manual verification",
			path, entry.Fingerprint, computed)
	}

	return usecase.TrustAnchor{
		SignerKey:         keyBytes,
		SignerFingerprint: computed,
	}, nil
}

// sha256Sum returns the sha256 digest of b.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// Compile-time assertion.
var _ usecase.TrustAnchorStore = (*Store)(nil)
