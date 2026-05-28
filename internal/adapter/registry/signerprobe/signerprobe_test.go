package signerprobe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ─── fake CommandRunner ────────────────────────────────────────────────────────

// fakeRunner records calls and returns canned responses.
type fakeRunner struct {
	// responses is a queue of (stdout, stderr, exitCode, err) tuples consumed in order.
	responses []fakeResponse
	// calls records each Run invocation for assertions.
	calls []fakeCall
}

type fakeResponse struct {
	stdout   []byte
	stderr   []byte
	exitCode int
	err      error
}

type fakeCall struct {
	dir  string
	env  []string
	name string
	args []string
}

func (f *fakeRunner) Run(_ context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, int, error) {
	f.calls = append(f.calls, fakeCall{dir: dir, env: env, name: name, args: args})
	if len(f.responses) == 0 {
		return nil, nil, 0, errors.New("fakeRunner: no more responses queued")
	}
	r := f.responses[0]
	f.responses = f.responses[1:]
	return r.stdout, r.stderr, r.exitCode, r.err
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// generateEd25519Key generates a random ed25519 key pair.
func generateEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	return pub, priv
}

// buildOpenSSHSigArmored constructs a minimal but valid OpenSSH armored signature
// blob containing the given public key.  The namespace, hash_algorithm, and
// signature fields are set to placeholder values; only the public key field
// matters for signerprobe.extractEd25519KeyFromOpenSSHSig.
func buildOpenSSHSigArmored(pub ed25519.PublicKey) string {
	blob := buildOpenSSHSigBlob(pub)
	b64 := base64.StdEncoding.EncodeToString(blob)
	return "-----BEGIN SSH SIGNATURE-----\n" + b64 + "\n-----END SSH SIGNATURE-----"
}

// buildOpenSSHSigBlob constructs the binary OpenSSH signature blob.
// Format: "SSHSIG" || uint32(version=1) || string(pubkey) || string(namespace)
//
//	|| string(reserved) || string(hash_algo) || string(sig)
func buildOpenSSHSigBlob(pub ed25519.PublicKey) []byte {
	var buf bytes.Buffer

	// Magic.
	buf.WriteString("SSHSIG")
	// Version = 1.
	writeUint32(&buf, 1)
	// Public key field: SSH wire format of an ed25519 key.
	pubKeyBlob := buildSSHEd25519PubKeyBlob(pub)
	writeSSHString(&buf, pubKeyBlob)
	// Namespace.
	writeSSHString(&buf, []byte("git"))
	// Reserved (empty).
	writeSSHString(&buf, []byte{})
	// Hash algorithm.
	writeSSHString(&buf, []byte("sha512"))
	// Signature (placeholder).
	writeSSHString(&buf, []byte("placeholder-signature"))

	return buf.Bytes()
}

// buildSSHEd25519PubKeyBlob builds the SSH wire format for an ed25519 public key.
// Format: string("ssh-ed25519") || string(key_bytes).
func buildSSHEd25519PubKeyBlob(pub ed25519.PublicKey) []byte {
	var buf bytes.Buffer
	writeSSHString(&buf, []byte("ssh-ed25519"))
	writeSSHString(&buf, []byte(pub))
	return buf.Bytes()
}

func writeUint32(buf *bytes.Buffer, v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	buf.Write(b)
}

func writeSSHString(buf *bytes.Buffer, data []byte) {
	writeUint32(buf, uint32(len(data))) //nolint:gosec // test helper: len fits uint32 for small test blobs
	buf.Write(data)
}

// buildRawCommitBytes constructs a minimal git commit object with a gpgsig
// header containing the given armored signature.
func buildRawCommitBytes(sig string) []byte {
	var sb strings.Builder
	sb.WriteString("tree 0000000000000000000000000000000000000000\n")
	sb.WriteString("author Test <t@example.com> 1234567890 +0000\n")
	sb.WriteString("committer Test <t@example.com> 1234567890 +0000\n")
	// gpgsig header: first line is "gpgsig <first-sig-line>", continuation
	// lines are " <line>".
	sigLines := strings.Split(sig, "\n")
	for i, line := range sigLines {
		if i == 0 {
			sb.WriteString("gpgsig " + line + "\n")
		} else {
			sb.WriteString(" " + line + "\n")
		}
	}
	sb.WriteString("\ncommit message\n")
	return []byte(sb.String())
}

// ─── unit tests: parsing helpers ──────────────────────────────────────────────

// TestExtractGPGSigBlock_Found verifies that a well-formed commit yields the
// expected armored signature.
func TestExtractGPGSigBlock_Found(t *testing.T) {
	pub, _ := generateEd25519Key(t)
	sig := buildOpenSSHSigArmored(pub)
	rawCommit := buildRawCommitBytes(sig)

	got, err := extractGPGSigBlock(rawCommit)
	if err != nil {
		t.Fatalf("extractGPGSigBlock: %v", err)
	}

	if !strings.Contains(string(got), "BEGIN SSH SIGNATURE") {
		t.Errorf("extracted block does not contain BEGIN marker:\n%s", got)
	}
	if !strings.Contains(string(got), "END SSH SIGNATURE") {
		t.Errorf("extracted block does not contain END marker:\n%s", got)
	}
}

// TestExtractGPGSigBlock_NoGPGSig verifies that a commit without a gpgsig
// header returns an error.
func TestExtractGPGSigBlock_NoGPGSig(t *testing.T) {
	raw := []byte("tree abc\nauthor x\ncommitter y\n\nbody\n")
	_, err := extractGPGSigBlock(raw)
	if err == nil {
		t.Fatal("expected error for commit with no gpgsig, got nil")
	}
}

// TestExtractEd25519KeyFromOpenSSHSig_Valid verifies round-trip extraction.
func TestExtractEd25519KeyFromOpenSSHSig_Valid(t *testing.T) {
	pub, _ := generateEd25519Key(t)
	sig := buildOpenSSHSigArmored(pub)

	got, err := extractEd25519KeyFromOpenSSHSig([]byte(sig))
	if err != nil {
		t.Fatalf("extractEd25519KeyFromOpenSSHSig: %v", err)
	}

	if !bytes.Equal(got, pub) {
		t.Errorf("extracted key = %x, want %x", got, pub)
	}
}

// TestExtractEd25519KeyFromOpenSSHSig_NotArmored verifies that a non-armored
// blob returns an error.
func TestExtractEd25519KeyFromOpenSSHSig_NotArmored(t *testing.T) {
	_, err := extractEd25519KeyFromOpenSSHSig([]byte("not armored"))
	if err == nil {
		t.Fatal("expected error for non-armored input, got nil")
	}
}

// TestComputeFingerprint verifies the hex sha256 derivation matches standard
// sha256 output (consistency with usecase.fingerprintOf).
func TestComputeFingerprint(t *testing.T) {
	pub, _ := generateEd25519Key(t)
	sum := sha256.Sum256(pub)
	want := hex.EncodeToString(sum[:])

	got := computeFingerprint(pub)
	if got != want {
		t.Errorf("computeFingerprint = %q, want %q", got, want)
	}
}

// ─── unit test: RegistrySigner with fake runner ────────────────────────────────

// TestProbe_RegistrySigner_Success verifies the full RegistrySigner flow using
// a fake runner that returns a synthetic commit object.
func TestProbe_RegistrySigner_Success(t *testing.T) {
	pub, _ := generateEd25519Key(t)
	sig := buildOpenSSHSigArmored(pub)
	rawCommit := buildRawCommitBytes(sig)

	runner := &fakeRunner{
		responses: []fakeResponse{
			// clone: success.
			{stdout: nil, stderr: nil, exitCode: 0, err: nil},
			// cat-file: success, returns raw commit.
			{stdout: rawCommit, stderr: nil, exitCode: 0, err: nil},
		},
	}

	probe, err := New(Config{
		Runner:    runner,
		MkdirTemp: os.MkdirTemp,
		RemoveAll: func(string) error { return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := probe.RegistrySigner(context.Background(), "file:///fake-registry")
	if err != nil {
		t.Fatalf("RegistrySigner: %v", err)
	}

	if !bytes.Equal(result.Key, pub) {
		t.Errorf("Key = %x, want %x", result.Key, pub)
	}

	want := computeFingerprint(pub)
	if result.Fingerprint != want {
		t.Errorf("Fingerprint = %q, want %q", result.Fingerprint, want)
	}
}

// TestProbe_RegistrySigner_CloneFailure verifies that a non-zero clone exit
// code returns an error without panicking.
func TestProbe_RegistrySigner_CloneFailure(t *testing.T) {
	runner := &fakeRunner{
		responses: []fakeResponse{
			{stdout: nil, stderr: []byte("fatal: repo not found"), exitCode: 128, err: nil},
		},
	}

	probe, err := New(Config{
		Runner:    runner,
		MkdirTemp: os.MkdirTemp,
		RemoveAll: func(string) error { return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, gotErr := probe.RegistrySigner(context.Background(), "https://github.com/fake/registry")
	if gotErr == nil {
		t.Fatal("expected error on clone failure, got nil")
	}
}

// TestProbe_RegistrySigner_NoGPGSig verifies that a commit without a gpgsig
// header returns an error.
func TestProbe_RegistrySigner_NoGPGSig(t *testing.T) {
	rawCommit := []byte("tree abc\nauthor x\ncommitter y\n\nbody\n")

	runner := &fakeRunner{
		responses: []fakeResponse{
			{stdout: nil, stderr: nil, exitCode: 0, err: nil},       // clone
			{stdout: rawCommit, stderr: nil, exitCode: 0, err: nil}, // cat-file
		},
	}

	probe, err := New(Config{
		Runner:    runner,
		MkdirTemp: os.MkdirTemp,
		RemoveAll: func(string) error { return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, gotErr := probe.RegistrySigner(context.Background(), "file:///fake")
	if gotErr == nil {
		t.Fatal("expected error on commit without gpgsig, got nil")
	}
}

// TestProbe_RegistrySigner_CancelledContext verifies that a pre-cancelled
// context returns immediately.
func TestProbe_RegistrySigner_CancelledContext(t *testing.T) {
	runner := &fakeRunner{}

	probe, err := New(Config{
		Runner:    runner,
		MkdirTemp: os.MkdirTemp,
		RemoveAll: func(string) error { return nil },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, gotErr := probe.RegistrySigner(ctx, "file:///fake")
	if gotErr == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
	if !errors.Is(gotErr, context.Canceled) {
		t.Errorf("error = %v, want wrapping context.Canceled", gotErr)
	}
}

// ─── integration test: real git repo (hermetic, file://) ─────────────────────

// TestProbe_RegistrySigner_RealGitRepo is an integration test that exercises
// the full RegistrySigner path against a real file:// git repo signed with a
// real ssh-keygen ed25519 key.  This is hermetic (no network, no external
// state) and confirms the SSH signature parsing works against git's actual
// output format.
func TestProbe_RegistrySigner_RealGitRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH — skipping real-git integration test")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH — skipping real-git integration test")
	}

	tmpDir := t.TempDir()

	// Generate an ed25519 SSH key pair.
	keyPath := filepath.Join(tmpDir, "test-signing-key")
	pubKeyPath := keyPath + ".pub"
	cmd := exec.CommandContext(context.Background(), "ssh-keygen", "-t", "ed25519", "-N", "", "-C", "test-anchor", "-q", "-f", keyPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}

	pubBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("reading pub key: %v", err)
	}
	anchorKey := decodeSSHEd25519PubkeyForTest(t, string(pubBytes))

	// Build a minimal git repo with one SSH-signed commit.
	repoDir := filepath.Join(tmpDir, "repo")
	if mkdirErr := os.MkdirAll(repoDir, 0o750); mkdirErr != nil {
		t.Fatalf("mkdir repo: %v", mkdirErr)
	}

	allowedSigners := filepath.Join(tmpDir, "allowed_signers")
	fields := strings.Fields(strings.TrimSpace(string(pubBytes)))
	if len(fields) < 2 {
		t.Fatalf("unexpected pub key format: %q", pubBytes)
	}
	signerContent := []byte("test-anchor " + fields[0] + " " + fields[1] + "\n")
	if writeErr := os.WriteFile(allowedSigners, signerContent, 0o600); writeErr != nil { //nolint:gosec // G703: path assembled from t.TempDir() + controlled basename, no traversal
		t.Fatalf("writing allowed_signers: %v", writeErr)
	}

	gitCmds := [][]string{
		{"init", "-q", "--initial-branch=main"},
		{"config", "user.name", "Test"},
		{"config", "user.email", "test@example.com"},
		{"config", "gpg.format", "ssh"},
		{"config", "user.signingkey", pubKeyPath},
		{"config", "gpg.ssh.allowedSignersFile", allowedSigners},
		{"config", "commit.gpgsign", "true"},
	}
	for _, args := range gitCmds {
		c := exec.CommandContext(context.Background(), "git", args...) //nolint:gosec // test helper: args are controlled literals
		c.Dir = repoDir
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if cmdOut, cmdErr := c.CombinedOutput(); cmdErr != nil {
			t.Fatalf("git %v: %v: %s", args, cmdErr, cmdOut)
		}
	}

	// Write a file and commit it with the SSH signature.
	if writeAdminErr := os.WriteFile(filepath.Join(repoDir, "admins.yaml"), []byte("admins: []\n"), 0o600); writeAdminErr != nil {
		t.Fatalf("writing admins.yaml: %v", writeAdminErr)
	}
	for _, args := range [][]string{
		{"add", "."},
		{"commit", "-q", "-m", "initial signed commit", "-S"},
	} {
		c := exec.CommandContext(context.Background(), "git", args...) //nolint:gosec // test helper: args are controlled literals
		c.Dir = repoDir
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
		if cmdOut, cmdErr := c.CombinedOutput(); cmdErr != nil {
			t.Fatalf("git %v: %v: %s", args, cmdErr, cmdOut)
		}
	}

	// Now run the probe against the file:// URL.
	probe, err := New(Config{
		Runner:    realRunner{},
		MkdirTemp: os.MkdirTemp,
		RemoveAll: os.RemoveAll,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := probe.RegistrySigner(context.Background(), "file://"+repoDir)
	if err != nil {
		t.Fatalf("RegistrySigner: %v", err)
	}

	if !bytes.Equal(result.Key, anchorKey) {
		t.Errorf("Key = %x, want %x", result.Key, anchorKey)
	}

	wantFP := computeFingerprint(anchorKey)
	if result.Fingerprint != wantFP {
		t.Errorf("Fingerprint = %q, want %q", result.Fingerprint, wantFP)
	}
}

// realRunner implements CommandRunner using os/exec.
type realRunner struct{}

func (realRunner) Run(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // test helper: name+args are controlled
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

// decodeSSHEd25519PubkeyForTest extracts the raw 32-byte ed25519 public key
// from an OpenSSH "ssh-ed25519 BASE64 [comment]" line.
func decodeSSHEd25519PubkeyForTest(t *testing.T, pubLine string) ed25519.PublicKey {
	t.Helper()
	fields := strings.Fields(strings.TrimSpace(pubLine))
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		t.Fatalf("unexpected ssh pubkey format: %q", pubLine)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatalf("base64-decoding ssh pubkey blob: %v", err)
	}
	if len(blob) < 4 {
		t.Fatalf("ssh pubkey blob too short")
	}
	// Wire format: uint32(typeLen) || typeStr || uint32(keyLen) || keyBytes.
	typeLen := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	if 4+typeLen+4 > len(blob) {
		t.Fatalf("ssh pubkey blob malformed")
	}
	keyOff := 4 + typeLen + 4
	keyLen := int(blob[4+typeLen])<<24 | int(blob[5+typeLen])<<16 |
		int(blob[6+typeLen])<<8 | int(blob[7+typeLen])
	if keyOff+keyLen > len(blob) || keyLen != ed25519.PublicKeySize {
		t.Fatalf("ssh pubkey blob: key length %d not %d", keyLen, ed25519.PublicKeySize)
	}
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, blob[keyOff:keyOff+keyLen])
	return out
}
