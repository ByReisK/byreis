//go:build shipgate

package app_test

// TestS3_GitAuthSchemeIsBasicNotBearer is the real-auth integration test that
// closes the coverage gap that let Bearer ship in v0.9.1.
//
// Background: the file:// hermetic fixture in TestS3_InitRoundTrip exercises no
// HTTP auth path at all. Bearer vs Basic is an HTTP-transport concern that only
// surfaces when git contacts an HTTPS origin. A git subprocess driven against a
// real httptest.Server is the minimal hermetic way to verify the Authorization
// header on the wire — no real GitHub network is needed.
//
// What this test asserts:
//  1. buildGitAuthEnv produces an Authorization header whose scheme is "Basic",
//     not "Bearer".
//  2. The base64-decoded payload has the form "x-access-token:<token>", matching
//     the GitHub PAT canonical form.
//  3. A real git subprocess directed at the httptest server actually sends that
//     header — proving the env block reaches the git process correctly.
//
// Strategy:
//   - Start an httptest.Server that handles the git smart-HTTP discovery endpoint
//     (GET /info/refs?service=git-upload-pack). The server captures the incoming
//     Authorization header and responds with a minimal valid smart-http pkt-line
//     so git considers the handshake successful.
//   - Build the auth env block using BuildGitAuthEnvForTest for a github.com URL
//     so the host-predicate fires and the header value is formed.
//   - Extract the Authorization header value from GIT_CONFIG_VALUE_2.
//   - Construct a new env block pointing at the httptest server with an unscoped
//     http.extraHeader (so git sends the header to localhost, not just github.com).
//   - Run "git ls-remote <httptest-url>" and verify the server captured the
//     Authorization header with scheme Basic and payload x-access-token:<token>.
//
// The TestS3_ prefix places this test inside the existing app-leg shipgate
// -run filter ('TestD1_PositiveComposition|TestV35_|TestS1_|TestS3_') so it is
// automatically included in `make test-shipgate`, ci.yml, and release.yml
// without any -run filter change.

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/ByReisK/byreis/internal/app"
)

// TestS3_GitAuthSchemeIsBasicNotBearer drives a real git subprocess against an
// httptest.Server and verifies that the Authorization header sent by git uses
// HTTP Basic auth with the x-access-token:<token> credential form, not Bearer.
func TestS3_GitAuthSchemeIsBasicNotBearer(t *testing.T) {
	if d1GitMissing() {
		t.Fatalf("required binary 'git' is not on PATH — " +
			"a ship-gate that cannot run must fail, never pass")
	}

	const fakeToken = "ghp_TestTokenForAuthSchemeVerification"

	// Build the auth env block as if the target were github.com. This exercises
	// the real buildGitAuthEnv implementation via the test export shim.
	authEnv := app.BuildGitAuthEnvForTest("https://github.com/owner/repo", fakeToken)
	if authEnv == nil {
		t.Fatal("BuildGitAuthEnvForTest returned nil for github.com URL — " +
			"predicate check failed; bearer-vs-basic cannot be verified")
	}

	// Extract the Authorization header value from GIT_CONFIG_VALUE_2.
	// We need this to inject it as an unscoped http.extraHeader for the
	// httptest server (the scoped form fires only for github.com hosts).
	var authHeaderValue string
	for _, entry := range authEnv {
		if strings.HasPrefix(entry, "GIT_CONFIG_VALUE_2=") {
			authHeaderValue = strings.TrimPrefix(entry, "GIT_CONFIG_VALUE_2=")
			break
		}
	}
	if authHeaderValue == "" {
		t.Fatal("GIT_CONFIG_VALUE_2 not found in auth env block")
	}

	// Fast-path assertion (env-block level): scheme must be Basic, not Bearer.
	// This catches the bug before the subprocess launches.
	if !strings.HasPrefix(authHeaderValue, "Authorization: Basic ") {
		t.Fatalf("auth header value scheme is not Basic — got %q; want prefix %q",
			authHeaderValue, "Authorization: Basic ")
	}

	// Decode and validate the base64 credential payload.
	encodedCred := strings.TrimPrefix(authHeaderValue, "Authorization: Basic ")
	decodedCred, decErr := base64.StdEncoding.DecodeString(encodedCred)
	if decErr != nil {
		t.Fatalf("base64.StdEncoding.Decode of auth credential failed: %v (encoded: %q)",
			decErr, encodedCred)
	}
	if !strings.HasPrefix(string(decodedCred), "x-access-token:") {
		t.Fatalf("decoded Basic credential does not start with x-access-token: — got %q",
			string(decodedCred))
	}
	if strings.TrimPrefix(string(decodedCred), "x-access-token:") != fakeToken {
		t.Fatalf("token in credential payload = %q, want %q",
			strings.TrimPrefix(string(decodedCred), "x-access-token:"), fakeToken)
	}

	// Start an httptest.Server that captures the Authorization header from the
	// git subprocess and serves a minimal git smart-HTTP discovery response so
	// git exits cleanly (empty repository, not a hard error).
	var (
		capturedMu     sync.Mutex
		capturedHeader string
		receivedCh     = make(chan struct{}, 1)
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMu.Lock()
		if capturedHeader == "" {
			capturedHeader = r.Header.Get("Authorization")
			select {
			case receivedCh <- struct{}{}:
			default:
			}
		}
		capturedMu.Unlock()

		// Serve a minimal git smart-HTTP info/refs advertisement so git does
		// not hard-error on parse. The response is: pkt-line header announcing
		// the service, then a flush packet (0000) signalling an empty repository.
		// git ls-remote prints nothing and exits 0 on an empty repo.
		if strings.HasSuffix(r.URL.Path, "/info/refs") &&
			r.URL.Query().Get("service") == "git-upload-pack" {
			w.Header().Set("Content-Type",
				"application/x-git-upload-pack-advertisement")
			// "001e# service=git-upload-pack\n" + "0000"
			// The 4-byte hex length prefix includes itself: 0x1e = 30 = 26 chars + 4.
			_, _ = fmt.Fprint(w, "001e# service=git-upload-pack\n0000")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// Build a minimal hermetic git env for the subprocess.
	// Points http.extraHeader at the auth value extracted above (unscoped so
	// it fires for the httptest localhost URL, not just github.com).
	// http.sslVerify=false is not needed for plain http httptest.NewServer.
	tmpDir := t.TempDir()
	gitEnv := []string{
		"HOME=" + tmpDir,
		"PATH=" + gitLookPath(t), // minimal PATH containing git
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ALLOW_PROTOCOL=file:https:http:",
		"GIT_CONFIG_COUNT=3",
		"GIT_CONFIG_KEY_0=core.hooksPath",
		"GIT_CONFIG_VALUE_0=/dev/null",
		"GIT_CONFIG_KEY_1=core.fsmonitor",
		"GIT_CONFIG_VALUE_1=",
		"GIT_CONFIG_KEY_2=http.extraHeader",
		"GIT_CONFIG_VALUE_2=" + authHeaderValue,
	}

	// Run git ls-remote against the httptest server. git sends the auth header
	// on the info/refs request; we capture it server-side and assert it.
	// Exit code is not asserted — an empty-repo response may cause git to exit
	// non-zero on some versions; what matters is the header was sent.
	gitCmd := exec.Command("git", "ls-remote", srv.URL+"/repo.git") //nolint:gosec // test-only, constant args
	gitCmd.Env = gitEnv
	gitCmd.Dir = tmpDir
	_, _ = gitCmd.CombinedOutput()

	// Wait for the server goroutine to signal it received the request.
	select {
	case <-receivedCh:
		// Server received the git request.
	default:
		capturedMu.Lock()
		h := capturedHeader
		capturedMu.Unlock()
		if h == "" {
			t.Fatal("httptest server was never contacted by the git subprocess — " +
				"verify git is installed and GIT_ALLOW_PROTOCOL includes http:; " +
				"the server must receive a request for the auth-header assertion to run")
		}
	}

	capturedMu.Lock()
	captured := capturedHeader
	capturedMu.Unlock()

	if captured == "" {
		t.Fatal("Authorization header was not captured from git subprocess — " +
			"git did not send the header (env block not forwarded or auth suppressed)")
	}

	// Primary on-wire assertion: scheme must be Basic.
	if !strings.HasPrefix(captured, "Basic ") {
		t.Fatalf("git sent Authorization: %q — scheme is not Basic; "+
			"GitHub git-over-HTTPS requires Basic auth, Bearer is rejected with 401",
			captured)
	}

	// Secondary on-wire assertion: credential payload must decode to
	// x-access-token:<token>.
	b64Part := strings.TrimPrefix(captured, "Basic ")
	wireBytes, wireDecErr := base64.StdEncoding.DecodeString(b64Part)
	if wireDecErr != nil {
		t.Fatalf("base64.StdEncoding.Decode of on-wire credential failed: %v (captured: %q)",
			wireDecErr, captured)
	}
	wireCred := string(wireBytes)
	if !strings.HasPrefix(wireCred, "x-access-token:") {
		t.Fatalf("on-wire Basic credential does not use x-access-token form — got %q",
			wireCred)
	}
	if strings.TrimPrefix(wireCred, "x-access-token:") != fakeToken {
		t.Fatalf("on-wire token mismatch: got %q, want %q",
			strings.TrimPrefix(wireCred, "x-access-token:"), fakeToken)
	}
}

// gitLookPath returns the directory containing the git binary. This is the
// minimal PATH needed to satisfy the subprocess without leaking ambient env.
func gitLookPath(t *testing.T) string {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("git not found on PATH: %v", err)
	}
	// Return the directory portion for PATH injection.
	idx := strings.LastIndex(gitPath, "/")
	if idx < 0 {
		return "/usr/bin:/usr/local/bin"
	}
	return gitPath[:idx]
}
