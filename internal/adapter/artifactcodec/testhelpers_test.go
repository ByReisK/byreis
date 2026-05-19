package artifactcodec_test

import "crypto/sha256"

// cryptoSHA256 returns the SHA-256 digest of b as a [32]byte.
// This helper is in a separate file so the test package has a clean
// import-isolated sha256 function without mixing concerns.
func cryptoSHA256(b []byte) [32]byte {
	return sha256.Sum256(b)
}

// escapeCTForYAML returns a simplified escape of a ciphertext string for
// inline YAML double-quoted scalar context. Age armored ciphertexts contain
// newlines and special characters that need to be handled. This function is
// only used in test code to construct adversarial YAML fixtures; production
// paths use the codec's own marshal logic.
func escapeCTForYAML(ct string) string {
	// For test fixtures we just use a placeholder; the actual age ciphertext
	// contains newlines which makes inline YAML tricky. Return a stub that
	// makes the YAML valid but the ciphertext not a real age ciphertext.
	_ = ct
	return "age-ciphertext-placeholder"
}
