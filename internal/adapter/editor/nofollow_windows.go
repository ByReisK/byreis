//go:build windows

package editor

// openNoFollowFlag returns 0 on Windows: O_NOFOLLOW is not available.
// The 0700 private temp dir still provides process isolation; the symlink
// attack surface is reduced but not eliminated. This is documented as a
// known limitation on Windows.
//
// Tracked: Windows: O_NOFOLLOW unavailable; symlink-swap in the private 0700 temp dir mitigated only by dir isolation — revisit if Windows becomes a supported target.
func openNoFollowFlag() int {
	return 0
}
