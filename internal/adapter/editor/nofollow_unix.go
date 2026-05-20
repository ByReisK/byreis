//go:build !windows

package editor

import "syscall"

// openNoFollowFlag returns syscall.O_NOFOLLOW on Unix platforms.
// O_NOFOLLOW causes the open to fail with ELOOP if the final path component
// is a symlink, binding the security decision to the object at open time.
func openNoFollowFlag() int {
	return syscall.O_NOFOLLOW
}
