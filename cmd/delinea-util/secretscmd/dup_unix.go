//go:build !windows && !linux

package secretscmd

import (
	"os"
	"syscall"
)

func dupToStdin(fd int) error {
	if fd == 0 {
		// dup2 with equal descriptors is a no-op and would leave os.Pipe's
		// close-on-exec flag set, so clear it explicitly.
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 0, syscall.F_SETFD, 0)
		if errno != 0 {
			return errno
		}
		return nil
	}
	return syscall.Dup2(fd, 0)
}

func restoreStdin(fd int, wasOpen bool) error {
	if !wasOpen {
		if err := syscall.Close(0); err != syscall.EBADF {
			return err
		}
		return nil
	}
	return syscall.Dup2(fd, 0)
}

// pipeFits assumes the conventional capacity: the BSD family grows a pipe's
// buffer to 64KB for large writes and exposes no capacity fcntl, and
// maxStdinPrebuffer already keeps headroom under that.
func pipeFits(*os.File, int) bool { return true }
