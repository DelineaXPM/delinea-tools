//go:build linux

package secretscmd

import (
	"os"
	"syscall"
)

// linux/arm64 has no dup2 syscall, so use dup3 everywhere on Linux.
func dupToStdin(fd int) error {
	if fd == 0 {
		// os.Pipe marks both ends close-on-exec. When stdin was closed, its
		// read end can already be fd 0; dup3 rejects equal descriptors, so clear
		// the flag in place and retain this pipe as the exec'd child's stdin.
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 0, syscall.F_SETFD, 0)
		if errno != 0 {
			return errno
		}
		return nil
	}
	return syscall.Dup3(fd, 0, 0)
}

func restoreStdin(fd int, wasOpen bool) error {
	if !wasOpen {
		if err := syscall.Close(0); err != syscall.EBADF {
			return err
		}
		return nil
	}
	return syscall.Dup3(fd, 0, 0)
}

// pipeFits reports whether the pipe's kernel buffer can prebuffer n bytes. A
// pipe normally holds 64KB, but a user over the kernel's pipe-user-pages-soft
// limit gets a single page; the buffer is grown when possible, and the caller
// abandons the prebuffer path when capacity still falls short.
func pipeFits(w *os.File, n int) bool {
	const fSetPipeSz, fGetPipeSz = 1031, 1032
	sz, _, errno := syscall.Syscall(syscall.SYS_FCNTL, w.Fd(), fGetPipeSz, 0)
	if errno != 0 {
		// Unknowable capacity fails closed: streaming always works, while a
		// wrong 64KB assumption is exactly the pre-exec hang this check
		// exists to prevent.
		return false
	}
	if int(sz) >= n {
		return true
	}
	sz, _, errno = syscall.Syscall(syscall.SYS_FCNTL, w.Fd(), fSetPipeSz, uintptr(n))
	return errno == 0 && int(sz) >= n
}
