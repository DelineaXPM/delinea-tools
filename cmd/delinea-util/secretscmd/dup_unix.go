//go:build !windows && !linux

package secretscmd

import (
	"os"
	"syscall"
)

func dupToStdin(fd int) error {
	return syscall.Dup2(fd, 0)
}

// pipeFits assumes the conventional capacity: the BSD family grows a pipe's
// buffer to 64KB for large writes and exposes no capacity fcntl, and
// maxStdinPrebuffer already keeps headroom under that.
func pipeFits(*os.File, int) bool { return true }
