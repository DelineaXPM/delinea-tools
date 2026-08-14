//go:build !windows

package secretscmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// maxStdinPrebuffer is how much payload fits in a pipe ahead of exec, with
// headroom under the common 64KB pipe capacity.
const maxStdinPrebuffer = 60 * 1024

func launch(command []string, env []string, payload []byte) error {
	if len(payload) > 0 {
		// A payload beyond the pipe's capacity cannot be prebuffered before
		// exec: spawn the child and stream instead, trading the exec-replace
		// property for delivering the payload at any size (the Windows path).
		if len(payload) > maxStdinPrebuffer {
			return streamLaunch(command, env, payload)
		}
		r, w, err := os.Pipe()
		if err != nil {
			return err
		}
		// The prebuffer write happens with no reader attached, so it only
		// works if the kernel buffer holds the whole payload; a pipe that
		// came up small (Linux pipe-user-pages-soft pressure) would block
		// this write forever with the child never spawned.
		if !pipeFits(w, len(payload)) {
			r.Close()
			w.Close()
			return streamLaunch(command, env, payload)
		}
		if _, err := w.Write(payload); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		if err := dupToStdin(int(r.Fd())); err != nil {
			return err
		}
		// r's last reference is the Fd() argument above; without this, its
		// finalizer could close the pipe fd between Fd() and the dup, letting
		// another goroutine reopen that number and bind the wrong descriptor
		// to the child's stdin.
		runtime.KeepAlive(r)
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("locating %q: %w", command[0], err)
	}
	return syscall.Exec(path, command, env)
}
