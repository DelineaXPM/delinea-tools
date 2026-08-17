//go:build !windows

package secretscmd

import (
	"errors"
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
	if len(command) == 0 {
		return fmt.Errorf("launch requires a command")
	}
	// A payload beyond the pipe's capacity cannot be prebuffered before exec:
	// spawn the child and stream instead, trading the exec-replace property for
	// delivering the payload at any size (the Windows path).
	if len(payload) > maxStdinPrebuffer {
		return streamLaunch(command, env, payload)
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("locating %q: %w", command[0], err)
	}
	if len(payload) > 0 {
		// Preserve fd 0 before creating the pipe: when stdin started closed, the
		// pipe's read end itself becomes fd 0. The backup is close-on-exec so a
		// successful replacement cannot leak it into the child.
		syscall.ForkLock.RLock()
		savedStdin, saveErr := syscall.Dup(0)
		stdinWasOpen := saveErr == nil
		if stdinWasOpen {
			syscall.CloseOnExec(savedStdin)
		}
		syscall.ForkLock.RUnlock()
		if saveErr != nil && !errors.Is(saveErr, syscall.EBADF) {
			return fmt.Errorf("preserving stdin: %w", saveErr)
		}
		closeSavedStdin := func() {
			if stdinWasOpen {
				_ = syscall.Close(savedStdin)
			}
		}
		r, w, err := os.Pipe()
		if err != nil {
			closeSavedStdin()
			return err
		}
		// The prebuffer write happens with no reader attached, so it only
		// works if the kernel buffer holds the whole payload; a pipe that
		// came up small (Linux pipe-user-pages-soft pressure) would block
		// this write forever with the child never spawned.
		if !pipeFits(w, len(payload)) {
			_ = r.Close()
			_ = w.Close()
			closeSavedStdin()
			return streamLaunch(command, env, payload)
		}
		if _, err := w.Write(payload); err != nil {
			_ = w.Close()
			_ = r.Close()
			closeSavedStdin()
			return err
		}
		if err := w.Close(); err != nil {
			_ = r.Close()
			closeSavedStdin()
			return err
		}
		pipeFD := int(r.Fd())
		// fd 0 is process-global. Block concurrent fork/exec operations, and
		// other launch calls, until Exec succeeds or the original stdin has
		// been restored. Without this lock, an unrelated child could inherit
		// the secret-bearing descriptor during this interval.
		syscall.ForkLock.Lock()
		if err := dupToStdin(pipeFD); err != nil {
			syscall.ForkLock.Unlock()
			_ = r.Close()
			closeSavedStdin()
			return err
		}
		if pipeFD != 0 {
			_ = r.Close() // fd 0 now owns the duplicate
		} else {
			// Keep the os.File alive until Exec; its finalizer owns fd 0 itself.
			runtime.KeepAlive(r)
		}
		if err := syscall.Exec(path, command, env); err != nil {
			// Mark an fd-0 os.File closed before restoring the old descriptor;
			// otherwise its finalizer could later close the restored stdin.
			if pipeFD == 0 {
				_ = r.Close()
			}
			restoreErr := restoreStdin(savedStdin, stdinWasOpen)
			closeSavedStdin()
			syscall.ForkLock.Unlock()
			if restoreErr != nil {
				return fmt.Errorf("executing %q: %w (restoring stdin: %v)", path, err, restoreErr)
			}
			return err
		}
		// syscall.Exec only returns on failure. Keep this defensive unlock for
		// alternate implementations on supported Unix platforms.
		syscall.ForkLock.Unlock()
		return nil
	}
	return syscall.Exec(path, command, env)
}
