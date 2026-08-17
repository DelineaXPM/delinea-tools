//go:build !windows

package secretscmd

import (
	"os"
	"os/exec"
	"syscall"
)

// signalsFor is the set the parent catches and forwards. Isolated (no
// terminal): every termination signal, since none reach the child's separate
// group on their own. Shared (terminal): only the signals a terminal never
// generates and a sender must aim at a PID — the terminal-generated ones
// (SIGINT/SIGQUIT/SIGHUP/SIGTSTP) are left at default so the kernel delivers
// them to the whole foreground group, the child included, with no forward.
func signalsFor(isolated bool) []os.Signal {
	if isolated {
		return []os.Signal{
			syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT,
			syscall.SIGUSR1, syscall.SIGUSR2,
		}
	}
	return []os.Signal{syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2}
}

// exitStatus reports the shell-convention status for a finished child: its
// exit code, or 128+signal when a signal killed it — ExitCode is -1 then,
// which os.Exit would render as an unrecognizable 255.
func exitStatus(err *exec.ExitError) int {
	if ws, ok := err.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return err.ExitCode()
}

// hasControllingTTY reports whether this process has a controlling terminal,
// which decides the streamed child's process-group placement: with one, the
// child must stay in the foreground group to keep terminal access.
func hasControllingTTY() bool {
	f, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// isolateProcessGroup puts the child in its own process group, so a signal a
// service manager sends to the parent's group (or the parent as group leader)
// does not also reach the child by kernel group delivery — only the parent's
// explicit forward does, exactly once. Used only with no controlling
// terminal: an isolated group cannot read the terminal (SIGTTIN would stop
// it), so interactive children stay in the foreground group.
func isolateProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// signalChild forwards s to the child process itself, not its group. Direct
// PID delivery is deterministic — a shell child runs its trap rather than
// racing a group signal against its own descendants — and mirrors a
// supervising init (tini's default): the child owns propagation to whatever
// it spawned. Best-effort: the child may already be gone.
func signalChild(p *os.Process, s os.Signal) {
	p.Signal(s) //nolint:errcheck
}
