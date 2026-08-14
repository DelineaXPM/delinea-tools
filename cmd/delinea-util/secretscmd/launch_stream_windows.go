//go:build windows

package secretscmd

import (
	"os"
	"os/exec"
)

func exitStatus(err *exec.ExitError) int { return err.ExitCode() }

// Windows console control events reach the process group on their own; there
// is no POSIX group to isolate or signal, and no controlling terminal in the
// POSIX sense, so the streamed child always takes the isolated path.
func hasControllingTTY() bool { return false }

func isolateProcessGroup(*exec.Cmd) {}

func signalsFor(bool) []os.Signal { return []os.Signal{os.Interrupt} }

func signalChild(p *os.Process, s os.Signal) {
	p.Signal(s) //nolint:errcheck
}
