package secretscmd

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"

	"github.com/DelineaXPM/delinea-tools/internal/cli"
)

// streamLaunch spawns the child and streams any payload to its stdin. It is
// the only launch path on Windows (which has no exec-replace) and the Unix
// fallback for a payload too large to prebuffer into a pipe ahead of exec.
// Termination signals are forwarded to the child — a SIGTERM aimed at this
// PID (systemd, Kubernetes) must reach the application exactly as it would
// on the exec-replace path — and the child's exit status is propagated as
// this process's own, including the 128+signal convention for a signal death.
func streamLaunch(command []string, env []string, payload []byte) error {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	var stdin io.WriteCloser
	if len(payload) == 0 {
		cmd.Stdin = os.Stdin
	} else {
		var err error
		if stdin, err = cmd.StdinPipe(); err != nil {
			return err
		}
	}
	// Two signal regimes, chosen by whether a controlling terminal exists:
	//
	// No terminal (systemd, Kubernetes, CI) — the case where programmatic
	// signal delivery must be right. The child gets its own process group so a
	// signal aimed at the parent's group does not also reach it by kernel
	// group delivery, and every catchable termination signal the parent
	// receives is forwarded to the child itself. A service manager that
	// signals only the main PID (KillMode=mixed) is relayed correctly; one
	// that signals the whole cgroup (KillMode=control-group) delivers the
	// kernel's own copy to the child too, so it may see a duplicate —
	// accepted, and standard for a forwarding supervisor (tini, dumb-init),
	// since termination handlers are expected to be idempotent. The child owns
	// signalling whatever it spawned.
	//
	// With a terminal — the interactive case. The child stays in the parent's
	// foreground process group so it can read /dev/tty (sudo's prompt) instead
	// of being stopped with SIGTTIN, and terminal-generated signals (SIGINT
	// from Ctrl-C, SIGQUIT, SIGHUP, SIGTSTP) are left at their default
	// disposition: the kernel delivers them to the whole foreground group, the
	// child included, and the parent dies alongside it — never swallowing them
	// and never sending a duplicate. Only the signals a terminal never
	// generates (SIGTERM, SIGUSR1/2), which a sender aims at a specific PID,
	// are caught and forwarded to the child.
	isolated := !hasControllingTTY()
	if isolated {
		isolateProcessGroup(cmd)
	}
	// Registration happens before Start: a termination signal landing in the
	// spawn window waits in the channel and is forwarded once the child
	// exists, instead of killing this parent and orphaning the child.
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, signalsFor(isolated)...)
	if err := cmd.Start(); err != nil {
		signal.Stop(ch)
		return err
	}
	stop := forwardSignals(ch, cmd.Process)
	defer stop()
	if stdin != nil {
		// Write on a separate goroutine so cmd.Wait is never blocked by it: a
		// payload larger than the pipe buffer feeding a child that reads only
		// part of its stdin (a wrapper that takes one line then works) would
		// otherwise wedge the write here and never reach Wait. When the child
		// exits, the kernel closes the read end and the blocked Write returns
		// with a pipe error. Write/close errors are dropped: a child that
		// exits without draining is exercising its prerogative (the Unix
		// prebuffer path discards an unread payload silently too), and a pipe
		// error must not turn a successful run into exit 1.
		go func() {
			stdin.Write(payload) //nolint:errcheck
			stdin.Close()        //nolint:errcheck
			// Wipe once the payload has been handed off (or the write failed),
			// not held in the parent for the child's whole lifetime.
			cli.Wipe(payload)
		}()
	}
	if err := cmd.Wait(); err != nil {
		return propagate(err)
	}
	return nil
}

// forwardSignals relays every signal from an already-registered channel to
// the supervised child until the returned stop function is called. The
// channel is only subscribed to the signals appropriate for the mode
// (signalsFor), so each one caught here is meant to be forwarded — there is
// nothing to filter. Delivery is best-effort: the child may already be gone.
func forwardSignals(ch chan os.Signal, p *os.Process) func() {
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-ch:
				signalChild(p, s)
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

func propagate(err error) error {
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		os.Exit(exitStatus(exitErr))
	}
	return err
}
