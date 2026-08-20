//go:build !windows

package secretscmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	ds "github.com/DelineaXPM/delinea-common/secrets"
)

func TestUnixRunNamesAreCaseSensitive(t *testing.T) {
	vars := []ds.Var{{Name: "TOKEN"}, {Name: "token"}}
	for _, mode := range []string{"env", "stdin", "sh"} {
		if err := checkRunCollisions(mode, vars); err != nil {
			t.Errorf("%s collision: got %v, want case-distinct names accepted", mode, err)
		}
	}
}

// TestLaunchHelperProcess is re-executed as a child by the launch tests below.
// When GO_LAUNCH_HELPER is set it calls launch, which exec-replaces this process
// with printenv/cat so the parent can inspect what the child received. The
// stdin-big modes exercise the streaming fallback for payloads beyond the
// prebuffer cap, where launch returns instead of exec-replacing.
func TestLaunchHelperProcess(t *testing.T) {
	switch os.Getenv("GO_LAUNCH_HELPER") {
	case "":
		return
	case "env":
		_ = launch([]string{"printenv"}, append(os.Environ(), "INJECTED=hello"), nil)
	case "stdin":
		_ = launch([]string{"cat"}, os.Environ(), []byte("INJECTED=hello\x00"))
	case "stdin-closed":
		if err := syscall.Close(0); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		if err := launch([]string{"cat"}, os.Environ(), []byte("INJECTED=hello\x00")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
	case "stdin-exec-failure":
		path := filepath.Join(t.TempDir(), "invalid-executable")
		if err := os.WriteFile(path, []byte("not an executable format"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := launch([]string{path}, os.Environ(), []byte("secret-payload")); err == nil {
			t.Fatal("launch unexpectedly succeeded")
		}
		original, err := io.ReadAll(os.Stdin)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Print(string(original))
		return
	case "stdin-fork-lock":
		path := filepath.Join(t.TempDir(), "invalid-executable")
		if err := os.WriteFile(path, []byte("not an executable format"), 0o700); err != nil {
			t.Fatal(err)
		}
		syscall.ForkLock.RLock()
		done := make(chan error, 1)
		go func() {
			done <- launch([]string{path}, os.Environ(), []byte("secret-payload"))
		}()
		select {
		case err := <-done:
			syscall.ForkLock.RUnlock()
			t.Fatalf("launch returned while ForkLock was held: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		syscall.ForkLock.RUnlock()
		if err := <-done; err == nil {
			t.Fatal("launch unexpectedly succeeded")
		}
		original, err := io.ReadAll(os.Stdin)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Print(string(original))
		return
	case "stdin-big":
		if err := launch([]string{"cat"}, os.Environ(), bytes.Repeat([]byte("x"), maxStdinPrebuffer+4096)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		os.Exit(0)
	case "stdin-big-ignored":
		if err := launch([]string{"sh", "-c", "exit 0"}, os.Environ(), bytes.Repeat([]byte("y"), maxStdinPrebuffer+4096)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		os.Exit(0)
	case "stdin-big-term":
		env := make([]string, 0, len(os.Environ()))
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "GO_LAUNCH_HELPER=") {
				env = append(env, entry)
			}
		}
		env = append(env, "GO_LAUNCH_HELPER=signal-target")
		_ = launch([]string{os.Args[0], "-test.run=TestLaunchHelperProcess"},
			env, bytes.Repeat([]byte("z"), maxStdinPrebuffer+4096))
		os.Exit(98)
	case "signal-target":
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM)
		defer signal.Stop(ch)
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		fmt.Println("ready")
		if sig := <-ch; sig == syscall.SIGTERM {
			os.Exit(7)
		}
		os.Exit(99)
	case "stdin-big-killed":
		_ = launch([]string{"sh", "-c", "cat >/dev/null; kill -KILL $$"},
			os.Environ(), bytes.Repeat([]byte("k"), maxStdinPrebuffer+4096))
		os.Exit(98)
	case "streamlaunch-nilenv":
		_ = streamLaunch([]string{"printenv"}, nil, nil)
		os.Exit(0)
	}
	os.Exit(99)
}

func runLaunchHelper(t *testing.T, mode string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestLaunchHelperProcess")
	cmd.Env = append(os.Environ(), "GO_LAUNCH_HELPER="+mode)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("launch helper (%s) failed: %v", mode, err)
	}
	return string(out)
}

func TestLaunchEnvInjection(t *testing.T) {
	if !strings.Contains(runLaunchHelper(t, "env"), "INJECTED=hello") {
		t.Errorf("env mode: child environment missing INJECTED=hello")
	}
}

func TestLaunchStdinInjection(t *testing.T) {
	if !strings.Contains(runLaunchHelper(t, "stdin"), "INJECTED=hello") {
		t.Errorf("stdin mode: child stdin missing injected payload")
	}
}

func TestLaunchStdinInjectionWithClosedStdin(t *testing.T) {
	if !strings.Contains(runLaunchHelper(t, "stdin-closed"), "INJECTED=hello") {
		t.Error("child stdin missing injected payload when the parent started with fd 0 closed")
	}
}

func TestLaunchExecFailureRestoresStdin(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestLaunchHelperProcess")
	cmd.Env = append(os.Environ(), "GO_LAUNCH_HELPER=stdin-exec-failure")
	cmd.Stdin = strings.NewReader("original-stdin")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); !strings.HasPrefix(got, "original-stdin") || strings.Contains(got, "secret-payload") {
		t.Errorf("stdin after failed exec = %q, want original input and no injected payload", got)
	}
}

func TestLaunchSerializesStdinReplacementWithFork(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestLaunchHelperProcess")
	cmd.Env = append(os.Environ(), "GO_LAUNCH_HELPER=stdin-fork-lock")
	cmd.Stdin = strings.NewReader("original-stdin")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); !strings.HasPrefix(got, "original-stdin") || strings.Contains(got, "secret-payload") {
		t.Errorf("stdin after serialized failed exec = %q, want original input and no injected payload", got)
	}
}

func TestStreamLaunchNilEnvIsEmptyNotInherited(t *testing.T) {
	if out := runLaunchHelper(t, "streamlaunch-nilenv"); strings.Contains(out, "GO_LAUNCH_HELPER") {
		t.Errorf("streamLaunch with a nil env leaked the parent environment to the child:\n%s", out)
	}
}

func TestLaunchStreamsOversizedPayload(t *testing.T) {
	out := runLaunchHelper(t, "stdin-big")
	if len(out) != maxStdinPrebuffer+4096 {
		t.Errorf("child received %d bytes, want %d: a payload over the prebuffer cap must stream instead of failing", len(out), maxStdinPrebuffer+4096)
	}
}

func TestLaunchOversizedPayloadIgnoredByChild(t *testing.T) {
	runLaunchHelper(t, "stdin-big-ignored")
}

func TestLaunchStreamForwardsSIGTERM(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestLaunchHelperProcess")
	cmd.Env = append(os.Environ(), "GO_LAUNCH_HELPER=stdin-big-term")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(stdout, buf); err != nil || string(buf) != "ready\n" {
		t.Fatalf("waiting for the child to be ready: %q, %v", buf, err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 7 {
		t.Fatalf("got %v, want exit 7: SIGTERM to the supervising parent must reach the child's trap", err)
	}
}

func TestLaunchStreamPropagatesSignalDeath(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestLaunchHelperProcess")
	cmd.Env = append(os.Environ(), "GO_LAUNCH_HELPER=stdin-big-killed")
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 128+9 {
		t.Fatalf("got %v, want exit 137: a SIGKILLed child must surface as 128+signal, not 255", err)
	}
}
