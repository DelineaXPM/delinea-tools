//go:build windows

package secretscmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	ds "github.com/DelineaXPM/delinea-common/secrets"
)

const windowsTestPayloadSize = 128 * 1024

// TestWindowsLaunchHelperProcess is both supervisor and child for the tests
// below, keeping the Windows suite independent of PowerShell or cmd syntax.
func TestWindowsLaunchHelperProcess(t *testing.T) {
	mode := os.Getenv("GO_WINDOWS_LAUNCH_HELPER")
	child := func(childMode string, payload []byte, extraEnv ...string) {
		env := append(os.Environ(), "GO_WINDOWS_LAUNCH_HELPER="+childMode)
		env = append(env, extraEnv...)
		if err := launch([]string{os.Args[0], "-test.run=TestWindowsLaunchHelperProcess"}, env, payload); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		os.Exit(0)
	}
	switch mode {
	case "":
		return
	case "parent-env":
		child("child-env", nil, "INJECTED=hello")
	case "parent-stdin":
		child("child-stdin", bytes.Repeat([]byte("x"), windowsTestPayloadSize))
	case "parent-ignored":
		child("child-ignored", bytes.Repeat([]byte("y"), windowsTestPayloadSize))
	case "parent-exit":
		child("child-exit", nil)
	// The child branches exit rather than return: a returned test function
	// hands control back to the framework, which writes its "PASS\n" summary
	// to the same stdout the supervisor streamed the child's output onto,
	// corrupting the bytes the parent test captures. os.Exit stops before that.
	case "child-env":
		fmt.Fprint(os.Stdout, os.Getenv("INJECTED"))
		os.Exit(0)
	case "child-stdin":
		_, _ = io.Copy(os.Stdout, os.Stdin)
		os.Exit(0)
	case "child-ignored":
		os.Exit(0)
	case "child-exit":
		os.Exit(7)
	default:
		os.Exit(98)
	}
}

func runWindowsLaunchHelper(t *testing.T, mode string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestWindowsLaunchHelperProcess")
	cmd.Env = append(os.Environ(), "GO_WINDOWS_LAUNCH_HELPER="+mode)
	out, err := cmd.Output()
	return string(out), err
}

func TestWindowsLaunchEnvInjection(t *testing.T) {
	out, err := runWindowsLaunchHelper(t, "parent-env")
	if err != nil || out != "hello" {
		t.Fatalf("got %q, %v; want hello", out, err)
	}
}

func TestWindowsLaunchStreamsPayload(t *testing.T) {
	out, err := runWindowsLaunchHelper(t, "parent-stdin")
	if err != nil || len(out) != windowsTestPayloadSize || strings.Trim(out, "x") != "" {
		t.Fatalf("got %d bytes, %v; want %d x bytes", len(out), err, windowsTestPayloadSize)
	}
}

func TestWindowsLaunchDoesNotHangWhenPayloadIsIgnored(t *testing.T) {
	if _, err := runWindowsLaunchHelper(t, "parent-ignored"); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsLaunchPropagatesExitCode(t *testing.T) {
	_, err := runWindowsLaunchHelper(t, "parent-exit")
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 7 {
		t.Fatalf("got %v, want exit code 7", err)
	}
}

func TestWindowsEnvironmentNamesAreCaseInsensitive(t *testing.T) {
	for _, name := range []string{"PATH", "Path", "path", "SystemRoot", "systemroot"} {
		if !inBaseline(name) {
			t.Errorf("inBaseline(%q) = false", name)
		}
	}
	if envNameKey("Node_Options") != envNameKey("NODE_OPTIONS") {
		t.Error("envNameKey does not fold Windows environment names")
	}
	vars := []ds.Var{{Name: "TOKEN"}, {Name: "token"}}
	if err := checkRunCollisions("env", vars); err == nil || !strings.Contains(err.Error(), "same child environment variable") {
		t.Errorf("env collision: got %v, want a case-insensitive Windows collision", err)
	}
	for _, mode := range []string{"stdin", "sh"} {
		if err := checkRunCollisions(mode, vars); err != nil {
			t.Errorf("%s collision: got %v, want case-distinct protocol names accepted", mode, err)
		}
	}
}
