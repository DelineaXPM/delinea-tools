//go:build e2e

package secretscmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DelineaXPM/delinea-tools/internal/e2etest"
)

// binPath is the freshly-built CLI, compiled once in TestMain. These tests are
// excluded from the default build and run only with `go test -tags e2e ./...`.
// They skip when fixtures are absent and never print secret values.
var binPath string

func TestMain(m *testing.M) {
	os.Exit(func() int {
		dir, err := os.MkdirTemp("", "ds-e2e")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer os.RemoveAll(dir)
		binPath = filepath.Join(dir, "delinea-util")
		if runtime.GOOS == "windows" {
			binPath += ".exe"
		}
		// The secrets commands are now the "secrets" subcommand group of the
		// delinea-util binary, one directory up.
		build := exec.Command("go", "build", "-o", binPath, "..")
		build.Stderr = os.Stderr
		if err := build.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "building CLI:", err)
			return 1
		}
		return m.Run()
	}())
}

type liveFixture struct {
	url, target, identityName, identity, credential, id, path, field, value string
}

func requirePlatform(t *testing.T) liveFixture {
	t.Helper()
	e := e2etest.Require(t,
		"DELINEA_TOOLS_TEST_PLATFORM_URL", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_ID",
		"DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET", "DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID",
		"DELINEA_TOOLS_TEST_PLATFORM_SECRET_FIELD", "DELINEA_TOOLS_TEST_PLATFORM_SECRET_VALUE")
	return liveFixture{
		url: e["DELINEA_TOOLS_TEST_PLATFORM_URL"], target: "platform",
		identityName: "DELINEA_TOOLS_CLIENT_ID", identity: e["DELINEA_TOOLS_TEST_PLATFORM_CLIENT_ID"],
		credential: e["DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET"], id: e["DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID"],
		field: e["DELINEA_TOOLS_TEST_PLATFORM_SECRET_FIELD"], value: e["DELINEA_TOOLS_TEST_PLATFORM_SECRET_VALUE"],
	}
}

func requireSecretServer(t *testing.T) liveFixture {
	t.Helper()
	e := e2etest.Require(t,
		"DELINEA_TOOLS_TEST_SS_URL", "DELINEA_TOOLS_TEST_SS_USERNAME", "DELINEA_TOOLS_TEST_SS_PASSWORD",
		"DELINEA_TOOLS_TEST_SS_SECRET_ID", "DELINEA_TOOLS_TEST_SS_SECRET_FIELD", "DELINEA_TOOLS_TEST_SS_SECRET_VALUE")
	return liveFixture{
		url: e["DELINEA_TOOLS_TEST_SS_URL"], target: "ss",
		identityName: "DELINEA_TOOLS_USERNAME", identity: e["DELINEA_TOOLS_TEST_SS_USERNAME"],
		credential: e["DELINEA_TOOLS_TEST_SS_PASSWORD"], id: e["DELINEA_TOOLS_TEST_SS_SECRET_ID"],
		field: e["DELINEA_TOOLS_TEST_SS_SECRET_FIELD"], value: e["DELINEA_TOOLS_TEST_SS_SECRET_VALUE"],
	}
}

func (f liveFixture) env() []string {
	return []string{
		"DELINEA_TOOLS_URL=" + f.url,
		"DELINEA_TOOLS_TARGET=" + f.target,
		f.identityName + "=" + f.identity,
	}
}

// runCLI invokes the secrets subcommand group of the built delinea-util binary.
// Every fixture credential is piped, so select stdin explicitly just as a real
// secret-manager integration must.
func runCLI(t *testing.T, extraEnv []string, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(binPath, append([]string{"--secret-stdin", "secrets"}, args...)...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w; stderr: %s", err, errb.String())
	}
	return out.String(), nil
}

func TestE2ECLIPrintRaw(t *testing.T) {
	f := requirePlatform(t)
	out, err := runCLI(t, f.env(), f.credential, "print", "--via", "raw", "V="+f.field+"#"+f.id)
	if err != nil {
		t.Fatal(err)
	}
	if out != f.value {
		t.Errorf("print --via raw output != expected (got len %d, want len %d)", len(out), len(f.value))
	}
}

func TestE2ECLITemplate(t *testing.T) {
	f := requirePlatform(t)
	tmpl := filepath.Join(t.TempDir(), "t.tmpl")
	if err := os.WriteFile(tmpl, []byte("val={{.V}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCLI(t, f.env(), f.credential, "template", "--in", tmpl, "V="+f.field+"#"+f.id)
	if err != nil {
		t.Fatal(err)
	}
	if want := "val=" + f.value; out != want {
		t.Errorf("template output != expected (got len %d, want len %d)", len(out), len(want))
	}
}

func TestE2ECLIPrintOut(t *testing.T) {
	f := requirePlatform(t)
	out := filepath.Join(t.TempDir(), "secret.txt")
	if _, err := runCLI(t, f.env(), f.credential, "print", "--via", "raw", "--out", out, "X="+f.field+"#"+f.id); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != f.value {
		t.Errorf("content mismatch (got len %d, want %d)", len(b), len(f.value))
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode: got %o, want 600", fi.Mode().Perm())
		}
	}
}

func TestE2ECLIPrintOutNoClobber(t *testing.T) {
	f := requirePlatform(t)
	out := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(out, []byte("PRESERVE"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A bogus field fails after the secret is fetched; --out must not be touched.
	if _, err := runCLI(t, f.env(), f.credential, "print", "--via", "raw", "--out", out, "X=definitely-not-a-field#"+f.id); err == nil {
		t.Fatalf("expected error for bogus field")
	}
	b, _ := os.ReadFile(out)
	if string(b) != "PRESERVE" {
		t.Errorf("file was clobbered on failure: %q", b)
	}
}

func TestE2ECLITemplateOut(t *testing.T) {
	f := requirePlatform(t)
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "t.tmpl")
	if err := os.WriteFile(tmpl, []byte("val={{.V}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.conf")
	if _, err := runCLI(t, f.env(), f.credential, "template", "--in", tmpl, "--out", out, "V="+f.field+"#"+f.id); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if want := "val=" + f.value; string(b) != want {
		t.Errorf("content mismatch (got len %d, want %d)", len(b), len(want))
	}
}

// echoEnvChild returns an OS-appropriate child command that writes the named
// injected environment variable to stdout verbatim, with no added newline, so
// the run-injection tests can assert the exact value on both platforms.
// Windows has no sh; PowerShell reads the value from the environment, so a
// secret's bytes never pass through command-line quoting.
func echoEnvChild(name string) []string {
	if runtime.GOOS == "windows" {
		return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
			"[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);[Console]::Out.Write($env:" + name + ")"}
	}
	return []string{"sh", "-c", `printf %s "$` + name + `"`}
}

func TestE2ECLIRunInjectsEnv(t *testing.T) {
	f := requirePlatform(t)
	// run injects V into the child's env, then execs it; the child echoes V back.
	runArgs := append([]string{"run", "V=" + f.field + "#" + f.id, "--"}, echoEnvChild("V")...)
	out, err := runCLI(t, f.env(), f.credential, runArgs...)
	if err != nil {
		t.Fatal(err)
	}
	if out != f.value {
		t.Errorf("run env injection output != expected (got len %d, want len %d)", len(out), len(f.value))
	}
}

// The path fixture is separate: a backslash-delimited path reaches the CLI as one
// argv element here, with no shell to mangle it, which is exactly the surface
// where the previously documented colon form was wrong.
func TestE2ECLIPrintRawByPath(t *testing.T) {
	f := requirePlatform(t)
	f.path = e2etest.Require(t, "DELINEA_TOOLS_TEST_PLATFORM_SECRET_PATH")["DELINEA_TOOLS_TEST_PLATFORM_SECRET_PATH"]
	out, err := runCLI(t, f.env(), f.credential, "print", "--via", "raw", "V="+f.field+"@"+f.path)
	if err != nil {
		t.Fatal(err)
	}
	if out != f.value {
		t.Errorf("path lookup output != expected (got len %d, want len %d)", len(out), len(f.value))
	}
}

func TestE2ECLISecretServer(t *testing.T) {
	f := requireSecretServer(t)
	t.Run("print-raw", func(t *testing.T) {
		out, err := runCLI(t, f.env(), f.credential, "print", "--via", "raw", "V="+f.field+"#"+f.id)
		if err != nil {
			t.Fatal(err)
		}
		if out != f.value {
			t.Errorf("raw output != expected (got len %d, want len %d)", len(out), len(f.value))
		}
	})
	t.Run("path", func(t *testing.T) {
		path := e2etest.Require(t, "DELINEA_TOOLS_TEST_SS_SECRET_PATH")["DELINEA_TOOLS_TEST_SS_SECRET_PATH"]
		out, err := runCLI(t, f.env(), f.credential, "print", "--via", "raw", "V="+f.field+"@"+path)
		if err != nil {
			t.Fatal(err)
		}
		if out != f.value {
			t.Errorf("path output != expected (got len %d, want len %d)", len(out), len(f.value))
		}
	})
	t.Run("run", func(t *testing.T) {
		runArgs := append([]string{"run", "V=" + f.field + "#" + f.id, "--"}, echoEnvChild("V")...)
		out, err := runCLI(t, f.env(), f.credential, runArgs...)
		if err != nil {
			t.Fatal(err)
		}
		if out != f.value {
			t.Errorf("run output != expected (got len %d, want len %d)", len(out), len(f.value))
		}
	})
}
