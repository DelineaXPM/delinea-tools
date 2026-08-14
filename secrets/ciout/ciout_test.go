package ciout

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/DelineaXPM/delinea-tools/secrets"
)

func v(name, value string) secrets.Var { return secrets.Var{Name: name, Value: value} }

func TestShellQuotesHostileValues(t *testing.T) {
	out, err := Shell([]secrets.Var{
		v("SIMPLE", "plain"),
		v("QUOTED", `it's got 'quotes' and $VAR and `+"`cmd` and \\ and\nnewline"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "export SIMPLE='plain'\n") {
		t.Errorf("simple value: %q", out)
	}
	if runtime.GOOS == "windows" {
		return
	}
	// The real arbiter: a POSIX shell must reproduce the exact value.
	script := out + `printf '%s' "$QUOTED"`
	got, err := exec.Command("/bin/sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := "it's got 'quotes' and $VAR and `cmd` and \\ and\nnewline"
	if string(got) != want {
		t.Errorf("shell round-trip: got %q, want %q", got, want)
	}
}

func TestShellRefusesNUL(t *testing.T) {
	if _, err := Shell([]secrets.Var{v("X", "a\x00b")}); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Errorf("got %v, want a NUL refusal", err)
	}
}

func TestGitHubEnvHeredoc(t *testing.T) {
	out, err := GitHubEnv([]secrets.Var{v("ONE", "line"), v("MULTI", "a\nb")})
	if err != nil {
		t.Fatal(err)
	}
	want := "ONE<<DELINEA_EOF\nline\nDELINEA_EOF\nMULTI<<DELINEA_EOF\na\nb\nDELINEA_EOF\n"
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestGitHubEnvDelimiterCollision(t *testing.T) {
	out, err := GitHubEnv([]secrets.Var{v("X", "a\nDELINEA_EOF\nb")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "X<<DELINEA_EOF_0\n") || strings.Contains(out, "X<<DELINEA_EOF\n") {
		t.Errorf("delimiter must move off a colliding value: %q", out)
	}
	nested, err := GitHubEnv([]secrets.Var{v("X", "DELINEA_EOF\nDELINEA_EOF_0")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nested, "X<<DELINEA_EOF_1\n") {
		t.Errorf("delimiter search must skip every colliding line: %q", nested)
	}
}

// A value crafted to contain DELINEA_EOF and every DELINEA_EOF_i in sequence —
// the shape that once made delimiter selection quadratic (O(value^2)) — still
// resolves correctly: the search lands on the first delimiter absent from the
// value, in linear time.
func TestGitHubEnvDelimiterSearchHandlesManyCollisions(t *testing.T) {
	const n = 1000
	var sb strings.Builder
	sb.WriteString("DELINEA_EOF")
	for i := range n {
		fmt.Fprintf(&sb, "\nDELINEA_EOF_%d", i)
	}
	out, err := GitHubEnv([]secrets.Var{v("X", sb.String())})
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("X<<DELINEA_EOF_%d\n", n); !strings.Contains(out, want) {
		t.Errorf("delimiter must land past every collision; want %q", want)
	}
}

func TestGitHubEnvRefusals(t *testing.T) {
	if _, err := GitHubEnv([]secrets.Var{v("X", string([]byte{0xff}))}); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("got %v, want an invalid UTF-8 refusal", err)
	}
	if _, err := GitHubEnv([]secrets.Var{v("X", "a\x00b")}); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Errorf("got %v, want a NUL refusal", err)
	}
	if _, err := GitHubEnv([]secrets.Var{v("X", "a\r\nb")}); err == nil || !strings.Contains(err.Error(), "carriage return") {
		t.Errorf("got %v, want a carriage-return refusal", err)
	}
}

func TestGitHubMask(t *testing.T) {
	// A bare CR is a line break, not payload: "100%\rinside" is two content
	// lines, both masked, and a trailing "last\r" masks "last" — so a later
	// step that normalizes CR away cannot leave any content line unmasked.
	out, err := GitHubMask([]secrets.Var{v("X", "top\nsecret with 100%\rinside\n\nlast\r")})
	if err != nil {
		t.Fatal(err)
	}
	want := "::add-mask::top\n::add-mask::secret with 100%25\n::add-mask::inside\n::add-mask::last\n"
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestGitHubMaskRefusesInvalidUTF8(t *testing.T) {
	if _, err := GitHubMask([]secrets.Var{v("X", string([]byte{0xff}))}); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("got %v, want an invalid UTF-8 refusal", err)
	}
}

func TestAllFormattersShareNameRules(t *testing.T) {
	formatters := map[string]func([]secrets.Var) (string, error){
		"Shell": Shell, "GitHubEnv": GitHubEnv, "GitHubMask": GitHubMask,
	}
	for name, f := range formatters {
		if _, err := f([]secrets.Var{v("1BAD", "x")}); err == nil || !strings.Contains(err.Error(), "not a valid variable name") {
			t.Errorf("%s: got %v, want the shared name rule", name, err)
		}
		if _, err := f([]secrets.Var{v("DUP", "x"), v("DUP", "y")}); err == nil || !strings.Contains(err.Error(), "two variables named") {
			t.Errorf("%s: got %v, want the duplicate refusal", name, err)
		}
	}
}

// A secret ending in a bare carriage return (no LF) must still be masked as
// its clean content, so a downstream step that drops the CR cannot leak it.
func TestGitHubMaskBareTrailingCR(t *testing.T) {
	out, err := GitHubMask([]secrets.Var{v("PW", "s3cr3t\r")})
	if err != nil {
		t.Fatal(err)
	}
	if out != "::add-mask::s3cr3t\n" {
		t.Errorf("got %q, want the CR-stripped content masked", out)
	}
}
