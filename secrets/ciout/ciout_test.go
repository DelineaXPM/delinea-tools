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

func TestGitHubEnvReservedNames(t *testing.T) {
	for _, name := range []string{"GITHUB_WORKSPACE", "github_custom", "RUNNER_OS", "runner_custom", "NODE_OPTIONS", "node_options"} {
		if out, err := GitHubEnv([]secrets.Var{v(name, "x")}); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: got output %q, error %v; want a name-specific refusal", name, out, err)
		}
		if _, err := GitHubOutput([]secrets.Var{v(name, "x")}); err != nil {
			t.Errorf("GitHubOutput %s: got %v, want the output name accepted", name, err)
		}
	}
}

func TestGitHubEnvRejectsCaseInsensitiveDuplicates(t *testing.T) {
	out, err := GitHubEnv([]secrets.Var{v("TOKEN", "first"), v("token", "second")})
	if err == nil || !strings.Contains(err.Error(), "case-insensitive") {
		t.Fatalf("got output %q, error %v; want a case-insensitive duplicate refusal", out, err)
	}
	if out != "" {
		t.Errorf("validation failure returned partial output %q", out)
	}
}

func TestGitHubOutputHeredoc(t *testing.T) {
	out, err := GitHubOutput([]secrets.Var{v("RESULT", "a\nb")})
	if err != nil {
		t.Fatal(err)
	}
	want := "RESULT<<DELINEA_EOF\na\nb\nDELINEA_EOF\n"
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestGitHubOutputRejectsCaseInsensitiveDuplicates(t *testing.T) {
	out, err := GitHubOutput([]secrets.Var{v("TOKEN", "first"), v("token", "second")})
	if err == nil || !strings.Contains(err.Error(), "case-insensitive") {
		t.Fatalf("got output %q, error %v; want a case-insensitive duplicate refusal", out, err)
	}
	if out != "" {
		t.Errorf("validation failure returned partial output %q", out)
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

func TestAzurePipelines(t *testing.T) {
	out, err := AzurePipelines([]secrets.Var{
		v("DB_PASS", "s3cr3t%0D]still-data"),
		v("EMPTY", ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "##vso[task.setsecret]s3cr3t%AZP250D]still-data\n" +
		"##vso[task.setvariable variable=DB_PASS;issecret=true]s3cr3t%AZP250D]still-data\n" +
		"##vso[task.setvariable variable=EMPTY;issecret=true]\n"
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestAzurePipelinesEscaping(t *testing.T) {
	if got, want := azureEscapeData("%0D\r\n"), "%AZP250D%0D%0A"; got != want {
		t.Errorf("data escaping: got %q, want %q", got, want)
	}
	if got, want := azureEscapeProperty("A%;]\r\n"), "A%AZP25%3B%5D%0D%0A"; got != want {
		t.Errorf("property escaping: got %q, want %q", got, want)
	}
}

func TestAzurePipelinesRefusals(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"BAD_UTF8", string([]byte{0xff}), "UTF-8"},
		{"HAS_NUL", "a\x00b", "NUL"},
		{"HAS_LF", "a\nb", "multiline"},
		{"HAS_CR", "a\rb", "multiline"},
	}
	for _, tt := range tests {
		out, err := AzurePipelines([]secrets.Var{v("GOOD", "first"), v(tt.name, tt.value)})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want an error containing %q", tt.name, err, tt.want)
		}
		if out != "" {
			t.Errorf("%s: validation failure returned partial output %q", tt.name, out)
		}
	}
}

func TestAzurePipelinesReservedPrefixes(t *testing.T) {
	for _, name := range []string{"ENDPOINT_URL", "inputValue", "SECRET_VALUE", "Path", "SecureFileKey"} {
		if _, err := AzurePipelines([]secrets.Var{v(name, "x")}); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("%s: got %v, want a reserved-prefix refusal", name, err)
		}
	}
	for _, name := range []string{"DB_SECRET", "APP_PATH", "SECURE_FILE"} {
		if _, err := AzurePipelines([]secrets.Var{v(name, "x")}); err != nil {
			t.Errorf("%s: got %v, want the non-prefix name accepted", name, err)
		}
	}
}

func TestAzurePipelinesRejectsCaseInsensitiveDuplicates(t *testing.T) {
	out, err := AzurePipelines([]secrets.Var{v("TOKEN", "first"), v("token", "second")})
	if err == nil || !strings.Contains(err.Error(), "case-insensitive") {
		t.Fatalf("got output %q, error %v; want a case-insensitive duplicate refusal", out, err)
	}
	if out != "" {
		t.Errorf("validation failure returned partial output %q", out)
	}
}

func TestAllFormattersShareNameRules(t *testing.T) {
	formatters := map[string]func([]secrets.Var) (string, error){
		"Shell": Shell, "GitHubEnv": GitHubEnv, "GitHubOutput": GitHubOutput,
		"GitHubMask": GitHubMask, "AzurePipelines": AzurePipelines,
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

func FuzzAzurePipelines(f *testing.F) {
	for _, seed := range []string{"", "plain", "%0D", "] ; ##vso[task.setvariable variable=PATH]owned", "a\nb", "a\x00b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		out, err := AzurePipelines([]secrets.Var{v("VALUE", value)})
		if err != nil {
			if out != "" {
				t.Fatalf("error %v returned partial output %q", err, out)
			}
			return
		}
		if strings.ContainsRune(out, '\r') {
			t.Fatalf("output contains a raw carriage return: %q", out)
		}
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		wantLines := 2
		if value == "" {
			wantLines = 1
		}
		if len(lines) != wantLines {
			t.Fatalf("got %d command lines, want %d: %q", len(lines), wantLines, out)
		}
		for _, line := range lines {
			if !strings.HasPrefix(line, "##vso[task.set") {
				t.Fatalf("value fabricated a physical output line: %q", line)
			}
		}
		const variablePrefix = "##vso[task.setvariable variable=VALUE;issecret=true]"
		encoded := strings.TrimPrefix(lines[len(lines)-1], variablePrefix)
		if encoded == lines[len(lines)-1] {
			t.Fatalf("missing setvariable command: %q", out)
		}
		if got := azureUnescapeData(encoded); got != value {
			t.Fatalf("round trip: got %q, want %q", got, value)
		}
	})
}

func azureUnescapeData(s string) string {
	s = strings.ReplaceAll(s, "%0D", "\r")
	s = strings.ReplaceAll(s, "%0A", "\n")
	return strings.ReplaceAll(s, "%AZP25", "%")
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
