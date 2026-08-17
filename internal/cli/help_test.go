package cli

import (
	"strings"
	"testing"
)

func TestFlagUsagesAlignment(t *testing.T) {
	flags := []Flag{
		{Short: "d", Long: "data", Arg: "BODY", Desc: "the request body"},
		{Long: "vault", Desc: "route to the vault"},
	}
	out := FlagUsages(flags)
	if !strings.Contains(out, "  -d, --data BODY") {
		t.Errorf("shorthand flag not rendered:\n%s", out)
	}
	if !strings.Contains(out, "      --vault") {
		t.Errorf("long-only flag not aligned under the shorthand column:\n%s", out)
	}
	// Descriptions align to a common column across both lines.
	col := func(line, desc string) int { return strings.Index(line, desc) }
	lines := strings.Split(out, "\n")
	if a, b := col(lines[0], "the request body"), col(lines[1], "route to the vault"); a != b || a < 0 {
		t.Errorf("descriptions not column-aligned (%d vs %d):\n%s", a, b, out)
	}
}

func TestCredentialsNamesEnvVars(t *testing.T) {
	c := Credentials()
	for _, want := range []string{"DELINEA_TOOLS_PASSWORD", "DELINEA_TOOLS_CLIENT_SECRET", "DELINEA_TOOLS_TOKEN", "never a flag"} {
		if !strings.Contains(c, want) {
			t.Errorf("Credentials missing %q", want)
		}
	}
}

func TestGlobalFlagsMarkURLRequiredAndHideSecrets(t *testing.T) {
	out := FlagUsages(GlobalFlags())
	if !strings.Contains(out, "(required)") {
		t.Error("GlobalFlags does not mark the required URL")
	}
	for _, secret := range []string{"--password", "--client-secret", "--token "} {
		if strings.Contains(out, secret) {
			t.Errorf("GlobalFlags exposes a credential as a flag: %s", secret)
		}
	}
}

func TestCommandHelpStructure(t *testing.T) {
	h := CommandHelp("thing", "Long desc.", []string{"delinea-util thing [flags]"},
		[]Flag{{Long: "opt", Desc: "an option"}}, GlobalFlags(), Credentials())
	for _, want := range []string{
		"Long desc.", "Usage:\n  delinea-util thing", "\nFlags:\n", "help for thing",
		"\nGlobal Flags:\n", "DELINEA_TOOLS_PASSWORD",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("CommandHelp missing %q", want)
		}
	}
}

func TestRootHelpStructure(t *testing.T) {
	h := RootHelp("delinea-util", "desc", []string{"delinea-util [command]"},
		[]CommandLine{{Name: "a", Short: "does a"}}, []CommandLine{{Name: "t", Short: "topic"}},
		[]Flag{{Long: "version", Desc: "v"}}, GlobalFlags(), "")
	for _, want := range []string{
		"Available Commands:", "  a ", "Additional help topics:", "  t ",
		"\nFlags:\n", "help for delinea-util", `Use "delinea-util COMMAND --help"`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("RootHelp missing %q", want)
		}
	}
}
