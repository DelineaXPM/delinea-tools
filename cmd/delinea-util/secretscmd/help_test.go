package secretscmd

import (
	"strings"
	"testing"
)

func TestWantsHelp(t *testing.T) {
	for _, args := range [][]string{
		{"-h"}, {"--help"}, {"help"},
		{"DB=password#1", "-h"},
		{"--via", "stdin", "--help"},
	} {
		if !wantsHelp(args) {
			t.Errorf("%v: got false, want true", args)
		}
	}
	// After --, the flag belongs to the child command, not to us.
	for _, args := range [][]string{
		{"DB=password#1", "--", "app", "-h"},
		{"DB=password#1", "--", "app", "--help"},
		{"DB=password#1", "--", "help"},
		{"DB=password#1"},
		{},
	} {
		if wantsHelp(args) {
			t.Errorf("%v: got true, want false", args)
		}
	}
}

// Every subcommand must answer -h with its own Cobra-style help: a Usage line,
// its Flags, and the shared Global Flags and Credentials.
func TestEachCommandHasHelp(t *testing.T) {
	rm := unifiedREADME(t)
	for _, name := range []string{"run", "print", "template"} {
		h := subHelpText(name, rm)
		for _, want := range []string{
			"Usage:\n  delinea-util secrets " + name,
			"\nFlags:\n",
			"\nGlobal Flags:\n",
			"Credentials (never a flag",
		} {
			if !strings.Contains(h, want) {
				t.Errorf("%s help missing %q", name, want)
			}
		}
	}
	// check's help is surfaced by CheckUsage, in the same format.
	if h := CheckUsage(rm); !strings.Contains(h, "Usage:\n  delinea-util check") || !strings.Contains(h, "\nFlags:\n") {
		t.Errorf("check help is not the Cobra-style page:\n%s", h)
	}
}

func TestCommandHelpNamesItsOwnFlags(t *testing.T) {
	rm := unifiedREADME(t)
	help := map[string]string{
		"run":      subHelpText("run", rm),
		"print":    subHelpText("print", rm),
		"template": subHelpText("template", rm),
		"check":    CheckUsage(rm),
	}
	for name, want := range map[string][]string{
		"run":      {"--via", "--pass-env"},
		"print":    {"--out", "--allow-terminal", "--via"},
		"template": {"--in", "--out"},
		"check":    {"--json", "--quiet", "--no-auth", "--pass-env"},
	} {
		for _, flag := range want {
			if !strings.Contains(help[name], flag) {
				t.Errorf("%s help does not mention %s", name, flag)
			}
		}
	}
	if !strings.Contains(help["print"], "github-env, github-output") {
		t.Error("print help does not distinguish GitHub environment and output modes")
	}
	// run has no --out and template has no --via; the Flags section must not
	// imply otherwise. (Global Flags mention neither, so a plain Contains is safe.)
	if strings.Contains(help["run"], "--out") {
		t.Errorf("run help mentions --out, which run does not accept")
	}
	if strings.Contains(help["template"], "--via") {
		t.Errorf("template help mentions --via, which template does not accept")
	}
	// The required URL and the credential sources appear on every command.
	for name, h := range help {
		if !strings.Contains(h, "(required) target base URL") {
			t.Errorf("%s help does not mark DELINEA_TOOLS_URL required", name)
		}
		if !strings.Contains(h, "DELINEA_TOOLS_PASSWORD") {
			t.Errorf("%s help does not name the credential env vars", name)
		}
	}
}

// The mapping forms come from the README so per-command help cannot describe them
// differently from the document.
func TestReadmeMappingBlock(t *testing.T) {
	block := readmeMappingBlock(unifiedREADME(t))
	for _, want := range []string{"NAME=field#id", "NAME=field@path", "PREFIX_*=#id", "PREFIX_*=@path"} {
		if !strings.Contains(block, want) {
			t.Errorf("mapping block missing %q", want)
		}
	}
	if strings.Contains(block, "delinea-util secrets") {
		t.Errorf("mapping block ran past the mapping forms:\n%s", block)
	}
}

func TestHelpDispatchDoesNotError(t *testing.T) {
	rm := unifiedREADME(t)
	for _, cmd := range []string{"run", "print", "template"} {
		if err := Dispatch([]string{cmd, "-h"}, rm); err != nil {
			t.Errorf("%s -h: got %v, want nil", cmd, err)
		}
	}
	// check is the top-level verb; its help goes through Check.
	if err := Check([]string{"-h"}, rm); err != nil {
		t.Errorf("check -h: got %v, want nil", err)
	}
}
