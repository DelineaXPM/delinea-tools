package secretscmd

import (
	"os"
	"strings"

	"github.com/DelineaXPM/delinea-tools/internal/cli"
)

// wantsHelp reports whether args ask for help rather than work. It is checked
// before any parsing so that -h never reaches the mapping parser, which would
// otherwise reject it as an invalid mapping.
func wantsHelp(args []string) bool {
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			return true
		case "--":
			return false
		}
	}
	return false
}

// subLong is the description shown above the Usage block for each secrets
// subcommand. Flags are rendered separately (Cobra-style), so they are not
// repeated here; the "Requires:" line names what must be set to run it.
var subLong = map[string]string{
	"run": `Fetch the secrets, then run command with them injected.

The child does not inherit this process's environment: it gets a small baseline
(PATH, HOME, TMPDIR, locale), the resolved secrets, and any variable named with
--pass-env. Proxy, TLS-trust and agent variables are not in the baseline; pass
them explicitly if the child needs them. On Unix the CLI exec-replaces itself
with the child; on Windows (and for a large --via stdin payload) it supervises
the child and propagates its exit status.

Requires: DELINEA_TOOLS_URL and one credential.`,

	"print": `Fetch the secrets and write them to stdout, or to --out FILE.

Refuses to write to a terminal unless --allow-terminal is given, since the values
would land in your scrollback; redirect or pipe the output instead. To feed a
program, prefer run, which never writes secrets to a visible sink.

Requires: DELINEA_TOOLS_URL and one credential.`,

	"template": `Render a Go text/template file with the secret values.

Each mapping's variable is available as {{.NAME}}. A key the template references
but no mapping defines is an error, not an empty string.

Requires: DELINEA_TOOLS_URL and one credential.`,
}

// subUsage and subFlags are the usage line and local flags for each subcommand.
var subUsage = map[string]string{
	"run":      "delinea-util secrets run [flags] MAPPING... -- command [args...]",
	"print":    "delinea-util secrets print [flags] MAPPING...",
	"template": "delinea-util secrets template --in FILE [flags] MAPPING...",
}

var subFlags = map[string][]cli.Flag{
	"run": {
		{Long: "via", Arg: "MODE", Desc: "how the secrets reach the child: env (default), stdin (NUL-delimited NAME=value), or sh (export lines)"},
		{Long: "pass-env", Arg: "NAME", Desc: "also pass this variable from the environment to the child; repeatable (a name, not NAME=VALUE)"},
	},
	"print": {
		{Long: "via", Arg: "MODE", Desc: "output format: stdin (default), sh, json, raw (one unnamed value), or github-env"},
		{Long: "out", Arg: "FILE", Desc: "write to FILE at mode 0600 instead of stdout (github-env appends; other modes replace on success)"},
		{Long: "allow-terminal", Desc: "permit writing secrets to a terminal (refused by default)"},
	},
	"template": {
		{Long: "in", Arg: "FILE", Desc: "(required) the Go text/template to render"},
		{Long: "out", Arg: "FILE", Desc: "write to FILE at mode 0600 instead of stdout, only on success"},
		{Long: "allow-terminal", Desc: "permit writing secrets to a terminal (refused by default)"},
	},
}

// mappingExtra is the shared trailing section for commands that take MAPPINGs:
// the credential sources and the mapping forms, so neither is ever invisible.
func mappingExtra(readme string) string {
	return cli.Credentials() + "\n\nMAPPING is one of:\n" + readmeMappingBlock(readme)
}

// subHelpText renders one secrets subcommand's Cobra-style help.
func subHelpText(name, readme string) string {
	return cli.CommandHelp(name, subLong[name], []string{subUsage[name]}, subFlags[name], cli.GlobalFlags(), mappingExtra(readme))
}

// printCommandHelp writes one secrets subcommand's Cobra-style help.
func printCommandHelp(name, readme string) {
	cli.PrintDoc(os.Stdout, subHelpText(name, readme))
}

// groupHelp renders the "delinea-util secrets" group page: its subcommands, the
// global flags, and the shared credential sources.
func groupHelp(readme string) string {
	desc := "Fetch secrets from Delinea Secret Server or the Delinea Platform and hand them\n" +
		"to a process, a file, or stdout."
	usage := []string{"delinea-util secrets COMMAND [flags]"}
	commands := []cli.CommandLine{
		{Name: "print", Short: "fetch secrets and write them to stdout or a file"},
		{Name: "run", Short: "fetch secrets and run a command with them injected"},
		{Name: "template", Short: "render a template file with the secret values"},
	}
	extra := cli.Credentials() + "\n\n" +
		"Requires: DELINEA_TOOLS_URL and one credential. Each subcommand takes MAPPINGs\n" +
		"(NAME=field#id or NAME=field@\\folder\\path); see a subcommand's --help."
	return cli.RootHelp("delinea-util secrets", desc, usage, commands, nil, nil, cli.GlobalFlags(), extra)
}

// checkHelp renders the top-level check verb's Cobra-style help.
func checkHelp(readme string) string {
	long := "Diagnose delinea-util itself: the connection settings, whether the URL is\n" +
		"reachable and which service answers there, and -- when a credential is\n" +
		"supplied -- whether it is valid for the target. It runs nothing, writes\n" +
		"nowhere, and never prints a secret value; it reports every problem it finds\n" +
		"and exits non-zero if any check failed.\n\n" +
		"Requires: DELINEA_TOOLS_URL. A credential is optional -- validated if present,\n" +
		"skipped with --no-auth. Optional MAPPINGs are additionally resolved, reporting\n" +
		"each variable and its value's length (never the value)."
	usage := []string{"delinea-util check [flags] [MAPPING...]"}
	flags := []cli.Flag{
		{Long: "json", Desc: "emit the findings as JSON, with a summary count per status"},
		{Long: "quiet", Desc: "report only warnings and failures; a clean run prints nothing"},
		{Long: "no-auth", Desc: "skip the credential entirely: configuration and reachability only"},
		{Long: "pass-env", Arg: "NAME", Desc: "include this variable when reporting the run child environment; repeatable"},
	}
	return cli.CommandHelp("check", long, usage, flags, cli.GlobalFlags(), mappingExtra(readme))
}

// readmeMappingBlock lifts the mapping forms from the unified README, so the
// per-command help cannot describe them differently from the document.
func readmeMappingBlock(readme string) string {
	var block []string
	for l := range strings.SplitSeq(readme, "\n") {
		switch {
		case strings.HasPrefix(l, "  NAME=") || strings.HasPrefix(l, "  PREFIX_"):
			block = append(block, l)
		case len(block) > 0:
			return strings.Join(block, "\n")
		}
	}
	return strings.Join(block, "\n")
}
