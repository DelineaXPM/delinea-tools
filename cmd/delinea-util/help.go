package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/DelineaXPM/delinea-tools/cmd/delinea-util/secretscmd"
	"github.com/DelineaXPM/delinea-tools/internal/cli"
)

// topLevelHelp renders the Cobra-style top-level page: only the commands and the
// flags that work at the top level (the meta flags and the shared connection
// "Global Flags"). Command-specific flags live on each command's own help.
func topLevelHelp() string {
	desc := "delinea-util makes one authenticated REST call against Delinea Secret Server or\n" +
		"the Delinea Platform, curl-style, with token, check, and secrets subcommands."
	usage := []string{
		"delinea-util METHOD PATH [flags]",
		"delinea-util COMMAND [flags]",
	}
	commands := []cli.CommandLine{
		{Name: "check", Short: "diagnose configuration, reachability, and the credential"},
		{Name: "secrets", Short: "fetch secrets to a process, a file, or stdout (run|print|template)"},
		{Name: "token", Short: "authenticate and print the bearer token (--interactive: MFA login)"},
	}
	topics := []cli.CommandLine{
		{Name: "request", Short: "the raw METHOD PATH request form and its flags"},
	}
	rootFlags := []cli.Flag{
		{Long: "readme", Desc: "print the full reference manual"},
		{Long: "tree", Desc: "print the command tree"},
		{Long: "version", Desc: "print version and build information"},
	}
	extra := cli.Credentials() + "\n\n" +
		"DELINEA_TOOLS_URL is required for network commands. Requests and secret delivery\n" +
		"also require one credential; check may run in reachability-only mode without one.\n" +
		"check --no-auth additionally ignores any ambient Delinea credential."
	return cli.RootHelp("delinea-util", desc, usage, commands, topics, rootFlags, cli.GlobalFlags(), extra)
}

// requestHelp renders the help for the raw METHOD PATH form.
func requestHelp() string {
	long := "Make one authenticated REST request and stream the response body to stdout.\n\n" +
		"METHOD is GET, POST, PUT, PATCH, DELETE, HEAD, or OPTIONS (any case). PATH is an\n" +
		"absolute path on the target and may carry a query string.\n\n" +
		"Requires: DELINEA_TOOLS_URL and one credential (see below)."
	usage := []string{"delinea-util METHOD PATH [flags]"}
	flags := []cli.Flag{
		{Short: "d", Long: "data", Arg: "BODY", Desc: "request body; @FILE reads a file, @- reads stdin; JSON Content-Type unless -H overrides"},
		{Short: "H", Long: "header", Arg: "LINE", Desc: "extra request header 'Name: value'; @FILE reads one per line for secret values; repeatable (not Authorization)"},
		{Long: "vault", Desc: "platform: route PATH to the default vault via the vault broker"},
		{Long: "vault-id", Arg: "ID", Desc: "with --vault, target a specific vault by its non-empty vaultId"},
		{Short: "i", Long: "include", Desc: "include the status line and headers on stdout"},
		{Short: "v", Long: "verbose", Desc: "request line and response status/headers on stderr"},
	}
	return cli.CommandHelp("request", long, usage, flags, cli.GlobalFlags(), cli.Credentials())
}

// tokenHelp renders the help for the token command.
func tokenHelp() string {
	long := "Authenticate and print the bearer token to stdout, for reuse via\n" +
		"  DELINEA_TOOLS_TOKEN=$(delinea-util token)\n\n" +
		"Refuses to print to a terminal unless --allow-terminal is passed; command\n" +
		"substitution and pipes are always fine.\n\n" +
		"Requires: DELINEA_TOOLS_URL and one credential for automatic authentication.\n" +
		"--interactive requires a username (--username or DELINEA_TOOLS_USERNAME) and\n" +
		"DELINEA_TOOLS_PASSWORD from the environment; stdin carries MFA answers. It\n" +
		"targets Platform when --target is omitted and rejects --target ss."
	usage := []string{"delinea-util token [flags]"}
	flags := []cli.Flag{
		{Long: "interactive", Desc: "obtain the token by interactive Platform Identity API login (password + MFA challenges) for MFA-gated accounts, instead of the automatic grant; omitted --target means platform, --target ss is rejected; not with --secret-stdin"},
		{Long: "allow-terminal", Desc: "allow printing the token to a terminal (refused by default)"},
	}
	return cli.CommandHelp("token", long, usage, flags, tokenGlobalFlags(), cli.Credentials())
}

func tokenGlobalFlags() []cli.Flag {
	all := cli.GlobalFlags()
	flags := make([]cli.Flag, 0, len(all)-1)
	for _, flag := range all {
		if flag.Long != "vault-allow" {
			flags = append(flags, flag)
		}
	}
	return flags
}

// usageFor returns the command name and help text to show alongside a usage
// error, matched to whatever command the arguments named.
func usageFor(args []string) (string, string) {
	cmdIndex, cmd, _ := topLevelCommand(args)
	switch {
	case cmd == "token":
		return "delinea-util token", tokenHelp()
	case cmd == "secrets":
		if cmdIndex+1 < len(args) {
			if usage, ok := secretscmd.CommandUsageText(args[cmdIndex+1], readmeText); ok {
				return "delinea-util secrets " + args[cmdIndex+1], usage
			}
		}
		return "delinea-util secrets", secretscmd.UsageText(readmeText)
	case cmd == "check":
		return "delinea-util check", secretscmd.CheckUsage(readmeText)
	case cmd != "" && httpMethods[strings.ToUpper(cmd)]:
		return "delinea-util " + strings.ToUpper(cmd), requestHelp()
	}
	return "delinea-util", topLevelHelp()
}

// helpTopic serves "delinea-util help [COMMAND]". With no argument it prints the
// top-level page; otherwise it prints that command's or topic's help.
func helpTopic(rest []string) error {
	if len(rest) == 0 {
		cli.PrintDoc(os.Stdout, topLevelHelp())
		return nil
	}
	return printCommandHelp(rest[0])
}

// printCommandHelp writes one command's help, resolving request/token here and
// delegating check and the secrets group to secretscmd. An unrecognized name is
// a usage error so "help frobnicate" is not silently the top-level page.
func printCommandHelp(name string) error {
	switch {
	case name == "request" || httpMethods[strings.ToUpper(name)]:
		cli.PrintDoc(os.Stdout, requestHelp())
	case name == "token":
		cli.PrintDoc(os.Stdout, tokenHelp())
	case name == "check":
		cli.PrintDoc(os.Stdout, secretscmd.CheckUsage(readmeText))
	case name == "secrets":
		cli.PrintDoc(os.Stdout, secretscmd.UsageText(readmeText))
	default:
		return &cli.UsageError{Msg: fmt.Sprintf("unknown command %q", name)}
	}
	return nil
}
