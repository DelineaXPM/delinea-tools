package cli

import (
	"fmt"
	"strings"
)

// Flag describes one flag for Cobra-style help rendering. Short is the single
// letter without its dash ("d"), Long the long name without dashes ("data"),
// Arg the value placeholder shown after the name ("string", "FILE") or "" for a
// boolean flag.
type Flag struct {
	Short, Long, Arg, Desc string
}

// CommandLine is one row of an "Available Commands" or "Additional help topics"
// listing: the name and its one-line summary.
type CommandLine struct {
	Name, Short string
}

// helpFlagFor is the -h/--help entry Cobra appends to every command's flags,
// described by the command's leaf name ("help for token" for "delinea-util token").
func helpFlagFor(path string) Flag {
	fields := strings.Fields(path)
	leaf := path
	if len(fields) > 0 {
		leaf = fields[len(fields)-1]
	}
	return Flag{Short: "h", Long: "help", Desc: "help for " + leaf}
}

// GlobalFlags is the connection-flag set shown as "Global Flags" on every help
// screen -- the DELINEA_TOOLS_* settings both faces of the tool share. It is
// defined once so the raw verbs and the secrets group cannot list different
// globals. The credential itself is never a flag: it comes from the
// DELINEA_TOOLS_PASSWORD/_CLIENT_SECRET/_TOKEN environment or --secret-stdin.
func GlobalFlags() []Flag {
	return []Flag{
		{Long: "url", Arg: "URL", Desc: "(required) target base URL ($DELINEA_TOOLS_URL)"},
		{Long: "target", Arg: "KIND", Desc: "ss or platform; inferred from the credential if unset ($DELINEA_TOOLS_TARGET)"},
		{Long: "username", Arg: "NAME", Desc: "Secret Server username ($DELINEA_TOOLS_USERNAME)"},
		{Long: "domain", Arg: "NAME", Desc: "Secret Server Active Directory domain ($DELINEA_TOOLS_DOMAIN)"},
		{Long: "client-id", Arg: "ID", Desc: "Platform OAuth client id ($DELINEA_TOOLS_CLIENT_ID)"},
		{Long: "ca-cert", Arg: "FILE", Desc: "PEM bundle of extra CAs to trust ($DELINEA_TOOLS_CA_CERT)"},
		{Long: "timeout", Arg: "DUR", Desc: "per-request timeout, e.g. 30s ($DELINEA_TOOLS_TIMEOUT)"},
		{Long: "retries", Arg: "N", Desc: "retry attempts for transient failures ($DELINEA_TOOLS_RETRIES)"},
		{Long: "tls-skip-verify", Desc: "disable TLS certificate verification ($DELINEA_TOOLS_TLS_SKIP_VERIFY)"},
		{Long: "vault-allow", Arg: "HOST", Desc: "additional allowed vault host or exact host:port, repeatable ($DELINEA_TOOLS_VAULT_ALLOW)"},
		{Long: "secret-stdin", Desc: "read the credential secret from stdin instead of the environment"},
	}
}

// Credentials renders the credential-source block. The secret is never a flag,
// so it cannot appear in a flag list; this block names the environment variables
// that supply it and which one each grant kind uses. Shown on every help screen
// whose command authenticates, so the required credential is never invisible.
func Credentials() string {
	names := []string{"DELINEA_TOOLS_PASSWORD", "DELINEA_TOOLS_CLIENT_SECRET", "DELINEA_TOOLS_TOKEN"}
	descs := []string{
		"Secret Server password (when a username is set)",
		"Platform OAuth client secret (when a client-id is set)",
		"a pre-obtained bearer token (otherwise)",
	}
	widest := 0
	for _, n := range names {
		if len(n) > widest {
			widest = len(n)
		}
	}
	var b strings.Builder
	b.WriteString("Credentials (never a flag; from the environment, or piped with --secret-stdin):\n")
	for i, n := range names {
		fmt.Fprintf(&b, "      %-*s   %s\n", widest, n, descs[i])
	}
	return strings.TrimRight(b.String(), "\n")
}

// helpWrap is the target line width for wrapped flag descriptions.
const helpWrap = 90

// FlagUsages renders flags in the pflag/Cobra two-column style: the shorthand
// and long name in an aligned left column, descriptions wrapped in the right.
func FlagUsages(flags []Flag) string {
	lefts := make([]string, len(flags))
	widest := 0
	for i, f := range flags {
		var b strings.Builder
		if f.Short != "" {
			fmt.Fprintf(&b, "  -%s, --%s", f.Short, f.Long)
		} else {
			fmt.Fprintf(&b, "      --%s", f.Long)
		}
		if f.Arg != "" {
			b.WriteString(" " + f.Arg)
		}
		lefts[i] = b.String()
		if len(lefts[i]) > widest {
			widest = len(lefts[i])
		}
	}
	col := widest + 3
	var b strings.Builder
	for i, f := range flags {
		lines := wrapText(f.Desc, helpWrap-col)
		fmt.Fprintf(&b, "%-*s%s\n", col, lefts[i], lines[0])
		for _, cont := range lines[1:] {
			fmt.Fprintf(&b, "%s%s\n", strings.Repeat(" ", col), cont)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// wrapText breaks s into word-wrapped lines no wider than width (always at
// least one line, even for an empty string).
func wrapText(s string, width int) []string {
	if width < 20 {
		width = 20
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > width {
			lines = append(lines, cur)
			cur = w
		} else {
			cur += " " + w
		}
	}
	return append(lines, cur)
}

func commandLines(cmds []CommandLine) string {
	widest := 0
	for _, c := range cmds {
		if len(c.Name) > widest {
			widest = len(c.Name)
		}
	}
	var b strings.Builder
	for _, c := range cmds {
		fmt.Fprintf(&b, "  %-*s   %s\n", widest, c.Name, c.Short)
	}
	return b.String()
}

// RootHelp renders the top-level Cobra-style help: description, usage lines,
// available commands, any additional help topics, the root's own flags, and the
// shared global flags, closed by the standard footer.
func RootHelp(path, desc string, usage []string, commands, topics []CommandLine, rootFlags, global []Flag, extra string) string {
	var b strings.Builder
	b.WriteString(strings.TrimRight(desc, "\n") + "\n\n")
	b.WriteString("Usage:\n")
	for _, u := range usage {
		b.WriteString("  " + u + "\n")
	}
	if len(commands) > 0 {
		b.WriteString("\nAvailable Commands:\n" + commandLines(commands))
	}
	if len(topics) > 0 {
		b.WriteString("\nAdditional help topics:\n" + commandLines(topics))
	}
	b.WriteString("\nFlags:\n" + FlagUsages(append(rootFlags, helpFlagFor(path))) + "\n")
	if len(global) > 0 {
		b.WriteString("\nGlobal Flags:\n" + FlagUsages(global) + "\n")
	}
	if extra != "" {
		b.WriteString("\n" + strings.TrimRight(extra, "\n") + "\n")
	}
	fmt.Fprintf(&b, "\nUse \"%s COMMAND --help\" for more information about a command.\n", path)
	return b.String()
}

// CommandHelp renders one command's Cobra-style help: its long description,
// usage lines, local flags (with -h/--help appended, as Cobra does), and the
// shared global flags.
func CommandHelp(name, long string, usage []string, flags, global []Flag, extra string) string {
	var b strings.Builder
	if long != "" {
		b.WriteString(strings.TrimRight(long, "\n") + "\n\n")
	}
	b.WriteString("Usage:\n")
	for _, u := range usage {
		b.WriteString("  " + u + "\n")
	}
	b.WriteString("\nFlags:\n" + FlagUsages(append(flags, helpFlagFor(name))) + "\n")
	if len(global) > 0 {
		b.WriteString("\nGlobal Flags:\n" + FlagUsages(global) + "\n")
	}
	if extra != "" {
		b.WriteString("\n" + strings.TrimRight(extra, "\n") + "\n")
	}
	return b.String()
}
