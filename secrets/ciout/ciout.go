// Package ciout formats resolved secrets for the sinks CI systems consume —
// shell export lines, GitHub Actions environment/output files and mask
// commands, and Azure Pipelines logging commands. Every CI integration
// hand-rolls this layer, and its quoting bugs are security bugs; this is the
// one tested copy.
//
// There is deliberately no GitLab dotenv formatter: a dotenv report is
// uploaded to the GitLab server and readable by pipeline users until it
// expires — GitLab's own documentation says not to put credentials in one.
// Fetch secrets in the consuming job instead (secrets run, or Shell into
// eval).
//
// Each formatter validates what its sink can carry intact and returns an
// error naming the first variable it cannot deliver — a value silently
// corrupted in transit (a stripped space, a mangled line) is worse than a
// loud failure. Duplicate variable names are refused everywhere.
//
// Every returned string contains secret values. Write it promptly to the
// sink it was formatted for and nowhere else — never a log. Emit GitHubMask
// output before writing values to any file GitHub echoes.
package ciout

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/DelineaXPM/delinea-tools/secrets"
)

// Shell renders export NAME='value' lines for a POSIX shell to eval or
// source. Single-quote escaping carries any byte except NUL, newlines
// included. Do not eval the result under set -x, which would echo the
// values.
func Shell(vars []secrets.Var) (string, error) {
	if err := checkNames(vars); err != nil {
		return "", err
	}
	var b strings.Builder
	for _, v := range vars {
		if strings.IndexByte(v.Value, 0) >= 0 {
			return "", fmt.Errorf("%s contains a NUL byte, which a shell variable cannot carry", v.Name)
		}
		b.WriteString("export " + v.Name + "='" + strings.ReplaceAll(v.Value, "'", `'\''`) + "'\n")
	}
	return b.String(), nil
}

// GitHubEnv renders the $GITHUB_ENV file format using a heredoc per variable,
// so multiline values carry intact. GitHub's GITHUB_* and RUNNER_* namespaces,
// and NODE_OPTIONS, are refused because the runner does not permit an
// environment command to override them. Use GitHubOutput for $GITHUB_OUTPUT,
// whose names do not have those environment-specific restrictions.
func GitHubEnv(vars []secrets.Var) (string, error) {
	if err := checkNames(vars); err != nil {
		return "", err
	}
	// Keep the formatter portable across runner operating systems. Windows
	// environment names are case-insensitive, and accepting TOKEN plus token on
	// another OS would make the same payload change meaning when moved there.
	if err := checkFoldedNames(vars, "GitHub Actions environment"); err != nil {
		return "", err
	}
	for _, v := range vars {
		upper := strings.ToUpper(v.Name)
		switch {
		case strings.HasPrefix(upper, "GITHUB_"), strings.HasPrefix(upper, "RUNNER_"):
			return "", fmt.Errorf("%s uses a GitHub-reserved environment-variable namespace", v.Name)
		case upper == "NODE_OPTIONS":
			return "", fmt.Errorf("%s cannot be set through GITHUB_ENV because GitHub blocks it for security", v.Name)
		}
	}
	return githubFile(vars)
}

// GitHubOutput renders the $GITHUB_OUTPUT file format. It shares GitHubEnv's
// wire encoding but deliberately does not apply environment-variable reserved
// names: output parameters are addressed through steps.<id>.outputs, not
// installed into the runner environment.
func GitHubOutput(vars []secrets.Var) (string, error) {
	if err := checkNames(vars); err != nil {
		return "", err
	}
	if err := checkFoldedNames(vars, "GitHub Actions output"); err != nil {
		return "", err
	}
	return githubFile(vars)
}

// githubFile renders the command-file encoding shared by GITHUB_ENV and
// GITHUB_OUTPUT. The delimiter is chosen deterministically to never collide
// with the value. Invalid UTF-8, NUL, and carriage returns are refused; the
// runner reads command files as UTF-8 Unix text.
func githubFile(vars []secrets.Var) (string, error) {
	var b strings.Builder
	for _, v := range vars {
		if !utf8.ValidString(v.Value) {
			return "", fmt.Errorf("%s is not valid UTF-8, which a GitHub command file cannot carry intact", v.Name)
		}
		if strings.IndexByte(v.Value, 0) >= 0 {
			return "", fmt.Errorf("%s contains a NUL byte, which a GitHub command file cannot carry", v.Name)
		}
		if strings.ContainsRune(v.Value, '\r') {
			return "", fmt.Errorf("%s contains a carriage return, which would corrupt the GitHub command file", v.Name)
		}
		// Choose a heredoc delimiter that is on no line of the value. Collect
		// the value's lines once — not once per candidate — so a value crafted
		// to contain each successive candidate cannot force a quadratic scan of
		// attacker-controlled bytes.
		valueLines := make(map[string]struct{})
		for line := range strings.Lines(v.Value) {
			valueLines[strings.TrimSuffix(line, "\n")] = struct{}{}
		}
		delim := "DELINEA_EOF"
		for i := 0; ; i++ {
			if _, clash := valueLines[delim]; !clash {
				break
			}
			delim = fmt.Sprintf("DELINEA_EOF_%d", i)
		}
		b.WriteString(v.Name + "<<" + delim + "\n" + v.Value + "\n" + delim + "\n")
	}
	return b.String(), nil
}

// GitHubMask renders ::add-mask:: workflow commands, one per line of each
// value, so GitHub's log masking covers multiline secrets (GitHub masks per
// line). A line is any maximal run between line breaks — split on both CR and
// LF, not LF alone — so a value ending in a bare carriage return, or using CR
// line endings, still has every content line registered as a mask rather than
// a "value\r" that a later CR-normalizing step would leave unmasked. Percent
// signs are encoded per the workflow-command data rules. Invalid UTF-8 and NUL
// are refused because the runner's text command stream cannot carry them
// intact. Print the result to the step's stdout before any value is written
// anywhere GitHub might echo.
func GitHubMask(vars []secrets.Var) (string, error) {
	if err := checkNames(vars); err != nil {
		return "", err
	}
	var b strings.Builder
	for _, v := range vars {
		if !utf8.ValidString(v.Value) {
			return "", fmt.Errorf("%s is not valid UTF-8, which a GitHub workflow command cannot carry intact", v.Name)
		}
		if strings.IndexByte(v.Value, 0) >= 0 {
			return "", fmt.Errorf("%s contains a NUL byte, which a workflow command cannot carry", v.Name)
		}
		for _, line := range strings.FieldsFunc(v.Value, isLineBreak) {
			b.WriteString("::add-mask::" + strings.ReplaceAll(line, "%", "%25") + "\n")
		}
	}
	return b.String(), nil
}

// AzurePipelines renders task.setsecret and secret task.setvariable logging
// commands. Each non-empty value is registered with the agent's masker before
// it is published as a variable. Azure Pipelines rejects multiline secret
// variables unless an explicitly unsafe agent setting is enabled, so this
// formatter refuses CR and LF rather than emitting a command that fails or
// weakens the agent's masking guarantees. Values must also be valid UTF-8
// without NUL because logging commands travel over the agent's UTF-8 text stream.
// Variable names beginning with Azure's reserved endpoint, input, secret, path,
// or securefile prefixes are refused case-insensitively. Names also compare
// case-insensitively for duplicate detection, matching the agent's variable map.
func AzurePipelines(vars []secrets.Var) (string, error) {
	if err := checkNames(vars); err != nil {
		return "", err
	}
	if err := checkFoldedNames(vars, "Azure Pipelines"); err != nil {
		return "", err
	}
	for _, v := range vars {
		if prefix := azureReservedPrefix(v.Name); prefix != "" {
			return "", fmt.Errorf("%s begins with Azure Pipelines reserved variable prefix %q", v.Name, prefix)
		}
		if !utf8.ValidString(v.Value) {
			return "", fmt.Errorf("%s is not valid UTF-8, which an Azure Pipelines logging command cannot carry intact", v.Name)
		}
		if strings.IndexByte(v.Value, 0) >= 0 {
			return "", fmt.Errorf("%s contains a NUL byte, which an Azure Pipelines logging command cannot carry", v.Name)
		}
		if strings.ContainsAny(v.Value, "\r\n") {
			return "", fmt.Errorf("%s is multiline; Azure Pipelines rejects multiline secret variables unless its unsafe multiline-secret setting is enabled", v.Name)
		}
	}

	var b strings.Builder
	for _, v := range vars {
		value := azureEscapeData(v.Value)
		if v.Value != "" {
			b.WriteString("##vso[task.setsecret]" + value + "\n")
		}
		b.WriteString("##vso[task.setvariable variable=" + azureEscapeProperty(v.Name) + ";issecret=true]" + value + "\n")
	}
	return b.String(), nil
}

var azureReservedPrefixes = [...]string{"endpoint", "input", "secret", "path", "securefile"}

func azureReservedPrefix(name string) string {
	lower := strings.ToLower(name)
	for _, prefix := range azureReservedPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return prefix
		}
	}
	return ""
}

// Percent must be escaped first so the percent signs introduced by the other
// substitutions remain protocol escapes rather than literal data.
func azureEscapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%AZP25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	return strings.ReplaceAll(s, "\n", "%0A")
}

func azureEscapeProperty(s string) string {
	s = azureEscapeData(s)
	s = strings.ReplaceAll(s, "]", "%5D")
	return strings.ReplaceAll(s, ";", "%3B")
}

func isLineBreak(r rune) bool { return r == '\n' || r == '\r' }

// checkNames enforces the naming rule every sink shares — the same rule the
// mapping parser applies — and refuses two variables with one name, where
// the last write would silently win.
func checkNames(vars []secrets.Var) error {
	seen := make(map[string]bool, len(vars))
	for _, v := range vars {
		if !secrets.ValidEnvName(v.Name) {
			return fmt.Errorf("%q is not a valid variable name (letters, digits, underscore; not starting with a digit)", v.Name)
		}
		if seen[v.Name] {
			return fmt.Errorf("two variables named %s; the later value would silently win", v.Name)
		}
		seen[v.Name] = true
	}
	return nil
}

// checkFoldedNames rejects names that a case-insensitive sink treats as one
// variable. Allowing FOO and foo would silently let the latter win.
func checkFoldedNames(vars []secrets.Var, sink string) error {
	seen := make(map[string]string, len(vars))
	for _, v := range vars {
		key := strings.ToUpper(v.Name)
		if prior, ok := seen[key]; ok {
			return fmt.Errorf("%s and %s are the same case-insensitive %s variable; the later value would silently win", prior, v.Name, sink)
		}
		seen[key] = v.Name
	}
	return nil
}
