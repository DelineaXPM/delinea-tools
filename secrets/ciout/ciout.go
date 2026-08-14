// Package ciout formats resolved secrets for the sinks CI systems consume —
// shell export lines, the GitHub Actions environment/output file, and
// GitHub's ::add-mask:: commands. Every CI integration hand-rolls this
// layer, and its quoting bugs are security bugs; this is the one tested
// copy.
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

// GitHubEnv renders the $GITHUB_ENV file format — which is also the
// $GITHUB_OUTPUT format — using a heredoc per variable, so multiline values
// carry intact. The delimiter is chosen deterministically to never collide
// with the value. Invalid UTF-8, NUL, and carriage returns are refused; the
// runner reads the file as UTF-8 Unix text.
func GitHubEnv(vars []secrets.Var) (string, error) {
	if err := checkNames(vars); err != nil {
		return "", err
	}
	var b strings.Builder
	for _, v := range vars {
		if !utf8.ValidString(v.Value) {
			return "", fmt.Errorf("%s is not valid UTF-8, which a GitHub environment file cannot carry intact", v.Name)
		}
		if strings.IndexByte(v.Value, 0) >= 0 {
			return "", fmt.Errorf("%s contains a NUL byte, which a GitHub environment file cannot carry", v.Name)
		}
		if strings.ContainsRune(v.Value, '\r') {
			return "", fmt.Errorf("%s contains a carriage return, which would corrupt the GitHub environment file", v.Name)
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
