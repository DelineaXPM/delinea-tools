// Package cli holds helpers shared across the faces of the delinea-util
// command-line tool — the raw REST verbs, the check diagnostic, and the secrets
// subcommand group. They are the pieces that must behave identically
// everywhere — credential-encoding and TLS-scheme guards, terminal and
// control-character handling, the version string — kept in one place so a
// security-relevant check cannot drift.
package cli

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"unicode"
	"unicode/utf8"
)

// UsageError is an error whose message deserves the tool's usage text beneath
// it: the invocation itself was malformed, so the remedy is the synopsis.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// MaxCredentialBytes bounds a stdin credential read so a wedged or hostile
// pipe cannot drive unbounded allocation; it is far larger than any password,
// client secret, or bearer token.
const MaxCredentialBytes = 64 * 1024

// ReadCredential reads a credential from r under the shared stdin contract:
// at most MaxCredentialBytes — one byte past the cap is read so an over-length
// credential is rejected rather than silently truncated — vetted against
// re-encoding damage, with trailing line endings trimmed. present reports that
// a delivery happened (bytes arrived, or a read failed partway), so a caller
// can distinguish "nothing piped" from a broken or rejected delivery. The raw
// buffer is wiped before returning.
func ReadCredential(r io.Reader) (secret string, present bool, err error) {
	raw, rerr := io.ReadAll(io.LimitReader(r, MaxCredentialBytes+1))
	defer Wipe(raw)
	if rerr != nil {
		return "", true, fmt.Errorf("reading credential from stdin: %w", rerr)
	}
	present = len(raw) > 0
	// Encoding damage is diagnosed before the size cap: a UTF-16 re-encoding
	// doubles a credential's bytes, and "exceeds 65536 bytes" would send the
	// operator hunting a size problem their credential does not have.
	if err := RequireDecodedCredential(raw); err != nil {
		return "", present, err
	}
	if len(raw) > MaxCredentialBytes {
		return "", present, fmt.Errorf("credential on stdin exceeds %d bytes", MaxCredentialBytes)
	}
	return strings.TrimRight(string(raw), "\r\n"), present, nil
}

// SplitInlineFlag splits a "--name=value" argument into its parts; ok reports
// that a was a long flag carrying an inline value.
func SplitInlineFlag(a string) (name, value string, ok bool) {
	if !strings.HasPrefix(a, "--") {
		return a, "", false
	}
	if eq := strings.Index(a, "="); eq > 0 {
		return a[:eq], a[eq+1:], true
	}
	return a, "", false
}

// FlagName reduces a flag argument to its name, dropping any inline "=value"
// or value compacted onto a short flag.
// Every error message that echoes an unrecognized flag must echo FlagName of
// it, never the raw argument: a mistyped credential flag ("--pasword=SECRET",
// "-token=SECRET", or "-pSECRET") carries the secret in its value, and an
// error that repeats the full argument writes that secret into terminal
// scrollback and CI logs.
func FlagName(a string) string {
	if eq := strings.Index(a, "="); eq > 0 {
		return a[:eq]
	}
	if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 2 {
		_, size := utf8.DecodeRuneInString(a[1:])
		return a[:1+size]
	}
	return a
}

// UnknownFlagName returns a diagnostic-safe spelling of an unrecognized flag.
// A long flag without '=' has no boundary between its name and a value a user
// may have compacted onto it, so none of that untrusted text is repeated.
func UnknownFlagName(a string) string {
	if eq := strings.Index(a, "="); eq > 0 {
		return a[:eq]
	}
	if strings.HasPrefix(a, "--") && len(a) > 2 {
		return "--<redacted>"
	}
	return FlagName(a)
}

// IsCredentialFlag reports a flag name that would carry secret material as a
// command-line argument. Both binaries' parsers reject these with
// CredentialFlagError; the flags do not exist, because argv is world-readable
// (ps, /proc/<pid>/cmdline) and leaks into shell history and CI logs.
func IsCredentialFlag(name string) bool {
	return name == "--token" || name == "--password" || name == "--client-secret"
}

// CredentialFlagError is the shared rejection for IsCredentialFlag names; it
// echoes only the flag's name, never an attached value.
func CredentialFlagError(name string) error {
	return &UsageError{Msg: fmt.Sprintf("%s is not accepted: the credential is never taken as a command-line argument (argv is visible via ps and /proc); set DELINEA_TOOLS_TOKEN/_PASSWORD/_CLIENT_SECRET or pipe it on stdin (--secret-stdin)", FlagName(name))}
}

// SplitHosts splits a comma-separated host list, trimming whitespace and
// dropping empty entries — the one parse both CLIs apply to their vault
// allow-lists.
func SplitHosts(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// TreeItem is one command in a Tree rendering.
type TreeItem struct{ Name, Desc string }

// Tree renders the --tree command listing both CLIs print: a title line and
// one branch per command.
func Tree(title string, items []TreeItem) string {
	var b strings.Builder
	b.WriteString(title + "\n")
	for i, c := range items {
		branch := "├──"
		if i == len(items)-1 {
			branch = "└──"
		}
		fmt.Fprintf(&b, "%s %s  — %s\n", branch, c.Name, c.Desc)
	}
	return b.String()
}

// PrintDoc writes an embedded document the way both CLIs present one: a blank
// line, the content without trailing newlines, a blank line.
func PrintDoc(w io.Writer, s string) {
	fmt.Fprintf(w, "\n%s\n\n", strings.TrimRight(s, "\n"))
}

// Truthy reports whether s is an affirmative environment-variable value.
func Truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on":
		return true
	}
	return false
}

// IsTerminal reports whether f is a character device (a terminal), used to
// refuse writing secrets where they would land in scrollback.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// Wipe zeroes a credential buffer, the one copy that can be scrubbed; the
// string copies made from it are immutable.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SanitizeText replaces control characters, which reach error text through
// server response bodies, so a hostile endpoint cannot write terminal escape
// sequences into a tool's output. Newlines and tabs are kept: they only move
// the cursor forward.
func SanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

// Version returns the version line for a tool: its name, the build's module
// version, the platform, and the VCS revision when the binary was built from a
// checkout. The formatting is in versionFrom so it can be tested against a
// synthetic BuildInfo — a test binary carries no VCS settings of its own.
func Version(name string) string {
	bi, ok := debug.ReadBuildInfo()
	return versionFrom(name, bi, ok)
}

func versionFrom(name string, bi *debug.BuildInfo, ok bool) string {
	version, rev, modified := "(unknown)", "", false
	if ok {
		version = bi.Main.Version
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}
	out := fmt.Sprintf("%s %s %s/%s", name, version, runtime.GOOS, runtime.GOARCH)
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev != "" {
		out += " " + rev
		if modified {
			out += "+dirty"
		}
	}
	return out
}

// RequireSecureURL rejects a non-https URL. The credential is sent on the very
// first request, so a plaintext http URL would disclose it on the wire; there
// is no TLS to downgrade from. An empty URL is left for the engine to reject.
// http is allowed only against a loopback host, for local testing. source
// names the setting in the error (e.g. "DELINEA_TOOLS_URL").
func RequireSecureURL(raw, source string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid %s URL", source)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("%s must not contain userinfo, a query, or a fragment", source)
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(u.Scheme, "http") && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%s must use https (got scheme %q); the credential is sent on the first request and http would expose it", source, u.Scheme)
}

// RequirePlainUsername rejects a domain-qualified DOMAIN\user. Secret Server
// accepts a domain either way -- qualified in the username, or as its own form
// field -- so this narrows two equivalent spellings to one rather than rejecting
// something invalid. The separate field is the one worth keeping: a backslash is a
// quoting hazard across shells, CI YAML and JSON, and one spelling means the
// domain is always visible in DELINEA_TOOLS_DOMAIN instead of hiding inside
// another variable.
func RequirePlainUsername(user string) error {
	if !strings.ContainsAny(user, `\/`) {
		return nil
	}
	return fmt.Errorf("DELINEA_TOOLS_USERNAME %q must be the username alone; put the domain in DELINEA_TOOLS_DOMAIN, which Secret Server accepts as a separate field", user)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// reencodingFix is appended to every mis-encoded-credential error: the repair
// belongs in the caller's shell, and naming it is the whole value of the check.
const reencodingFix = "; PowerShell encodes a pipeline to a native command using the console output encoding. " +
	"Run [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) first, use PowerShell 7, or pipe from a byte-clean source"

// RequireDecodedCredential rejects a credential that arrived in an encoding
// other than the bytes of the value itself. It deliberately does not transcode:
// a legacy console codepage replaces non-ASCII characters with "?" before the
// bytes arrive, which is undetectable here, so quietly decoding the detectable
// cases would keep a broken pipe working until the first non-ASCII value.
func RequireDecodedCredential(cred []byte) error {
	switch {
	case bytes.HasPrefix(cred, []byte{0xEF, 0xBB, 0xBF}):
		return fmt.Errorf("credential on stdin begins with a UTF-8 byte-order mark, which is not part of it%s", reencodingFix)
	case bytes.HasPrefix(cred, []byte{0xFF, 0xFE}):
		return fmt.Errorf("credential on stdin begins with a UTF-16LE byte-order mark, so it was re-encoded in transit%s", reencodingFix)
	case bytes.HasPrefix(cred, []byte{0xFE, 0xFF}):
		return fmt.Errorf("credential on stdin begins with a UTF-16BE byte-order mark, so it was re-encoded in transit%s", reencodingFix)
	case bytes.IndexByte(cred, 0) >= 0:
		return fmt.Errorf("credential on stdin contains a NUL byte, so it was re-encoded as UTF-16 without a byte-order mark%s", reencodingFix)
	}
	return nil
}
