//go:build !windows

package secretscmd

import "slices"

// baseline is the set of variables a child inherits. Every entry is an inert
// description of the session -- where things live, who and where you are, what
// locale. None can redirect the child's traffic, change what it trusts, or hand
// it a capability, which is why HTTP_PROXY, SSL_CERT_FILE, SSH_AUTH_SOCK and
// KRB5CCNAME are absent: pass those with --pass-env, per invocation.
//
// Of the locale variables only LANG, LC_ALL and LC_CTYPE are here. LC_CTYPE sets
// the character encoding, so dropping it can make a child misread a secret
// containing non-ASCII bytes; LANG and LC_ALL are the defaults it falls back to
// and the override that wins over it. The remaining categories (LC_COLLATE,
// LC_MESSAGES, LC_MONETARY, LC_NUMERIC, LC_TIME) only change how a child formats
// its own output, which is the child's business -- pass those with --pass-env.
// They are listed by name rather than matched as LC_*: a prefix rule would make
// the child's environment unenumerable, and an allowlist is only auditable if it
// can be read.
var baseline = []string{
	"PATH", "HOME", "PWD", "TMPDIR",
	"USER", "LOGNAME", "SHELL",
	"TZ", "TERM",
	"LANG", "LC_ALL", "LC_CTYPE",
}

func inBaseline(name string) bool { return slices.Contains(baseline, name) }

// envNameKey is the identity: Unix environment names are case-sensitive, so
// two names that differ only in case are genuinely different variables.
func envNameKey(name string) string { return name }

// execve carries arbitrary non-NUL bytes in environment values.
const envRequiresUTF8 = false
