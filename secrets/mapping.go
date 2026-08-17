package secrets

import (
	"fmt"
	"strconv"
	"strings"
)

// Mapping describes one secret field to resolve and the variable to bind it to.
// Construct with ParseMapping, or directly: every field is exported.
type Mapping struct {
	EnvName  string
	Prefix   string
	ByPath   bool
	SecretID int
	Path     string
	Field    string
	Expand   bool
}

// Ref names the secret a mapping resolves against, for diagnostics and error text.
func (m Mapping) Ref() string {
	if m.ByPath {
		return "path " + m.Path
	}
	return "id " + strconv.Itoa(m.SecretID)
}

// cacheKey identifies the secret a mapping resolves against, so mappings sharing
// a secret fetch it once. The prefix keeps a numeric id from colliding with a path.
func (m Mapping) cacheKey() string {
	if m.ByPath {
		return "@" + m.Path
	}
	return "#" + strconv.Itoa(m.SecretID)
}

// ParseMapping parses one CLI-style mapping: NAME=field#id, NAME=field@path,
// PREFIX_*=#id, or PREFIX_*=@path.
//
// The separator names the kind of reference: "#" an id, "@" a folder path. Both
// characters are impossible in a field, because Secret Server rewrites them to
// "-" when it generates a slug, so the first occurrence of either is always the
// separator and a path may contain both. The field is required: defaulting it to
// "password" meant DB_USER=126 silently resolved to the password field, and the
// default was wrong outright for a template with no password field.
func ParseMapping(a string) (Mapping, error) {
	name, ref, ok := strings.Cut(a, "=")
	if !ok {
		return Mapping{}, fmt.Errorf("invalid mapping %q: want NAME=field#id or NAME=field@path", a)
	}
	if name == "" {
		return Mapping{}, fmt.Errorf("invalid mapping %q: empty variable name", a)
	}
	expand := strings.HasSuffix(name, "*")
	if expand {
		name = strings.TrimSuffix(name, "*")
	}
	// The name reaches a child process as an environment-variable name (or, in
	// an expansion, as the prefix that every generated name starts with), so it
	// must be a well-formed identifier. An expansion with an empty prefix is
	// refused outright: it would let a secret's field slugs name top-level
	// variables directly (PREFIX_ namespacing is what keeps an attacker-chosen
	// slug from becoming LD_PRELOAD), and validating the empty string here is
	// not enough because the generated names are only assembled later.
	if expand && name == "" {
		return Mapping{}, fmt.Errorf("invalid mapping %q: an expansion needs a non-empty prefix (PREFIX_*=...), so its generated names are namespaced", a)
	}
	if !validEnvName(name) {
		return Mapping{}, fmt.Errorf("invalid mapping %q: %q is not a valid variable name (%s)", a, name, envNameRule)
	}

	at := strings.IndexAny(ref, "#@")
	if at < 0 {
		return Mapping{}, fmt.Errorf("invalid mapping %q: needs a field and a reference, as field#id or field@path", a)
	}
	field, target := ref[:at], ref[at+1:]
	byPath := ref[at] == '@'

	switch {
	case target == "" && byPath:
		return Mapping{}, fmt.Errorf("invalid mapping %q: empty secret path", a)
	case target == "":
		return Mapping{}, fmt.Errorf("invalid mapping %q: empty secret id", a)
	case expand && field != "":
		return Mapping{}, fmt.Errorf("invalid mapping %q: PREFIX_* takes no field", a)
	case !expand && field == "":
		return Mapping{}, fmt.Errorf("invalid mapping %q: needs a field, as field#id or field@path", a)
	}

	if byPath {
		return Mapping{EnvName: name, Prefix: prefixIf(expand, name), ByPath: true, Path: target, Field: field, Expand: expand}.normalised(), nil
	}
	id, err := strconv.Atoi(target)
	if err != nil {
		return Mapping{}, fmt.Errorf("invalid secret id in %q: %w", a, err)
	}
	if id <= 0 {
		return Mapping{}, fmt.Errorf("invalid secret id in %q: id must be positive", a)
	}
	return Mapping{EnvName: name, Prefix: prefixIf(expand, name), SecretID: id, Field: field, Expand: expand}.normalised(), nil
}

func prefixIf(expand bool, name string) string {
	if expand {
		return name
	}
	return ""
}

// envNameRule is the human phrasing of validEnvName's rule, shared by every
// message that rejects a bad variable name so they cannot drift.
const envNameRule = "letters, digits, underscore; not starting with a digit"

// ValidEnvName reports whether s is a well-formed environment-variable name
// by the one rule every mapping enforces: letters, digits, and underscores,
// not starting with a digit. Exported so companion packages (retrievejson,
// future output formatters) validate names identically instead of drifting.
func ValidEnvName(s string) bool { return validEnvName(s) }

// validEnvName reports whether s is a POSIX-shell-safe environment variable
// name: an initial letter or underscore, then letters, digits, or underscores.
// This both keeps a shell metacharacter (backtick, $, ;, space) out of the
// name emitted by --via sh and forces an expansion prefix to be an identifier
// so PREFIX_<slug> stays well-formed.
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// normalised clears EnvName for an expansion, which names variables by prefix.
func (m Mapping) normalised() Mapping {
	if m.Expand {
		m.EnvName = ""
	}
	return m
}

func envify(slug string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(slug) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
