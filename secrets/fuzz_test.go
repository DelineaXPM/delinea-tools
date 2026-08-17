package secrets

import (
	"strings"
	"testing"
)

// FuzzParseMapping asserts the parser's invariants over arbitrary input: it
// never panics, and every accepted mapping is internally consistent with the
// separator-first grammar.
func FuzzParseMapping(f *testing.F) {
	for _, seed := range []string{
		"DB_PASS=password#128",
		`DB_PASS=password@\ci\database\prod`,
		"DB_*=#128",
		`DB_*=@\ci\database\prod`,
		"P=a/b#128",
		`P=password@\ci\user@host`,
		"P=password@128",
		"DB_USER=126",
		"nope",
		"=password#1",
		"P=password#",
		"P=password@",
		"P=#",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		m, err := ParseMapping(in)
		if err != nil {
			return
		}
		name, ref, ok := strings.Cut(in, "=")
		if !ok || name == "" {
			t.Fatalf("accepted %q, which has no NAME=", in)
		}
		if m.Expand {
			if m.EnvName != "" {
				t.Errorf("%q: expansion carries an EnvName %q", in, m.EnvName)
			}
			if m.Prefix+"*" != name {
				t.Errorf("%q: prefix %q does not reconstruct the name", in, m.Prefix)
			}
			if m.Field != "" {
				t.Errorf("%q: expansion carries a field %q", in, m.Field)
			}
		} else {
			if m.EnvName != name {
				t.Errorf("%q: EnvName %q != name %q", in, m.EnvName, name)
			}
			if m.Field == "" {
				t.Errorf("%q: accepted without a field", in)
			}
			if strings.ContainsAny(m.Field, "#@") {
				t.Errorf("%q: field %q contains a separator", in, m.Field)
			}
		}
		at := strings.IndexAny(ref, "#@")
		if at < 0 {
			t.Fatalf("accepted %q, which has no separator", in)
		}
		if m.ByPath {
			if ref[at] != '@' {
				t.Errorf("%q: ByPath but the first separator is %q", in, ref[at])
			}
			if m.Path == "" {
				t.Errorf("%q: accepted with an empty path", in)
			}
			if m.SecretID != 0 {
				t.Errorf("%q: path mapping carries id %d", in, m.SecretID)
			}
		} else {
			if ref[at] != '#' {
				t.Errorf("%q: by id but the first separator is %q", in, ref[at])
			}
			if m.Path != "" {
				t.Errorf("%q: id mapping carries path %q", in, m.Path)
			}
		}
	})
}
