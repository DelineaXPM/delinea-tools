// Package retrievejson parses the retrieve-secrets JSON schema Delinea's CI
// integrations share — the GitHub action, the GitLab component, and their
// rebuilds all accept the same array:
//
//	[
//	  {"secretId": 126,               "secretKey": "password", "outputVariable": "DB_PASS"},
//	  {"secretPath": "\\ci\\db\\prod", "secretKey": "password", "outputVariable": "DB_PASS2"}
//	]
//
// Each hand-rolled copy of this parser has grown its own landmines — one
// integration documented unquoted secretId numbers while its parser required
// strings, so the documented example failed the whole parse; another returned
// empty results on malformed input. This parser is the one canonical, strict
// copy: secretId accepts a JSON number or string, anything malformed is an
// error naming the entry, unknown keys are typos and refused (key matching
// is case-insensitive, per encoding/json, so "outputvariable" still binds to
// outputVariable), and no malformed input ever yields silently-empty mappings.
package retrievejson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/DelineaXPM/delinea-tools/secrets"
)

// secretID accepts the two spellings integrations have shipped: a JSON
// number (126) and a JSON string ("126").
type secretID struct {
	value int
	set   bool
}

func (s *secretID) UnmarshalJSON(data []byte) error {
	raw := string(bytes.TrimSpace(data))
	if raw == "null" {
		return nil
	}
	if len(raw) >= 2 && raw[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		raw = str
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("secretId %s is not a whole number", string(data))
	}
	if n <= 0 {
		return fmt.Errorf("secretId %d must be positive", n)
	}
	s.value, s.set = n, true
	return nil
}

type entry struct {
	SecretID       secretID `json:"secretId"`
	SecretPath     string   `json:"secretPath"`
	SecretKey      string   `json:"secretKey"`
	OutputVariable string   `json:"outputVariable"`
}

// Parse turns the retrieve-secrets JSON array into mappings for
// secrets.Client.Resolve or Verify. It is strict: on any malformed input it
// returns a nil slice and an error naming the first offending entry (1-based)
// — never a silently shortened result. An empty array is valid and yields no
// mappings.
func Parse(data []byte) ([]secrets.Mapping, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var rawEntries []json.RawMessage
	if err := dec.Decode(&rawEntries); err != nil {
		return nil, fmt.Errorf("parsing retrieve-secrets JSON: %w", err)
	}
	if rawEntries == nil {
		return nil, fmt.Errorf("parsing retrieve-secrets JSON: expected an array, not null")
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, fmt.Errorf("parsing retrieve-secrets JSON: trailing data after the array")
	}
	mappings := make([]secrets.Mapping, 0, len(rawEntries))
	seen := make(map[string]int, len(rawEntries))
	for i, raw := range rawEntries {
		n := i + 1
		e, err := decodeEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", n, err)
		}
		switch {
		case e.SecretID.set && e.SecretPath != "":
			return nil, fmt.Errorf("entry %d: secretId and secretPath are both set; give exactly one", n)
		case !e.SecretID.set && e.SecretPath == "":
			return nil, fmt.Errorf("entry %d: one of secretId or secretPath is required", n)
		case e.SecretKey == "":
			return nil, fmt.Errorf("entry %d: secretKey is required", n)
		case e.OutputVariable == "":
			return nil, fmt.Errorf("entry %d: outputVariable is required", n)
		case !secrets.ValidEnvName(e.OutputVariable):
			return nil, fmt.Errorf("entry %d: outputVariable %q is not a valid variable name (letters, digits, underscore; not starting with a digit)", n, e.OutputVariable)
		}
		if prev, dup := seen[e.OutputVariable]; dup {
			return nil, fmt.Errorf("entries %d and %d both define outputVariable %q", prev, n, e.OutputVariable)
		}
		seen[e.OutputVariable] = n
		m := secrets.Mapping{EnvName: e.OutputVariable, Field: e.SecretKey}
		if e.SecretID.set {
			m.SecretID = e.SecretID.value
		} else {
			m.ByPath = true
			m.Path = e.SecretPath
		}
		mappings = append(mappings, m)
	}
	return mappings, nil
}

// decodeEntry handles object keys explicitly so duplicate keys cannot be
// silently resolved with last-value-wins semantics. Matching remains
// case-insensitive, consistent with encoding/json's struct-field behavior.
func decodeEntry(data []byte) (entry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return entry{}, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return entry{}, fmt.Errorf("expected an object")
	}
	var e entry
	seen := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return entry{}, err
		}
		name, ok := tok.(string)
		if !ok {
			return entry{}, fmt.Errorf("expected an object field name")
		}
		canonical := strings.ToLower(name)
		if previous, duplicate := seen[canonical]; duplicate {
			return entry{}, fmt.Errorf("duplicate field %q (already set as %q)", name, previous)
		}
		seen[canonical] = name
		switch canonical {
		case "secretid":
			err = dec.Decode(&e.SecretID)
		case "secretpath":
			err = dec.Decode(&e.SecretPath)
		case "secretkey":
			err = dec.Decode(&e.SecretKey)
		case "outputvariable":
			err = dec.Decode(&e.OutputVariable)
		default:
			return entry{}, fmt.Errorf("unknown field %q", name)
		}
		if err != nil {
			return entry{}, err
		}
	}
	if _, err := dec.Token(); err != nil {
		return entry{}, err
	}
	return e, nil
}
