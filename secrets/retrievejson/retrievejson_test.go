package retrievejson

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DelineaXPM/delinea-tools/secrets"
	"github.com/DelineaXPM/delinea-tools/secrets/secretstest"
)

func TestParseAcceptsBothIDSpellings(t *testing.T) {
	got, err := Parse([]byte(`[
		{"secretId": 126, "secretKey": "password", "outputVariable": "DB_PASS"},
		{"secretId": "127", "secretKey": "username", "outputVariable": "DB_USER"},
		{"secretPath": "\\ci\\db\\prod", "secretKey": "password", "outputVariable": "PROD_PASS"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	want := []secrets.Mapping{
		{EnvName: "DB_PASS", SecretID: 126, Field: "password"},
		{EnvName: "DB_USER", SecretID: 127, Field: "username"},
		{EnvName: "PROD_PASS", ByPath: true, Path: `\ci\db\prod`, Field: "password"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("mappings:\n got %v\nwant %v", got, want)
	}
}

func TestParseEmptyArrayIsValid(t *testing.T) {
	got, err := Parse([]byte(`[]`))
	if err != nil || len(got) != 0 {
		t.Errorf("got %v, %v; want no mappings and no error", got, err)
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	cases := []struct {
		name, in, wantErr string
	}{
		{"not json", `nope`, "parsing"},
		{"not an array", `{"secretId":1}`, "parsing"},
		{"null", `null`, "expected an array"},
		{"trailing data", `[] []`, "trailing data"},
		{"unknown key typo", `[{"secretId":1,"secretKey":"k","outputVar":"V"}]`, "unknown field"},
		{"duplicate key", `[{"secretId":1,"secretId":2,"secretKey":"k","outputVariable":"V"}]`, "duplicate field"},
		{"duplicate mixed-case key", `[{"secretId":1,"SECRETID":2,"secretKey":"k","outputVariable":"V"}]`, "duplicate field"},
		{"both refs", `[{"secretId":1,"secretPath":"\\a","secretKey":"k","outputVariable":"V"}]`, "exactly one"},
		{"neither ref", `[{"secretKey":"k","outputVariable":"V"}]`, "one of secretId or secretPath"},
		{"missing key", `[{"secretId":1,"outputVariable":"V"}]`, "secretKey is required"},
		{"missing variable", `[{"secretId":1,"secretKey":"k"}]`, "outputVariable is required"},
		{"bad variable", `[{"secretId":1,"secretKey":"k","outputVariable":"1BAD"}]`, "not a valid variable name"},
		{"duplicate variable", `[{"secretId":1,"secretKey":"k","outputVariable":"V"},{"secretId":2,"secretKey":"k","outputVariable":"V"}]`, "both define"},
		{"zero id", `[{"secretId":0,"secretKey":"k","outputVariable":"V"}]`, "positive"},
		{"negative id", `[{"secretId":-3,"secretKey":"k","outputVariable":"V"}]`, "positive"},
		{"float id", `[{"secretId":1.5,"secretKey":"k","outputVariable":"V"}]`, "whole number"},
		{"non-numeric string id", `[{"secretId":"abc","secretKey":"k","outputVariable":"V"}]`, "whole number"},
		{"exponent id", `[{"secretId":1e2,"secretKey":"k","outputVariable":"V"}]`, "whole number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse([]byte(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got %v, want an error containing %q", err, tc.wantErr)
			}
			if got != nil {
				t.Errorf("a failed parse must return nil mappings, got %v", got)
			}
		})
	}
}

func TestParseErrorsNameTheEntry(t *testing.T) {
	_, err := Parse([]byte(`[
		{"secretId": 1, "secretKey": "k", "outputVariable": "A"},
		{"secretId": 2, "outputVariable": "B"}
	]`))
	if err == nil || !strings.Contains(err.Error(), "entry 2") {
		t.Errorf("got %v, want the error to name entry 2", err)
	}
}

// Every mapping a successful parse yields must be resolvable by the real
// client, so the parser cannot emit shapes the engine would reject.
func TestParsedMappingsDriveTheClient(t *testing.T) {
	mappings, err := Parse([]byte(`[{"secretId":126,"secretKey":"password","outputVariable":"DB_PASS"}]`))
	if err != nil {
		t.Fatal(err)
	}
	c := secrets.NewWithFetcher(&secretstest.Fetcher{ByID: map[int]*secrets.Secret{
		126: secretstest.NewSecret(126, "db", map[string]string{"password": "pw-126"}),
	}})
	vars, err := c.Resolve(t.Context(), mappings)
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 1 || vars[0].Name != "DB_PASS" || vars[0].Value != "pw-126" {
		t.Errorf("resolve: got %v", vars)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`[{"secretId":126,"secretKey":"password","outputVariable":"DB_PASS"}]`)
	f.Add(`[{"secretId":"127","secretKey":"k","outputVariable":"V"}]`)
	f.Add(`[{"secretPath":"\\a\\b","secretKey":"k","outputVariable":"V"}]`)
	f.Add(`[]`)
	f.Add(`[{`)
	f.Add(`[{"secretId":1e309,"secretKey":"k","outputVariable":"V"}]`)
	f.Fuzz(func(t *testing.T, in string) {
		mappings, err := Parse([]byte(in))
		if err != nil && mappings != nil {
			t.Errorf("error with non-nil mappings: %v / %v", err, mappings)
		}
		for _, m := range mappings {
			if !secrets.ValidEnvName(m.EnvName) || m.Field == "" {
				t.Errorf("accepted an invalid mapping: %+v", m)
			}
			if (m.SecretID > 0) == m.ByPath {
				t.Errorf("mapping must reference exactly one of id or path: %+v", m)
			}
			if m.ByPath && m.Path == "" {
				t.Errorf("by-path mapping without a path: %+v", m)
			}
		}
	})
}
