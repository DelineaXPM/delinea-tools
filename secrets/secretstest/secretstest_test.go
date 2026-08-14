package secretstest

import (
	"context"
	"errors"
	"testing"

	"github.com/DelineaXPM/delinea-tools/secrets"
)

func fixture() *Fetcher {
	return &Fetcher{
		ByID: map[int]*secrets.Secret{
			126: NewSecret(126, "prod-db", map[string]string{"password": "pw-1", "username": "svc"}),
		},
		ByPath: map[string]*secrets.Secret{
			`\ci\database\prod`: NewSecret(126, "prod-db", map[string]string{"password": "pw-1"}),
		},
	}
}

// The stub drives the real Client end to end: mappings by id and by path
// resolve through secrets.NewWithFetcher exactly as against a live server.
func TestFetcherResolvesThroughClient(t *testing.T) {
	c := secrets.NewWithFetcher(fixture())
	vars, err := c.Resolve(context.Background(), []secrets.Mapping{
		{EnvName: "DB_PASS", SecretID: 126, Field: "password"},
		{EnvName: "DB_PASS_BY_PATH", ByPath: true, Path: `\ci\database\prod`, Field: "password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range vars {
		got[v.Name] = v.Value
	}
	want := map[string]string{"DB_PASS": "pw-1", "DB_PASS_BY_PATH": "pw-1"}
	for name, val := range want {
		if got[name] != val {
			t.Errorf("%s: got %q, want %q", name, got[name], val)
		}
	}
}

// Missing and unauthorized are one answer, as on a real server: the stub
// must not become an existence oracle that a consumer's tests learn to rely
// on.
func TestFetcherDeniesMissingSecrets(t *testing.T) {
	f := fixture()
	if _, err := f.Secret(context.Background(), 999); !errors.Is(err, secrets.ErrAccessDenied) {
		t.Errorf("missing id: got %v, want ErrAccessDenied", err)
	}
	if _, err := f.SecretByPath(context.Background(), `\nope`); !errors.Is(err, secrets.ErrAccessDenied) {
		t.Errorf("missing path: got %v, want ErrAccessDenied", err)
	}
	var zero Fetcher
	if _, err := zero.Secret(context.Background(), 126); !errors.Is(err, secrets.ErrAccessDenied) {
		t.Errorf("zero-value fetcher: got %v, want ErrAccessDenied", err)
	}
}

func TestFetcherErrAndContext(t *testing.T) {
	f := fixture()
	f.Err = secrets.ErrTransport
	if _, err := f.Secret(context.Background(), 126); !errors.Is(err, secrets.ErrTransport) {
		t.Errorf("forced error: got %v, want ErrTransport", err)
	}
	f.Err = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Secret(ctx, 126); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: got %v, want context.Canceled", err)
	}
}

func TestFetcherReturnsCopies(t *testing.T) {
	f := fixture()
	first, err := f.Secret(context.Background(), 126)
	if err != nil {
		t.Fatal(err)
	}
	first.Name = "mutated"
	first.Fields[0].ItemValue = "mutated"
	second, err := f.Secret(context.Background(), 126)
	if err != nil {
		t.Fatal(err)
	}
	if second.Name != "prod-db" || second.Fields[0].ItemValue != "pw-1" {
		t.Errorf("mutating a fetched secret corrupted the stub: %+v", second)
	}
}

func TestNewSecretDeterministicOrder(t *testing.T) {
	s := NewSecret(1, "s", map[string]string{"b": "2", "a": "1", "c": "3"})
	var slugs []string
	for _, fld := range s.Fields {
		slugs = append(slugs, fld.Slug)
		if fld.FieldName != fld.Slug {
			t.Errorf("FieldName should mirror slug: %+v", fld)
		}
	}
	if len(slugs) != 3 || slugs[0] != "a" || slugs[1] != "b" || slugs[2] != "c" {
		t.Errorf("fields should be slug-ordered: %v", slugs)
	}
}
