// Package secretstest provides an in-memory secrets.Fetcher for testing code
// that consumes the secrets package, so consumer tests need neither a live
// Secret Server nor an httptest fake of its REST API.
//
//	f := &secretstest.Fetcher{ByID: map[int]*secrets.Secret{
//	    126: secretstest.NewSecret(126, "prod-db", map[string]string{"password": "pw"}),
//	}}
//	c := secrets.NewWithFetcher(f)
//
// The stub mirrors the real server's semantics where tests tend to get them
// wrong: a secret that is missing is indistinguishable from one the caller
// may not read — both return secrets.ErrAccessDenied. (A real Secret Server
// answers both with 400 API_AccessDenied; it does not 404, and it offers no
// existence oracle.)
package secretstest

import (
	"context"
	"fmt"
	"sort"

	"github.com/DelineaXPM/delinea-tools/secrets"
)

// Fetcher serves secrets from maps. It is strict: register every id and
// path a test uses, because anything absent from the maps is denied — the
// zero value denies every fetch. A fake that answers ids the test never
// registered would hide tests that do not mean what they say. Concurrent
// use is safe as long as the maps are not mutated while fetches run.
type Fetcher struct {
	ByID   map[int]*secrets.Secret
	ByPath map[string]*secrets.Secret

	// Err, when set, is returned by every call — for simulating transport
	// failures (secrets.ErrTransport wrapped, or any error under test).
	Err error
}

// Secret returns the secret stored under id, a deep copy per call so a test
// mutating the result cannot corrupt later fetches. A missing id reports
// secrets.ErrAccessDenied, exactly as a real server would.
func (f *Fetcher) Secret(ctx context.Context, id int) (*secrets.Secret, error) {
	if err := f.gate(ctx); err != nil {
		return nil, err
	}
	if s, ok := f.ByID[id]; ok {
		return clone(s), nil
	}
	return nil, fmt.Errorf("fetching secret id %d: %w", id, secrets.ErrAccessDenied)
}

// SecretByPath returns the secret stored under path, with the same copy and
// denial semantics as Secret.
func (f *Fetcher) SecretByPath(ctx context.Context, path string) (*secrets.Secret, error) {
	if err := f.gate(ctx); err != nil {
		return nil, err
	}
	if s, ok := f.ByPath[path]; ok {
		return clone(s), nil
	}
	return nil, fmt.Errorf("fetching secret path %q: %w", path, secrets.ErrAccessDenied)
}

func (f *Fetcher) gate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.Err
}

func clone(s *secrets.Secret) *secrets.Secret {
	c := *s
	c.Fields = append([]secrets.SecretField(nil), s.Fields...)
	return &c
}

// NewSecret builds a Secret whose fields carry the given slug-to-value pairs
// (FieldName mirrors the slug), ordered by slug so tests are deterministic.
func NewSecret(id int, name string, fields map[string]string) *secrets.Secret {
	slugs := make([]string, 0, len(fields))
	for slug := range fields {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	s := &secrets.Secret{ID: id, Name: name}
	for _, slug := range slugs {
		s.Fields = append(s.Fields, secrets.SecretField{Slug: slug, FieldName: slug, ItemValue: fields[slug]})
	}
	return s
}
