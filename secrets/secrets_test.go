package secrets

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DelineaXPM/delinea-tools/api"
)

func field(slug, value string) SecretField {
	return SecretField{FieldName: slug, Slug: slug, ItemValue: value}
}

type fakeFetcher struct {
	byID         map[int]*Secret
	byPath       map[string]*Secret
	calls        map[string]int
	delay        time.Duration
	failuresLeft int
	forceErr     error
	closeCalls   int
}

func newFake(byID map[int]*Secret) *fakeFetcher {
	return &fakeFetcher{byID: byID, byPath: map[string]*Secret{}, calls: map[string]int{}}
}

func (f *fakeFetcher) CloseIdleConnections() { f.closeCalls++ }

func (f *fakeFetcher) inject(ctx context.Context) error {
	if f.delay > 0 {
		timer := time.NewTimer(f.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.failuresLeft > 0 {
		f.failuresLeft--
		return errors.New("dial tcp 10.0.0.1:443: connect: connection refused")
	}
	return f.forceErr
}

func (f *fakeFetcher) Secret(ctx context.Context, id int) (*Secret, error) {
	f.calls["#"+strconv.Itoa(id)]++
	if err := f.inject(ctx); err != nil {
		return nil, err
	}
	s, ok := f.byID[id]
	if !ok {
		return nil, fmt.Errorf("secret %d not found", id)
	}
	return s, nil
}

func (f *fakeFetcher) SecretByPath(ctx context.Context, path string) (*Secret, error) {
	f.calls["@"+path]++
	if err := f.inject(ctx); err != nil {
		return nil, err
	}
	s, ok := f.byPath[path]
	if !ok {
		return nil, fmt.Errorf("secret path %q not found", path)
	}
	return s, nil
}

func TestParseMapping(t *testing.T) {
	cases := []struct {
		in      string
		want    Mapping
		wantErr bool
	}{
		{in: "DB_PASS=password#128", want: Mapping{EnvName: "DB_PASS", SecretID: 128, Field: "password"}},
		{in: "DB_USER=username#128", want: Mapping{EnvName: "DB_USER", SecretID: 128, Field: "username"}},
		{in: "DB_*=#128", want: Mapping{Prefix: "DB_", SecretID: 128, Expand: true}},
		{in: `DB_PASS=password@\ci\database\prod`, want: Mapping{EnvName: "DB_PASS", ByPath: true, Path: `\ci\database\prod`, Field: "password"}},
		{in: `DB_*=@\ci\database\prod`, want: Mapping{Prefix: "DB_", ByPath: true, Path: `\ci\database\prod`, Expand: true}},

		// A path may contain either separator: the field cannot, so the first
		// occurrence is always the one that counts.
		{in: "P=password@/ci/database/prod", want: Mapping{EnvName: "P", ByPath: true, Path: "/ci/database/prod", Field: "password"}},
		{in: `P=password@\ci\a/b`, want: Mapping{EnvName: "P", ByPath: true, Path: `\ci\a/b`, Field: "password"}},
		{in: `P=password@\ci\user@host`, want: Mapping{EnvName: "P", ByPath: true, Path: `\ci\user@host`, Field: "password"}},
		{in: `P=password@\ci\a#b`, want: Mapping{EnvName: "P", ByPath: true, Path: `\ci\a#b`, Field: "password"}},
		// A slug may contain "/", and an id is bounded by the separator.
		{in: "P=a/b#128", want: Mapping{EnvName: "P", SecretID: 128, Field: "a/b"}},
		// An id and a folderless secret named the same digits are both reachable.
		{in: "P=password#128", want: Mapping{EnvName: "P", SecretID: 128, Field: "password"}},
		{in: "P=password@128", want: Mapping{EnvName: "P", ByPath: true, Path: "128", Field: "password"}},

		// The field is required: it was defaulting to "password", so DB_USER=126
		// silently resolved to the password.
		{in: "DB_USER=126", wantErr: true},
		{in: "DB_USER=#126", wantErr: true},
		{in: `DB_USER=@\ci\prod`, wantErr: true},
		{in: "nope", wantErr: true},
		{in: "P=password#abc", wantErr: true},
		{in: "P=password#0", wantErr: true},
		{in: "P=password#-1", wantErr: true},
		{in: "P=password#", wantErr: true},
		{in: "P=password@", wantErr: true},
		{in: "=password#1", wantErr: true},
		{in: `DB_*=password@\ci\db`, wantErr: true},
		{in: "DB_*=password#128", wantErr: true},

		// An expansion with an empty prefix is refused: it would let a secret's
		// field slugs name top-level variables (e.g. LD_PRELOAD) directly.
		{in: "*=#128", wantErr: true},
		{in: `*=@\ci\db`, wantErr: true},
		// A name must be a well-formed identifier, so a shell metacharacter can
		// never reach the name side of --via sh output.
		{in: "`id`=password#1", wantErr: true},
		{in: "A B=password#1", wantErr: true},
		{in: "A;B=password#1", wantErr: true},
		{in: "A$X=password#1", wantErr: true},
		{in: "1ABC=password#1", wantErr: true},
		{in: "_OK=password#1", want: Mapping{EnvName: "_OK", SecretID: 1, Field: "password"}},
	}
	for _, c := range cases {
		got, err := ParseMapping(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseMapping(%q): got nil error, want error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMapping(%q): got error %v, want nil", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseMapping(%q): got %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestClientRejectsInvalidReferencesBeforeFetcher(t *testing.T) {
	f := newFake(nil)
	c := NewWithFetcher(f)
	for _, m := range []Mapping{{SecretID: 0}, {SecretID: -1}, {ByPath: true}} {
		if _, err := c.fetch(context.Background(), m); err == nil {
			t.Errorf("fetch(%+v): got nil error", m)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("invalid references reached the fetcher: %v", f.calls)
	}
}

func TestResolveOrderAndCache(t *testing.T) {
	f := newFake(map[int]*Secret{
		128: {Fields: []SecretField{field("username", "u"), field("password", "p")}},
	})
	got, err := NewWithFetcher(f).Resolve(context.Background(), []Mapping{
		{EnvName: "DB_USER", SecretID: 128, Field: "username"},
		{EnvName: "DB_PASS", SecretID: 128, Field: "password"},
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	want := []Var{{Name: "DB_USER", Value: "u"}, {Name: "DB_PASS", Value: "p"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if f.calls["#128"] != 1 {
		t.Errorf("fetch count for 128: got %d, want 1 (should cache)", f.calls["#128"])
	}
}

func TestResolveExpand(t *testing.T) {
	f := newFake(map[int]*Secret{
		9: {Fields: []SecretField{
			field("username", "u"),
			field("password", "p"),
			{Slug: "keyfile", IsFile: true},
			{Slug: "", ItemValue: "ignored"},
		}},
	})
	got, err := NewWithFetcher(f).Resolve(context.Background(), []Mapping{{Prefix: "DB_", SecretID: 9, Expand: true}})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	want := []Var{{Name: "DB_USERNAME", Value: "u"}, {Name: "DB_PASSWORD", Value: "p"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestResolveExpandEmptyPrefixRefused(t *testing.T) {
	f := newFake(map[int]*Secret{
		9: {Fields: []SecretField{field("ld-preload", "evil")}},
	})
	_, err := NewWithFetcher(f).Resolve(context.Background(), []Mapping{{SecretID: 9, Expand: true}})
	if err == nil || !strings.Contains(err.Error(), "non-empty Prefix") {
		t.Errorf("got %v, want a refusal: an unprefixed expansion would let the vault name variables like LD_PRELOAD", err)
	}
}

func TestDirectMappingRejectsInvalidStateBeforeFetcher(t *testing.T) {
	f := newFake(map[int]*Secret{9: {Fields: []SecretField{field("password", "p")}}})
	c := NewWithFetcher(f)
	for _, m := range []Mapping{
		{EnvName: "BAD=NAME", SecretID: 9, Field: "password"},
		{Prefix: "BAD-", SecretID: 9, Expand: true},
		{EnvName: "A", Field: "password"},
		{EnvName: "A", ByPath: true, Field: "password"},
		{EnvName: "A", ByPath: true, Path: `\p`, SecretID: 9, Field: "password"},
		{EnvName: "A", Path: `\p`, SecretID: 9, Field: "password"},
		{EnvName: "A", Prefix: "P_", SecretID: 9, Expand: true},
		{Prefix: "P_", SecretID: 9, Field: "password", Expand: true},
		{EnvName: "A", Prefix: "P_", SecretID: 9, Field: "password"},
		{EnvName: "A", SecretID: 9},
	} {
		if _, err := c.Resolve(context.Background(), []Mapping{m}); err == nil {
			t.Errorf("Resolve(%+v): got nil error", m)
		}
	}
	if len(f.calls) != 0 {
		t.Errorf("invalid output names reached the fetcher: %v", f.calls)
	}
}

func TestCloseIdleConnectionsDelegatesWhenFetcherSupportsIt(t *testing.T) {
	f := newFake(nil)
	c := NewWithFetcher(f)
	c.CloseIdleConnections()
	if f.closeCalls != 1 {
		t.Fatalf("CloseIdleConnections delegated %d times, want 1", f.closeCalls)
	}
}

func TestVerifyReportsInvalidDirectMappingWithoutFetching(t *testing.T) {
	f := newFake(map[int]*Secret{9: {Fields: []SecretField{field("password", "p")}}})
	results, err := NewWithFetcher(f).Verify(context.Background(), []Mapping{{EnvName: "BAD=NAME", SecretID: 9, Field: "password"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Err == nil {
		t.Errorf("got %+v, want one per-mapping validation error", results)
	}
	if len(f.calls) != 0 {
		t.Errorf("invalid output name reached the fetcher: %v", f.calls)
	}
}

func TestResolveExpandWithNoUsableFieldsErrors(t *testing.T) {
	f := newFake(map[int]*Secret{
		9: {Fields: []SecretField{
			{Slug: "keyfile", IsFile: true},
			{Slug: "", ItemValue: "ignored"},
		}},
	})
	_, err := NewWithFetcher(f).Resolve(context.Background(), []Mapping{{Prefix: "P_", SecretID: 9, Expand: true}})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want errors.Is ErrNotFound: an expansion defining nothing must not succeed silently", err)
	}
}

func TestResolveByPath(t *testing.T) {
	f := newFake(nil)
	f.byPath[`\ci\db\prod`] = &Secret{Fields: []SecretField{field("password", "p")}}
	got, err := NewWithFetcher(f).Resolve(context.Background(), []Mapping{
		{EnvName: "DB_PASS", ByPath: true, Path: `\ci\db\prod`, Field: "password"},
	})
	if err != nil {
		t.Fatalf("got error %v, want nil", err)
	}
	want := []Var{{Name: "DB_PASS", Value: "p"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if f.calls[`@\ci\db\prod`] != 1 {
		t.Errorf("fetch count for path: got %d, want 1", f.calls[`@\ci\db\prod`])
	}
}

func TestResolveErrors(t *testing.T) {
	f := newFake(map[int]*Secret{
		1: {Fields: []SecretField{field("password", "p")}},
	})
	if _, err := NewWithFetcher(f).Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 1, Field: "token"}}); err == nil {
		t.Errorf("missing field: got nil error, want error")
	}
	if _, err := NewWithFetcher(f).Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 99, Field: "password"}}); err == nil {
		t.Errorf("missing secret: got nil error, want error")
	}
}

func TestClassify(t *testing.T) {
	if !errors.Is(classify(errors.New(`400 Bad Request: {"errorCode":"API_AccessDenied","message":"Access denied"}`)), ErrAccessDenied) {
		t.Errorf("API_AccessDenied should classify as ErrAccessDenied")
	}
	if !errors.Is(classify(errors.New("oauth2: invalid_client")), ErrAccessDenied) {
		t.Errorf("invalid_client should classify as ErrAccessDenied")
	}
	if !errors.Is(classify(errors.New("dial tcp: connect: connection refused")), ErrTransport) {
		t.Errorf("connection refused should classify as ErrTransport")
	}
}

// The engine's sentinel errors decide the classification directly, without
// string matching.
func TestClassifyEngineSentinels(t *testing.T) {
	cases := []struct {
		in   error
		want error
	}{
		{fmt.Errorf("%w: token endpoint returned 400", api.ErrAccessDenied), ErrAccessDenied},
		{fmt.Errorf("%w: parsing token response", api.ErrAuth), ErrAccessDenied},
		{fmt.Errorf("%w: no response headers within 30s", api.ErrTimeout), ErrTimeout},
		{fmt.Errorf("%w: connection reset", api.ErrTransport), ErrTransport},
	}
	for _, c := range cases {
		if got := classify(c.in); !errors.Is(got, c.want) {
			t.Errorf("classify(%v): got %v, want %v", c.in, got, c.want)
		}
	}
	// Config and vault-discovery errors pass through unchanged.
	for _, sentinel := range []error{api.ErrConfig, api.ErrVault} {
		in := fmt.Errorf("%w: something", sentinel)
		if got := classify(in); got != in {
			t.Errorf("classify(%v): got %v, want it unchanged", in, got)
		}
	}
}

// The fetcher formats a non-2xx response with the status at the front, so the
// code never has a space before it.
func TestClassifyBareHTTPStatus(t *testing.T) {
	for _, s := range []string{"401 Unauthorized: ", "403 Forbidden: ", `401 Unauthorized: <html>Denied</html>`} {
		if !errors.Is(classify(errors.New(s)), ErrAccessDenied) {
			t.Errorf("%q: got ErrTransport, want ErrAccessDenied", s)
		}
	}
	for s, transient := range map[string]bool{
		"500 Internal Server Error: oops": true,
		"502 Bad Gateway: proxy":          true,
		"429 Too Many Requests: slow":     true,
		"404 Not Found: no such path":     false,
		"400 Bad Request: nope":           false,
	} {
		in := errors.New(s)
		got := classify(in)
		if transient {
			if !errors.Is(got, ErrTransport) {
				t.Errorf("classify(%q): got %v, want the ErrTransport sentinel (embedders requeue on it)", s, got)
			}
		} else if got != in {
			t.Errorf("classify(%q): got %v, want it unchanged (a completed 4xx is not a transport failure)", s, got)
		}
		if _, sent := diagnose(in); errors.Is(sent, ErrTransport) != transient {
			t.Errorf("diagnose(%q): transport %v, want %v", s, errors.Is(sent, ErrTransport), transient)
		}
	}
}

// A transient status wins over a denial substring in the body: a 503 from a
// WAF whose block page says "Access denied" is retriable, not a permanent
// denial. But a non-transient status that IS a denial (Secret Server's 400
// with API_AccessDenied) stays ErrAccessDenied.
func TestClassifyTransientStatusBeatsDenialSubstring(t *testing.T) {
	transient := errors.New("503 Service Unavailable: <html>Access denied by WAF</html>")
	if _, sent := diagnose(transient); !errors.Is(sent, ErrTransport) || !errors.Is(classify(transient), ErrTransport) {
		t.Errorf("503 with a denial substring: got %v (diagnose sentinel %v), want retriable ErrTransport", classify(transient), sent)
	}
	denied := errors.New(`400 Bad Request: {"errorCode":"API_AccessDenied","message":"Access denied"}`)
	if !errors.Is(classify(denied), ErrAccessDenied) {
		t.Errorf("400 API_AccessDenied: got %v, want ErrAccessDenied", classify(denied))
	}
	// A transient status whose body carries a named-cause fragment
	// (invalid_grant/invalid_client) is still retried, not frozen permanent.
	for _, s := range []string{
		`503 Service Unavailable: {"error":"invalid_grant"}`,
		`429 Too Many Requests: {"error":"invalid_client"}`,
	} {
		if _, sent := diagnose(errors.New(s)); !errors.Is(sent, ErrTransport) {
			t.Errorf("%q: got %v, want ErrTransport (transient wins over the named-cause substring)", s, sent)
		}
	}
	// A wrapped engine transport error whose message embeds invalid_client is
	// still retriable.
	wrapped := fmt.Errorf("fetching secret: %w", fmt.Errorf("%w: token endpoint returned 503: invalid_client", api.ErrTransport))
	if _, sent := diagnose(wrapped); !errors.Is(sent, ErrTransport) {
		t.Errorf("wrapped ErrTransport with invalid_client: got %v, want ErrTransport", sent)
	}
	// A non-transient named cause keeps its explanation.
	if cause, _ := diagnose(errors.New(`400 Bad Request: {"error":"invalid_grant"}`)); cause == "" {
		t.Errorf("400 invalid_grant: want a named cause, got none")
	}
}

func TestClassifyNamesCause(t *testing.T) {
	err := classify(errors.New(`400 Bad Request: {"message":"No internal user found for mapping the external user"}`))
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want ErrAccessDenied", err)
	}
	if !strings.Contains(err.Error(), "no mapped Secret Server user") {
		t.Errorf("got %q, want the unmapped-user cause named", err)
	}
	err = classify(errors.New(`400 Bad Request: {"error":"invalid_client"}`))
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want ErrAccessDenied", err)
	}
	if !strings.Contains(err.Error(), "client_id") {
		t.Errorf("got %q, want the client-credentials cause named", err)
	}
}

func TestHTTPStatus(t *testing.T) {
	got := map[string]int{}
	for _, s := range []string{"401 Unauthorized: x", "500 Internal Server Error", "dial tcp: refused", "40", "999 Nope", "099 Low"} {
		got[s] = httpStatus(s)
	}
	want := map[string]int{
		"401 Unauthorized: x":       401,
		"500 Internal Server Error": 500,
		"dial tcp: refused":         0,
		"40":                        0,
		"999 Nope":                  0,
		"099 Low":                   0,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A 401 reaching this layer is a genuine denial: the engine already replays
// once with a fresh grant when a cached token is rejected, and re-running the
// grant here would count toward account suspension.
func TestResolveUnauthorizedNoRetry(t *testing.T) {
	f := newFake(nil)
	f.forceErr = errors.New("401 Unauthorized: ")
	c := NewWithFetcher(f)
	_, err := c.Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 5, Field: "password"}})
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want ErrAccessDenied", err)
	}
	if f.calls["#5"] != 1 {
		t.Errorf("401 must not retry: got %d attempts", f.calls["#5"])
	}
}

func TestResolveForbiddenNoRetry(t *testing.T) {
	f := newFake(nil)
	f.forceErr = errors.New("403 Forbidden: ")
	c := NewWithFetcher(f)
	_, err := c.Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 5, Field: "password"}})
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want ErrAccessDenied", err)
	}
	if f.calls["#5"] != 1 {
		t.Errorf("403 must not retry: got %d attempts", f.calls["#5"])
	}
}

// A permanent misconfiguration must not re-run the password grant; repeated
// password failures suspend the account.
func TestResolveUnmappedUserNoRetry(t *testing.T) {
	f := newFake(nil)
	f.forceErr = errors.New(`400 Bad Request: {"message":"No internal user found for mapping the external user"}`)
	c := NewWithFetcher(f)
	_, err := c.Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 5, Field: "password"}})
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want ErrAccessDenied", err)
	}
	if f.calls["#5"] != 1 {
		t.Errorf("unmapped user must not retry: got %d attempts", f.calls["#5"])
	}
}

func TestVerifyReportsEveryOutcome(t *testing.T) {
	f := newFake(map[int]*Secret{
		1: {Fields: []SecretField{field("password", "s3cr3t"), field("blank", "")}},
	})
	mappings := []Mapping{
		{EnvName: "A", SecretID: 1, Field: "password"},
		{EnvName: "B", SecretID: 1, Field: "token"},
		{EnvName: "C", SecretID: 99, Field: "password"},
		{Prefix: "P_", SecretID: 1, Expand: true},
	}
	got, err := NewWithFetcher(f).Verify(context.Background(), mappings)
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if len(got) != len(mappings) {
		t.Fatalf("got %d results, want %d", len(got), len(mappings))
	}

	if !reflect.DeepEqual(got[0].Fields, []Field{{Name: "A", Bytes: 6}}) {
		t.Errorf("A: got %+v, want A/6 bytes", got[0].Fields)
	}
	if got[0].Err != nil {
		t.Errorf("A: got %v, want nil", got[0].Err)
	}
	if !errors.Is(got[1].Err, ErrNotFound) {
		t.Errorf("B: got %v, want ErrNotFound", got[1].Err)
	}
	if got[2].Err == nil {
		t.Errorf("C: got nil error, want a fetch failure")
	}
	if !reflect.DeepEqual(got[3].Fields, []Field{{Name: "P_PASSWORD", Bytes: 6}, {Name: "P_BLANK", Bytes: 0}}) {
		t.Errorf("P_*: got %+v, want PASSWORD/6 and BLANK/0", got[3].Fields)
	}
	for i, r := range got {
		if !reflect.DeepEqual(r.Mapping, mappings[i]) {
			t.Errorf("result %d: mapping got %+v, want %+v", i, r.Mapping, mappings[i])
		}
	}
}

func TestVerifyCancellationIsWholeCallError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewWithFetcher(newFake(nil))
	got, err := c.verify(ctx, []Mapping{{EnvName: "A", SecretID: 1, Field: "password"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	if got != nil {
		t.Fatalf("got partial results %+v on whole-call cancellation", got)
	}
}

// One unreachable secret named by several mappings must be attempted once, not
// once per mapping: each attempt re-runs the password grant.
func TestVerifyCachesFailures(t *testing.T) {
	f := newFake(nil)
	f.forceErr = errors.New("403 Forbidden: ")
	c := NewWithFetcher(f)
	got, err := c.Verify(context.Background(), []Mapping{
		{EnvName: "A", SecretID: 5, Field: "password"},
		{EnvName: "B", SecretID: 5, Field: "token"},
		{EnvName: "C", SecretID: 5, Field: "other"},
	})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	for i, r := range got {
		if !errors.Is(r.Err, ErrAccessDenied) {
			t.Errorf("result %d: got %v, want ErrAccessDenied", i, r.Err)
		}
	}
	if f.calls["#5"] != 1 {
		t.Errorf("got %d fetches, want 1", f.calls["#5"])
	}
}

func TestVerifyCachesSuccesses(t *testing.T) {
	f := newFake(map[int]*Secret{1: {Fields: []SecretField{field("password", "p")}}})
	got, err := NewWithFetcher(f).Verify(context.Background(), []Mapping{
		{EnvName: "A", SecretID: 1, Field: "password"},
		{EnvName: "B", SecretID: 1, Field: "password"},
	})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if len(got) != 2 || got[0].Err != nil || got[1].Err != nil {
		t.Errorf("got %+v, want two clean results", got)
	}
	if f.calls["#1"] != 1 {
		t.Errorf("got %d fetches, want 1", f.calls["#1"])
	}
}

func TestVerifyTimeout(t *testing.T) {
	f := newFake(map[int]*Secret{1: {Fields: []SecretField{field("password", "p")}}})
	f.delay = 100 * time.Millisecond
	c := NewWithFetcher(f)
	c.timeout = 10 * time.Millisecond
	got, err := c.Verify(context.Background(), []Mapping{{EnvName: "A", SecretID: 1, Field: "password"}})
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("got %v, want ErrTimeout", err)
	}
	if got != nil {
		t.Errorf("got %+v, want nil results on timeout", got)
	}
}

func TestVerifyByPath(t *testing.T) {
	f := newFake(nil)
	f.byPath[`\ci\db\prod`] = &Secret{Fields: []SecretField{field("password", "abcd")}}
	got, err := NewWithFetcher(f).Verify(context.Background(), []Mapping{{EnvName: "A", ByPath: true, Path: `\ci\db\prod`, Field: "password"}})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if !reflect.DeepEqual(got[0].Fields, []Field{{Name: "A", Bytes: 4}}) {
		t.Errorf("got %+v, want A/4 bytes", got[0].Fields)
	}
}

func TestResolveFieldNotFound(t *testing.T) {
	f := newFake(map[int]*Secret{1: {Fields: []SecretField{field("password", "p")}}})
	_, err := NewWithFetcher(f).Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 1, Field: "token"}})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestResolveAccessDeniedNoRetry(t *testing.T) {
	f := newFake(nil)
	f.forceErr = errors.New(`400 Bad Request: {"errorCode":"API_AccessDenied"}`)
	c := NewWithFetcher(f)
	_, err := c.Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 5, Field: "password"}})
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want ErrAccessDenied", err)
	}
	if f.calls["#5"] != 1 {
		t.Errorf("access-denied must not retry: got %d attempts", f.calls["#5"])
	}
}

func TestResolveTimeout(t *testing.T) {
	f := newFake(map[int]*Secret{1: {Fields: []SecretField{field("password", "p")}}})
	f.delay = 100 * time.Millisecond
	c := NewWithFetcher(f)
	c.timeout = 10 * time.Millisecond
	_, err := c.Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 1, Field: "password"}})
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("got %v, want ErrTimeout", err)
	}
}

// A context cancelled before the call returns without invoking the Fetcher.
func TestResolveHonorsCallerContext(t *testing.T) {
	f := newFake(map[int]*Secret{1: {Fields: []SecretField{field("password", "p")}}})
	f.delay = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewWithFetcher(f).Resolve(ctx, []Mapping{{EnvName: "A", SecretID: 1, Field: "password"}})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
	if f.calls["#1"] != 0 {
		t.Errorf("cancelled call reached the Fetcher %d times", f.calls["#1"])
	}
}

// A Fetcher must honor cancellation itself. The resolver calls it synchronously
// rather than returning while an uncooperative worker remains leaked.
func TestRunDoesNotAbandonUncooperativeCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := run(ctx, 0, func(context.Context) (struct{}, error) {
			close(started)
			<-release
			return struct{}{}, nil
		})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		close(release)
		t.Fatalf("run returned %v while the Fetcher call was still active", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v after the Fetcher returned, want context.Canceled", err)
	}
}

func TestNewBadCACert(t *testing.T) {
	if _, err := New(Config{URL: "https://example", Username: "u", Password: "p", CACert: []byte("not a pem")}); err == nil {
		t.Errorf("want error for invalid CA PEM")
	}
}

func TestResolveTimeoutSuccess(t *testing.T) {
	f := newFake(map[int]*Secret{1: {Fields: []SecretField{field("password", "p")}}})
	c := NewWithFetcher(f)
	c.timeout = 5 * time.Second
	got, err := c.Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 1, Field: "password"}})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if len(got) != 1 || got[0].Value != "p" {
		t.Errorf("got %+v, want A=p", got)
	}
}

// The resolver performs one attempt per fetch — retries live in the Fetcher
// (the api engine) — so a transport failure from the Fetcher surfaces as
// ErrTransport after a single call. Engine-level retry is covered by
// TestConfigRetriesAndBackoffReachTheEngine and the api package tests.
func TestResolveTransportErrorSurfaces(t *testing.T) {
	f := newFake(map[int]*Secret{1: {Fields: []SecretField{field("password", "p")}}})
	f.failuresLeft = 10
	c := NewWithFetcher(f)
	_, err := c.Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 1, Field: "password"}})
	if !errors.Is(err, ErrTransport) {
		t.Errorf("got %v, want ErrTransport", err)
	}
	if f.calls["#1"] != 1 {
		t.Errorf("attempts: got %d, want 1 (the resolver does not retry; the Fetcher owns retries)", f.calls["#1"])
	}
}

func TestMappingRef(t *testing.T) {
	if got := (Mapping{SecretID: 5}).Ref(); got != "id 5" {
		t.Errorf("id ref: got %q, want %q", got, "id 5")
	}
	if got := (Mapping{ByPath: true, Path: `\a\b`}).Ref(); got != `path \a\b` {
		t.Errorf("path ref: got %q, want %q", got, `path \a\b`)
	}
}

func TestNewMissingURL(t *testing.T) {
	if _, err := New(Config{Username: "u", Password: "p"}); err == nil {
		t.Errorf("no URL: want error from underlying client")
	}
}

func TestValidEnvName(t *testing.T) {
	for _, s := range []string{"A", "_", "DB_PASS", "_x9", "A1B2"} {
		if !validEnvName(s) {
			t.Errorf("validEnvName(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "1A", "A B", "a-b", "a.b", "`id`", "A;B", "A$B", "PATH="} {
		if validEnvName(s) {
			t.Errorf("validEnvName(%q) = true, want false", s)
		}
	}
}

func TestEnvify(t *testing.T) {
	cases := []struct{ in, want string }{
		{"password", "PASSWORD"},
		{"api-key", "API_KEY"},
		{"host.name", "HOST_NAME"},
		{"a1_b", "A1_B"},
	}
	for _, c := range cases {
		if got := envify(c.in); got != c.want {
			t.Errorf("envify(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

// An embedded standalone 401/403 is a denial; a longer number that merely
// starts with those digits — a secret id in a 400 body — is not.
func TestDiagnoseEmbeddedStatusWordBoundary(t *testing.T) {
	cases := []struct {
		msg    string
		denial bool
	}{
		{"fetching secret: 400 Bad Request: secret 4013 is checked out by another user", false},
		{"fetching secret: 400 Bad Request: item 4030 unavailable", false},
		{"fetching secret: upstream failed after 403ms", false},
		{"fetching secret: worker job401 failed", false},
		{"fetching secret: HTTP_403_CODE", false},
		{"fetching secret: upstream said 401 Unauthorized", true},
		{"fetching secret: gateway returned 403", true},
		// status:401 is undetectable without also matching port numbers
		// (dial tcp host:401) and id=401 shapes; the prose form and the
		// denials markers cover real servers.
		{"fetching secret: upstream status:401", false},
	}
	for _, tc := range cases {
		_, sentinel := diagnose(errors.New(tc.msg))
		if got := errors.Is(sentinel, ErrAccessDenied); got != tc.denial {
			t.Errorf("%q: denial=%v, want %v", tc.msg, got, tc.denial)
		}
	}
}

// Punctuation-adjacent numbers are not denials: only a whitespace-preceded,
// strictly-terminated 401/403 reads as an embedded status.
func TestDenialStatusRequiresProseBoundaries(t *testing.T) {
	cases := []struct {
		msg    string
		denial bool
	}{
		{"400 Bad Request: invalid secret path /prod/403/db", false},
		{"400 Bad Request: item id=401 rejected", false},
		{"proxy said (403) while routing", false},
		{"took 403ms to answer", false},
		{"upstream returned 401 Unauthorized", true},
		{"gateway returned 403", true},
	}
	for _, tc := range cases {
		if got := containsDenialStatus(tc.msg); got != tc.denial {
			t.Errorf("%q: got %v, want %v", tc.msg, got, tc.denial)
		}
	}
}
