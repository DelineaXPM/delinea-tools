package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ssKey(url string) CacheKey {
	return CacheKey{URL: url, Kind: TargetSecretServer, Identity: "u"}
}

func freshToken(now time.Time, tok string) CachedToken {
	return CachedToken{AccessToken: tok, TokenType: "Bearer", ObtainedAt: now, ExpiresAt: now.Add(time.Hour)}
}

func TestCachedTokenFresh(t *testing.T) {
	obtained := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := obtained.Add(time.Hour)
	tok := CachedToken{AccessToken: "test-token", ObtainedAt: obtained, ExpiresAt: expires}
	cases := []struct {
		name string
		tok  CachedToken
		now  time.Time
		want bool
	}{
		{"fresh", tok, obtained.Add(time.Minute), true},
		{"just under 90 percent", tok, obtained.Add(53 * time.Minute), true},
		{"past 90 percent", tok, obtained.Add(55 * time.Minute), false},
		{"past expiry", tok, expires.Add(time.Minute), false},
		{"inside final minute", tok, expires.Add(-30 * time.Second), false},
		{"empty token", CachedToken{ObtainedAt: obtained, ExpiresAt: expires}, obtained.Add(time.Minute), false},
		{"inverted lifetime", CachedToken{AccessToken: "test-token", ObtainedAt: expires, ExpiresAt: obtained}, obtained, false},
		{"short lifetime reusable early", CachedToken{AccessToken: "test-token", ObtainedAt: obtained, ExpiresAt: obtained.Add(30 * time.Second)}, obtained.Add(time.Second), true},
		{"short lifetime past 90 percent", CachedToken{AccessToken: "test-token", ObtainedAt: obtained, ExpiresAt: obtained.Add(30 * time.Second)}, obtained.Add(28 * time.Second), false},
		{"60s lifetime reusable early", CachedToken{AccessToken: "test-token", ObtainedAt: obtained, ExpiresAt: obtained.Add(time.Minute)}, obtained.Add(time.Second), true},
	}
	for _, tc := range cases {
		if got := tc.tok.Fresh(tc.now); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// CachedToken crosses the public TokenCache boundary into consumer code, so
// fmt and JSON must redact the live AccessToken — while field access keeps the
// real value for a cache that reads it directly.
func TestCachedTokenRedaction(t *testing.T) {
	tok := CachedToken{AccessToken: "tok-cache-leakme-9999", TokenType: "Bearer"}
	jsonBytes, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, out := range []string{
		fmt.Sprintf("%v", tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%#v", tok),
		fmt.Sprintf("%v", &tok), string(jsonBytes),
	} {
		if strings.Contains(out, "tok-cache-leakme-9999") {
			t.Errorf("leaked token: %s", out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("expected [REDACTED] marker: %s", out)
		}
	}
	if tok.AccessToken != "tok-cache-leakme-9999" {
		t.Errorf("field access must return the real token, got %q", tok.AccessToken)
	}
	if out := fmt.Sprintf("%+v", CachedToken{TokenType: "Bearer"}); strings.Contains(out, "[REDACTED]") {
		t.Errorf("an empty AccessToken must not be marked [REDACTED]: %s", out)
	}
}

func TestMemoryCacheRoundtrip(t *testing.T) {
	mc := NewMemoryCache()
	now := time.Now()
	key := ssKey("https://x.example.com")
	mc.Store(key, freshToken(now, "tok"))
	got, ok := mc.Load(key)
	if !ok || got.AccessToken != "tok" {
		t.Errorf("load: got %q/%v, want tok/true", got.AccessToken, ok)
	}
	mc.Evict(key)
	if _, ok := mc.Load(key); ok {
		t.Error("load after evict should miss")
	}
}

func TestMemoryCacheEvictMatchingLeavesFreshPeerToken(t *testing.T) {
	mc, ok := NewMemoryCache().(CompareEvicter)
	if !ok {
		t.Fatal("NewMemoryCache must implement CompareEvicter")
	}
	now := time.Now()
	key := ssKey("https://x.example.com")
	mc.Store(key, freshToken(now, "stale"))

	mc.EvictMatching(key, "stale")
	if _, ok := mc.Load(key); ok {
		t.Error("EvictMatching should remove the entry when the stored token matches")
	}

	mc.Store(key, freshToken(now, "fresh"))
	mc.EvictMatching(key, "stale")
	got, ok := mc.Load(key)
	if !ok || got.AccessToken != "fresh" {
		t.Errorf("EvictMatching must not clobber a peer's fresh token: got %q/%v, want fresh/true", got.AccessToken, ok)
	}
}

func TestMemoryCacheKeysAreDistinct(t *testing.T) {
	mc := NewMemoryCache()
	now := time.Now()
	base := CacheKey{URL: "https://x.example.com", Kind: TargetSecretServer, Identity: "u", CredentialDigest: "d1"}
	mc.Store(base, freshToken(now, "tok"))
	variants := []CacheKey{
		{URL: "https://y.example.com", Kind: TargetSecretServer, Identity: "u", CredentialDigest: "d1"},
		{URL: "https://x.example.com", Kind: TargetPlatform, Identity: "u", CredentialDigest: "d1"},
		{URL: "https://x.example.com", Kind: TargetSecretServer, Identity: "v", CredentialDigest: "d1"},
		{URL: "https://x.example.com", Kind: TargetSecretServer, Identity: "u", CredentialDigest: "d2"},
	}
	for _, k := range variants {
		if _, ok := mc.Load(k); ok {
			t.Errorf("key %+v should miss", k)
		}
	}
}

func TestMemoryCacheCapPurgesStale(t *testing.T) {
	mc := NewMemoryCache().(*memoryCache)
	now := time.Now()
	stale := CachedToken{AccessToken: "old", ObtainedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	for i := range maxMemoryCacheEntries {
		mc.Store(CacheKey{URL: fmt.Sprintf("https://%d.example.com", i)}, stale)
	}
	mc.Store(ssKey("https://fresh.example.com"), freshToken(now, "tok"))
	if len(mc.entries) != 1 {
		t.Errorf("entries after purge: got %d, want 1", len(mc.entries))
	}
	if _, ok := mc.Load(ssKey("https://fresh.example.com")); !ok {
		t.Error("fresh entry should survive the purge")
	}
}

func TestMemoryCacheCapEvictsWhenAllFresh(t *testing.T) {
	mc := NewMemoryCache().(*memoryCache)
	now := time.Now()
	for i := range maxMemoryCacheEntries {
		mc.Store(CacheKey{URL: fmt.Sprintf("https://%d.example.com", i)}, freshToken(now, "tok"))
	}
	mc.Store(ssKey("https://one-more.example.com"), freshToken(now, "tok"))
	if len(mc.entries) != maxMemoryCacheEntries {
		t.Errorf("entries: got %d, want %d", len(mc.entries), maxMemoryCacheEntries)
	}
	if _, ok := mc.Load(ssKey("https://one-more.example.com")); !ok {
		t.Error("newest entry should be stored")
	}
}

func TestCredentialDigest(t *testing.T) {
	if credentialDigest("") != "" {
		t.Error("empty secret should produce an empty digest")
	}
	d1, d1again, d2 := credentialDigest("p1"), credentialDigest("p1"), credentialDigest("p2")
	if d1 == "" || d1 != d1again {
		t.Error("digest should be non-empty and stable within the process")
	}
	if d1 == d2 {
		t.Error("different secrets should produce different digests")
	}
}

func TestClientsShareMemoryCache(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants++
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()

	mc := NewMemoryCache()
	cfg := Config{URL: srv.URL, Username: "u", Password: "p", Cache: mc}
	for range 3 {
		c, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := c.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if tok != "test-token" {
			t.Errorf("token: got %q, want test-token", tok)
		}
	}
	if grants != 1 {
		t.Errorf("grants: got %d, want 1", grants)
	}
}

func TestClientDiscardsMalformedCachedToken(t *testing.T) {
	for _, cached := range []string{"abc", "bad\nvalue"} {
		t.Run(fmt.Sprintf("%q", cached), func(t *testing.T) {
			grants := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				grants++
				fmt.Fprint(w, grantJSON("fresh-token"))
			}))
			defer srv.Close()

			mc := NewMemoryCache()
			key := CacheKey{URL: srv.URL, Kind: TargetSecretServer, Identity: "u", CredentialDigest: credentialDigest("p")}
			mc.Store(key, freshToken(time.Now(), cached))
			c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: mc})
			if err != nil {
				t.Fatal(err)
			}
			tok, err := c.Token(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if tok != "fresh-token" || grants != 1 {
				t.Errorf("Token returned %q after %d grants, want fresh-token after 1", tok, grants)
			}
			stored, ok := mc.Load(key)
			if !ok || stored.AccessToken != "fresh-token" {
				t.Errorf("cache after grant: got %q/%v, want fresh-token/true", stored.AccessToken, ok)
			}
		})
	}
}

func TestMemoryCacheInvalidatedByCredentialChange(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants++
		fmt.Fprint(w, grantJSON(fmt.Sprintf("tok-%d", grants)))
	}))
	defer srv.Close()

	mc := NewMemoryCache()
	for _, password := range []string{"p1", "p2"} {
		c, err := New(Config{URL: srv.URL, Username: "u", Password: password, Cache: mc})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if grants != 2 {
		t.Errorf("grants: got %d, want 2 (a changed password must not reuse the cached token)", grants)
	}
}

func TestClientEvictsAndReplaysOn401(t *testing.T) {
	grants, apiCalls := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			grants++
			fmt.Fprint(w, grantJSON("fresh"))
		case "/api/v1/thing":
			apiCalls++
			if r.Header.Get("Authorization") == "Bearer stale" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	mc := NewMemoryCache()
	seed := CacheKey{URL: srv.URL, Kind: TargetSecretServer, Identity: "u", CredentialDigest: credentialDigest("p")}
	mc.Store(seed, freshToken(time.Now(), "stale"))

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: mc})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/api/v1/thing"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if grants != 1 {
		t.Errorf("grants: got %d, want 1", grants)
	}
	if apiCalls != 2 {
		t.Errorf("api calls: got %d, want 2", apiCalls)
	}
	got, ok := mc.Load(seed)
	if !ok || got.AccessToken != "fresh" {
		t.Errorf("cache after replay: got %q/%v, want fresh/true", got.AccessToken, ok)
	}
}

func TestClientFreshGrantNotMarkedFromCache(t *testing.T) {
	grants, apiCalls := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			grants++
			fmt.Fprint(w, grantJSON("test-token"))
		default:
			apiCalls++
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: NewMemoryCache()})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/api/v1/thing"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", resp.StatusCode)
	}
	if grants != 1 {
		t.Errorf("grants: got %d, want 1 (no replay for a token granted this run)", grants)
	}
	if apiCalls != 1 {
		t.Errorf("api calls: got %d, want 1", apiCalls)
	}
}

func TestDomainScopesTheCacheKey(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants++
		fmt.Fprint(w, grantJSON(fmt.Sprintf("tok-%d", grants)))
	}))
	defer srv.Close()

	mc := NewMemoryCache()
	for _, domain := range []string{"corp", "lab"} {
		c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Domain: domain, Cache: mc})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if grants != 2 {
		t.Errorf("grants: got %d, want 2 (different domains must not share a token)", grants)
	}
}

// Two clients built without a Cache share the process-wide default: code
// that constructs a client per operation performs one grant, not one per
// client. The zero-value Config is the safe configuration.
func TestDefaultCacheSharesGrantsAcrossClients(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants++
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()

	for range 3 {
		c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if grants != 1 {
		t.Errorf("grants: got %d, want 1 (clients without a Cache share the default)", grants)
	}
}

func TestDisableCacheGrantsPerClient(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants++
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()

	for range 2 {
		c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", DisableCache: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if grants != 2 {
		t.Errorf("grants: got %d, want 2 (DisableCache must not share tokens)", grants)
	}
}

func TestDisableCacheWithExplicitCacheIsConfigError(t *testing.T) {
	_, err := New(Config{URL: "https://x.example.com", Username: "u", Password: "p",
		Cache: NewMemoryCache(), DisableCache: true})
	if !errors.Is(err, ErrConfig) {
		t.Errorf("got %v, want ErrConfig for DisableCache + explicit Cache", err)
	}
}

func TestCacheSeparatesGrantHeaders(t *testing.T) {
	var grants atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants.Add(1)
		fmt.Fprint(w, grantJSON("token-"+r.Header.Get("X-Tenant")))
	}))
	defer srv.Close()
	shared := NewMemoryCache()
	for _, tenant := range []string{"alpha", "beta"} {
		c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: shared,
			Header: http.Header{"X-Tenant": {tenant}}})
		if err != nil {
			t.Fatal(err)
		}
		if tok, err := c.Token(context.Background()); err != nil || tok != "token-"+tenant {
			t.Errorf("tenant %s: got %q, %v", tenant, tok, err)
		}
	}
	if got := grants.Load(); got != 2 {
		t.Errorf("grants: got %d, want 2 for distinct gateway contexts", got)
	}
}

// A custom Transport can change what a grant means, so its tokens are never
// interchangeable: transport clients do not participate in caching at all —
// each grants through its own transport — and an explicit Cache alongside a
// Transport is refused as contradictory rather than left as dead weight.
func TestCacheSeparatesCustomTransports(t *testing.T) {
	makeTransport := func(token string) *roundTripFunc {
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(grantJSON(token))),
				Request:    r,
			}, nil
		})
		return &rt
	}
	for _, tc := range []struct {
		transport http.RoundTripper
		token     string
	}{{makeTransport("transport-a"), "transport-a"}, {makeTransport("transport-b"), "transport-b"}} {
		c, err := New(Config{URL: "https://vault.example.com", Username: "u", Password: "p", Transport: tc.transport})
		if err != nil {
			t.Fatal(err)
		}
		if tok, err := c.Token(context.Background()); err != nil || tok != tc.token {
			t.Errorf("got %q, %v; want %q", tok, err, tc.token)
		}
	}
	_, err := New(Config{URL: "https://vault.example.com", Username: "u", Password: "p",
		Cache: NewMemoryCache(), Transport: makeTransport("x")})
	if !errors.Is(err, ErrConfig) {
		t.Errorf("explicit Cache with a custom Transport: got %v, want ErrConfig", err)
	}
}

// A process-level replacement of http.DefaultTransport is just as opaque as
// Config.Transport. Clients that capture different replacements must not share
// a cached grant merely because their URL and credentials match.
func TestCacheSeparatesOpaqueDefaultTransports(t *testing.T) {
	orig := http.DefaultTransport
	defer func() { http.DefaultTransport = orig }()

	var calls atomic.Int32
	makeTransport := func(token string) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(grantJSON(token))),
				Request:    r,
			}, nil
		})
	}

	for _, token := range []string{"default-a", "default-b"} {
		http.DefaultTransport = makeTransport(token)
		c, err := New(Config{URL: "https://opaque-default-cache.example.com", Username: "u", Password: "p"})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.Token(context.Background()); err != nil || got != token {
			t.Errorf("got %q, %v; want %q", got, err, token)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("grant calls: got %d, want 2", got)
	}

	_, err := New(Config{URL: "https://opaque-default-cache.example.com", Username: "u", Password: "p", Cache: NewMemoryCache()})
	if !errors.Is(err, ErrConfig) {
		t.Errorf("explicit Cache with an opaque default transport: got %v, want ErrConfig", err)
	}
}

// TLS trust settings scope the grant: a client that skips verification (or
// trusts extra roots) must not share tokens — or in-flight grants — with a
// strictly verifying client for the same credential, or the strict client
// would authenticate with a token granted over a channel it refused to trust.
func TestCacheSeparatesTLSTrustSettings(t *testing.T) {
	base := Config{URL: "https://vault.example.com", Username: "u", Password: "p"}
	strict, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	skipCfg := base
	skipCfg.SkipTLSVerify = true
	skip, err := New(skipCfg)
	if err != nil {
		t.Fatal(err)
	}
	caCfg := base
	caCfg.CACert = selfSignedCACertPEM(t)
	ca, err := New(caCfg)
	if err != nil {
		t.Fatal(err)
	}
	if strict.key == skip.key || strict.key == ca.key || skip.key == ca.key {
		t.Errorf("TLS-trust variants must not share a cache key: strict=%v skip=%v ca=%v",
			strict.key, skip.key, ca.key)
	}
}

// The opacity rule keys on identity, not type: a replacement that happens to
// be another *http.Transport still changes the network path, so two clients
// built under two different *http.Transport replacements must not share a
// cached grant either.
func TestCacheSeparatesReplacedHTTPTransportDefaults(t *testing.T) {
	orig := http.DefaultTransport
	defer func() { http.DefaultTransport = orig }()

	var grants atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, grantJSON(fmt.Sprintf("replaced-%d", grants.Add(1))))
	}))
	defer srv.Close()

	for i := range 2 {
		replacement := http.DefaultTransport.(*http.Transport)
		if i == 1 {
			replacement = orig.(*http.Transport)
		}
		http.DefaultTransport = replacement.Clone() // a distinct *http.Transport each time
		c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("replaced-%d", i+1)
		if got, err := c.Token(context.Background()); err != nil || got != want {
			t.Errorf("client %d: got %q, %v; want %q (no sharing across replacements)", i, got, err, want)
		}
	}
	if got := grants.Load(); got != 2 {
		t.Errorf("grants: got %d, want 2", got)
	}
}
