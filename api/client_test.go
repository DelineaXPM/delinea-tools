package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeTransport struct {
	calls      int
	failures   int
	err        error
	status     int
	statuses   []int
	retryAfter string
	lastReq    *http.Request
	lastBody   string
}

// Response started as a five-field public data type. Keep every field exported
// so downstream positional literals continue to compile when diagnostics gain
// new internal state.
func TestResponsePublicShape(t *testing.T) {
	typ := reflect.TypeFor[Response]()
	want := []string{"StatusCode", "Status", "Proto", "Header", "Body"}
	if typ.NumField() != len(want) {
		t.Fatalf("Response has %d fields, want %d exported fields", typ.NumField(), len(want))
	}
	for i, name := range want {
		field := typ.Field(i)
		if field.Name != name || !field.IsExported() {
			t.Errorf("Response field %d: got %s (exported=%v), want exported %s", i, field.Name, field.IsExported(), name)
		}
	}
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.calls++
	f.lastReq = r
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		f.lastBody = string(b)
	}
	if f.calls <= f.failures {
		err := f.err
		if err == nil {
			err = errors.New("connection reset")
		}
		return nil, err
	}
	status := f.status
	if len(f.statuses) > 0 {
		status = f.statuses[0]
		f.statuses = f.statuses[1:]
	}
	if status == 0 {
		status = 200
	}
	h := http.Header{}
	if f.retryAfter != "" && (status == 429 || status == 503) {
		h.Set("Retry-After", f.retryAfter)
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d status", status),
		Proto:      "HTTP/1.1",
		Header:     h,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    r,
	}, nil
}

// A process that has replaced http.DefaultTransport with a non-*http.Transport
// wrapper must get an ErrConfig from New when TLS options need the default
// transport, not a panic.
func TestNewErrsWhenDefaultTransportSwapped(t *testing.T) {
	orig := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, nil })
	defer func() { http.DefaultTransport = orig }()

	if _, err := New(Config{URL: "https://x.example.com", Token: "test-token", SkipTLSVerify: true}); !errors.Is(err, ErrConfig) {
		t.Errorf("got %v, want ErrConfig instead of a panic", err)
	}
	// With no TLS options, the swapped transport is used as-is (no panic).
	if _, err := New(Config{URL: "https://x.example.com", Token: "test-token"}); err != nil {
		t.Errorf("got %v, want the swapped transport used without error", err)
	}
}

func TestNewHandlesNonComparableInitialDefaultTransport(t *testing.T) {
	originalDefault := http.DefaultTransport
	originalInitial := initialDefaultTransport
	defer func() {
		http.DefaultTransport = originalDefault
		initialDefaultTransport = originalInitial
	}()

	rt := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") })
	http.DefaultTransport = rt
	initialDefaultTransport = rt
	if _, err := New(Config{URL: "https://vault.example.com", Token: "test-token"}); err != nil {
		t.Fatalf("New rejected a non-comparable default transport: %v", err)
	}
}

func TestNewIgnoresInPlaceDefaultTransportMutation(t *testing.T) {
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok || initialDefaultHTTPTransport == nil {
		t.Skip("package did not initialize under the standard HTTP transport")
	}
	original := dt.MaxIdleConns
	t.Cleanup(func() { dt.MaxIdleConns = original })
	dt.MaxIdleConns = initialDefaultHTTPTransport.MaxIdleConns + 123

	c, err := New(Config{URL: "https://vault.example.com", Token: "test-token", DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	got := c.hc.Transport.(*http.Transport).MaxIdleConns
	if want := initialDefaultHTTPTransport.MaxIdleConns; got != want {
		t.Errorf("client cloned mutated http.DefaultTransport: got MaxIdleConns %d, want startup value %d", got, want)
	}
}

func TestConfiguredTokenIgnoresStaleGrantIdentity(t *testing.T) {
	ft := &fakeTransport{}
	c, err := New(Config{
		URL: "https://example.com", Token: "test-token", Username: "stale-user",
		Transport: ft,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Target() != TargetAuto {
		t.Fatalf("target = %q, want auto for a targetless bearer token", c.Target())
	}
	resp, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ft.calls != 1 || ft.lastReq.Header.Get("Authorization") != "Bearer test-token" {
		t.Fatalf("token was not used directly: calls=%d authorization=%q", ft.calls, ft.lastReq.Header.Get("Authorization"))
	}
}

func TestRejectsInvalidHeadersAsConfiguration(t *testing.T) {
	for _, header := range []http.Header{
		{"X-Bad": {"ok\nbad"}},
		{"X-Gateway": {"one"}, "x-gateway": {"two"}},
	} {
		if _, err := New(Config{
			URL: "https://example.com", Token: "test-token", Header: header,
		}); !errors.Is(err, ErrConfig) {
			t.Errorf("Config.Header %v: got %v, want ErrConfig", header, err)
		}
	}

	ft := &fakeTransport{}
	c := tokenClient(t, ft)
	for _, header := range []http.Header{
		{"Bad Name": {"value"}},
		{"X-Bad": {"ok\nbad"}},
		{"Host": {"bad host"}},
		{"X-Gateway": {"one"}, "x-gateway": {"two"}},
	} {
		if _, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x", Header: header}); !errors.Is(err, ErrConfig) {
			t.Errorf("header %v: got %v, want ErrConfig", header, err)
		}
	}
	if ft.calls != 0 {
		t.Fatalf("invalid headers reached the transport %d times", ft.calls)
	}
}

func TestValidateHeadersDoesNotExposeValues(t *testing.T) {
	if err := ValidateHeaders(http.Header{"X-Gateway": {"valid-value"}}); err != nil {
		t.Fatalf("valid header rejected: %v", err)
	}
	const secret = "do-not-repeat-header-secret"
	for _, header := range []http.Header{
		{"Bad Name": {secret}},
		{"X-Gateway": {secret + "\n"}},
		{"Host": {secret + " invalid"}},
	} {
		err := ValidateHeaders(header)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Errorf("ValidateHeaders error = %v, want a refusal without the value", err)
		}
	}
}

func TestNewSnapshotsMutableConfig(t *testing.T) {
	ft := &fakeTransport{}
	header := http.Header{"X-Gateway": {"original"}}
	allowed := []string{"vault.example.com"}
	c, err := New(Config{
		URL: "https://example.com", Token: "test-token", Transport: ft,
		Header: header, AllowedVaultHosts: allowed,
	})
	if err != nil {
		t.Fatal(err)
	}

	header.Set("X-Gateway", "mutated")
	header.Set("X-Bad", "ok\nbad")
	allowed[0] = "attacker.example.com"

	resp, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := ft.lastReq.Header.Get("X-Gateway"); got != "original" {
		t.Errorf("request header = %q, want the value snapshotted by New", got)
	}
	if got := ft.lastReq.Header.Get("X-Bad"); got != "" {
		t.Errorf("post-New header mutation reached request: %q", got)
	}
	if got := c.cfg.AllowedVaultHosts; len(got) != 1 || got[0] != "vault.example.com" {
		t.Errorf("allowed vault hosts = %v, want the value snapshotted by New", got)
	}

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	caCert := certPEM(tlsServer)
	cWithCA, err := New(Config{URL: tlsServer.URL, Token: "test-token", CACert: caCert})
	if err != nil {
		t.Fatal(err)
	}
	wantCA := string(caCert)
	caCert[0] = 'X'
	if got := string(cWithCA.cfg.CACert); got != wantCA {
		t.Error("CA certificate changed through caller-owned storage")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type contextBlockingBody struct{ ctx context.Context }

func (b *contextBlockingBody) Read([]byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (*contextBlockingBody) Close() error { return nil }

func TestDoRefusesCrossOriginRedirectAsConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example.com/x", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	_, derr := c.Do(context.Background(), Request{Method: "GET", Path: "/x"})
	if !errors.Is(derr, ErrConfig) {
		t.Errorf("got %v, want ErrConfig: a refused cross-origin redirect is a permanent misconfiguration", derr)
	}
	if errors.Is(derr, ErrTransport) {
		t.Errorf("a refused redirect must not be classified retriable transport: %v", derr)
	}
}

func TestConcurrentGrantsCoalesce(t *testing.T) {
	var grants atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants.Add(1)
			time.Sleep(20 * time.Millisecond) // widen the window for peers to coalesce
			fmt.Fprint(w, grantJSON("test-token"))
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/x"})
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if g := grants.Load(); g != 1 {
		t.Errorf("token grants: got %d, want 1 (concurrent callers must coalesce onto one grant)", g)
	}
}

// Concurrent 401s on a shared token collapse to one re-grant: evictToken only
// clears the token the caller was rejected on, so a peer that already
// refreshed is not wiped again.
func TestConcurrent401sCoalesceReauth(t *testing.T) {
	var grants atomic.Int64
	var fresh atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			n := grants.Add(1)
			if n >= 2 {
				fresh.Store(true)
			}
			time.Sleep(15 * time.Millisecond)
			fmt.Fprint(w, grantJSON(fmt.Sprintf("tok-%d", n)))
			return
		}
		if !fresh.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil { // prime tok-1
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/x"})
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if g := grants.Load(); g != 2 {
		t.Errorf("grants: got %d, want 2 (one prime + one coalesced re-auth for the whole 401 storm)", g)
	}
}

// A panic in the grant path must not wedge the client: the in-flight-grant
// cleanup runs even on panic, so c.granting is cleared and g.done closed, and
// a later call (after the panic is recovered) is not blocked forever.
type panicOnceTransport struct {
	grants int
}

func (t *panicOnceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/oauth2/token" {
		t.grants++
		if t.grants == 1 {
			panic("transport fault")
		}
		return &http.Response{StatusCode: 200, Status: "200", Proto: "HTTP/1.1", Header: http.Header{},
			Body: io.NopCloser(strings.NewReader(grantJSON("test-token"))), Request: r}, nil
	}
	return &http.Response{StatusCode: 200, Status: "200", Proto: "HTTP/1.1", Header: http.Header{},
		Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
}

func TestGrantPanicDoesNotWedgeClient(t *testing.T) {
	c, err := New(Config{URL: "https://example.com", Username: "u", Password: "p", DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	c.hc.Transport = &panicOnceTransport{}

	func() {
		defer func() { _ = recover() }() // the embedder recovers, as a server would
		c.Token(context.Background())
	}()

	// The client must still be usable — not blocked forever on a stale
	// c.granting whose done channel never closed.
	done := make(chan error, 1)
	go func() { _, e := c.Token(context.Background()); done <- e }()
	select {
	case e := <-done:
		if e != nil {
			t.Errorf("second Token after a recovered grant panic: got %v, want success", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client wedged: a grant panic left c.granting set and waiters blocked")
	}
}

// The grant leader's own context cancellation is not inherited by a waiter
// with a healthy context: the waiter takes its own attempt and succeeds.
func TestWaiterDoesNotInheritLeaderContextCancel(t *testing.T) {
	var grants atomic.Int64
	proceed := make(chan struct{})
	leaderStarted := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			if grants.Add(1) == 1 {
				close(leaderStarted)
				<-proceed // hold the first (leader's) grant until its ctx cancels
			}
			fmt.Fprint(w, grantJSON("test-token"))
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan struct{})
	go func() { c.Token(leaderCtx); close(leaderDone) }() // becomes the granter, blocks
	<-leaderStarted

	// A waiter with a healthy context coalesces onto the leader.
	waiterDone := make(chan error, 1)
	go func() { _, e := c.Token(context.Background()); waiterDone <- e }()
	waitForGrantWaiters(t, c, 1)

	cancelLeader() // the leader's grant now fails on its cancelled context
	<-leaderDone   // let the leader finish and publish its failure
	close(proceed) // the waiter's own retry grant can complete

	select {
	case e := <-waiterDone:
		if e != nil {
			t.Errorf("waiter with a healthy context got %v, want success (it must not inherit the leader's cancellation)", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiter never completed")
	}
}

// When the leader's grant fails on its own cancelled context, the coalesced
// waiters do not each mount a grant: exactly one takes over and the rest share
// its result. A wave of 20 waiters behind a cancelled leader costs two grants
// (the leader's abandoned attempt plus one shared retry), never one per waiter.
func TestConcurrentWaitersBoundGrantsOnLeaderCancel(t *testing.T) {
	var grants atomic.Int64
	proceed := make(chan struct{})
	leaderStarted := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			if grants.Add(1) == 1 {
				close(leaderStarted)
				<-proceed // hold the leader's grant until its ctx cancels
			}
			fmt.Fprint(w, grantJSON("test-token"))
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan struct{})
	go func() { c.Token(leaderCtx); close(leaderDone) }()
	<-leaderStarted

	const waiters = 20
	got := make(chan error, waiters)
	for range waiters {
		go func() { _, e := c.Token(context.Background()); got <- e }()
	}
	waitForGrantWaiters(t, c, waiters)

	cancelLeader()
	<-leaderDone
	close(proceed)

	for range waiters {
		select {
		case e := <-got:
			if e != nil {
				t.Errorf("waiter with a healthy context got %v, want success", e)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a waiter never completed")
		}
	}
	if g := grants.Load(); g != 2 {
		t.Errorf("grants: got %d, want 2 (leader's cancelled attempt + one shared retry for all waiters)", g)
	}
}

// A failed grant is shared with coalesced waiters, not re-attempted by each:
// a concurrent wave against a rejected credential must cost one grant, or the
// repeated failures race the account toward a lockout.
func TestConcurrentFailedGrantsCoalesce(t *testing.T) {
	var grants atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants.Add(1)
			time.Sleep(20 * time.Millisecond)
			w.WriteHeader(http.StatusUnauthorized) // credential rejected
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var denied atomic.Int64
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Token(context.Background()); errors.Is(err, ErrAccessDenied) {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()
	if denied.Load() != 20 {
		t.Errorf("all 20 callers should see the denial, got %d", denied.Load())
	}
	if g := grants.Load(); g != 1 {
		t.Errorf("grants: got %d, want 1 (a failed grant must be shared, not re-attempted per caller)", g)
	}
}

// A server transient that fails the leader's grant is shared with the
// coalesced waiters, not re-mounted as a fresh grant sequence by each: 20
// waiters against a 503-ing endpoint must cost one grant, and every waiter
// gets the transient to hand to its own caller's retry loop.
func TestConcurrentTransientGrantsShareNotStorm(t *testing.T) {
	var grants atomic.Int64
	proceed := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			if grants.Add(1) == 1 {
				<-proceed // hold the leader's grant until the waiters have parked
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}

	leaderDone := make(chan error, 1)
	go func() { _, e := c.Token(context.Background()); leaderDone <- e }()
	time.Sleep(30 * time.Millisecond) // let the leader claim the grant and block

	const waiters = 20
	got := make(chan error, waiters)
	for range waiters {
		go func() { _, e := c.Token(context.Background()); got <- e }()
	}
	time.Sleep(30 * time.Millisecond) // let every waiter coalesce onto the leader
	close(proceed)                    // the leader's grant now fails with 503

	if e := <-leaderDone; !errors.Is(e, ErrTransport) {
		t.Errorf("leader: got %v, want ErrTransport", e)
	}
	for range waiters {
		if e := <-got; !errors.Is(e, ErrTransport) {
			t.Errorf("waiter: got %v, want ErrTransport (shared, not re-granted)", e)
		}
	}
	if g := grants.Load(); g != 1 {
		t.Errorf("grants: got %d, want 1 (a server transient must be shared, not re-attempted per waiter)", g)
	}
}

// A slow endpoint that times out the leader's grant — while the leader's own
// context stays healthy — is the endpoint's condition, shared by every waiter,
// not the leader's alone. Waiters must share the timeout rather than each
// mount a fresh grant against the same slow endpoint: an endpoint timeout
// classifies as ErrTimeout exactly like a leader deadline, so only the
// leader's parent-context state can tell them apart.
func TestConcurrentEndpointTimeoutSharedNotStorm(t *testing.T) {
	var grants atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants.Add(1)
			<-release // never answers within the client's per-request timeout
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	defer close(release)

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 1, Timeout: 250 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	leaderDone := make(chan error, 1)
	go func() { _, e := c.Token(context.Background()); leaderDone <- e }() // healthy context
	time.Sleep(25 * time.Millisecond)

	const waiters = 15
	got := make(chan error, waiters)
	for range waiters {
		go func() { _, e := c.Token(context.Background()); got <- e }()
	}

	if e := <-leaderDone; !errors.Is(e, ErrTimeout) {
		t.Errorf("leader: got %v, want ErrTimeout", e)
	}
	for range waiters {
		if e := <-got; !errors.Is(e, ErrTimeout) {
			t.Errorf("waiter: got %v, want ErrTimeout (shared endpoint timeout, not re-granted)", e)
		}
	}
	if g := grants.Load(); g != 1 {
		t.Errorf("grants: got %d, want 1 (an endpoint timeout must be shared, not re-attempted per waiter)", g)
	}
}

func TestLeaderLocalFailure(t *testing.T) {
	cases := []struct {
		name     string
		ctxErr   error
		grantErr error
		want     bool
	}{
		{"cancelled grant wrapping cancel", context.Canceled, classifyTransport(context.Canceled), true},
		{"deadline grant wrapping deadline", context.DeadlineExceeded, classifyTransport(context.DeadlineExceeded), true},
		{"endpoint 503 with late cancel is shared", context.Canceled, fmt.Errorf("%w: 503", ErrTransport), false},
		{"denial with late cancel is shared", context.Canceled, fmt.Errorf("%w: bad creds", ErrAccessDenied), false},
		{"config error with late cancel is shared", context.Canceled, fmt.Errorf("%w: bad url", ErrConfig), false},
		{"bare net timeout with late cancel is shared", context.Canceled, fmt.Errorf("%w: i/o timeout", ErrTimeout), false},
		{"endpoint timeout, healthy context", nil, classifyTransport(context.DeadlineExceeded), false},
		{"denial, healthy context", nil, fmt.Errorf("%w: bad creds", ErrAccessDenied), false},
	}
	for _, tc := range cases {
		if got := leaderLocalFailure(tc.ctxErr, tc.grantErr); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// spyCompareEvicter is a custom TokenCache that also implements CompareEvicter,
// counting the atomic evictions and delegating to a real cache.
type spyCompareEvicter struct {
	TokenCache
	evictMatching int
}

func (s *spyCompareEvicter) EvictMatching(key CacheKey, token string) {
	s.evictMatching++
	s.TokenCache.(CompareEvicter).EvictMatching(key, token)
}

// A caller-supplied cache that implements CompareEvicter gets the atomic
// eviction path, not the racy Load-then-Evict fallback.
func TestEvictTokenUsesCompareEvicterForCustomCache(t *testing.T) {
	spy := &spyCompareEvicter{TokenCache: NewMemoryCache()}
	c, err := New(Config{URL: "https://vault.example.com", Username: "u", Password: "p", Cache: spy})
	if err != nil {
		t.Fatal(err)
	}
	spy.Store(c.key, freshToken(time.Now(), "rejected"))

	c.evictToken("rejected")

	if spy.evictMatching != 1 {
		t.Errorf("EvictMatching calls: got %d, want 1 (a custom CompareEvicter must get the atomic path)", spy.evictMatching)
	}
	if _, ok := spy.Load(c.key); ok {
		t.Error("the rejected token should have been evicted")
	}
}

// reentrantEvicter is a custom cache whose EvictMatching calls back into the
// Client. If evictToken held c.mu across the call, that reentrancy would
// self-deadlock on the non-reentrant mutex.
type reentrantEvicter struct {
	TokenCache
	c *Client
}

func (r *reentrantEvicter) EvictMatching(CacheKey, string) { r.c.Token(context.Background()) }

// evictToken must not hold c.mu while calling a caller-supplied cache: a cache
// that blocks or re-enters the Client would otherwise stall or deadlock every
// concurrent Token() caller. A reentrant EvictMatching completing proves the
// lock is released first.
func TestEvictTokenReleasesLockBeforeCacheCall(t *testing.T) {
	c, err := New(Config{URL: "https://vault.example.com", Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	c.cache = &reentrantEvicter{TokenCache: NewMemoryCache(), c: c}
	c.mu.Lock()
	c.token = freshToken(c.now(), "other") // a reentrant Token() returns this without granting
	c.mu.Unlock()

	done := make(chan struct{})
	go func() { c.evictToken("rejected"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("evictToken deadlocked: it held c.mu across the cache's reentrant call")
	}
}

// lockProbingLoader.Load acquires c.mu itself, which deadlocks unless
// accessToken released the lock before calling the cache. It returns a fresh
// token so the caller finishes without a grant.
type lockProbingLoader struct {
	TokenCache
	c      *Client
	tok    CachedToken
	probed atomic.Bool
}

func (l *lockProbingLoader) Load(CacheKey) (CachedToken, bool) {
	// Take c.mu to prove accessToken released it before calling the cache, and
	// record it under the lock (a real critical section, not an empty one).
	l.c.mu.Lock()
	l.probed.Store(true)
	l.c.mu.Unlock()
	return l.tok, true
}

// accessToken must run the cache Load with c.mu released; a cache whose Load
// takes the lock would otherwise deadlock the process.
func TestAccessTokenLoadsCacheOutsideLock(t *testing.T) {
	c, err := New(Config{URL: "https://vault.example.com", Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	loader := &lockProbingLoader{TokenCache: NewMemoryCache(), c: c, tok: freshToken(c.now(), "cached")}
	c.cache = loader

	type result struct {
		tok    string
		reused bool
		err    error
	}
	res := make(chan result, 1)
	go func() {
		tok, reused, err := c.accessToken(context.Background())
		res <- result{tok, reused, err}
	}()
	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("accessToken: %v", r.err)
		}
		if r.tok != "cached" {
			t.Errorf("got token %q, want the token the cache Load returned", r.tok)
		}
		if !r.reused {
			t.Error("a token loaded from the cache must be marked reused")
		}
		if !loader.probed.Load() {
			t.Error("cache Load was never called")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("accessToken deadlocked: it held c.mu across the cache Load")
	}
}

// blockingLoader.Load blocks until released, so the test can grant a newer
// token while a cache Load is in flight and prove accessToken does not clobber
// it with the (older) loaded token when it reacquires the lock.
type blockingLoader struct {
	TokenCache
	started chan struct{}
	release chan struct{}
	tok     CachedToken
	once    sync.Once
}

func (l *blockingLoader) Load(CacheKey) (CachedToken, bool) {
	l.once.Do(func() { close(l.started) })
	<-l.release
	return l.tok, true
}

// A cache Load that returns late must not overwrite a token another caller
// granted in the meantime: accessToken rechecks c.token before installing the
// loaded value and returns the fresher one.
func TestAccessTokenLoadDoesNotClobberNewerToken(t *testing.T) {
	c, err := New(Config{URL: "https://vault.example.com", Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	loader := &blockingLoader{
		TokenCache: NewMemoryCache(),
		started:    make(chan struct{}),
		release:    make(chan struct{}),
		tok:        freshToken(c.now(), "stale-loaded"),
	}
	c.cache = loader

	type result struct {
		tok    string
		reused bool
		err    error
	}
	res := make(chan result, 1)
	go func() {
		tok, reused, err := c.accessToken(context.Background())
		res <- result{tok: tok, reused: reused, err: err}
	}()

	<-loader.started // Load is now blocked
	// A peer grants a newer token while the Load is in flight.
	c.mu.Lock()
	c.token = freshToken(c.now(), "newer-granted")
	c.mu.Unlock()
	close(loader.release) // let Load return the stale token

	select {
	case got := <-res:
		if got.err != nil || got.tok != "newer-granted" {
			t.Errorf("got token=%q err=%v, want newer-granted/nil (a late Load must not clobber a freshly granted token)", got.tok, got.err)
		}
		if got.reused {
			t.Error("a token granted by a peer during this call must not be marked reused")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("accessToken did not return")
	}
}

// New defaults oobPollInterval to a positive value so interactive-login OOB
// polling is rate-limited; tests set it to 0 to poll without delay.
func TestNewSetsDefaultOOBPollInterval(t *testing.T) {
	c, err := New(Config{URL: "https://vault.example.com", Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if c.oobPollInterval <= 0 {
		t.Errorf("oobPollInterval = %v, want a positive default so OOB polling is rate-limited", c.oobPollInterval)
	}
}

// A waiter whose context expires while a peer is granting returns promptly,
// rather than blocking on a lock that ignores the deadline.
func TestAccessTokenWaiterHonorsContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			<-release // hold the grant open
			fmt.Fprint(w, grantJSON("test-token"))
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	defer close(release)

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	go c.Token(context.Background()) // becomes the granter, blocks on release
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.Token(ctx)
	if !errors.Is(err, ErrTimeout) || time.Since(start) > 2*time.Second {
		t.Errorf("waiter got %v after %v, want a prompt ErrTimeout", err, time.Since(start))
	}
}

// unreadableBody401 answers a data request with a 401 whose body errors on
// read while the first-granted token is presented, and 200 only once a fresh
// token is presented — so recovery requires DoBufferedResponse's evict-and-replay to
// fire on the 401 even though its body could never be read.
type unreadableBody401 struct {
	grants int
}

func (rt *unreadableBody401) RoundTrip(r *http.Request) (*http.Response, error) {
	resp := func(status int, body io.ReadCloser) *http.Response {
		return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d", status), Proto: "HTTP/1.1", Header: http.Header{}, Body: body, Request: r}
	}
	if r.URL.Path == "/oauth2/token" {
		rt.grants++
		return resp(200, io.NopCloser(strings.NewReader(grantJSON(fmt.Sprintf("tok-%d", rt.grants))))), nil
	}
	if r.Header.Get("Authorization") == "Bearer tok-1" {
		return resp(401, io.NopCloser(errReaderBody{})), nil
	}
	return resp(200, io.NopCloser(strings.NewReader("secret"))), nil
}

type errReaderBody struct{}

func (errReaderBody) Read([]byte) (int, error) { return 0, errors.New("connection reset mid-body") }

func TestDoBufferedRecoversOn401WithUnreadableBody(t *testing.T) {
	c, err := New(Config{URL: "https://example.com", Username: "u", Password: "p", Retries: 2, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	rt := &unreadableBody401{}
	c.hc.Transport = rt
	c.backoff = nil
	// Prime a memoized token so the first data call reuses it and the 401
	// triggers evict-and-replay.
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, err := c.DoBufferedResponse(context.Background(), Request{Method: "GET", Path: "/api/v1/secrets/1"}, 1<<20)
	if err != nil {
		t.Fatalf("got %v, want recovery after the 401 whose body could not be read", err)
	}
	if resp.StatusCode != 200 || string(resp.Body) != "secret" {
		t.Errorf("got %d/%q, want 200/secret", resp.StatusCode, resp.Body)
	}
	if rt.grants != 2 {
		t.Errorf("grants: got %d, want 2 (initial + one re-auth)", rt.grants)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func tokenClient(t *testing.T, ft *fakeTransport) *Client {
	t.Helper()
	c, err := New(Config{URL: "https://example.com", Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	c.hc.Transport = ft
	c.backoff = nil
	return c
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"no url", Config{Token: "test-token"}, true},
		{"relative url", Config{URL: "not a url", Token: "test-token"}, true},
		{"ftp url", Config{URL: "ftp://x.example.com", Token: "test-token"}, true},
		{"plaintext remote url", Config{URL: "http://x.example.com", Token: "test-token"}, true},
		{"plaintext remote url explicit opt-in", Config{URL: "http://x.example.com", Token: "test-token", AllowInsecureHTTP: true}, false},
		{"uppercase https", Config{URL: "HTTPS://x.example.com", Token: "test-token"}, false},
		{"url userinfo", Config{URL: "https://user:secret@x.example.com", Token: "test-token"}, true},
		{"url query", Config{URL: "https://x.example.com?tenant=one", Token: "test-token"}, true},
		{"url fragment", Config{URL: "https://x.example.com#fragment", Token: "test-token"}, true},
		{"no credentials", Config{URL: "https://x.example.com"}, true},
		{"both pairs", Config{URL: "https://x.example.com", Username: "u", Password: "p", ClientID: "c", ClientSecret: "s"}, true},
		{"ss missing password", Config{URL: "https://x.example.com", Username: "u"}, true},
		{"platform missing secret", Config{URL: "https://x.example.com", ClientID: "c"}, true},
		{"explicit ss missing creds", Config{URL: "https://x.example.com", Target: TargetSecretServer}, true},
		{"explicit platform missing creds", Config{URL: "https://x.example.com", Target: TargetPlatform}, true},
		{"bad target", Config{URL: "https://x.example.com", Target: "weird", Token: "test-token"}, true},
		{"bad ca cert", Config{URL: "https://x.example.com", Token: "test-token", CACert: []byte("junk")}, true},
		{"token newline", Config{URL: "https://x.example.com", Token: "a\nb"}, true},
		{"token unicode control", Config{URL: "https://x.example.com", Token: "a\u009bb"}, true},
		{"token only", Config{URL: "https://x.example.com", Token: "test-token"}, false},
		{"ss pair", Config{URL: "https://x.example.com", Username: "u", Password: "p"}, false},
		{"platform pair", Config{URL: "https://x.example.com", ClientID: "c", ClientSecret: "s"}, false},
		{"explicit platform userpass for login", Config{URL: "https://x.example.com", Target: TargetPlatform, Username: "u", Password: "p"}, false},
		{"both pairs explicit target", Config{URL: "https://x.example.com", Target: TargetSecretServer, Username: "u", Password: "p", ClientID: "c", ClientSecret: "s"}, false},
	}
	for _, tc := range cases {
		_, err := New(tc.cfg)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: got err %v, wantErr %v", tc.name, err, tc.wantErr)
		}
		if err != nil && !errors.Is(err, ErrConfig) {
			t.Errorf("%s: got %v, want errors.Is ErrConfig", tc.name, err)
		}
	}
}

func TestNewURLValidationDoesNotEchoUserinfo(t *testing.T) {
	_, err := New(Config{URL: "https://user:supersecret@x.example.com", Token: "test-token"})
	if err == nil || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("got %q, want a redacted URL validation error", err)
	}
}

func TestResolveTarget(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want Target
	}{
		{"ss pair", Config{Username: "u", Password: "p"}, TargetSecretServer},
		{"platform pair", Config{ClientID: "c", ClientSecret: "s"}, TargetPlatform},
		{"token only", Config{Token: "test-token"}, TargetAuto},
		{"explicit ss with token", Config{Target: TargetSecretServer, Token: "test-token"}, TargetSecretServer},
		{"explicit platform with token", Config{Target: TargetPlatform, Token: "test-token"}, TargetPlatform},
		{"explicit platform with userpass", Config{Target: TargetPlatform, Username: "u", Password: "p"}, TargetPlatform},
	}
	for _, tc := range cases {
		got, err := resolveTarget(tc.cfg)
		if err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestNewLeavesDefaultTransportAlone(t *testing.T) {
	dt := http.DefaultTransport.(*http.Transport)
	// http.DefaultTransport lazily initializes its own TLSClientConfig for HTTP/2
	// the first time it is cloned (Clone -> nextProtoOnce). That one-time mutation
	// is Go's, not ours, and fools a naive before/after pointer comparison when
	// this test happens to run first (isolation or a shuffle order). Trigger the
	// lazy init up front so the snapshot is stable.
	dt.Clone()
	before := dt.TLSClientConfig
	if _, err := New(Config{URL: "https://x.example.com", Token: "test-token", SkipTLSVerify: true}); err != nil {
		t.Fatal(err)
	}
	after := dt.TLSClientConfig
	if before != after {
		t.Error("http.DefaultTransport TLSClientConfig was replaced")
	}
	// The invariant that actually matters: New must not leak SkipTLSVerify onto
	// the shared default transport.
	if after != nil && after.InsecureSkipVerify {
		t.Error("New leaked SkipTLSVerify onto http.DefaultTransport")
	}
}

func TestDoRetriesGetOnTransportError(t *testing.T) {
	ft := &fakeTransport{failures: 2}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if ft.calls != 3 {
		t.Errorf("calls: got %d, want 3", ft.calls)
	}
}

// A retry backoff must not outlive the caller: with a cancelled context the
// call returns promptly instead of sleeping through the backoff.
func TestDoBackoffHonorsContext(t *testing.T) {
	ft := &fakeTransport{failures: 5}
	c, err := New(Config{URL: "https://example.com", Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	c.hc.Transport = ft
	c.retries = 5
	c.backoff = func(int) time.Duration { return time.Hour } // would hang without ctx handling
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { _, e := c.Do(ctx, Request{Method: "GET", Path: "/a"}); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Errorf("got nil error, want a cancellation/transport error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Do slept through the backoff instead of honoring the cancelled context")
	}
}

func TestDoDoesNotRetryPost(t *testing.T) {
	ft := &fakeTransport{failures: 1}
	c := tokenClient(t, ft)
	_, err := c.Do(context.Background(), Request{Method: "POST", Path: "/a"})
	if !errors.Is(err, ErrTransport) {
		t.Errorf("got %v, want errors.Is ErrTransport", err)
	}
	if ft.calls != 1 {
		t.Errorf("calls: got %d, want 1", ft.calls)
	}
}

// A GET/HEAD timeout is transient (a connection that accepted but never
// answered) and idempotent-safe, so it is retried like any transport error —
// both CLIs even file timeout under "transport error" in their exit-code
// taxonomy.
func TestDoRetriesTimeout(t *testing.T) {
	ft := &fakeTransport{failures: 2, err: timeoutError{}}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ft.calls != 3 {
		t.Errorf("calls: got %d, want 3 (a timeout is retried)", ft.calls)
	}
}

func TestDoTimeoutExhausted(t *testing.T) {
	ft := &fakeTransport{failures: 10, err: timeoutError{}}
	c := tokenClient(t, ft)
	_, err := c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("got %v, want errors.Is ErrTimeout", err)
	}
	if ft.calls != 3 {
		t.Errorf("calls: got %d, want 3 (retries exhausted)", ft.calls)
	}
}

func TestStreamedBodyReadErrorIsTransport(t *testing.T) {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	var timedOut atomic.Bool
	body := &idleBody{
		rc:       io.NopCloser(errorReader{err: errors.New("connection reset")}),
		timer:    timer,
		idle:     time.Hour,
		cancel:   func() {},
		timedOut: &timedOut,
	}
	if _, err := body.Read(make([]byte, 1)); !errors.Is(err, ErrTransport) {
		t.Fatalf("got %v, want ErrTransport", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestDoGivesUpAfterRetries(t *testing.T) {
	ft := &fakeTransport{failures: 10}
	c := tokenClient(t, ft)
	_, err := c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if !errors.Is(err, ErrTransport) {
		t.Errorf("got %v, want errors.Is ErrTransport", err)
	}
	if ft.calls != 3 {
		t.Errorf("calls: got %d, want 3", ft.calls)
	}
}

func TestDoRetries429UntilSuccess(t *testing.T) {
	ft := &fakeTransport{statuses: []int{429, 200}, retryAfter: "0"}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if ft.calls != 2 {
		t.Errorf("calls: got %d, want 2", ft.calls)
	}
}

func TestDoRetries503WithBackoff(t *testing.T) {
	ft := &fakeTransport{statuses: []int{503, 200}}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if ft.calls != 2 {
		t.Errorf("calls: got %d, want 2", ft.calls)
	}
}

func TestDoSetsHostFromHeader(t *testing.T) {
	ft := &fakeTransport{status: 200}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{
		Method: "GET",
		Path:   "/x",
		Header: http.Header{"Host": {"tenant.internal"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ft.lastReq.Host != "tenant.internal" {
		t.Errorf("req.Host: got %q, want tenant.internal (a Host header entry is ignored by net/http)", ft.lastReq.Host)
	}
	if got := ft.lastReq.Header.Get("Host"); got != "" {
		t.Errorf("Host left in the header map: %q", got)
	}
}

func TestDoRetriesTransient5xx(t *testing.T) {
	ft := &fakeTransport{statuses: []int{502, 408, 200}}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if ft.calls != 3 {
		t.Errorf("calls: got %d, want 3", ft.calls)
	}
}

func TestDoAllowsURLValuedQuery(t *testing.T) {
	ft := &fakeTransport{status: 200}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/api/v1/secrets?filter.searchText=https://db.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := ft.lastReq.URL.RawQuery; got != "filter.searchText=https://db.example.com" {
		t.Errorf("query: got %q", got)
	}
}

func TestDoDoesNotRetry429OnPost(t *testing.T) {
	ft := &fakeTransport{status: 429, retryAfter: "0"}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "POST", Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Errorf("status: got %d, want 429", resp.StatusCode)
	}
	if ft.calls != 1 {
		t.Errorf("calls: got %d, want 1", ft.calls)
	}
}

func TestDo429ExhaustsRetries(t *testing.T) {
	ft := &fakeTransport{status: 429, retryAfter: "0"}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Errorf("status: got %d, want 429 after exhausting retries", resp.StatusCode)
	}
	if ft.calls != 3 {
		t.Errorf("calls: got %d, want 3", ft.calls)
	}
}

func TestDoHugeRetryAfterReturnsImmediately(t *testing.T) {
	ft := &fakeTransport{statuses: []int{429, 200}, retryAfter: "3600"}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Errorf("status: got %d, want 429 returned without waiting", resp.StatusCode)
	}
	if ft.calls != 1 {
		t.Errorf("calls: got %d, want 1", ft.calls)
	}
}

func TestClassifyTransportKeepsCauseInChain(t *testing.T) {
	err := classifyTransport(context.Canceled)
	if !errors.Is(err, ErrTransport) || !errors.Is(err, context.Canceled) {
		t.Errorf("got %v; must match both ErrTransport and context.Canceled", err)
	}
	err = classifyTransport(context.DeadlineExceeded)
	if !errors.Is(err, ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v; must match both ErrTimeout and context.DeadlineExceeded", err)
	}
}

func TestRetryDelay(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	backoff := func(int) time.Duration { return 250 * time.Millisecond }
	cases := []struct {
		name       string
		header     string
		want       time.Duration
		fromHeader bool
	}{
		{"absent uses backoff", "", 250 * time.Millisecond, false},
		{"seconds", "5", 5 * time.Second, true},
		{"zero seconds", "0", 0, true},
		{"negative clamped", "-3", 0, true},
		{"http date", now.Add(10 * time.Second).UTC().Format(http.TimeFormat), 10 * time.Second, true},
		{"past date clamped", now.Add(-time.Minute).UTC().Format(http.TimeFormat), 0, true},
		{"garbage uses backoff", "soon", 250 * time.Millisecond, false},
		{"huge seconds capped without overflow", "10000000000", maxRetryAfterWait + time.Second, true},
		{"seconds beyond int range still capped", "999999999999999999999999", maxRetryAfterWait + time.Second, true},
		{"negative beyond int range clamped", "-999999999999999999999999", 0, true},
		{"just over the honor limit", "31", maxRetryAfterWait + time.Second, true},
	}
	for _, tc := range cases {
		got, fromHeader := retryDelay(tc.header, 0, backoff, now)
		if got != tc.want || fromHeader != tc.fromHeader {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", tc.name, got, fromHeader, tc.want, tc.fromHeader)
		}
	}
}

func TestRetryWait(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	longBackoff := func(int) time.Duration { return time.Minute }
	cases := []struct {
		name    string
		header  string
		backoff func(int) time.Duration
		want    time.Duration
		retry   bool
	}{
		{"short header honored", "5", longBackoff, 5 * time.Second, true},
		{"long header returns the response", "60", longBackoff, maxRetryAfterWait + time.Second, false},
		{"overflowing header returns the response", "999999999999999999999999", longBackoff, maxRetryAfterWait + time.Second, false},
		{"long backoff clamped, still retried", "", longBackoff, maxRetryAfterWait, true},
		{"negative backoff clamped to zero", "", func(int) time.Duration { return -time.Second }, 0, true},
		{"nil backoff retries immediately", "", nil, 0, true},
	}
	for _, tc := range cases {
		got, retry := retryWait(tc.header, 0, tc.backoff, now)
		if got != tc.want || retry != tc.retry {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", tc.name, got, retry, tc.want, tc.retry)
		}
	}
}

func TestDoBodySurvivesSlowButFlowingDownload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		for range 8 {
			w.Write(make([]byte, 16))
			fl.Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Token: "test-token", Timeout: 200 * time.Millisecond, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/big"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("a flowing download must outlive the timeout: %v", err)
	}
	if len(body) != 128 {
		t.Errorf("body length: got %d, want 128", len(body))
	}
}

func TestDoBodySurvivesPausedConsumer(t *testing.T) {
	const timeout = 500 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 16))
		w.(http.Flusher).Flush()
		w.Write(make([]byte, 16))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Token: "test-token", Timeout: timeout, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadFull(resp.Body, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(timeout + 250*time.Millisecond)
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read after a pause longer than Timeout: %v; the stall watchdog must not run between reads", err)
	}
	if len(rest) != 16 {
		t.Errorf("rest length: got %d, want 16", len(rest))
	}
}

func TestDoUnreadBodyReleasedWithinTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 16))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Token: "test-token", Timeout: 100 * time.Millisecond, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	time.Sleep(300 * time.Millisecond)
	if _, err := io.ReadAll(resp.Body); !errors.Is(err, ErrTimeout) {
		t.Errorf("got %v, want errors.Is ErrTimeout: a body never read must still be torn down within Timeout", err)
	}
}

func TestDoAbandonedBodyReleasedByGC(t *testing.T) {
	released := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 16))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(released)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Token: "test-token", Timeout: time.Minute, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	func() {
		resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/x"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(resp.Body, make([]byte, 16)); err != nil {
			t.Fatal(err)
		}
	}()
	deadline := time.After(5 * time.Second)
	for {
		runtime.GC()
		select {
		case <-released:
			return
		case <-deadline:
			t.Fatal("a body read and then dropped without Close still pins its connection after GC")
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func TestDoStalledBodyTimesOut(t *testing.T) {
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			Header:     make(http.Header),
			Body:       &contextBlockingBody{ctx: r.Context()},
			Request:    r,
		}, nil
	})

	c, err := New(Config{URL: "https://example.com", Token: "test-token", Transport: rt, Timeout: 100 * time.Millisecond, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/stall"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("got %v, want errors.Is ErrTimeout", err)
	}
}

func TestDoHeaderTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Token: "test-token", Timeout: 100 * time.Millisecond, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(context.Background(), Request{Method: "GET", Path: "/slow"})
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("got %v, want errors.Is ErrTimeout", err)
	}
}

func TestDoNon2xxIsNotAnError(t *testing.T) {
	ft := &fakeTransport{status: 500}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Errorf("status: got %d, want 500", resp.StatusCode)
	}
}

func TestDoPathValidation(t *testing.T) {
	c := tokenClient(t, &fakeTransport{})
	for _, path := range []string{"api/v1/x", "https://evil.example.com/x", ""} {
		_, err := c.Do(context.Background(), Request{Method: "GET", Path: path})
		if !errors.Is(err, ErrConfig) {
			t.Errorf("path %q: got %v, want errors.Is ErrConfig", path, err)
		}
	}
	const querySecret = "query-value-must-not-leak"
	for _, path := range []string{
		"api/v1/x?filter=" + querySecret,
		"/api/v1/x?filter=" + querySecret + "\n",
	} {
		_, err := c.Do(context.Background(), Request{Method: "GET", Path: path})
		if !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), querySecret) {
			t.Errorf("path error leaked query data: %v", err)
		}
	}
}

func TestDoRejectsVaultOnSecretServer(t *testing.T) {
	c, err := New(Config{URL: "https://x.example.com", Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(context.Background(), Request{Method: "GET", Path: "/a", UseVault: true})
	if !errors.Is(err, ErrConfig) {
		t.Errorf("got %v, want errors.Is ErrConfig", err)
	}
}

func TestDoHeaders(t *testing.T) {
	ft := &fakeTransport{}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "POST", Path: "/a", Body: strings.NewReader(`{"x":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := ft.lastReq.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Errorf("authorization: got %q, want %q", got, "Bearer test-token")
	}
	if got := ft.lastReq.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type: got %q, want application/json", got)
	}
	if ft.lastBody != `{"x":1}` {
		t.Errorf("body: got %q", ft.lastBody)
	}

	hdr := http.Header{}
	hdr.Set("Content-Type", "text/plain")
	hdr.Set("X-Extra", "1")
	resp, err = c.Do(context.Background(), Request{Method: "POST", Path: "/a", Body: strings.NewReader("hi"), Header: hdr})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := ft.lastReq.Header.Get("Content-Type"); got != "text/plain" {
		t.Errorf("content type override: got %q, want text/plain", got)
	}
	if got := ft.lastReq.Header.Get("X-Extra"); got != "1" {
		t.Errorf("extra header: got %q, want 1", got)
	}

	resp, err = c.Do(context.Background(), Request{Method: "GET", Path: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := ft.lastReq.Header.Get("Content-Type"); got != "" {
		t.Errorf("content type without body: got %q, want empty", got)
	}
}

func TestDoCancellationClosesBlockingRequestBody(t *testing.T) {
	c := tokenClient(t, &fakeTransport{})
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.Do(ctx, Request{Method: "POST", Path: "/a", Body: reader})
		done <- err
	}()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want errors.Is context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Do stayed blocked reading a closable body after cancellation")
	}
}

type trackingReadCloser struct {
	reader io.Reader
	reads  int
	closed bool
}

type failingBodyReader struct{ err error }

func (r failingBodyReader) Read([]byte) (int, error) { return 0, r.err }

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	r.reads++
	return r.reader.Read(p)
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestReadRequestBodyAlreadyCanceledClosesWithoutReading(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := &trackingReadCloser{reader: strings.NewReader("do not read")}
	_, err := readRequestBody(ctx, body)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want errors.Is context.Canceled", err)
	}
	if !body.closed || body.reads != 0 {
		t.Errorf("closed=%v reads=%d, want true/0", body.closed, body.reads)
	}
}

func TestReadRequestBodySuccessDoesNotTakeOwnership(t *testing.T) {
	body := &trackingReadCloser{reader: strings.NewReader("payload")}
	got, err := readRequestBody(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload" {
		t.Errorf("body = %q, want payload", got)
	}
	if body.closed {
		t.Error("successful read closed the caller-owned body")
	}
}

func TestReadRequestBodyReportsReadError(t *testing.T) {
	const bodySecret = "request-body-content-must-not-leak"
	want := errors.New("body read cause")
	bodyErr := fmt.Errorf("%w: buffered bytes=%s", want, bodySecret)
	_, err := readRequestBody(context.Background(), failingBodyReader{err: bodyErr})
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "reading request body") {
		t.Fatalf("got %v, want a wrapped body read error", err)
	}
	if strings.Contains(err.Error(), bodySecret) {
		t.Errorf("request-body read diagnostic exposed body content: %v", err)
	}
}

func TestDoBuildsURL(t *testing.T) {
	ft := &fakeTransport{}
	c := tokenClient(t, ft)
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/api/v1/secrets?filter.searchText=web"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want := "https://example.com/api/v1/secrets?filter.searchText=web"
	if got := ft.lastReq.URL.String(); got != want {
		t.Errorf("url: got %q, want %q", got, want)
	}
}
