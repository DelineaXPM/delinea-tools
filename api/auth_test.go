package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func grantJSON(token string) string {
	return fmt.Sprintf(`{"access_token":%q,"token_type":"bearer","expires_in":3600}`, token)
}

func TestGrantSecretServerForm(t *testing.T) {
	var gotPath, gotContentType string
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Errorf("parsing form: %v", err)
		}
		gotForm = r.PostForm
		fmt.Fprint(w, grantJSON("ss-tok"))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Domain: "d"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "ss-tok" {
		t.Errorf("token: got %q, want %q", tok, "ss-tok")
	}
	if gotPath != "/oauth2/token" {
		t.Errorf("path: got %q, want %q", gotPath, "/oauth2/token")
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("content type: got %q", gotContentType)
	}
	want := url.Values{
		"grant_type": {"password"},
		"username":   {"u"},
		"password":   {"p"},
		"domain":     {"d"},
	}
	if !reflect.DeepEqual(gotForm, want) {
		t.Errorf("form: got %v, want %v", gotForm, want)
	}
}

func TestAuthenticateGrantCredential(t *testing.T) {
	grants, dataCalls := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants++
			fmt.Fprint(w, grantJSON("granted"))
			return
		}
		dataCalls++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Target: TargetSecretServer, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.Authenticate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "granted" || grants != 1 || dataCalls != 0 {
		t.Errorf("got token=%q grants=%d dataCalls=%d, want granted/1/0", tok, grants, dataCalls)
	}
}

// Authenticate's contract is to exercise the configured credential: a fresh
// memoized or cached token — possibly granted under a since-rotated password —
// must not satisfy it. Token, by contrast, keeps returning the cached token.
func TestAuthenticateExercisesGrantDespiteFreshToken(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants++
			w.WriteHeader(http.StatusUnauthorized) // the credential has been rotated
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	cache := NewMemoryCache()
	c, err := New(Config{URL: srv.URL, Target: TargetSecretServer, Username: "u", Password: "rotated", Cache: cache})
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.token = freshToken(c.now(), "stale-but-fresh")
	c.mu.Unlock()
	cache.Store(c.key, freshToken(c.now(), "stale-but-fresh"))

	if tok, err := c.Token(context.Background()); err != nil || tok != "stale-but-fresh" {
		t.Fatalf("Token: got %q, %v; want the memoized token without a grant", tok, err)
	}
	if _, err := c.Authenticate(context.Background()); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("Authenticate with a rotated credential: got %v, want ErrAccessDenied (a cached token must not vouch for it)", err)
	}
	if grants != 1 {
		t.Errorf("grants: got %d, want 1 (Authenticate must perform a real grant)", grants)
	}
}

// waitForGrantWaiters blocks until n callers have parked on the client's
// in-flight local grant (c.granting), so a coalescing test releases the leader
// only once the wave has provably joined — deterministic where a fixed sleep is
// not. It mirrors waitForFlightWaiters for the cross-client shared flight.
func waitForGrantWaiters(t *testing.T, c *Client, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		g := c.granting
		c.mu.Unlock()
		if g != nil && g.waiters.Load() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("in-flight grant never gathered %d waiters", n)
}

func TestConcurrentAuthenticateCoalescesRejectedGrant(t *testing.T) {
	var grants atomic.Int32
	firstGrant := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if grants.Add(1) == 1 {
			close(firstGrant)
		}
		<-release
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "rejected", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	const callers = 20
	start := make(chan struct{})
	errs := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for range callers {
		go func() {
			ready.Done()
			<-start
			_, err := c.Authenticate(context.Background())
			errs <- err
		}()
	}
	ready.Wait()
	close(start)
	<-firstGrant
	waitForGrantWaiters(t, c, callers-1) // all but the leader park on the in-flight grant
	close(release)
	for range callers {
		if err := <-errs; !errors.Is(err, ErrAccessDenied) {
			t.Errorf("got %v, want ErrAccessDenied", err)
		}
	}
	if got := grants.Load(); got != 1 {
		t.Fatalf("grants = %d, want 1; concurrent Authenticate calls must share a denial", got)
	}
}

func TestAuthenticatePreobtainedToken(t *testing.T) {
	for _, tc := range []struct {
		name       string
		target     Target
		wantPath   string
		status     int
		wantDenied bool
	}{
		{"secret server accepted", TargetSecretServer, "/api/v1/users/current", http.StatusOK, false},
		{"platform accepted", TargetPlatform, "/vaultbroker/api/vaults", http.StatusOK, false},
		{"secret server rejected", TargetSecretServer, "/api/v1/users/current", http.StatusUnauthorized, true},
		{"platform forbidden", TargetPlatform, "/vaultbroker/api/vaults", http.StatusForbidden, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			c, err := New(Config{URL: srv.URL, Target: tc.target, Token: "supplied"})
			if err != nil {
				t.Fatal(err)
			}
			tok, err := c.Authenticate(context.Background())
			if tc.wantDenied {
				if !errors.Is(err, ErrAccessDenied) {
					t.Fatalf("got %v, want ErrAccessDenied", err)
				}
			} else if err != nil || tok != "supplied" {
				t.Fatalf("got token=%q err=%v, want supplied/nil", tok, err)
			}
			if gotPath != tc.wantPath || gotAuth != "Bearer supplied" {
				t.Errorf("got path=%q auth=%q, want %q and bearer token", gotPath, gotAuth, tc.wantPath)
			}
		})
	}
}

func TestAuthenticatePreobtainedTokenNeedsTarget(t *testing.T) {
	c, err := New(Config{URL: "https://vault.example.com", Token: "supplied"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Authenticate(context.Background()); !errors.Is(err, ErrConfig) {
		t.Fatalf("got %v, want ErrConfig", err)
	}
}

// A platform config carrying only Username/Password is constructible (for
// interactive login) but cannot serve an automatic client-credentials grant.
// Such a grant must fail with direction to interactive login, not by sending
// empty client credentials to the server.
func TestGrantPlatformUserPassDirectsToInteractiveLogin(t *testing.T) {
	c, err := New(Config{URL: "https://platform.example.com", Target: TargetPlatform, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Token(context.Background())
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("got %v, want ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "interactive login") {
		t.Errorf("got %q, want a message pointing at interactive login", err)
	}
}

func TestAuthenticatePreobtainedTokenTransientIsTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, Target: TargetSecretServer, Token: "supplied", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Authenticate(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatalf("got %v, want ErrTransport", err)
	}
}

func TestAuthenticatePreobtainedTokenNonTransientIsAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, Target: TargetSecretServer, Token: "supplied", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Authenticate(context.Background()); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestGrantRetriesTransientStatus(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants++
		if grants == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 3,
		Backoff: func(int) time.Duration { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatalf("got %v, want the grant to survive one 429 (it carries no authentication answer)", err)
	}
	if tok != "test-token" || grants != 2 {
		t.Errorf("got token %q after %d grants, want test-token after 2", tok, grants)
	}
}

func TestGrantRetriesTransportFailure(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants++
		if grants == 1 {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 3,
		Backoff: func(int) time.Duration { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatalf("got %v, want the grant to survive one dropped connection", err)
	}
	if grants != 2 {
		t.Errorf("grants: got %d, want 2", grants)
	}
}

func TestGrantNeverRetriesAuthAnswer(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 3,
		Backoff: func(int) time.Duration { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	_, terr := c.Token(context.Background())
	if !errors.Is(terr, ErrAccessDenied) {
		t.Errorf("got %v, want ErrAccessDenied", terr)
	}
	if grants != 1 {
		t.Errorf("grants: got %d, want 1 (a completed credential answer is never replayed)", grants)
	}
}

type unreadableGrantAnswer struct {
	calls        int
	status       int
	succeedAfter bool
}

func (rt *unreadableGrantAnswer) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.calls++
	if rt.succeedAfter && rt.calls > 1 {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(grantJSON("test-token"))),
			Request:    r,
		}, nil
	}
	return &http.Response{
		StatusCode: rt.status,
		Status:     fmt.Sprintf("%d status", rt.status),
		Header:     http.Header{},
		Body:       io.NopCloser(errReaderBody{}),
		Request:    r,
	}, nil
}

func TestGrantDoesNotRetryUnreadableAuthAnswer(t *testing.T) {
	rt := &unreadableGrantAnswer{status: http.StatusUnauthorized}
	c, err := New(Config{
		URL: "https://example.com", Username: "u", Password: "p",
		Transport: rt, Retries: 3, Backoff: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Token(context.Background())
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want ErrAccessDenied from the completed 401", err)
	}
	if rt.calls != 1 {
		t.Errorf("grant calls: got %d, want 1 (an unreadable rejection is still a completed answer)", rt.calls)
	}
}

func TestGrantRetriesUnreadableTransientAnswer(t *testing.T) {
	rt := &unreadableGrantAnswer{status: http.StatusServiceUnavailable, succeedAfter: true}
	c, err := New(Config{
		URL: "https://example.com", Username: "u", Password: "p",
		Transport: rt, Retries: 3, Backoff: func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.Token(context.Background())
	if err != nil || tok != "test-token" {
		t.Fatalf("Token() = %q, %v; want test-token after retry", tok, err)
	}
	if rt.calls != 2 {
		t.Errorf("grant calls: got %d, want 2 (an unreadable 503 remains transient)", rt.calls)
	}
}

func TestGrantExhaustedTransientIsTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, terr := c.Token(context.Background())
	if !errors.Is(terr, ErrTransport) || errors.Is(terr, ErrAuth) {
		t.Errorf("got %v, want ErrTransport: a rate-limited or restarting token endpoint is not an authentication answer", terr)
	}
}

func TestGrantCarriesConfigHeader(t *testing.T) {
	var gotGateway, gotAuth, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGateway = r.Header.Get("X-Gateway")
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p",
		Header: http.Header{
			"X-Gateway":     {"g"},
			"Authorization": {"Bearer stray"},
			"Content-Type":  {"text/plain"},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotGateway != "g" {
		t.Errorf("X-Gateway on the grant: got %q, want %q", gotGateway, "g")
	}
	if gotAuth != "" {
		t.Errorf("the grant must not carry a Config.Header Authorization, got %q", gotAuth)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("a Config.Header Content-Type must not corrupt the form post, got %q", gotContentType)
	}
}

func TestGrantSecretServerOmitsEmptyDomain(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gotForm = r.PostForm
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotForm["domain"]; ok {
		t.Errorf("form contains domain: %v", gotForm)
	}
}

func TestGrantPlatformForm(t *testing.T) {
	var gotPath string
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		r.ParseForm()
		gotForm = r.PostForm
		fmt.Fprint(w, grantJSON("plat-tok"))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, ClientID: "cid", ClientSecret: "cs"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "plat-tok" {
		t.Errorf("token: got %q, want %q", tok, "plat-tok")
	}
	if gotPath != "/identity/api/oauth2/token/xpmplatform" {
		t.Errorf("path: got %q", gotPath)
	}
	want := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"cid"},
		"client_secret": {"cs"},
		"scope":         {"xpmheadless"},
	}
	if !reflect.DeepEqual(gotForm, want) {
		t.Errorf("form: got %v, want %v", gotForm, want)
	}
}

func TestGrantErrorClassification(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   error
	}{
		{400, `{"error":"invalid_grant"}`, ErrAccessDenied},
		{401, "denied", ErrAccessDenied},
		{403, "denied", ErrAccessDenied},
		{500, "boom", ErrTransport},
		{501, "not implemented", ErrAuth},
		{200, "not json", ErrAuth},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			fmt.Fprint(w, tc.body)
		}))
		c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 1})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Token(context.Background())
		if !errors.Is(err, tc.want) {
			t.Errorf("status %d: got %v, want errors.Is %v", tc.status, err, tc.want)
		}
		srv.Close()
	}
}

// A token rotated out by a 401 evict-and-replay is still redacted: a response
// already in flight was sent with the old token and can reflect it after the
// rotation installed a new one.
func TestDiagnosticSnippetRedactsRotatedToken(t *testing.T) {
	var grants int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants++
			fmt.Fprint(w, grantJSON(fmt.Sprintf("rotated-token-%d", grants)))
			return
		}
		fmt.Fprint(w, "request used "+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil { // grants rotated-token-1
		t.Fatal(err)
	}
	buffered, err := c.DoBufferedResponse(context.Background(), Request{Method: http.MethodGet, Path: "/reflect"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	streamed, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/reflect"})
	if err != nil {
		t.Fatal(err)
	}
	defer streamed.Body.Close()
	for i := 1; i <= 40; i++ {
		c.evictToken(fmt.Sprintf("rotated-token-%d", i))
		if _, err := c.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	got := buffered.DiagnosticSnippet()
	if strings.Contains(got, "rotated-token-1") || !strings.Contains(got, "[REDACTED]") {
		t.Errorf("rotated-out token escaped response-bound redaction: %q", got)
	}
	streamBody, err := io.ReadAll(streamed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := streamed.DiagnosticSnippet(streamBody); strings.Contains(got, "rotated-token-1") || !strings.Contains(got, "[REDACTED]") {
		t.Errorf("rotated-out token escaped streaming response redaction: %q", got)
	}
	if got2 := c.DiagnosticSnippet([]byte("current rotated-token-41 here")); strings.Contains(got2, "rotated-token-41") {
		t.Errorf("current token escaped redaction: %q", got2)
	}
}

func TestResponseDiagnosticRedactsOutboundHeaderValues(t *testing.T) {
	const configuredSecret = "gateway-header-secret"
	const requestSecret = "request-header-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "gateway=%s request=%s", r.Header.Get("X-Gateway-Key"), r.Header.Get("X-Request-Key"))
	}))
	defer srv.Close()

	c, err := New(Config{
		URL:    srv.URL,
		Token:  "configured-bearer-token",
		Header: http.Header{"X-Gateway-Key": {configuredSecret}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.DoBufferedResponse(context.Background(), Request{
		Method: http.MethodGet,
		Path:   "/reflect",
		Header: http.Header{"X-Request-Key": {requestSecret}},
	}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	got := resp.DiagnosticSnippet()
	for _, secret := range []string{configuredSecret, requestSecret} {
		if strings.Contains(got, secret) {
			t.Errorf("response diagnostic exposed header value %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("response diagnostic did not show redaction: %q", got)
	}
}

// BufferedResponse must not leak its request token through reflection-based
// formatting: the redaction context lives in the weak registry, not in fields
// a debug log's %+v would print. A copied value has no binding and fails
// closed, exactly as for Response.
func TestBufferedResponseFormattingDoesNotLeakToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			fmt.Fprint(w, grantJSON("fmt-leak-token-value"))
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.DoBufferedResponse(context.Background(), Request{Method: http.MethodGet, Path: "/x"}, 64)
	if err != nil {
		t.Fatal(err)
	}
	if formatted := fmt.Sprintf("%+v %#v", resp, resp); strings.Contains(formatted, "fmt-leak-token-value") {
		t.Errorf("formatting a BufferedResponse leaked the request token: %s", formatted)
	}
	if resp.DiagnosticSnippet() == "(diagnostic unavailable)" {
		t.Error("the bound pointer should render a diagnostic")
	}
	copied := *resp
	if got := copied.DiagnosticSnippet(); got != "(diagnostic unavailable)" {
		t.Errorf("a copied BufferedResponse should fail closed, got %q", got)
	}
	var nilResp *BufferedResponse
	if got := nilResp.DiagnosticSnippet(); got != "(diagnostic unavailable)" {
		t.Errorf("a nil BufferedResponse should fail closed, got %q", got)
	}
}

// Every bearer token accepted by configuration is a secret and redacts
// unconditionally. Degenerate one- to three-byte values are never accepted:
// redacting them would substring-shred every diagnostic, so New rejects them
// at admission instead of letting validation and redaction disagree.
func TestEveryAcceptedConfiguredTokenIsRedacted(t *testing.T) {
	for _, token := range []string{"e", "xy", "abc"} {
		_, err := New(Config{URL: "https://vault.example.com", Token: token})
		if !errors.Is(err, ErrConfig) {
			t.Errorf("New with token %q: got %v, want ErrConfig (below the four-byte minimum)", token, err)
		}
	}
	for _, token := range []string{"test", "abcd", "a-much-longer-bearer-token-value"} {
		c, err := New(Config{URL: "https://vault.example.com", Token: token})
		if err != nil {
			t.Fatalf("New with token %q: %v", token, err)
		}
		if got := c.DiagnosticSnippet([]byte(token)); got != "[REDACTED]" {
			t.Errorf("accepted token %q was not redacted: %q", token, got)
		}
	}
}

// The streaming redaction context is bound to the Response identity rather
// than Body, so callers can routinely rewrap or reassign Body without losing
// the exact token used for the request.
func TestResponseDiagnosticSurvivesBodyRewrap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			fmt.Fprint(w, grantJSON("wrap-token-value"))
			return
		}
		fmt.Fprint(w, "reflected wrap-token-value in body")
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if rendered := fmt.Sprintf("%+v", resp); strings.Contains(rendered, "wrap-token-value") {
		t.Fatalf("formatting Response exposed its diagnostic credential: %q", rendered)
	}
	copied := *resp
	if got := copied.DiagnosticSnippet([]byte("wrap-token-value")); got != diagnosticUnavailable {
		t.Errorf("copied Response should fail closed, got %q", got)
	}
	var captured strings.Builder
	resp.Body = io.NopCloser(io.TeeReader(resp.Body, &captured)) // a routine rewrap
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	got := resp.DiagnosticSnippet(body)
	if got == "(diagnostic unavailable)" {
		t.Fatal("a Body rewrap degraded the diagnostic to the fail-closed sentinel")
	}
	if strings.Contains(got, "wrap-token-value") || !strings.Contains(got, "[REDACTED]") {
		t.Errorf("token escaped redaction after a Body rewrap: %q", got)
	}
	// A zero-value Response still fails closed.
	if got := (&Response{}).DiagnosticSnippet([]byte("x")); got != "(diagnostic unavailable)" {
		t.Errorf("zero-value Response should fail closed, got %q", got)
	}
}

func TestZeroResponseDiagnosticFailsClosed(t *testing.T) {
	const secret = "SHOULD-NOT-APPEAR"
	for _, resp := range []*BufferedResponse{nil, {Body: []byte(secret)}} {
		if got := resp.DiagnosticSnippet(); strings.Contains(got, secret) {
			t.Errorf("zero-value buffered response exposed its body: %q", got)
		}
	}
	for _, resp := range []*Response{nil, {}} {
		if got := resp.DiagnosticSnippet([]byte(secret)); strings.Contains(got, secret) {
			t.Errorf("zero-value streaming response exposed its body: %q", got)
		}
	}
}

// DiagnosticSnippet redacts every credential regardless of length. A short
// dictionary-word password may also hide ordinary text, but preserving that
// text must never take precedence over keeping a credential out of output.
func TestDiagnosticSnippetRedactsCredentialsAtAnyLength(t *testing.T) {
	c, err := New(Config{URL: "https://vault.example.com", Username: "u", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	body := "secret 5 field test not found"
	if got := c.DiagnosticSnippet([]byte(body)); strings.Contains(got, "secret") || !strings.Contains(got, "[REDACTED]") {
		t.Errorf("short password escaped diagnostic redaction: %q", got)
	}
	if got := c.authSnippet([]byte(body)); strings.Contains(got, "secret ") || !strings.Contains(got, "[REDACTED]") {
		t.Errorf("authSnippet did not redact the short password: %q", got)
	}
	platform, err := New(Config{URL: "https://platform.example.com", ClientID: "c", ClientSecret: "key"})
	if err != nil {
		t.Fatal(err)
	}
	if got := platform.DiagnosticSnippet([]byte("reflected key here")); strings.Contains(got, "key") || !strings.Contains(got, "[REDACTED]") {
		t.Errorf("short client secret escaped diagnostic redaction: %q", got)
	}
	long, err := New(Config{URL: "https://vault.example.com", Token: "long-bearer-token-value"})
	if err != nil {
		t.Fatal(err)
	}
	if got := long.DiagnosticSnippet([]byte("sent long-bearer-token-value out")); strings.Contains(got, "long-bearer-token-value") {
		t.Errorf("long token escaped the diagnostic redaction: %q", got)
	}
	// A configured bearer remains a secret even when it is short. Validation
	// accepts such values, so redaction must prefer over-redacting an ordinary
	// word to emitting an accepted authentication credential.
	short, err := New(Config{URL: "https://vault.example.com", Token: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if got := short.DiagnosticSnippet([]byte("latest schema: field test not found")); strings.Contains(got, "test") || !strings.Contains(got, "[REDACTED]") {
		t.Errorf("short configured token escaped the diagnostic redaction: %q", got)
	}
}

func TestRedactorDoesNotReprocessReplacementMarkers(t *testing.T) {
	// Each distinct character in [REDACTED] is itself a one-byte secret. A
	// sequence of ReplaceAll calls would process markers inserted by earlier
	// replacements and amplify this small input by orders of magnitude.
	redact := buildRedactor([]string{"[", "]", "R", "E", "D", "A", "C", "T"})
	in := strings.Repeat("AREDCT", 100)
	want := strings.Repeat("[REDACTED]", len(in))
	if got := redact(in); got != want {
		t.Fatalf("single-pass redaction: got %d bytes, want %d", len(got), len(want))
	}
	if got, want := buildRedactor([]string{"ab", "abc"})("abc ab"), "[REDACTED] [REDACTED]"; got != want {
		t.Fatalf("longest match must win: got %q, want %q", got, want)
	}
}

func TestGrantErrorRedactsSubmittedCredential(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cfg    Config
		secret string
	}{
		{"password", Config{Username: "u", Password: "SUPERSECRET"}, "SUPERSECRET"},
		{"client secret", Config{ClientID: "c", ClientSecret: "CLIENTSECRET"}, "CLIENTSECRET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, tc.secret)
			}))
			defer srv.Close()
			tc.cfg.URL, tc.cfg.Retries = srv.URL, 1
			c, err := New(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Token(context.Background())
			if err == nil || strings.Contains(err.Error(), tc.secret) || !strings.Contains(err.Error(), "[REDACTED]") {
				t.Fatalf("credential reflection was not redacted: %v", err)
			}
		})
	}
}

func TestGrantErrorRedactsReflectedConfiguredHeader(t *testing.T) {
	const secret = "gateway-header-secret"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "gateway rejected "+r.Header.Get("X-Gateway-Key"))
	}))
	defer srv.Close()
	c, err := New(Config{
		URL: srv.URL, Username: "u", Password: "password-value", Retries: 1,
		Header: http.Header{"X-Gateway-Key": {secret}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Token(context.Background())
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("configured header reflection was not redacted: %v", err)
	}
}

func TestGrantRejectsOversizedResponse(t *testing.T) {
	prefix := grantJSON("test-token")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, prefix)
		fmt.Fprint(w, strings.Repeat(" ", maxAuthResponseBytes-len(prefix)))
		fmt.Fprint(w, "x")
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); !errors.Is(err, ErrAuth) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v, want an ErrAuth size error", err)
	}
}

func TestGrantRefusesRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example.com/oauth2/token", http.StatusFound)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Token(context.Background())
	if !errors.Is(err, ErrConfig) {
		t.Errorf("got %v, want errors.Is ErrConfig (a redirected grant endpoint is a misconfigured URL)", err)
	}
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("error should mention the redirect status: %v", err)
	}
}

func TestTokenPassthrough(t *testing.T) {
	c, err := New(Config{URL: "https://example.com", Token: "pre-token"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "pre-token" {
		t.Errorf("token: got %q, want %q", tok, "pre-token")
	}
}

// Token output is explicitly reusable as Config.Token. Keep the grant and
// configuration admission rules aligned, including at the minimum length.
func TestGrantedTokenCanBeReusedAsConfiguredToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, grantJSON("four"))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{URL: srv.URL, Token: tok}); err != nil {
		t.Fatalf("reusing granted token as Config.Token: %v", err)
	}
}

func TestTokenMemoized(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants++
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := c.Token(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if grants != 1 {
		t.Errorf("grants: got %d, want 1", grants)
	}
}

// A memoized token near expiry is replaced with a fresh grant rather than
// reused, so a long-lived client keeps working past its first token.
func TestTokenRefreshesAfterExpiry(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants++
		fmt.Fprint(w, grantJSON(fmt.Sprintf("tok-%d", grants)))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	c.now = func() time.Time { return base }
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-1" {
		t.Errorf("first token: got %q, want tok-1", tok)
	}
	c.now = func() time.Time { return base.Add(time.Hour) }
	tok, err = c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-2" {
		t.Errorf("token after expiry: got %q, want tok-2", tok)
	}
	if grants != 2 {
		t.Errorf("grants: got %d, want 2", grants)
	}
}

// A reused token rejected with 401 is discarded and the request replayed once
// with a fresh grant.
func TestDoReplaysReusedTokenOn401(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants++
			fmt.Fprint(w, grantJSON(fmt.Sprintf("tok-%d", grants)))
			return
		}
		if r.Header.Get("Authorization") == "Bearer tok-1" {
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
	// Memoize tok-1 so the Do call reuses a token that predates it.
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200 after the replay", resp.StatusCode)
	}
	if grants != 2 {
		t.Errorf("grants: got %d, want 2", grants)
	}
}

func TestDoDoesNotReplayPostWithReusedTokenOn401(t *testing.T) {
	grants, writes := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants++
			fmt.Fprint(w, grantJSON(fmt.Sprintf("tok-%d", grants)))
			return
		}
		writes++
		if r.Header.Get("Authorization") == "Bearer tok-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: http.MethodPost, Path: "/write", Body: strings.NewReader(`{"value":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401 returned without replay", resp.StatusCode)
	}
	if writes != 1 || grants != 1 {
		t.Errorf("writes=%d grants=%d, want one of each (a write must never be replayed)", writes, grants)
	}

	resp, err = c.Do(context.Background(), Request{Method: http.MethodPost, Path: "/write", Body: strings.NewReader(`{"value":2}`)})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("second status: got %d, want 200 with a fresh token", resp.StatusCode)
	}
	if writes != 2 || grants != 2 {
		t.Errorf("after second call writes=%d grants=%d, want two writes and two grants", writes, grants)
	}
}

// An ordinary 403 is an authorization answer about the resource, not Secret
// Server's exact expired-token signal: it must be returned as-is, without
// spending a grant or evicting the token.
func TestDoDoesNotReplayReusedTokenOn403(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants++
			fmt.Fprint(w, grantJSON("test-token"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/denied"})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status: got %d, want 403 returned as-is", resp.StatusCode)
		}
	}
	if grants != 1 {
		t.Errorf("grants: got %d, want 1 (denied resources must not cost a grant each)", grants)
	}
}

// A token granted within the same call cannot be stale, so a 401 against it
// is a genuine denial and must not trigger a second grant.
func TestDoDoesNotReplayFreshGrant(t *testing.T) {
	grants := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants++
			fmt.Fprint(w, grantJSON("test-token"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status: got %d, want the 401 returned", resp.StatusCode)
	}
	if grants != 1 {
		t.Errorf("grants: got %d, want 1 (no replay for a fresh grant)", grants)
	}
}

func TestValidateGrant(t *testing.T) {
	cases := []struct {
		name    string
		g       grantResponse
		wantErr bool
	}{
		{"ok", grantResponse{AccessToken: "abcd", TokenType: "Bearer", ExpiresIn: 3600}, false},
		{"ok lowercase bearer", grantResponse{AccessToken: "abcd", TokenType: "bearer", ExpiresIn: 3600}, false},
		{"ok empty type", grantResponse{AccessToken: "abcd", ExpiresIn: 3600}, false},
		{"empty token", grantResponse{TokenType: "Bearer", ExpiresIn: 3600}, true},
		{"short token", grantResponse{AccessToken: "abc", TokenType: "Bearer", ExpiresIn: 3600}, true},
		{"token with space", grantResponse{AccessToken: "a b", ExpiresIn: 3600}, true},
		{"token with newline", grantResponse{AccessToken: "a\nb", ExpiresIn: 3600}, true},
		{"token with DEL", grantResponse{AccessToken: "a\u007fb", ExpiresIn: 3600}, true},
		{"bad type", grantResponse{AccessToken: "abcd", TokenType: "MAC", ExpiresIn: 3600}, true},
		{"zero expiry", grantResponse{AccessToken: "abcd"}, true},
		{"negative expiry", grantResponse{AccessToken: "abcd", ExpiresIn: -1}, true},
		{"huge expiry", grantResponse{AccessToken: "abcd", ExpiresIn: 366 * 24 * 3600}, true},
		{"overflowing expiry", grantResponse{AccessToken: "abcd", ExpiresIn: int(^uint(0) >> 1)}, true},
	}
	for _, tc := range cases {
		err := validateGrant(tc.g)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: got err %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestGrantValidationDoesNotExposeEndpointFields(t *testing.T) {
	const (
		password = "reflected-password-value"
		token    = "newly-issued-token-value"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"access_token":%q,"token_type":%q,"expires_in":3600}`, token, password)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: password, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Token(context.Background())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
	for _, secret := range []string{password, token} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("grant validation error exposed %q: %v", secret, err)
		}
	}
}

func TestSnippet(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "(empty body)"},
		{"a\n b\t c", "a b c"},
		{"a\x1b[31mred\u009bb", "a?[31mred?b"},
		{strings.Repeat("x", 300), strings.Repeat("x", 200) + "..."},
	}
	for _, tc := range cases {
		if got := snippet([]byte(tc.in)); got != tc.want {
			t.Errorf("snippet(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}
