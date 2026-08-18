package api

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateVaultURL(t *testing.T) {
	platform, err := url.Parse("https://acme.secureplatform.io")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		raw     string
		allowed []string
		wantErr bool
	}{
		{"same origin", "https://acme.secureplatform.io/SecretServer", nil, false},
		{"same origin explicit default port", "https://acme.secureplatform.io:443/SecretServer", nil, false},
		{"cloud suffix com", "https://x.secretservercloud.com", nil, false},
		{"cloud suffix explicit default port", "https://x.secretservercloud.com:443", nil, false},
		{"cloud suffix alternate port", "https://x.secretservercloud.com:8443", nil, true},
		{"cloud suffix alternate port explicitly allowlisted", "https://x.secretservercloud.com:8443", []string{"x.secretservercloud.com:8443"}, false},
		{"cloud suffix co.uk", "https://x.secretservercloud.co.uk", nil, false},
		{"dev cloud suffix", "https://x.dart.devsecretservercloud.com", nil, false},
		{"trailing dot host", "https://x.secretservercloud.com.", nil, false},
		{"allowlisted hostname", "https://vault.internal.example.com", []string{"vault.internal.example.com"}, false},
		{"allowlisted hostname explicit default port", "https://vault.internal.example.com:443", []string{"vault.internal.example.com"}, false},
		{"allowlisted hostname does not cover alternate port", "https://vault.internal.example.com:8443", []string{"vault.internal.example.com"}, true},
		{"allowlisted host with port", "https://vault.internal.example.com:8443", []string{"vault.internal.example.com:8443"}, false},
		{"http scheme", "http://x.secretservercloud.com", nil, true},
		{"userinfo", "https://u:p@x.secretservercloud.com", nil, true},
		{"query", "https://x.secretservercloud.com?q=1", nil, true},
		{"fragment", "https://x.secretservercloud.com#f", nil, true},
		{"suffix squat", "https://evilsecretservercloud.com", nil, true},
		{"untrusted host", "https://vault.internal.example.com", nil, true},
		{"empty", "", nil, true},
		{"garbage", "://", nil, true},
	}
	for _, tc := range cases {
		_, err := validateVaultURL(platform, tc.raw, tc.allowed)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: got err %v, wantErr %v", tc.name, err, tc.wantErr)
		}
		if err != nil && !errors.Is(err, ErrVault) {
			t.Errorf("%s: got %v, want errors.Is ErrVault", tc.name, err)
		}
	}
}

func certPEM(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func TestUseVaultRoutesToDiscoveredVault(t *testing.T) {
	var vaultAuth, vaultPath string
	vaultSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vaultAuth = r.Header.Get("Authorization")
		vaultPath = r.URL.Path
		fmt.Fprint(w, `{"id":4}`)
	}))
	defer vaultSrv.Close()

	brokerCalls := 0
	platformSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			brokerCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer plat-tok" {
				t.Errorf("broker authorization: got %q", got)
			}
			fmt.Fprintf(w, `{"vaults":[
				{"vaultId":"1","name":"inactive","isDefault":true,"isActive":false,"connection":{"url":"https://dead.secretservercloud.com"}},
				{"vaultId":"2","name":"nondefault","isDefault":false,"isActive":true,"connection":{"url":"https://other.secretservercloud.com"}},
				{"vaultId":"3","name":"main","isDefault":true,"isActive":true,"connection":{"url":%q}}
			]}`, vaultSrv.URL)
		default:
			http.NotFound(w, r)
		}
	}))
	defer platformSrv.Close()

	vu, err := url.Parse(vaultSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{
		URL:               platformSrv.URL,
		ClientID:          "cid",
		ClientSecret:      "cs",
		CACert:            append(certPEM(platformSrv), certPEM(vaultSrv)...),
		AllowedVaultHosts: []string{vu.Host},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/api/v1/secrets/4", UseVault: true})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != `{"id":4}` {
			t.Errorf("body: got %q", body)
		}
	}
	if vaultAuth != "Bearer plat-tok" {
		t.Errorf("vault authorization: got %q, want %q", vaultAuth, "Bearer plat-tok")
	}
	if vaultPath != "/api/v1/secrets/4" {
		t.Errorf("vault path: got %q", vaultPath)
	}
	if brokerCalls != 1 {
		t.Errorf("broker calls: got %d, want 1 (vault URL should be memoized)", brokerCalls)
	}
}

func TestVaultURLRefreshesAfterFreshnessWindow(t *testing.T) {
	var brokerCalls atomic.Int32
	var route atomic.Value
	route.Store("https://one.secretservercloud.com")
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			brokerCalls.Add(1)
			fmt.Fprintf(w, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":%q}}]}`, route.Load().(string))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(platformSrv.Close)

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	for range 2 {
		vu, err := c.VaultURL(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := vu.String(); got != "https://one.secretservercloud.com" {
			t.Fatalf("cached route = %q", got)
		}
	}
	if got := brokerCalls.Load(); got != 1 {
		t.Fatalf("broker calls inside freshness window = %d, want 1", got)
	}

	route.Store("https://two.secretservercloud.com")
	now = now.Add(vaultURLFreshness)
	vu, err := c.VaultURL(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := vu.String(); got != "https://two.secretservercloud.com" {
		t.Fatalf("refreshed route = %q", got)
	}
	if got := brokerCalls.Load(); got != 2 {
		t.Fatalf("broker calls after expiry = %d, want 2", got)
	}
}

func TestConcurrentExpiredVaultURLRefreshCoalesces(t *testing.T) {
	var brokerCalls atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			call := brokerCalls.Add(1)
			if call == 2 {
				close(refreshStarted)
				<-releaseRefresh
			}
			fmt.Fprint(w, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":"https://vault.secretservercloud.com"}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(platformSrv.Close)

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	var unixNano atomic.Int64
	unixNano.Store(time.Unix(1000, 0).UnixNano())
	c.now = func() time.Time { return time.Unix(0, unixNano.Load()) }
	if _, err := c.VaultURL(context.Background()); err != nil {
		t.Fatal(err)
	}
	unixNano.Add(vaultURLFreshness.Nanoseconds())

	const callers = 24
	errCh := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			_, err := c.VaultURL(context.Background())
			errCh <- err
		}()
	}
	<-refreshStarted
	close(releaseRefresh)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Errorf("coalesced refresh: %v", err)
		}
	}
	if got := brokerCalls.Load(); got != 2 {
		t.Fatalf("broker calls = %d, want one initial lookup and one coalesced refresh", got)
	}
}

func TestVaultURLRejectsUntrustedRefreshWithoutCachingIt(t *testing.T) {
	var brokerCalls atomic.Int32
	var phase atomic.Int32
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			brokerCalls.Add(1)
			route := "https://one.secretservercloud.com"
			switch phase.Load() {
			case 1:
				route = "https://vault.attacker.example"
			case 2:
				route = "https://two.secretservercloud.com"
			}
			fmt.Fprintf(w, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":%q}}]}`, route)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(platformSrv.Close)

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	if _, err := c.VaultURL(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(vaultURLFreshness)
	phase.Store(1)
	if _, err := c.VaultURL(context.Background()); !errors.Is(err, ErrVault) {
		t.Fatalf("untrusted replacement: got %v, want ErrVault", err)
	}
	phase.Store(2)
	vu, err := c.VaultURL(context.Background())
	if err != nil {
		t.Fatalf("lookup after rejected replacement: %v", err)
	}
	if got := vu.String(); got != "https://two.secretservercloud.com" {
		t.Fatalf("route after rejected replacement = %q", got)
	}
	if got := brokerCalls.Load(); got != 3 {
		t.Fatalf("broker calls = %d, want rejected route not to be cached", got)
	}
}

func TestVaultURLDoesNotUseExpiredRouteAfterBrokerFailure(t *testing.T) {
	var brokerCalls atomic.Int32
	var phase atomic.Int32
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			brokerCalls.Add(1)
			if phase.Load() == 1 {
				http.Error(w, "broker unavailable", http.StatusServiceUnavailable)
				return
			}
			route := "https://one.secretservercloud.com"
			if phase.Load() == 2 {
				route = "https://two.secretservercloud.com"
			}
			fmt.Fprintf(w, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":%q}}]}`, route)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(platformSrv.Close)

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	if _, err := c.VaultURL(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(vaultURLFreshness)
	phase.Store(1)
	if _, err := c.VaultURL(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatalf("expired route with failed refresh: got %v, want ErrTransport", err)
	}
	phase.Store(2)
	vu, err := c.VaultURL(context.Background())
	if err != nil {
		t.Fatalf("lookup after failed refresh: %v", err)
	}
	if got := vu.String(); got != "https://two.secretservercloud.com" {
		t.Fatalf("route after broker recovery = %q", got)
	}
	if got := brokerCalls.Load(); got != 3 {
		t.Fatalf("broker calls = %d, want failed refresh not to cache stale routing", got)
	}
}

func TestCanceledVaultRefreshDoesNotPoisonWaiters(t *testing.T) {
	var brokerCalls atomic.Int32
	refreshStarted := make(chan struct{})
	response := func(r *http.Request, body string) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}
	}
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			return response(r, grantJSON("plat-tok")), nil
		case "/vaultbroker/api/vaults":
			call := brokerCalls.Add(1)
			if call == 2 {
				close(refreshStarted)
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			return response(r, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":"https://vault.secretservercloud.com"}}]}`), nil
		default:
			return response(r, "not found"), nil
		}
	})
	c, err := New(Config{
		URL: "https://platform.example.com", Target: TargetPlatform,
		ClientID: "c", ClientSecret: "s", Transport: rt, Retries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	if _, err := c.VaultURL(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(vaultURLFreshness)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := c.VaultURL(leaderCtx)
		leaderDone <- err
	}()
	<-refreshStarted
	waiterDone := make(chan error, 1)
	go func() {
		_, err := c.VaultURL(context.Background())
		waiterDone <- err
	}()
	for {
		c.vaultMu.Lock()
		lookup := c.vaultDiscover[""]
		waiting := lookup != nil && lookup.waiters.Load() > 0
		c.vaultMu.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader: got %v, want context.Canceled", err)
	}
	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter inherited canceled refresh: %v", err)
	}
	if got := brokerCalls.Load(); got != 3 {
		t.Fatalf("broker calls = %d, want waiter to retry after canceled refresh", got)
	}
}

func TestPanickingVaultLookupReleasesWaiters(t *testing.T) {
	var brokerCalls atomic.Int32
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	response := func(r *http.Request, body string) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Proto:      "HTTP/1.1",
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}
	}
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			return response(r, grantJSON("plat-tok")), nil
		case "/vaultbroker/api/vaults":
			if brokerCalls.Add(1) == 1 {
				close(lookupStarted)
				<-releaseLookup
				panic("caller transport panic")
			}
			return response(r, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":"https://vault.secretservercloud.com"}}]}`), nil
		default:
			return response(r, "not found"), nil
		}
	})
	c, err := New(Config{
		URL: "https://platform.example.com", Target: TargetPlatform,
		ClientID: "c", ClientSecret: "s", Transport: rt, Retries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	leaderPanic := make(chan any, 1)
	go func() {
		defer func() { leaderPanic <- recover() }()
		_, _ = c.VaultURL(context.Background())
	}()
	<-lookupStarted
	waiterDone := make(chan error, 1)
	go func() {
		_, err := c.VaultURL(context.Background())
		waiterDone <- err
	}()
	for {
		c.vaultMu.Lock()
		lookup := c.vaultDiscover[""]
		waiting := lookup != nil && lookup.waiters.Load() > 0
		c.vaultMu.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(releaseLookup)
	if recovered := <-leaderPanic; recovered == nil {
		t.Fatal("leader did not propagate caller transport panic")
	}
	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter remained poisoned after leader panic: %v", err)
	}
	if got := brokerCalls.Load(); got != 2 {
		t.Fatalf("broker calls = %d, want waiter retry after panic", got)
	}
}

func TestVaultURLCachesDifferentIDsIndependently(t *testing.T) {
	var brokerCalls atomic.Int32
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			brokerCalls.Add(1)
			fmt.Fprint(w, `{"vaults":[
				{"vaultId":"default","isDefault":true,"isActive":true,"connection":{"url":"https://default.secretservercloud.com"}},
				{"vaultId":"named","isDefault":false,"isActive":true,"connection":{"url":"https://named.secretservercloud.com"}}
			]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(platformSrv.Close)

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		defaultURL, err := c.VaultURL(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		namedURL, err := c.VaultURLByID(context.Background(), "named")
		if err != nil {
			t.Fatal(err)
		}
		if defaultURL.Host != "default.secretservercloud.com" || namedURL.Host != "named.secretservercloud.com" {
			t.Fatalf("routes crossed ids: default=%s named=%s", defaultURL, namedURL)
		}
	}
	if got := brokerCalls.Load(); got != 2 {
		t.Fatalf("broker calls = %d, want one independently cached lookup per id", got)
	}
}

func TestVaultURLRejectsUntrustedHost(t *testing.T) {
	const token = "plat-tok"
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON(token))
		case "/vaultbroker/api/vaults":
			fmt.Fprintf(w, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":"https://%s.evil.example.com"}}]}`, token)
		}
	}))
	defer platformSrv.Close()

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.VaultURL(context.Background())
	if !errors.Is(err, ErrVault) {
		t.Errorf("got %v, want errors.Is ErrVault", err)
	}
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "[REDACTED].evil.example.com") {
		t.Errorf("error should redact credentials reflected in the untrusted host: %v", err)
	}
}

func TestVaultURLNoDefaultActiveVault(t *testing.T) {
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			fmt.Fprint(w, `{"vaults":[]}`)
		}
	}))
	defer platformSrv.Close()

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.VaultURL(context.Background())
	if !errors.Is(err, ErrVault) {
		t.Errorf("got %v, want errors.Is ErrVault", err)
	}
}

func TestVaultsAccessDenied(t *testing.T) {
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer platformSrv.Close()

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Vaults(context.Background())
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want errors.Is ErrAccessDenied", err)
	}
}

func TestVaultsRedactsReflectedBearerToken(t *testing.T) {
	const token = "VERYSECRETBEARER"
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "broker reflected "+token)
	}))
	defer platformSrv.Close()

	c, err := New(Config{URL: platformSrv.URL, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Vaults(context.Background())
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("bearer token reflection was not redacted: %v", err)
	}
}

func TestVaultsRetriesBodyReadFailure(t *testing.T) {
	calls := 0
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			calls++
			if calls == 1 {
				w.Header().Set("Content-Length", "1000")
				w.Write([]byte("{"))
				return
			}
			fmt.Fprint(w, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":"https://x.secretservercloud.com"}}]}`)
		}
	}))
	defer platformSrv.Close()

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s", Retries: 3,
		Backoff: func(int) time.Duration { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	vaults, verr := c.Vaults(context.Background())
	if verr != nil {
		t.Fatalf("got %v, want the body-read failure to be retried", verr)
	}
	if len(vaults) != 1 || calls != 2 {
		t.Errorf("got %d vaults after %d calls, want 1 after 2", len(vaults), calls)
	}
}

func TestDoRefusesVaultIDWithoutUseVault(t *testing.T) {
	c, err := New(Config{URL: "https://platform.example.com", ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	_, derr := c.Do(context.Background(), Request{Method: "GET", Path: "/x", VaultID: "abc"})
	if !errors.Is(derr, ErrConfig) {
		t.Errorf("got %v, want ErrConfig: a VaultID without UseVault must not silently route to the primary origin", derr)
	}
}

func TestVaultURLByIDRefusesEmptyID(t *testing.T) {
	c, err := New(Config{URL: "https://platform.example.com", ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VaultURLByID(context.Background(), ""); !errors.Is(err, ErrConfig) {
		t.Errorf("got %v, want ErrConfig: an unset vault id must not silently resolve the default vault", err)
	}
}

func TestVaultsRejectsOversizedInventory(t *testing.T) {
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			// Well-formed JSON prefix, padded past the cap: a truncating read
			// would misreport it as a parse error instead of a size error.
			w.Write([]byte(`{"vaults":[`))
			w.Write(make([]byte, maxVaultResponseBytes))
		}
	}))
	defer platformSrv.Close()

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, verr := c.Vaults(context.Background())
	if !errors.Is(verr, ErrVault) || verr == nil || !strings.Contains(verr.Error(), "exceeds") {
		t.Errorf("got %v, want an ErrVault size error, not a parse error", verr)
	}
}

// A 401/403 with an oversized (verbose WAF) body is an access-denied answer,
// not a size error: status is classified before the size cap.
func TestVaultsOversizedAccessDeniedIsDenied(t *testing.T) {
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			w.WriteHeader(http.StatusForbidden)
			w.Write(make([]byte, maxVaultResponseBytes+10))
		}
	}))
	defer platformSrv.Close()

	c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s", Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, verr := c.Vaults(context.Background())
	if !errors.Is(verr, ErrAccessDenied) {
		t.Errorf("got %v, want ErrAccessDenied (status is classified before the size cap)", verr)
	}
}

func TestVaultsBrokerStatusClassification(t *testing.T) {
	for status, want := range map[int]error{
		http.StatusServiceUnavailable: ErrTransport,
		http.StatusBadGateway:         ErrTransport,
		http.StatusRequestTimeout:     ErrTransport,
		http.StatusBadRequest:         ErrVault,
		http.StatusNotFound:           ErrVault,
	} {
		platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/identity/api/oauth2/token/xpmplatform":
				fmt.Fprint(w, grantJSON("plat-tok"))
			case "/vaultbroker/api/vaults":
				w.WriteHeader(status)
			}
		}))
		c, err := New(Config{URL: platformSrv.URL, ClientID: "c", ClientSecret: "s", Retries: 1})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Vaults(context.Background())
		if !errors.Is(err, want) {
			t.Errorf("broker %d: got %v, want errors.Is %v", status, err, want)
		}
		platformSrv.Close()
	}
}
