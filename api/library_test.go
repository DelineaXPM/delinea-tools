package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Config.Transport is used verbatim as the base RoundTripper.
func TestConfigTransportUsed(t *testing.T) {
	rt := &fakeTransport{status: 200}
	c, err := New(Config{URL: "https://example.com", Token: "test-token", Transport: rt})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if rt.calls != 1 {
		t.Errorf("custom transport not used: %d calls", rt.calls)
	}
}

// A caller-owned transport owns its TLS, so combining it with CACert or
// SkipTLSVerify is refused.
func TestConfigTransportRejectsTLSCombo(t *testing.T) {
	for _, cfg := range []Config{
		{URL: "https://example.com", Token: "test-token", Transport: &fakeTransport{}, SkipTLSVerify: true},
		{URL: "https://example.com", Token: "test-token", Transport: &fakeTransport{}, CACert: []byte("x")},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("Transport + TLS setting: got nil error, want ErrConfig")
		}
	}
}

// Config.Header is sent on every request; a per-request header wins; the
// Authorization header is always the client's and cannot be overridden.
func TestConfigHeaderMergeAndAuthWins(t *testing.T) {
	rt := &fakeTransport{status: 200}
	c, err := New(Config{
		URL:    "https://example.com",
		Token:  "test-token",
		Header: http.Header{"X-Gateway": {"g"}, "X-Both": {"config"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.hc.Transport = rt
	resp, err := c.Do(context.Background(), Request{
		Method: "GET",
		Path:   "/x",
		Header: http.Header{"X-Both": {"request"}, "Authorization": {"Bearer attacker"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := rt.lastReq.Header.Get("X-Gateway"); got != "g" {
		t.Errorf("config header dropped: %q", got)
	}
	if got := rt.lastReq.Header.Get("X-Both"); got != "request" {
		t.Errorf("per-request header should win: got %q", got)
	}
	if got := rt.lastReq.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Errorf("Authorization must be the client's: got %q", got)
	}
}

// Config.Backoff replaces the default backoff during retries.
func TestConfigBackoffUsed(t *testing.T) {
	rt := &fakeTransport{failures: 1, status: 200}
	calls := 0
	c, err := New(Config{
		URL:     "https://example.com",
		Token:   "test-token",
		Retries: 2,
		Backoff: func(int) time.Duration { calls++; return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	c.hc.Transport = rt
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if calls != 1 {
		t.Errorf("custom backoff invocations: got %d, want 1", calls)
	}
}

// Config.Header goes to the primary target but not to a vault on a different
// host, so a gateway header cannot leak cross-origin.
func TestConfigHeaderNotSentToVault(t *testing.T) {
	var vaultSawGateway bool
	vaultSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Gateway") != "" {
			vaultSawGateway = true
		}
		fmt.Fprint(w, `{"id":4}`)
	}))
	defer vaultSrv.Close()

	var brokerSawGateway bool
	platform := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			if r.Header.Get("X-Gateway") != "" {
				brokerSawGateway = true // broker is on the platform origin, so it may
			}
			fmt.Fprintf(w, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":%q}}]}`, vaultSrv.URL)
		default:
			http.NotFound(w, r)
		}
	}))
	defer platform.Close()

	vu, _ := url.Parse(vaultSrv.URL)
	c, err := New(Config{
		URL:               platform.URL,
		ClientID:          "cid",
		ClientSecret:      "cs",
		Header:            http.Header{"X-Gateway": {"secret-gw-token"}},
		CACert:            append(certPEM(platform), certPEM(vaultSrv)...),
		AllowedVaultHosts: []string{vu.Host},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/api/v1/secrets/4", UseVault: true})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if vaultSawGateway {
		t.Errorf("Config.Header leaked to the vault host on a different origin")
	}
	if !brokerSawGateway {
		t.Errorf("Config.Header should reach the broker on the platform origin")
	}
}

func TestTargetAccessor(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want Target
	}{
		{Config{URL: "https://x", Username: "u", Password: "p"}, TargetSecretServer},
		{Config{URL: "https://x", ClientID: "c", ClientSecret: "s"}, TargetPlatform},
		{Config{URL: "https://x", Token: "test-token"}, TargetAuto},
	} {
		c, err := New(tc.cfg)
		if err != nil {
			t.Fatal(err)
		}
		if c.Target() != tc.want {
			t.Errorf("Target(): got %q, want %q", c.Target(), tc.want)
		}
	}
}

type idleCloseTransport struct {
	closeCalls int
}

func (*idleCloseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("unexpected request")
}

func (t *idleCloseTransport) CloseIdleConnections() {
	t.closeCalls++
}

func TestCloseIdleConnections(t *testing.T) {
	rt := &idleCloseTransport{}
	c, err := New(Config{
		URL:       "https://x",
		Token:     "test-token",
		Transport: rt,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.CloseIdleConnections()
	if rt.closeCalls != 1 {
		t.Fatalf("CloseIdleConnections delegated %d times, want 1", rt.closeCalls)
	}
}

// VaultURLByID resolves and validates a specific (non-default) vault, and Do
// with Request.VaultID routes there.
func TestVaultURLByIDAndRouting(t *testing.T) {
	var hitPath string
	vault2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		fmt.Fprint(w, `{"id":9}`)
	}))
	defer vault2.Close()

	platform := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			fmt.Fprintf(w, `{"vaults":[
				{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":"https://main.secretservercloud.com"}},
				{"vaultId":"2","isDefault":false,"isActive":true,"connection":{"url":%q}},
				{"vaultId":"3","isDefault":false,"isActive":false,"connection":{"url":"https://dead.secretservercloud.com"}}
			]}`, vault2.URL)
		default:
			http.NotFound(w, r)
		}
	}))
	defer platform.Close()

	vu, _ := url.Parse(vault2.URL)
	c, err := New(Config{
		URL:               platform.URL,
		ClientID:          "cid",
		ClientSecret:      "cs",
		CACert:            append(certPEM(platform), certPEM(vault2)...),
		AllowedVaultHosts: []string{vu.Host},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := c.VaultURLByID(context.Background(), "2")
	if err != nil {
		t.Fatalf("VaultURLByID: %v", err)
	}
	if got.Host != vu.Host {
		t.Errorf("VaultURLByID host: got %q, want %q", got.Host, vu.Host)
	}

	resp, err := c.Do(context.Background(), Request{Method: "GET", Path: "/api/v1/secrets/9", UseVault: true, VaultID: "2"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != `{"id":9}` || hitPath != "/api/v1/secrets/9" {
		t.Errorf("routing: body %q, path %q", body, hitPath)
	}

	if _, err := c.VaultURLByID(context.Background(), "3"); err == nil {
		t.Errorf("inactive vault: want an error")
	}
	if _, err := c.VaultURLByID(context.Background(), "404"); err == nil {
		t.Errorf("missing vault: want an error")
	}
}
