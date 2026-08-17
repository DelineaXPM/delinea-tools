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
		{"cloud suffix co.uk", "https://x.secretservercloud.co.uk", nil, false},
		{"dev cloud suffix", "https://x.dart.devsecretservercloud.com", nil, false},
		{"trailing dot host", "https://x.secretservercloud.com.", nil, false},
		{"allowlisted hostname", "https://vault.internal.example.com", []string{"vault.internal.example.com"}, false},
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

func TestVaultURLRejectsUntrustedHost(t *testing.T) {
	platformSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			fmt.Fprint(w, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":"https://vault.evil.example.com"}}]}`)
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
	if err == nil || !strings.Contains(err.Error(), "vault.evil.example.com") {
		t.Errorf("error should name the untrusted host: %v", err)
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
