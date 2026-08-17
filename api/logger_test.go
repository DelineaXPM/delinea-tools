package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func debugLogger() (*slog.Logger, *logBuffer) {
	buf := &logBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func TestLoggerReportsGrantAndRetry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			fmt.Fprint(w, grantJSON("granted-token"))
			return
		}
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	logger, buf := debugLogger()
	c, err := New(Config{URL: srv.URL, Username: "svc", Password: "hunter2-pw",
		Logger: logger, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: http.MethodGet,
		Path: "/api/v1/things?filter.searchText=query-is-caller-data"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	out := buf.String()
	if !strings.Contains(out, "token grant succeeded") {
		t.Errorf("grant success not logged:\n%s", out)
	}
	if !strings.Contains(out, "identity=svc") {
		t.Errorf("grant log should carry the identity:\n%s", out)
	}
	if !strings.Contains(out, "retrying request") || !strings.Contains(out, "status=503") {
		t.Errorf("retry not logged with its status:\n%s", out)
	}
	for _, secret := range []string{"hunter2-pw", "granted-token", "query-is-caller-data"} {
		if strings.Contains(out, secret) {
			t.Errorf("log leaked %q:\n%s", secret, out)
		}
	}
}

func TestTransportFailureDoesNotExposeQuery(t *testing.T) {
	const querySecret = "query-value-must-not-leak"
	transportErr := errors.New("dial failed")
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	})
	logger, buf := debugLogger()
	c, err := New(Config{
		URL: "https://vault.example.com", Token: "test-token", Transport: rt,
		Logger: logger, Retries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/things?filter=" + querySecret})
	if !errors.Is(err, transportErr) {
		t.Fatalf("got %v, want the underlying transport error preserved", err)
	}
	if strings.Contains(err.Error(), querySecret) {
		t.Errorf("returned error leaked request query: %v", err)
	}
	if out := buf.String(); strings.Contains(out, querySecret) {
		t.Errorf("retry log leaked request query:\n%s", out)
	}
}

func TestLoggerReportsGrantFailureWithoutCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"bad credentials for hunter2-pw"}`)
	}))
	defer srv.Close()

	logger, buf := debugLogger()
	c, err := New(Config{URL: srv.URL, Username: "svc", Password: "hunter2-pw",
		Logger: logger, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err == nil {
		t.Fatal("grant should have failed")
	}
	out := buf.String()
	if !strings.Contains(out, "token grant attempt failed") || !strings.Contains(out, "status=401") {
		t.Errorf("grant failure not logged with its status:\n%s", out)
	}
	if strings.Contains(out, "hunter2-pw") {
		t.Errorf("log leaked the password (the grant error embeds a redacted body, which must stay redacted):\n%s", out)
	}
}

func TestLoggerReportsVaultSelection(t *testing.T) {
	var vaultHost string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/identity/api/oauth2/token/xpmplatform", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, grantJSON("platform-token"))
	})
	mux.HandleFunc("/vaultbroker/api/vaults", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"vaults":[{"vaultId":"v-1","name":"Primary","isDefault":true,"isActive":true,"connection":{"url":"https://%s"}}]}`, vaultHost)
	})
	vaultHost = strings.TrimPrefix(srv.URL, "http://")

	logger, buf := debugLogger()
	c, err := New(Config{URL: srv.URL, Target: TargetPlatform, ClientID: "ci", ClientSecret: "cs-secret",
		Logger: logger, DisableCache: true, AllowedVaultHosts: []string{vaultHost}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VaultURL(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "vault selected") || !strings.Contains(out, "vault_id=v-1") {
		t.Errorf("vault selection not logged:\n%s", out)
	}
	if strings.Contains(out, "cs-secret") || strings.Contains(out, "platform-token") {
		t.Errorf("log leaked a credential:\n%s", out)
	}
}

func TestNilLoggerIsSilentAndSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, grantJSON("tok-quiet"))
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The sanitized transport diagnostic keeps the operation-naming wrap prefix:
// an operator must be able to tell a failed token grant from a failed API
// call, while the request URL (whose query may carry caller data) stays out.
func TestTransportDiagnosticKeepsOperationPrefix(t *testing.T) {
	rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: connection refused")
	})
	c, err := New(Config{URL: "https://vault.example.com", Username: "u", Password: "p", Transport: rt, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "requesting token") {
		t.Errorf("got %v, want the grant failure to name the token operation", err)
	}
	if strings.Contains(err.Error(), "vault.example.com") {
		t.Errorf("diagnostic leaked the request URL: %v", err)
	}
}
