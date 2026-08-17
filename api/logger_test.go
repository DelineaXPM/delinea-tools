package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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

type closeErrorBody struct{ err error }

func (b closeErrorBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b closeErrorBody) Close() error             { return b.err }

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
		Path: "/api/v1/granted-token#fragment-is-caller-data"})
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
	for _, secret := range []string{"hunter2-pw", "granted-token", "fragment-is-caller-data"} {
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

func TestTransportFailureRedactsOutboundCredentials(t *testing.T) {
	t.Run("authenticated request", func(t *testing.T) {
		const token = "configured-bearer-token"
		const configuredHeader = "gateway-header-secret"
		const requestHeader = "request-header-secret"
		const requestBody = "api-request-body-secret"
		cause := errors.New("transport cause")
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: auth=%s gateway=%s request=%s body=%s", cause,
				r.Header.Get("Authorization"), r.Header.Get("X-Gateway-Key"), r.Header.Get("X-Request-Key"), body)
		})
		logger, buf := debugLogger()
		c, err := New(Config{
			URL: "https://vault.example.com", Token: token, Transport: rt, Logger: logger, Retries: 2,
			Header:  http.Header{"X-Gateway-Key": {configuredHeader}},
			Backoff: func(int) time.Duration { return 0 },
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Do(context.Background(), Request{
			Method: http.MethodGet,
			Path:   "/api/v1/things",
			Header: http.Header{"X-Request-Key": {requestHeader}},
			Body:   strings.NewReader(requestBody),
		})
		if !errors.Is(err, cause) {
			t.Fatalf("got %v, want original transport cause in the unwrap chain", err)
		}
		for _, secret := range []string{token, configuredHeader, requestHeader, requestBody} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("transport diagnostic exposed %q: %v", secret, err)
			}
			if strings.Contains(buf.String(), secret) {
				t.Errorf("retry log exposed %q:\n%s", secret, buf.String())
			}
		}
	})

	t.Run("grant body", func(t *testing.T) {
		const password = "password-value"
		cause := errors.New("grant transport cause")
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: submitted %s", cause, body)
		})
		logger, buf := debugLogger()
		c, err := New(Config{
			URL: "https://vault.example.com", Username: "svc", Password: password,
			Transport: rt, Logger: logger, Retries: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Token(context.Background())
		if !errors.Is(err, cause) {
			t.Fatalf("got %v, want original grant transport cause in the unwrap chain", err)
		}
		if strings.Contains(err.Error(), password) {
			t.Errorf("grant transport diagnostic exposed the password: %v", err)
		}
		for _, bodyPart := range []string{password, "grant_type=password", "password="} {
			if strings.Contains(err.Error(), bodyPart) {
				t.Errorf("grant transport diagnostic exposed request-body content %q: %v", bodyPart, err)
			}
			if out := buf.String(); strings.Contains(out, bodyPart) {
				t.Errorf("grant failure log exposed request-body content %q:\n%s", bodyPart, out)
			}
		}
	})

	t.Run("response body read", func(t *testing.T) {
		const token = "stream-bearer-token"
		const requestHeader = "stream-header-secret"
		const responseBody = "response-body-must-not-leak"
		cause := errors.New("stream transport cause")
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			bodyErr := fmt.Errorf("%w: auth=%s request=%s body=%s", cause,
				r.Header.Get("Authorization"), r.Header.Get("X-Request-Key"), responseBody)
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Proto:      "HTTP/1.1",
				Header:     http.Header{},
				Body:       io.NopCloser(errorReader{err: bodyErr}),
				Request:    r,
			}, nil
		})
		c, err := New(Config{URL: "https://vault.example.com", Token: token, Transport: rt})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(context.Background(), Request{
			Method: http.MethodGet,
			Path:   "/api/v1/things",
			Header: http.Header{"X-Request-Key": {requestHeader}},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, err = resp.Body.Read(make([]byte, 1))
		if !errors.Is(err, cause) {
			t.Fatalf("got %v, want original body-read cause in the unwrap chain", err)
		}
		for _, secret := range []string{token, requestHeader, responseBody} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("body-read diagnostic exposed %q: %v", secret, err)
			}
		}
	})

	t.Run("response body close", func(t *testing.T) {
		const token = "close-bearer-token"
		const requestHeader = "close-header-secret"
		const responseBody = "close-response-body-must-not-leak"
		cause := errors.New("close transport cause")
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			closeErr := fmt.Errorf("%w: auth=%s request=%s body=%s", cause,
				r.Header.Get("Authorization"), r.Header.Get("X-Request-Key"), responseBody)
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Proto:      "HTTP/1.1",
				Header:     http.Header{},
				Body:       closeErrorBody{err: closeErr},
				Request:    r,
			}, nil
		})
		c, err := New(Config{URL: "https://vault.example.com", Token: token, Transport: rt})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(context.Background(), Request{
			Method: http.MethodGet,
			Path:   "/api/v1/things",
			Header: http.Header{"X-Request-Key": {requestHeader}},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = resp.Body.Close()
		if !errors.Is(err, cause) {
			t.Fatalf("got %v, want original body-close cause in the unwrap chain", err)
		}
		for _, secret := range []string{token, requestHeader, responseBody} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("body-close diagnostic exposed %q: %v", secret, err)
			}
		}
	})

	t.Run("buffered response body retry", func(t *testing.T) {
		const responseBody = "buffered-response-body-must-not-leak"
		cause := errors.New("buffered stream transport cause")
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Proto:      "HTTP/1.1",
				Header:     http.Header{},
				Body:       io.NopCloser(errorReader{err: fmt.Errorf("%w: body=%s", cause, responseBody)}),
				Request:    r,
			}, nil
		})
		logger, buf := debugLogger()
		c, err := New(Config{
			URL: "https://vault.example.com", Token: "configured-bearer-token", Transport: rt,
			Logger: logger, Retries: 2, Backoff: func(int) time.Duration { return 0 },
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.DoBufferedResponse(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/things"}, 1024)
		if !errors.Is(err, cause) {
			t.Fatalf("got %v, want original body-read cause in the unwrap chain", err)
		}
		if strings.Contains(err.Error(), responseBody) {
			t.Errorf("buffered body-read diagnostic exposed response content: %v", err)
		}
		if out := buf.String(); strings.Contains(out, responseBody) {
			t.Errorf("buffered body-read retry log exposed response content:\n%s", out)
		}
	})
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
	const (
		platformToken = "platform-token"
		clientSecret  = "client-secret-value"
		gatewaySecret = "gateway-secret-value"
	)
	var vaultHost string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/identity/api/oauth2/token/xpmplatform", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, grantJSON(platformToken))
	})
	mux.HandleFunc("/vaultbroker/api/vaults", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"vaults":[{"vaultId":"v-%s","name":"Primary %s %s","isDefault":true,"isActive":true,"connection":{"url":"https://%s"}}]}`,
			platformToken, clientSecret, gatewaySecret, vaultHost)
	})
	vaultHost = strings.TrimPrefix(srv.URL, "http://")

	logger, buf := debugLogger()
	c, err := New(Config{
		URL: srv.URL, Target: TargetPlatform, ClientID: "ci", ClientSecret: clientSecret,
		Header: http.Header{"X-Gateway-Key": {gatewaySecret}}, Logger: logger,
		DisableCache: true, AllowedVaultHosts: []string{vaultHost},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VaultURL(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "vault selected") || !strings.Contains(out, "[REDACTED]") {
		t.Errorf("vault selection not logged:\n%s", out)
	}
	for _, secret := range []string{clientSecret, platformToken, gatewaySecret} {
		if strings.Contains(out, secret) {
			t.Errorf("log leaked credential %q:\n%s", secret, out)
		}
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
