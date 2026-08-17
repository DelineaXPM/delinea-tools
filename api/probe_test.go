package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func healthServer(t *testing.T, healthyPath, body string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if healthyPath != "" && r.URL.Path == healthyPath {
			fmt.Fprint(w, body)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// A probe that fails at the transport layer must carry the ErrTransport
// sentinel like every other network path, so WithProbedTarget consumers can
// classify a transient outage for retry.
func TestProbeBackendClassifiesTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listening now -> connection refused
	if _, err := ProbeBackend(context.Background(), Config{URL: url}); !errors.Is(err, ErrTransport) {
		t.Fatalf("got %v, want ErrTransport", err)
	}
}

func TestProbeBackendSecretServer(t *testing.T) {
	srv := healthServer(t, "/api/v1/healthcheck", `{"healthy":true,"databaseHealthy":true}`)
	got, err := ProbeBackend(context.Background(), Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if got != BackendSecretServer {
		t.Errorf("got %q, want %q", got, BackendSecretServer)
	}
}

func TestProbeBackendClosesOwnedTransportIdleConnections(t *testing.T) {
	closed := make(chan struct{}, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"healthy":true}`)
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)

	if _, err := ProbeBackend(context.Background(), Config{URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("ProbeBackend left its transport's idle connection open")
	}
}

func TestProbeBackendPlatform(t *testing.T) {
	srv := healthServer(t, "/health", `{"healthy":true}`)
	got, err := ProbeBackend(context.Background(), Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if got != BackendPlatform {
		t.Errorf("got %q, want %q", got, BackendPlatform)
	}
}

// A host that answers both probes but reports neither backend healthy is
// reachable, not a reachability failure: ProbeBackend returns BackendUnknown
// with no error, so check reports "reachable, but neither healthy" rather
// than a misleading transport error.
func TestProbeBackendReachableButUnhealthyIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	got, err := ProbeBackend(context.Background(), Config{URL: srv.URL})
	if err != nil {
		t.Errorf("got error %v, want nil: the host answered, so it is reachable", err)
	}
	if got != BackendUnknown {
		t.Errorf("got %q, want BackendUnknown", got)
	}
}

// A non-2xx response whose body happens to contain "Healthy" (an error page,
// a WAF block) must not be read as a healthy backend.
func TestProbeBackendIgnoresUnhealthyStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"healthy":true} Healthy`)
	}))
	defer srv.Close()
	got, err := ProbeBackend(context.Background(), Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if got != BackendUnknown {
		t.Errorf("got %q, want BackendUnknown: a 503 body is not a healthy verdict", got)
	}
}

func TestProbeHealthyRecognizesOnlyAuthoritativeResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"json healthy", http.StatusOK, `{"healthy":true}`, true},
		{"json unhealthy", http.StatusOK, `{"healthy":false}`, false},
		{"json without field", http.StatusOK, `{"status":"Healthy"}`, false},
		{"trimmed legacy", http.StatusOK, " \tHealthy\r\n", true},
		{"lowercase legacy", http.StatusOK, "healthy", true},
		{"not healthy", http.StatusOK, "Not Healthy", false},
		{"unhealthy", http.StatusOK, "UnHealthy", false},
		{"html", http.StatusOK, "<html>Healthy</html>", false},
		{"redirect", http.StatusFound, `{"healthy":true}`, false},
		{"client error", http.StatusNotFound, "Healthy", false},
		{"server error", http.StatusServiceUnavailable, "Healthy", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			t.Cleanup(srv.Close)
			client := srv.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			got, err := probeHealthy(context.Background(), client, srv.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("probeHealthy(%d, %q) = %v, want %v", tt.status, tt.body, got, tt.want)
			}
		})
	}
}

// Secret Server is tried first, so it wins when both endpoints answer.
func TestProbeBackendPrefersSecretServer(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"healthy":true}`)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"healthy":true}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	got, err := ProbeBackend(context.Background(), Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if got != BackendSecretServer {
		t.Errorf("got %q, want %q", got, BackendSecretServer)
	}
}

// The probe must not follow a redirect: a hostile endpoint could otherwise
// point it at an internal host (SSRF) or at a service that answers "Healthy"
// to flip the reported backend. A 302 toward a healthy target is not followed,
// so the backend stays unknown.
func TestProbeBackendDoesNotFollowRedirect(t *testing.T) {
	var healthyHit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthyHit = true
		fmt.Fprint(w, `{"healthy":true}`)
	}))
	t.Cleanup(target.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v1/healthcheck", http.StatusFound)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/health", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	got, err := ProbeBackend(context.Background(), Config{URL: srv.URL})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if got != BackendUnknown {
		t.Errorf("got %q, want unknown (redirect must not be followed)", got)
	}
	if healthyHit {
		t.Errorf("probe followed the redirect to the healthy target")
	}
}

func TestProbeBackendReachableButNeitherHealthy(t *testing.T) {
	srv := healthServer(t, "", "")
	got, err := ProbeBackend(context.Background(), Config{URL: srv.URL})
	if got != BackendUnknown {
		t.Errorf("got %q, want unknown", got)
	}
	if err != nil {
		t.Errorf("a reachable host that is simply not healthy is not an error: got %v", err)
	}
}

func TestProbeBackendUnreachable(t *testing.T) {
	got, err := ProbeBackend(context.Background(), Config{URL: "http://127.0.0.1:1", Timeout: 2 * time.Second})
	if got != BackendUnknown {
		t.Errorf("got %q, want unknown", got)
	}
	if err == nil {
		t.Errorf("got nil error, want a connection failure")
	}
}

func TestProbeBackendRejectsRemotePlaintextHTTP(t *testing.T) {
	if _, err := ProbeBackend(context.Background(), Config{URL: "http://vault.example.com"}); !errors.Is(err, ErrConfig) {
		t.Fatalf("got %v, want ErrConfig", err)
	}
}

func TestProbeBackendBadCACert(t *testing.T) {
	if _, err := ProbeBackend(context.Background(), Config{URL: "https://example.invalid", CACert: []byte("not a pem")}); err == nil {
		t.Errorf("got nil error, want a PEM failure")
	}
}

// The probe must not send a credential: it exists to be safe to run before
// authentication is known to work, and a failed attempt can suspend an account.
func TestProbeBackendSendsNoCredential(t *testing.T) {
	var sawAuth, sawBody bool
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth = true
		}
		if r.ContentLength > 0 {
			sawBody = true
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if _, err := ProbeBackend(context.Background(), Config{URL: srv.URL, Username: "svc", Password: "pw", Token: "test-token"}); err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if sawAuth {
		t.Errorf("probe sent an Authorization header")
	}
	if sawBody {
		t.Errorf("probe sent a request body")
	}
}

func TestProbeBackendUsesConfiguredRoutingHeadersWithoutAuthorization(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("probe sent Config.Header Authorization %q", got)
		}
		if got := r.Header.Get("X-Gateway"); got != "open" {
			t.Errorf("X-Gateway = %q, want open", got)
			http.Error(w, "missing gateway header", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/api/v1/healthcheck" {
			fmt.Fprint(w, `{"healthy":true}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	got, err := ProbeBackend(context.Background(), Config{
		URL: srv.URL,
		Header: http.Header{
			"Authorization": {"Bearer must-not-send"},
			"X-Gateway":     {"open"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != BackendSecretServer {
		t.Fatalf("got %q, want %q", got, BackendSecretServer)
	}
	if requests != 1 {
		t.Fatalf("got %d requests, want 1", requests)
	}
}

func TestProbeBackendRejectsInvalidConfiguredHeader(t *testing.T) {
	got, err := ProbeBackend(context.Background(), Config{
		URL:    "http://127.0.0.1:1",
		Header: http.Header{"X-Invalid": {"line one\nline two"}},
	})
	if got != BackendUnknown {
		t.Fatalf("got %q, want unknown", got)
	}
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("got %v, want ErrConfig", err)
	}
}

type headerEchoErrorTransport struct{}

func (headerEchoErrorTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("gateway rejected key %s", r.Header.Get("X-Gateway-Key"))
}

func TestProbeBackendRedactsConfiguredHeaderFromTransportError(t *testing.T) {
	const secret = "short-gateway-secret"
	_, err := ProbeBackend(context.Background(), Config{
		URL:       "https://unroutable.invalid",
		Header:    http.Header{"X-Gateway-Key": {secret}},
		Transport: headerEchoErrorTransport{},
	})
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("got %v, want ErrTransport", err)
	}
	if strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "opaque transport details suppressed") {
		t.Fatalf("probe transport diagnostic exposed configured header: %v", err)
	}
}

func selfSignedCACertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "delinea-tools-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// A private CA must supplement the public roots, not replace them: the Platform
// flow reaches the Platform host and then a broker-supplied vault URL, which may
// chain to a public CA.
type healthyTransport struct {
	calls      int
	closeCalls int
}

func (h *healthyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	h.calls++
	status, body := http.StatusNotFound, "not here"
	if r.URL.Path == "/api/v1/healthcheck" {
		status, body = http.StatusOK, `{"healthy":true}`
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d status", status),
		Proto:      "HTTP/1.1",
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}, nil
}

func (h *healthyTransport) CloseIdleConnections() { h.closeCalls++ }

func TestProbeBackendUsesConfigTransport(t *testing.T) {
	rt := &healthyTransport{}
	got, err := ProbeBackend(context.Background(), Config{URL: "https://unroutable.invalid", Transport: rt})
	if err != nil {
		t.Fatal(err)
	}
	if got != BackendSecretServer {
		t.Errorf("backend: got %q, want %q", got, BackendSecretServer)
	}
	if rt.calls == 0 {
		t.Error("the probe did not go through Config.Transport")
	}
	if rt.closeCalls != 0 {
		t.Errorf("ProbeBackend closed caller-owned transport %d times", rt.closeCalls)
	}
}

func TestRootPoolAddsToSystemRoots(t *testing.T) {
	// Subjects() is empty for a system pool on platforms with their own verifier
	// (macOS), so compare pools with Equal, which also compares the system-pool
	// flag, rather than counting certificates.
	system, err := x509.SystemCertPool()
	if err != nil || system == nil {
		t.Skip("no system trust store on this platform")
	}
	pemBytes := selfSignedCACertPEM(t)

	got, err := rootPool(pemBytes)
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if got.Equal(system) {
		t.Errorf("the supplied CA was not added to the pool")
	}
	onlyOurs := x509.NewCertPool()
	if !onlyOurs.AppendCertsFromPEM(pemBytes) {
		t.Fatal("test certificate did not parse")
	}
	if got.Equal(onlyOurs) {
		t.Errorf("the system roots were replaced rather than supplemented")
	}
}

func TestRootPoolRejectsGarbage(t *testing.T) {
	if _, err := rootPool([]byte("not a pem")); err == nil {
		t.Errorf("got nil error, want a PEM failure")
	}
}
