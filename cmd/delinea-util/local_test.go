package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// These tests drive the CLI end to end — env config, the engine's grant, the
// call, and the response copy — against a loopback server, which the https
// requirement's loopback exception exists for. Everything runs offline.

func loopbackServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"test-token","token_type":"bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/api/v1/thing", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/api/v1/header", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("X-Request-Key") != "file-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/api/v1/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"no such thing"}`)
	})
	mux.HandleFunc("/api/v1/users/current", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"id":42,"userName":"svc"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func clearAPIEnv(t *testing.T) {
	t.Helper()
	for _, n := range []string{
		"DELINEA_TOOLS_URL", "DELINEA_TOOLS_TARGET", "DELINEA_TOOLS_USERNAME", "DELINEA_TOOLS_PASSWORD",
		"DELINEA_TOOLS_DOMAIN", "DELINEA_TOOLS_CLIENT_ID", "DELINEA_TOOLS_CLIENT_SECRET", "DELINEA_TOOLS_TOKEN",
		"DELINEA_TOOLS_CA_CERT", "DELINEA_TOOLS_TLS_SKIP_VERIFY", "DELINEA_TOOLS_TIMEOUT", "DELINEA_TOOLS_RETRIES",
		"DELINEA_TOOLS_VAULT_ALLOW",
		"DELINEA_TOOLS_GATEWAY_HEADER_FILE",
	} {
		t.Setenv(n, "")
		os.Unsetenv(n)
	}
}

// runCapture runs the CLI in-process with stdout captured.
func runCapture(t *testing.T, args ...string) (string, int) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = outW
	code := run(args)
	os.Stdout = old
	outW.Close()
	out, readErr := io.ReadAll(outR)
	outR.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(out), code
}

func TestLocalGet(t *testing.T) {
	srv := loopbackServer(t)
	clearAPIEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "u")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "p")

	out, code := runCapture(t, "GET", "/api/v1/thing")
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if out != `{"ok":true}` {
		t.Errorf("body: got %q", out)
	}
}

func TestLocalGetReadsSecretHeaderFile(t *testing.T) {
	srv := loopbackServer(t)
	clearAPIEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")

	headerFile := t.TempDir() + "/headers"
	if err := os.WriteFile(headerFile, []byte("X-Request-Key: file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runCapture(t, "-H", "@"+headerFile, "GET", "/api/v1/header")
	if code != 0 || out != `{"ok":true}` {
		t.Fatalf("header-file request: code=%d body=%q", code, out)
	}
}

func TestLocalGatewayHeaderFileCoversGrantAndRequest(t *testing.T) {
	const gatewaySecret = "gateway-secret"
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Gateway-Key") != gatewaySecret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"access_token":"gateway-token","token_type":"bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/api/v1/thing", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Gateway-Key") != gatewaySecret || r.Header.Get("Authorization") != "Bearer gateway-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	clearAPIEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "pw")
	headerFile := t.TempDir() + "/gateway.headers"
	if err := os.WriteFile(headerFile, []byte("X-Gateway-Key: "+gatewaySecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runCapture(t, "--gateway-header-file", headerFile, "GET", "/api/v1/thing")
	if code != 0 || out != `{"ok":true}` {
		t.Fatalf("gateway request: code=%d body=%q", code, out)
	}
}

// A completed non-2xx call exits 4 with the body still printed.
func TestLocalGetNotFound(t *testing.T) {
	srv := loopbackServer(t)
	clearAPIEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")

	out, code := runCapture(t, "GET", "/api/v1/missing")
	if code != 4 {
		t.Fatalf("exit code: got %d, want 4", code)
	}
	if out != `{"message":"no such thing"}` {
		t.Errorf("body: got %q", out)
	}
}

func TestLocalTokenIgnoresStaleUsername(t *testing.T) {
	srv := loopbackServer(t)
	clearAPIEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")
	t.Setenv("DELINEA_TOOLS_USERNAME", "stale-user")

	out, code := runCapture(t, "GET", "/api/v1/thing")
	if code != 0 || out != `{"ok":true}` {
		t.Fatalf("targetless token did not ignore the stale Username: code=%d body=%q", code, out)
	}
}

func TestLocalToken(t *testing.T) {
	srv := loopbackServer(t)
	clearAPIEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "u")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "p")

	out, code := runCapture(t, "token")
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if strings.TrimSpace(out) != "test-token" {
		t.Errorf("Token: got %q, want tok", out)
	}
}

// -i prepends the status line and headers to stdout, exercising cmdCall's
// include branch.
func TestLocalInclude(t *testing.T) {
	srv := loopbackServer(t)
	clearAPIEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")

	out, code := runCapture(t, "-i", "GET", "/api/v1/thing")
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if !strings.HasPrefix(out, "HTTP/") || !strings.Contains(out, `{"ok":true}`) {
		t.Errorf("include output missing status line or body:\n%s", out)
	}
}

// token --interactive drives the Identity API. A UP-only challenge answers from
// the configured password and never consults the interactive prompter, so it
// runs end to end offline and prints the token.
func TestLocalTokenInteractive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/Security/StartAuthentication", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"Result":{"SessionId":"s","TenantId":"t","Challenges":[{"Mechanisms":[{"MechanismId":"m-up","Name":"UP","AnswerType":"Text"}]}]}}`)
	})
	mux.HandleFunc("/identity/Security/AdvanceAuthentication", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"login-tok"}}}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	clearAPIEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "cloudadmin@tenant")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "pw")

	out, code := runCapture(t, "token", "--interactive")
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if strings.TrimSpace(out) != "login-tok" {
		t.Errorf("interactive token: got %q, want login-tok", out)
	}
}

// token --interactive with an explicit DELINEA_TOOLS_TARGET=platform is the
// natural Platform configuration. Config validation must accept
// platform+username/password on the login path; previously it rejected it for
// lacking client credentials.
func TestLocalTokenInteractiveExplicitPlatformTarget(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/identity/Security/StartAuthentication", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"Result":{"SessionId":"s","TenantId":"t","Challenges":[{"Mechanisms":[{"MechanismId":"m-up","Name":"UP","AnswerType":"Text"}]}]}}`)
	})
	mux.HandleFunc("/identity/Security/AdvanceAuthentication", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"Result":{"Summary":"LoginSuccess","OAuthTokens":{"access_token":"login-tok"}}}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	clearAPIEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TARGET", "platform")
	t.Setenv("DELINEA_TOOLS_USERNAME", "cloudadmin@tenant")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "pw")

	out, code := runCapture(t, "token", "--interactive")
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	if strings.TrimSpace(out) != "login-tok" {
		t.Errorf("interactive token: got %q, want login-tok", out)
	}
}

func TestLocalRefusesInsecureURL(t *testing.T) {
	clearAPIEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "http://vault.example.com")
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")
	if _, code := runCapture(t, "GET", "/api/v1/thing"); code != 1 {
		t.Errorf("exit code: got %d, want 1 for a non-loopback http URL", code)
	}
}
