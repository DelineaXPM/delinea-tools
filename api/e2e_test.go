//go:build e2e

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/DelineaXPM/delinea-tools/internal/e2etest"
)

// These tests run only with `go test -tags e2e ./...`, skip when fixtures are
// absent, and never print secret values: assertions compare lengths and
// status codes only.

func requireEnv(t *testing.T, keys ...string) map[string]string {
	t.Helper()
	return e2etest.Require(t, keys...)
}

func ssConfig(t *testing.T) Config {
	f := requireEnv(t, "DELINEA_TOOLS_TEST_SS_URL", "DELINEA_TOOLS_TEST_SS_USERNAME", "DELINEA_TOOLS_TEST_SS_PASSWORD")
	return Config{
		URL:      f["DELINEA_TOOLS_TEST_SS_URL"],
		Username: f["DELINEA_TOOLS_TEST_SS_USERNAME"],
		Password: f["DELINEA_TOOLS_TEST_SS_PASSWORD"],
		Timeout:  time.Minute,
	}
}

func platformConfig(t *testing.T) Config {
	f := requireEnv(t, "DELINEA_TOOLS_TEST_PLATFORM_URL", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_ID", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET")
	return Config{
		URL:          f["DELINEA_TOOLS_TEST_PLATFORM_URL"],
		ClientID:     f["DELINEA_TOOLS_TEST_PLATFORM_CLIENT_ID"],
		ClientSecret: f["DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET"],
		Timeout:      time.Minute,
	}
}

func mustJSONObject(t *testing.T, r io.Reader) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		t.Fatalf("response is not a JSON object: %v", err)
	}
	return m
}

func TestE2ESecretServerToken(t *testing.T) {
	c, err := New(ssConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 20 {
		t.Errorf("token suspiciously short: len %d", len(tok))
	}
}

func TestE2ESecretServerCurrentUser(t *testing.T) {
	c, err := New(ssConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/users/current"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	m := mustJSONObject(t, resp.Body)
	if len(m) == 0 {
		t.Error("empty identity object")
	}
}

func TestE2EPlatformVaultSecret(t *testing.T) {
	cfg := platformConfig(t)
	id := requireEnv(t, "DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID")["DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID"]
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	vaults, err := c.Vaults(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range vaults {
		if v.IsDefault && v.IsActive {
			found = true
		}
	}
	if !found {
		t.Fatal("no default active vault in the broker inventory")
	}
	resp, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/secrets/" + id, UseVault: true})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	m := mustJSONObject(t, resp.Body)
	if m["id"] == nil {
		t.Error("secret response has no id field")
	}
}

func TestE2ECacheReuse(t *testing.T) {
	cfg := ssConfig(t)
	cfg.Cache = NewMemoryCache()
	c1, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok1, err := c1.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := c2.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok1 != tok2 {
		t.Errorf("second client did not reuse the cached token (len %d vs %d)", len(tok1), len(tok2))
	}
}

func TestE2EProbeBackend(t *testing.T) {
	tests := []struct {
		name string
		url  func(*testing.T) string
		want Backend
	}{
		{"secret-server", func(t *testing.T) string {
			return requireEnv(t, "DELINEA_TOOLS_TEST_SS_URL")["DELINEA_TOOLS_TEST_SS_URL"]
		}, BackendSecretServer},
		{"platform", func(t *testing.T) string {
			return requireEnv(t, "DELINEA_TOOLS_TEST_PLATFORM_URL")["DELINEA_TOOLS_TEST_PLATFORM_URL"]
		}, BackendPlatform},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ProbeBackend(context.Background(), Config{URL: tt.url(t), Timeout: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("ProbeBackend = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestE2EWithProbedTarget(t *testing.T) {
	tests := []struct {
		name string
		cfg  func(*testing.T) Config
		want Target
	}{
		{"secret-server", ssConfig, TargetSecretServer},
		{"platform-credential-relocation", func(t *testing.T) Config {
			cfg := platformConfig(t)
			cfg.Username, cfg.Password = cfg.ClientID, cfg.ClientSecret
			cfg.ClientID, cfg.ClientSecret = "", ""
			return cfg
		}, TargetPlatform},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := tt.cfg(t).WithProbedTarget(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Target != tt.want {
				t.Fatalf("Target = %q, want %q", cfg.Target, tt.want)
			}
			client, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Authenticate(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestE2EPreobtainedTokenAuthentication(t *testing.T) {
	tests := []struct {
		name   string
		cfg    func(*testing.T) Config
		target Target
	}{
		{"secret-server", ssConfig, TargetSecretServer},
		{"platform", platformConfig, TargetPlatform},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg(t)
			grantClient, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			token, err := grantClient.Token(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			client, err := New(Config{URL: cfg.URL, Target: tt.target, Token: token, Timeout: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.Authenticate(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got != token {
				t.Errorf("Authenticate returned a different token (got len %d, want len %d)", len(got), len(token))
			}
		})
	}
}

// Invalid bearer tokens must be distinguished from resource authorization and
// from Secret Server's separately tested, exact expired-token 403. Both product
// paths use 401 for an arbitrary invalid bearer.
func TestE2EInvalidBearerIsUnauthorized(t *testing.T) {
	tests := []struct {
		name   string
		cfg    func(*testing.T) Config
		target Target
		path   string
	}{
		{"secret-server", ssConfig, TargetSecretServer, "/api/v1/users/current"},
		{"platform", platformConfig, TargetPlatform, "/vaultbroker/api/vaults"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := tt.cfg(t)
			client, err := New(Config{
				URL: base.URL, Target: tt.target,
				Token: "delinea-tools-deliberately-invalid-token", Timeout: time.Minute,
			})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(context.Background(), Request{Method: http.MethodGet, Path: tt.path})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("invalid bearer status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

// Secret Server intentionally returns its documented expired-token signal as
// a 403 rather than the 401 used for an arbitrary invalid bearer. Expire only
// the disposable token this client just obtained, then prove a cached client
// recognizes that exact signal, grants again, and safely replays the read.
func TestE2ESecretServerExpiredTokenRecovery(t *testing.T) {
	cfg := ssConfig(t)
	cfg.Cache = NewMemoryCache()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	baseline, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/users/current"})
	if err != nil {
		t.Fatal(err)
	}
	baseline.Body.Close()
	if baseline.StatusCode != http.StatusOK {
		t.Fatalf("baseline status = %d, want 200", baseline.StatusCode)
	}

	expire, err := c.Do(context.Background(), Request{Method: http.MethodPost, Path: "/api/v1/oauth-expiration"})
	if err != nil {
		t.Fatal(err)
	}
	expire.Body.Close()
	if expire.StatusCode < 200 || expire.StatusCode > 299 {
		t.Fatalf("token expiration status = %d, want 2xx", expire.StatusCode)
	}

	recovered, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/users/current"})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Body.Close()
	if recovered.StatusCode != http.StatusOK {
		t.Fatalf("status after expiring cached token = %d, want 200 after re-grant", recovered.StatusCode)
	}
}
