package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DelineaXPM/delinea-tools/api"
)

// Every fmt verb and JSON encoding of a secrets.Config must redact the
// credentials — including %+v of a struct that embeds one, the shape
// consumers like tss-k8s use for their role configs.
func TestConfigFormattingRedactsCredentials(t *testing.T) {
	cache := api.NewMemoryCache()
	cache.Store(api.CacheKey{Identity: "cache-key-secret"}, api.CachedToken{AccessToken: "cache-token-secret"})
	cfg := Config{URL: "https://url-user:url-password@vault.example.com/path?token=query-secret#fragment-secret", Username: "svc", Password: "hunter2-pass", Token: "tok-abcd1234", Cache: cache}
	type role struct {
		Name string
		Config
	}
	jsonBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	outputs := map[string]string{
		"%v":       fmt.Sprintf("%v", cfg),
		"%+v":      fmt.Sprintf("%+v", cfg),
		"%#v":      fmt.Sprintf("%#v", cfg),
		"%+v role": fmt.Sprintf("%+v", role{Name: "r", Config: cfg}),
		"json":     string(jsonBytes),
	}
	for verb, out := range outputs {
		for _, secret := range []string{"hunter2-pass", "tok-abcd1234", "cache-key-secret", "cache-token-secret", "url-user", "url-password", "query-secret", "fragment-secret"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s leaked %q: %s", verb, secret, out)
			}
		}
		if !strings.Contains(out, "[REDACTED]") || !strings.Contains(out, "svc") {
			t.Errorf("%s should redact credentials but keep other fields: %s", verb, out)
		}
	}
	if out := fmt.Sprintf("%+v", Config{URL: "https://x"}); strings.Contains(out, "[REDACTED]") {
		t.Errorf("empty credentials must not be marked [REDACTED]: %s", out)
	}
	if out := fmt.Sprintf("%+v", Config{URL: "%://url-secret"}); strings.Contains(out, "url-secret") {
		t.Errorf("an unparseable URL must be hidden in full: %s", out)
	}
	if out := fmt.Sprintf("%+v", Config{URL: "secret-scheme:opaque-secret"}); strings.Contains(out, "opaque-secret") {
		t.Errorf("an invalid opaque URL must be hidden in full: %s", out)
	}
}

// A secrets.Client wraps an api.Client behind an unexported fetcher; fmt must
// not reflect through it into the underlying Config's credentials when a Client
// is logged (%+v).
func TestClientFormattingRedactsCredentials(t *testing.T) {
	ac, err := api.New(api.Config{URL: "https://vault.example.com", Token: "tok-secret-leakme-abcd"})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	c := NewWithClient(ac)
	for _, out := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(out, "tok-secret-leakme-abcd") {
			t.Errorf("secrets.Client leaked the token: %s", out)
		}
	}
}

func TestConfigJSONDecodeStrict(t *testing.T) {
	dec := json.NewDecoder(strings.NewReader(
		`{"URL":"https://vault.example.com","Username":"svc","Password":"pw-live","Retries":2}`))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if cfg.Password != "pw-live" || cfg.Retries != 2 {
		t.Errorf("decode dropped fields: %+q %d", cfg.Password, cfg.Retries)
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(out, []byte("pw-live")) {
		t.Errorf("marshal must not round-trip a credential: %s", out)
	}
}

func TestWithProbedTargetSetsTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			fmt.Fprint(w, "Healthy")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	cfg, err := Config{URL: srv.URL, Username: "id", Password: "sec"}.WithProbedTarget(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target != api.TargetPlatform {
		t.Errorf("target: got %q, want platform", cfg.Target)
	}
	engine := cfg.EngineConfig()
	if engine.ClientID != "id" || engine.ClientSecret != "sec" || engine.Username != "" {
		t.Errorf("probed config must route the pair to client credentials: %s", engine)
	}
}

func TestEngineConfigForwardsInsecureHTTPOptIn(t *testing.T) {
	engine := (Config{URL: "http://vault.internal", Token: "test-token", AllowInsecureHTTP: true}).EngineConfig()
	if !engine.AllowInsecureHTTP {
		t.Fatal("EngineConfig dropped AllowInsecureHTTP")
	}
	if _, err := api.New(engine); err != nil {
		t.Fatalf("forwarded config was rejected: %v", err)
	}
}
