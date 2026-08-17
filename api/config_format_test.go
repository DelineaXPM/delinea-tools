package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Every fmt verb and JSON encoding of a Config must redact the credentials —
// including %+v of a struct that embeds one, the common consumer shape.
func TestConfigFormattingRedactsCredentials(t *testing.T) {
	cache := NewMemoryCache()
	cache.Store(CacheKey{Identity: "cache-key-secret"}, CachedToken{AccessToken: "cache-token-secret"})
	cfg := Config{
		URL: "https://url-user:url-password@vault.example.com/path?token=query-secret#fragment-secret", Username: "svc",
		Password: "hunter2-pass", ClientSecret: "cs-secret-9", Token: "tok-abcd1234",
		Header:    http.Header{"X-Gateway-Token": {"gateway-secret"}},
		Cache:     cache,
		Transport: &formatSecretTransport{secret: "transport-secret"},
	}
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
		"%v ptr":   fmt.Sprintf("%v", &cfg),
		"%+v role": fmt.Sprintf("%+v", role{Name: "r", Config: cfg}),
		"json":     string(jsonBytes),
	}
	for verb, out := range outputs {
		for _, secret := range []string{"hunter2-pass", "cs-secret-9", "tok-abcd1234", "gateway-secret", "cache-key-secret", "cache-token-secret", "transport-secret", "url-user", "url-password", "query-secret", "fragment-secret"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s leaked %q: %s", verb, secret, out)
			}
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("%s should mark set credentials as [REDACTED]: %s", verb, out)
		}
		if !strings.Contains(out, "svc") {
			t.Errorf("%s should keep non-credential fields readable: %s", verb, out)
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

// A *Client holds its Config in an unexported field, so fmt cannot call
// Config.String on it; without Client.String it would format the struct
// reflectively and print the credentials. A Client is the object an embedder
// most often logs (%+v), so it must redact like Config does.
func TestClientFormattingRedactsCredentials(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		secret string
	}{
		{"token", Config{URL: "https://vault.example.com", Token: "tok-leak-abcd1234"}, "tok-leak-abcd1234"},
		{"password", Config{URL: "https://vault.example.com", Username: "svc", Password: "pw-leak-hunter2"}, "pw-leak-hunter2"},
		{"clientsecret", Config{URL: "https://vault.example.com", ClientID: "cid", ClientSecret: "cs-leak-9999"}, "cs-leak-9999"},
	}
	for _, tc := range cases {
		c, err := New(tc.cfg)
		if err != nil {
			t.Fatalf("%s: New: %v", tc.name, err)
		}
		for _, out := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
			if strings.Contains(out, tc.secret) {
				t.Errorf("%s leaked %q: %s", tc.name, tc.secret, out)
			}
			if !strings.Contains(out, "[REDACTED]") {
				t.Errorf("%s should mark the set credential [REDACTED]: %s", tc.name, out)
			}
		}
	}
}

type formatSecretTransport struct{ secret string }

func (t *formatSecretTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }
func (t *formatSecretTransport) String() string                                  { return t.secret }

// A configuration file decodes into Config strictly — the shape consumers
// like tss-k8s rely on — and marshaling never round-trips a credential.
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

func TestCloudURL(t *testing.T) {
	cases := []struct {
		tenant, tld string
		want        string
	}{
		{"acme", "", "https://acme.secretservercloud.com"},
		{"acme", "com", "https://acme.secretservercloud.com"},
		{"Acme", "COM", "https://acme.secretservercloud.com"},
		{"my-corp", "co.uk", "https://my-corp.secretservercloud.co.uk"},
		{"acme", "com.au", "https://acme.secretservercloud.com.au"},
	}
	for _, tc := range cases {
		got, err := CloudURL(tc.tenant, tc.tld)
		if err != nil || got != tc.want {
			t.Errorf("CloudURL(%q, %q): got %q, %v; want %q", tc.tenant, tc.tld, got, err, tc.want)
		}
	}
	invalid := []struct{ tenant, tld string }{
		{"", ""},
		{"acme corp", ""},
		{"-acme", ""},
		{"acme.secretservercloud.com", ""},
		{"https://acme", ""},
		{"acme", "org"},
		{"acme", "devsecretservercloud.com"},
	}
	for _, tc := range invalid {
		if _, err := CloudURL(tc.tenant, tc.tld); !errors.Is(err, ErrConfig) {
			t.Errorf("CloudURL(%q, %q): got %v, want ErrConfig", tc.tenant, tc.tld, err)
		}
	}
}

// Every cloud region in the vault trust table (except the dev domain) must be
// reachable through CloudURL, so the two lists cannot drift apart.
func TestCloudURLCoversTrustTable(t *testing.T) {
	for _, domain := range delineaCloudVaultDomains {
		tld, ok := strings.CutPrefix(domain, "secretservercloud.")
		if !ok {
			continue
		}
		got, err := CloudURL("acme", tld)
		if err != nil || got != "https://acme."+domain {
			t.Errorf("tld %q from the trust table: got %q, %v", tld, got, err)
		}
	}
}
