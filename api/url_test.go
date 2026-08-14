package api

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		raw      string
		insecure bool
		want     string
	}{
		{"acme.secretservercloud.com", false, "https://acme.secretservercloud.com"},
		{" https://vault.example.com/SecretServer/ ", false, "https://vault.example.com/SecretServer"},
		{"HTTPS://Vault.example.com", false, "https://Vault.example.com"},
		{"http://localhost:8080", false, "http://localhost:8080"},
		{"http://127.0.0.1", false, "http://127.0.0.1"},
		{"http://vault.internal", true, "http://vault.internal"},
		{"HTTP://vault.internal", true, "http://vault.internal"},
	}
	for _, tc := range cases {
		got, err := NormalizeURL(tc.raw, tc.insecure)
		if err != nil || got != tc.want {
			t.Errorf("NormalizeURL(%q, %v): got %q, %v; want %q", tc.raw, tc.insecure, got, err, tc.want)
		}
	}
	invalid := []struct {
		raw      string
		insecure bool
	}{
		{"", false},
		{"http://vault.example.com", false},
		{"HTTP://vault.example.com", false},
		{"ftp://vault.example.com", false},
		{"https://u:p@vault.example.com", false},
		{"https://vault.example.com?x=1", false},
		{"https://vault.example.com?", false}, // bare '?' => RawQuery "" but ForceQuery true
		{"https://vault.example.com#frag", false},
		{"https://", false},
	}
	for _, tc := range invalid {
		if _, err := NormalizeURL(tc.raw, tc.insecure); !errors.Is(err, ErrConfig) {
			t.Errorf("NormalizeURL(%q, %v): got %v, want ErrConfig", tc.raw, tc.insecure, err)
		}
	}
}

func TestNormalizeURLErrorsDoNotEchoPotentialUserinfo(t *testing.T) {
	const secret = "password-that-must-not-appear"
	for _, raw := range []string{"https://u:" + secret + "@", "http://u:" + secret + "@vault.example.com", secret + "://vault.example.com"} {
		_, err := NormalizeURL(raw, false)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Errorf("NormalizeURL(%q): error leaked input: %v", raw, err)
		}
	}
}

// The normalized form must be accepted by New verbatim, so the two functions
// cannot drift.
func TestNormalizeURLFeedsNew(t *testing.T) {
	u, err := NormalizeURL("acme.secretservercloud.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{URL: u, Token: "test-token"}); err != nil {
		t.Errorf("New rejected a normalized URL: %v", err)
	}
	insecure, err := NormalizeURL("http://vault.internal", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{URL: insecure, Token: "test-token", AllowInsecureHTTP: true}); err != nil {
		t.Errorf("New rejected an explicitly allowed normalized HTTP URL: %v", err)
	}
}
