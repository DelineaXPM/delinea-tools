package api

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode"
)

func FuzzRecognizedHealthyBody(f *testing.F) {
	f.Add(`{"healthy":true}`)
	f.Add(`{"healthy":false}`)
	f.Add(`{"status":"Healthy"}`)
	f.Add(" Healthy\r\n")
	f.Add("Not Healthy")
	f.Add("<html>Healthy</html>")
	f.Fuzz(func(t *testing.T, body string) {
		var parsed struct {
			Healthy *bool `json:"healthy"`
		}
		want := false
		if err := json.Unmarshal([]byte(body), &parsed); err == nil {
			want = parsed.Healthy != nil && *parsed.Healthy
		} else {
			want = strings.EqualFold(strings.TrimSpace(body), "Healthy")
		}
		if got := recognizedHealthyBody([]byte(body)); got != want {
			t.Errorf("recognizedHealthyBody(%q) = %v, want %v", body, got, want)
		}
	})
}

func FuzzRetryDelay(f *testing.F) {
	f.Add("")
	f.Add("5")
	f.Add("-3")
	f.Add("0")
	f.Add("Sat, 09 Aug 2026 12:00:00 GMT")
	f.Add("soon")
	f.Add("999999999999999999999")
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	backoff := func(int) time.Duration { return time.Millisecond }
	f.Fuzz(func(t *testing.T, header string) {
		if d, _ := retryDelay(header, 0, backoff, now); d < 0 {
			t.Errorf("retryDelay(%q) = %v; must never be negative", header, d)
		}
		if d, retry := retryWait(header, 0, backoff, now); retry && (d < 0 || d > maxRetryAfterWait) {
			t.Errorf("retryWait(%q) = %v; an honored wait must be within [0, %v]", header, d, maxRetryAfterWait)
		}
	})
}

func FuzzValidateVaultURL(f *testing.F) {
	f.Add("https://x.secretservercloud.com", "")
	f.Add("http://x.secretservercloud.com", "")
	f.Add("https://u:p@x.secretservercloud.com", "")
	f.Add("https://vault.internal.example.com", "vault.internal.example.com")
	f.Add("://", "")
	f.Add("https://x.secretservercloud.com.?q=1#f", " x.example.com. ,")
	platform, err := url.Parse("https://acme.secureplatform.io")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw, allowed string) {
		vu, err := validateVaultURL(platform, raw, []string{allowed})
		if err != nil {
			return
		}
		if vu.Scheme != "https" {
			t.Errorf("validateVaultURL(%q) accepted scheme %q", raw, vu.Scheme)
		}
		if vu.User != nil || vu.RawQuery != "" || vu.Fragment != "" {
			t.Errorf("validateVaultURL(%q) accepted userinfo/query/fragment", raw)
		}
	})
}

func FuzzValidateGrant(f *testing.F) {
	f.Add("test-token", "Bearer", 3600)
	f.Add("abc", "Bearer", 3600)
	f.Add("", "", 0)
	f.Add("a b", "MAC", -1)
	f.Add("a\x7fb", "bearer", 1<<30)
	f.Fuzz(func(t *testing.T, token, tokenType string, expires int) {
		if validateGrant(grantResponse{AccessToken: token, TokenType: tokenType, ExpiresIn: expires}) != nil {
			return
		}
		// An accepted grant must satisfy every property the client then trusts:
		// a well-formed bearer token, an empty or Bearer token_type, and a
		// positive lifetime within the sane maximum.
		if len(token) < minAccessTokenLen {
			t.Errorf("accepted a %d-byte access_token (< %d)", len(token), minAccessTokenLen)
		}
		if strings.IndexFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			t.Errorf("accepted an access_token containing whitespace or control bytes: %q", token)
		}
		if tokenType != "" && !strings.EqualFold(tokenType, "Bearer") {
			t.Errorf("accepted token_type %q", tokenType)
		}
		if expires <= 0 || expires > int(maxTokenLifetime/time.Second) {
			t.Errorf("accepted expires_in %d, outside (0, %d]", expires, int(maxTokenLifetime/time.Second))
		}
	})
}
