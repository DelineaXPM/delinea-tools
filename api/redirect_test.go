package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func req(t *testing.T, ctx context.Context, url string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// checkRedirect is the guard that keeps a bearer token from being replayed to
// another origin. Its branches are security-load-bearing, so exercise each.
func TestCheckRedirect(t *testing.T) {
	ctx := context.Background()
	first := req(t, ctx, "https://vault.example.com/a")

	t.Run("same origin allowed", func(t *testing.T) {
		if err := checkRedirect(req(t, ctx, "https://vault.example.com/b"), []*http.Request{first}); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})
	t.Run("mutating method refused", func(t *testing.T) {
		mutating, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://vault.example.com/a", strings.NewReader("body"))
		if err != nil {
			t.Fatal(err)
		}
		redirected, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://vault.example.com/b", strings.NewReader("body"))
		if err != nil {
			t.Fatal(err)
		}
		if err := checkRedirect(redirected, []*http.Request{mutating}); !errors.Is(err, errRefusedRedirect) {
			t.Errorf("got %v, want a refused redirect", err)
		}
	})
	t.Run("cross host refused", func(t *testing.T) {
		err := checkRedirect(req(t, ctx, "https://evil.example.com/b"), []*http.Request{first})
		if err == nil {
			t.Errorf("cross-host redirect not refused")
		}
	})
	t.Run("scheme downgrade refused", func(t *testing.T) {
		err := checkRedirect(req(t, ctx, "http://vault.example.com/b"), []*http.Request{first})
		if err == nil {
			t.Errorf("https->http downgrade not refused")
		}
	})
	t.Run("host match is case-insensitive", func(t *testing.T) {
		if err := checkRedirect(req(t, ctx, "https://VAULT.Example.com/b"), []*http.Request{first}); err != nil {
			t.Errorf("got %v, want nil for a case-only host difference", err)
		}
	})
	t.Run("default port is the same origin", func(t *testing.T) {
		if err := checkRedirect(req(t, ctx, "https://vault.example.com:443/b"), []*http.Request{first}); err != nil {
			t.Errorf("got %v, want nil for an explicit default port", err)
		}
	})
	t.Run("too many redirects", func(t *testing.T) {
		via := make([]*http.Request, 10)
		for i := range via {
			via[i] = first
		}
		if err := checkRedirect(req(t, ctx, "https://vault.example.com/b"), via); err == nil {
			t.Errorf("10th redirect not stopped")
		}
	})
	t.Run("no-redirects context uses last response", func(t *testing.T) {
		nrCtx := context.WithValue(ctx, noRedirectsKey{}, true)
		if err := checkRedirect(req(t, nrCtx, "https://vault.example.com/b"), []*http.Request{first}); err != http.ErrUseLastResponse {
			t.Errorf("got %v, want ErrUseLastResponse", err)
		}
	})
}

func TestMutatingRequestDoesNotFollowSameOriginRedirect(t *testing.T) {
	var initial, redirected atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/initial":
			initial.Add(1)
			http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
		case "/redirected":
			redirected.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := New(Config{
		URL: srv.URL, Target: TargetSecretServer, Token: "redirect-token", Retries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DoBufferedResponse(context.Background(), Request{
		Method: http.MethodPost,
		Path:   "/initial",
		Body:   strings.NewReader("sensitive mutation"),
	}, 1024)
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("got %v, want a refused-redirect configuration error", err)
	}
	if initial.Load() != 1 || redirected.Load() != 0 {
		t.Fatalf("requests: initial=%d redirected=%d, want 1 and 0", initial.Load(), redirected.Load())
	}
}

func TestDefaultBackoff(t *testing.T) {
	for attempt, want := range map[int]int{0: 200, 1: 400, 2: 800} {
		if got := defaultBackoff(attempt).Milliseconds(); got != int64(want) {
			t.Errorf("defaultBackoff(%d): got %dms, want %dms", attempt, got, want)
		}
	}
}
