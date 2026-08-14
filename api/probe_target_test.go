package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func backendServer(t *testing.T, kind Backend) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case kind == BackendSecretServer && r.URL.Path == "/api/v1/healthcheck":
			fmt.Fprint(w, `{"healthy":true}`)
		case kind == BackendPlatform && r.URL.Path == "/health":
			fmt.Fprint(w, "Healthy")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The one-credential-pair CI shape: the same id/secret lands in the fields
// the probed grant reads, whichever pair it started in.
func TestWithProbedTargetRoutesTheCredentialPair(t *testing.T) {
	ss := backendServer(t, BackendSecretServer)
	plat := backendServer(t, BackendPlatform)
	cases := []struct {
		name string
		cfg  Config
		want Config
	}{
		{"user pair stays on ss", Config{URL: ss.URL, Username: "id", Password: "sec"},
			Config{URL: ss.URL, Target: TargetSecretServer, Username: "id", Password: "sec"}},
		{"client pair moves to ss", Config{URL: ss.URL, ClientID: "id", ClientSecret: "sec"},
			Config{URL: ss.URL, Target: TargetSecretServer, Username: "id", Password: "sec"}},
		{"user pair moves to platform", Config{URL: plat.URL, Username: "id", Password: "sec"},
			Config{URL: plat.URL, Target: TargetPlatform, ClientID: "id", ClientSecret: "sec"}},
		{"client pair stays on platform", Config{URL: plat.URL, ClientID: "id", ClientSecret: "sec"},
			Config{URL: plat.URL, Target: TargetPlatform, ClientID: "id", ClientSecret: "sec"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.cfg.WithProbedTarget(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got.Target != tc.want.Target || got.Username != tc.want.Username ||
				got.Password != tc.want.Password || got.ClientID != tc.want.ClientID ||
				got.ClientSecret != tc.want.ClientSecret {
				t.Errorf("got %s, want %s", got, tc.want)
			}
			if _, err := New(got); err != nil {
				t.Errorf("New rejected the probed config: %v", err)
			}
		})
	}
}

func TestWithProbedTargetExplicitTargetSkipsProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("an explicit target must not probe, got %s", r.URL.Path)
	}))
	defer srv.Close()
	cfg := Config{URL: srv.URL, Target: TargetSecretServer, Username: "u", Password: "p"}
	got, err := cfg.WithProbedTarget(context.Background())
	if err != nil || got.String() != cfg.String() {
		t.Errorf("got %s, %v; want the config unchanged", got, err)
	}
}

func TestWithProbedTargetRefusesAmbiguityAndUnknown(t *testing.T) {
	ss := backendServer(t, BackendSecretServer)
	both := Config{URL: ss.URL, Username: "u", Password: "p", ClientID: "c", ClientSecret: "s"}
	if _, err := both.WithProbedTarget(context.Background()); !errors.Is(err, ErrConfig) {
		t.Errorf("both pairs: got %v, want ErrConfig", err)
	}
	unknown := httptest.NewServer(http.NotFoundHandler())
	defer unknown.Close()
	cfg := Config{URL: unknown.URL, Username: "u", Password: "p"}
	if _, err := cfg.WithProbedTarget(context.Background()); !errors.Is(err, ErrConfig) {
		t.Errorf("unknown backend: got %v, want ErrConfig", err)
	}
}
