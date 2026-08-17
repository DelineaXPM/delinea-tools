package secrets

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DelineaXPM/delinea-tools/api"
)

func grantJSON(token string) string {
	return fmt.Sprintf(`{"access_token":%q,"token_type":"bearer","expires_in":3600}`, token)
}

func certPEM(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func ssServer(t *testing.T, secretsHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			fmt.Fprint(w, grantJSON("test-token"))
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("authorization: got %q", got)
		}
		secretsHandler(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func ssClient(t *testing.T, url string) *Client {
	t.Helper()
	c, err := New(Config{URL: url, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFetcherSecretByID(t *testing.T) {
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/secrets/126" {
			t.Errorf("path: got %q", r.URL.Path)
		}
		fmt.Fprint(w, `{"id":126,"name":"db","items":[
			{"fieldName":"Username","slug":"username","itemValue":"svc"},
			{"fieldName":"Password","slug":"password","itemValue":"pw","isPassword":true}]}`)
	})
	vars, err := ssClient(t, srv.URL).Resolve(context.Background(), []Mapping{{EnvName: "DB", SecretID: 126, Field: "password"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 1 || vars[0].Value != "pw" {
		t.Errorf("got %+v, want DB=pw", vars)
	}
}

func TestFetcherSecretByPath(t *testing.T) {
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/secrets/0" {
			t.Errorf("path: got %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("secretPath"); got != `\ci\database prod` {
			t.Errorf("secretPath: got %q", got)
		}
		fmt.Fprint(w, `{"id":9,"items":[{"fieldName":"Password","slug":"password","itemValue":"pw"}]}`)
	})
	vars, err := ssClient(t, srv.URL).Resolve(context.Background(), []Mapping{{EnvName: "DB", ByPath: true, Path: `\ci\database prod`, Field: "password"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 1 || vars[0].Value != "pw" {
		t.Errorf("got %+v, want DB=pw", vars)
	}
}

func TestFetcherDownloadsFileFields(t *testing.T) {
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets/7":
			fmt.Fprint(w, `{"id":7,"items":[
				{"fieldName":"Private Key","slug":"private-key","isFile":true,"fileAttachmentId":12,"filename":"id_rsa","itemValue":"placeholder"}]}`)
		case "/api/v1/secrets/7/fields/private-key":
			fmt.Fprint(w, "KEYCONTENT")
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	vars, err := ssClient(t, srv.URL).Resolve(context.Background(), []Mapping{{EnvName: "KEY", SecretID: 7, Field: "private-key"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 1 || vars[0].Value != "KEYCONTENT" {
		t.Errorf("file field content not substituted: %+v", vars)
	}
}

// A server-supplied slug is path-escaped into the follow-up attachment GET, so
// it cannot shape the request path or inject a query.
func TestFetcherEscapesAttachmentSlug(t *testing.T) {
	var attachmentURI, attachmentQuery string
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/secrets/7":
			fmt.Fprint(w, `{"id":7,"items":[
				{"fieldName":"K","slug":"a/b?x=1","isFile":true,"fileAttachmentId":12,"filename":"id_rsa","itemValue":"placeholder"}]}`)
		default:
			// RequestURI is the raw request line, so it shows the escaping as
			// sent; r.URL.Path would be decoded and hide it.
			attachmentURI, attachmentQuery = r.RequestURI, r.URL.RawQuery
			fmt.Fprint(w, "KEYCONTENT")
		}
	})
	if _, err := ssClient(t, srv.URL).Resolve(context.Background(), []Mapping{{EnvName: "K", SecretID: 7, Field: "a/b?x=1"}}); err != nil {
		t.Fatal(err)
	}
	if attachmentQuery != "" {
		t.Errorf("slug leaked into the query string: %q", attachmentQuery)
	}
	if attachmentURI != "/api/v1/secrets/7/fields/a%2Fb%3Fx=1" {
		t.Errorf("attachment path not escaped: %q", attachmentURI)
	}
}

func TestFetcherRejectsAttachmentDotSegments(t *testing.T) {
	for _, slug := range []string{"", ".", ".."} {
		t.Run(fmt.Sprintf("%q", slug), func(t *testing.T) {
			attachmentCalls := 0
			srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/secrets/7" {
					attachmentCalls++
					http.Error(w, "attachment request must not be sent", http.StatusInternalServerError)
					return
				}
				fmt.Fprintf(w, `{"id":7,"items":[{"fieldName":"K","slug":%q,"isFile":true,"fileAttachmentId":12,"filename":"key"}]}`, slug)
			})
			_, err := ssClient(t, srv.URL).Resolve(context.Background(), []Mapping{{EnvName: "K", SecretID: 7, Field: "K"}})
			if !errors.Is(err, errBadResponse) {
				t.Errorf("got %v, want errBadResponse", err)
			}
			if attachmentCalls != 0 {
				t.Errorf("attachment requests: got %d, want 0", attachmentCalls)
			}
		})
	}
}

func TestFetcherRetriesBodyReadFailure(t *testing.T) {
	calls := 0
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Content-Length", "1000")
			w.Write([]byte("{"))
			return
		}
		fmt.Fprint(w, `{"id":5,"items":[{"fieldName":"Password","slug":"password","itemValue":"pw"}]}`)
	})
	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 3,
		Backoff: func(int) time.Duration { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	vars, rerr := c.Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 5, Field: "password"}})
	if rerr != nil {
		t.Fatalf("got %v, want a body read that dies after the headers to be retried", rerr)
	}
	if len(vars) != 1 || vars[0].Value != "pw" || calls != 2 {
		t.Errorf("got %+v after %d calls, want A=pw after 2", vars, calls)
	}
}

func TestFetcherNonJSONResponseIsPermanent(t *testing.T) {
	calls := 0
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, "<html>captive portal</html>")
	})
	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 3})
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := c.Resolve(context.Background(), []Mapping{{EnvName: "X", SecretID: 5, Field: "password"}})
	if rerr == nil || errors.Is(rerr, ErrTransport) {
		t.Errorf("got %v, want a non-transport error: the server answered, the body is just not a secret", rerr)
	}
	if calls != 1 {
		t.Errorf("fetch attempts: got %d, want 1 (another attempt fetches the same bytes)", calls)
	}
}

func TestFetcherRejectsOversizedAttachment(t *testing.T) {
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets/7":
			fmt.Fprint(w, `{"id":7,"items":[
				{"fieldName":"Blob","slug":"blob","isFile":true,"fileAttachmentId":12,"filename":"big.bin","itemValue":"placeholder"}]}`)
		case "/api/v1/secrets/7/fields/blob":
			w.Write(make([]byte, maxSecretResponseBytes+1))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	_, err := ssClient(t, srv.URL).Resolve(context.Background(), []Mapping{{EnvName: "BLOB", SecretID: 7, Field: "blob"}})
	if !errors.Is(err, errTooLarge) {
		t.Errorf("got %v, want errors.Is errTooLarge instead of silent truncation", err)
	}
	if errors.Is(err, ErrTransport) {
		t.Errorf("oversized response misclassified as a transport error: %v", err)
	}
}

// A hostile secret enumerating too many file attachments is refused rather than
// fanned out into unbounded downloads.
func TestFetcherCapsAttachmentFanout(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"id":8,"items":[`)
	for i := range maxAttachments + 5 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"slug":"f%d","isFile":true,"fileAttachmentId":%d,"filename":"n"}`, i, i+1)
	}
	b.WriteString(`]}`)
	body := b.String()
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/secrets/8" {
			fmt.Fprint(w, body)
			return
		}
		fmt.Fprint(w, "x")
	})
	_, err := ssClient(t, srv.URL).Resolve(context.Background(), []Mapping{{Prefix: "P_", SecretID: 8, Expand: true}})
	if err == nil || !strings.Contains(err.Error(), "file attachments") {
		t.Errorf("got %v, want a fan-out refusal", err)
	}
	if !errors.Is(err, errTooLarge) || errors.Is(err, ErrTransport) {
		t.Errorf("got %v, want a permanent errTooLarge, not a retriable transport error", err)
	}
}

// NewWithClient shares an already-configured api.Client with the resolver, and
// the typed Secret/SecretByPath reads return the whole secret.
func TestNewWithClientTypedReads(t *testing.T) {
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets/126":
			fmt.Fprint(w, `{"id":126,"name":"db","items":[
				{"fieldName":"Password","slug":"password","itemValue":"pw"}]}`)
		case "/api/v1/secrets/0":
			fmt.Fprint(w, `{"id":9,"items":[{"fieldName":"Password","slug":"password","itemValue":"bypath"}]}`)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})
	ac, err := api.New(api.Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	c := NewWithClient(ac)

	sec, err := c.Secret(context.Background(), 126)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := sec.Field("password"); !ok || v != "pw" {
		t.Errorf("Secret.Field: got (%q,%v), want pw", v, ok)
	}

	sec, err = c.SecretByPath(context.Background(), `\ci\db`)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := sec.Field("password"); v != "bypath" {
		t.Errorf("SecretByPath: got %q, want bypath", v)
	}
}

func TestClientSafeForConcurrentUse(t *testing.T) {
	var grants atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants.Add(1)
			fmt.Fprint(w, grantJSON("shared-token"))
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer shared-token" {
			http.Error(w, "unexpected authorization", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/secrets/126":
			fmt.Fprint(w, `{"id":126,"name":"db","items":[{"fieldName":"Password","slug":"password","itemValue":"pw"}]}`)
		case "/api/v1/secrets/0":
			if got := r.URL.Query().Get("secretPath"); got != `\ci\db` {
				http.Error(w, "unexpected secret path", http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"id":126,"name":"db","items":[{"fieldName":"Password","slug":"password","itemValue":"pw"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := ssClient(t, srv.URL)
	const callers = 48
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := range callers {
		go func() {
			defer wg.Done()
			<-start
			switch i % 3 {
			case 0:
				secret, err := c.Secret(context.Background(), 126)
				if err != nil {
					errs <- err
					return
				}
				if value, ok := secret.Field("password"); !ok || value != "pw" {
					errs <- fmt.Errorf("Secret.Field returned %q, %v", value, ok)
				}
			case 1:
				secret, err := c.SecretByPath(context.Background(), `\ci\db`)
				if err != nil {
					errs <- err
					return
				}
				if value, ok := secret.Field("password"); !ok || value != "pw" {
					errs <- fmt.Errorf("SecretByPath.Field returned %q, %v", value, ok)
				}
			case 2:
				vars, err := c.Resolve(context.Background(), []Mapping{{EnvName: "DB_PASS", SecretID: 126, Field: "password"}})
				if err != nil {
					errs <- err
					return
				}
				if len(vars) != 1 || vars[0] != (Var{Name: "DB_PASS", Value: "pw"}) {
					errs <- fmt.Errorf("Resolve returned %+v", vars)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := grants.Load(); got != 1 {
		t.Errorf("token grants: got %d, want 1 from concurrent use of one client", got)
	}
}

func TestConfigRetriesAndBackoffReachTheEngine(t *testing.T) {
	attempts, backoffs := 0, 0
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		if attempts++; attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `{"id":5,"items":[{"fieldName":"Password","slug":"password","itemValue":"pw"}]}`)
	})
	c, err := New(Config{
		URL:      srv.URL,
		Username: "u",
		Password: "p",
		Cache:    api.NewMemoryCache(),
		Retries:  3,
		Backoff:  func(int) time.Duration { backoffs++; return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	vars, err := c.Resolve(context.Background(), []Mapping{{EnvName: "A", SecretID: 5, Field: "password"}})
	if err != nil {
		t.Fatalf("got %v, want the fetch to survive two 503s (Config.Retries drives the engine, which owns Retry-After)", err)
	}
	if len(vars) != 1 || vars[0].Value != "pw" {
		t.Errorf("got %+v, want A=pw", vars)
	}
	if attempts != 3 {
		t.Errorf("attempts: got %d, want 3", attempts)
	}
	if backoffs != 2 {
		t.Errorf("Config.Backoff invocations: got %d, want 2", backoffs)
	}
}

func TestFetcherAccessDeniedStatus(t *testing.T) {
	srv := ssServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"errorCode":"API_AccessDenied","message":"Access denied"}`)
	})
	_, err := ssClient(t, srv.URL).Resolve(context.Background(), []Mapping{{EnvName: "X", SecretID: 5, Field: "password"}})
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want errors.Is ErrAccessDenied", err)
	}
}

func TestFetcherRedactsReflectedBearerToken(t *testing.T) {
	const token = "VERYSECRETBEARER"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			fmt.Fprint(w, grantJSON(token))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "request used "+token)
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Resolve(context.Background(), []Mapping{{EnvName: "X", SecretID: 5, Field: "password"}})
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("bearer token reflection was not redacted: %v", err)
	}
}

func TestFetcherBadCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	defer srv.Close()
	_, err := ssClient(t, srv.URL).Resolve(context.Background(), []Mapping{{EnvName: "X", SecretID: 5, Field: "password"}})
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("got %v, want errors.Is ErrAccessDenied", err)
	}
}

func TestFetcherPlatformRoutesToVault(t *testing.T) {
	vaultSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer plat-tok" {
			t.Errorf("vault authorization: got %q", got)
		}
		if r.URL.Path != "/api/v1/secrets/4" {
			t.Errorf("vault path: got %q", r.URL.Path)
		}
		fmt.Fprint(w, `{"id":4,"items":[{"fieldName":"Password","slug":"password","itemValue":"vault-pw"}]}`)
	}))
	defer vaultSrv.Close()

	platformSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/oauth2/token/xpmplatform":
			fmt.Fprint(w, grantJSON("plat-tok"))
		case "/vaultbroker/api/vaults":
			fmt.Fprintf(w, `{"vaults":[{"vaultId":"1","isDefault":true,"isActive":true,"connection":{"url":%q}}]}`, vaultSrv.URL)
		default:
			http.NotFound(w, r)
		}
	}))
	defer platformSrv.Close()

	c, err := New(Config{
		URL:               platformSrv.URL,
		Target:            api.TargetPlatform,
		Username:          "cid",
		Password:          "cs",
		CACert:            append(certPEM(platformSrv), certPEM(vaultSrv)...),
		AllowedVaultHosts: []string{hostOf(t, vaultSrv.URL)},
	})
	if err != nil {
		t.Fatal(err)
	}
	vars, err := c.Resolve(context.Background(), []Mapping{{EnvName: "PW", SecretID: 4, Field: "password"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 1 || vars[0].Value != "vault-pw" {
		t.Errorf("got %+v, want PW=vault-pw", vars)
	}
}
