package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const expiredTokenJSON = `{"message":"Authentication failed or expired token."}`

type closeReleaseBody struct {
	io.Reader
	once    sync.Once
	release func()
}

func (b *closeReleaseBody) Close() error {
	b.once.Do(b.release)
	return nil
}

func TestSecretServerExpiredTokenBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"exact", expiredTokenJSON, true},
		{"surrounding whitespace", " \n\t" + expiredTokenJSON + "\r\n", true},
		{"different message", `{"message":"Access denied"}`, false},
		{"additional field", `{"message":"Authentication failed or expired token.","code":403}`, false},
		{"duplicate message", `{"message":"ignored","message":"Authentication failed or expired token."}`, false},
		{"wrong field", `{"error":"Authentication failed or expired token."}`, false},
		{"string", `"Authentication failed or expired token."`, false},
		{"malformed", `{"message":"Authentication failed or expired token."`, false},
		{"empty", "", false},
		{"oversized", expiredTokenJSON + strings.Repeat(" ", secretServerExpiredTokenBodyLimit), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := secretServerExpiredTokenBody([]byte(tt.body)); got != tt.want {
				t.Errorf("secretServerExpiredTokenBody() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReusedSecretServerExpiredTokenReplaysSafeReads(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		name := "streaming"
		responseBody := "ok"
		if buffered {
			name = "buffered"
			responseBody = "o"
		}
		t.Run(name, func(t *testing.T) {
			grants, calls := 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth2/token" {
					grants++
					fmt.Fprint(w, grantJSON(fmt.Sprintf("tok-%d", grants)))
					return
				}
				calls++
				if r.Header.Get("Authorization") == "Bearer tok-1" {
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, expiredTokenJSON)
					return
				}
				fmt.Fprint(w, "ok")
			}))
			defer srv.Close()

			c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: NewMemoryCache()})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Token(context.Background()); err != nil {
				t.Fatal(err)
			}

			var status int
			var body []byte
			if buffered {
				// A caller's small result limit must not prevent the engine from
				// inspecting its own bounded authentication signal.
				resp, err := c.DoBufferedResponse(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/thing"}, 1)
				if err != nil {
					t.Fatal(err)
				}
				status, body = resp.StatusCode, resp.Body
			} else {
				resp, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/thing"})
				if err != nil {
					t.Fatal(err)
				}
				body, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				status = resp.StatusCode
			}
			if status != http.StatusOK || string(body) != responseBody {
				t.Errorf("response = %d %q, want 200 %q", status, body, responseBody)
			}
			if grants != 2 || calls != 2 {
				t.Errorf("grants=%d calls=%d, want two of each", grants, calls)
			}
		})
	}
}

func TestExpiredToken403EvictsButDoesNotReplayMutation(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		name := "streaming"
		if buffered {
			name = "buffered"
		}
		t.Run(name, func(t *testing.T) {
			grants, writes, reads := 0, 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth2/token" {
					grants++
					fmt.Fprint(w, grantJSON(fmt.Sprintf("tok-%d", grants)))
					return
				}
				if r.Method == http.MethodPost {
					writes++
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, expiredTokenJSON)
					return
				}
				reads++
				fmt.Fprint(w, "ok")
			}))
			defer srv.Close()

			c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: NewMemoryCache()})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Token(context.Background()); err != nil {
				t.Fatal(err)
			}

			var status int
			var body []byte
			request := Request{Method: http.MethodPost, Path: "/api/v1/write", Body: strings.NewReader(`{"value":1}`)}
			if buffered {
				resp, err := c.DoBufferedResponse(context.Background(), request, 1024)
				if err != nil {
					t.Fatal(err)
				}
				status, body = resp.StatusCode, resp.Body
			} else {
				resp, err := c.Do(context.Background(), request)
				if err != nil {
					t.Fatal(err)
				}
				body, err = io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				status = resp.StatusCode
			}
			if status != http.StatusForbidden || string(body) != expiredTokenJSON {
				t.Errorf("response = %d %q, want 403 with the original body", status, body)
			}
			if writes != 1 || grants != 1 {
				t.Errorf("writes=%d grants=%d, want one of each before the next call", writes, grants)
			}

			resp, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/read"})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("next read status = %d, want 200", resp.StatusCode)
			}
			if writes != 1 || reads != 1 || grants != 2 {
				t.Errorf("writes=%d reads=%d grants=%d, want 1, 1, 2", writes, reads, grants)
			}
		})
	}
}

func TestExpiredToken403IsSecretServerSpecific(t *testing.T) {
	grants, calls := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/identity/api/oauth2/token/xpmplatform" {
			grants++
			fmt.Fprint(w, grantJSON("platform-token"))
			return
		}
		calls++
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, expiredTokenJSON)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Target: TargetPlatform, ClientID: "id", ClientSecret: "secret", Cache: NewMemoryCache()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/vaultbroker/api/vaults"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden || string(body) != expiredTokenJSON {
		t.Errorf("response = %d %q, want original 403", resp.StatusCode, body)
	}
	if grants != 1 || calls != 1 {
		t.Errorf("grants=%d calls=%d, want one of each", grants, calls)
	}
}

func TestUnreadableExpiredToken403IsNotReplayedAndReadErrorIsPreserved(t *testing.T) {
	grants, calls := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants++
			fmt.Fprint(w, grantJSON("token"))
			return
		}
		calls++
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, expiredTokenJSON)
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: NewMemoryCache()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/thing"})
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || string(body) != expiredTokenJSON {
		t.Errorf("response = %d %q, want original partial 403", resp.StatusCode, body)
	}
	if readErr == nil {
		t.Fatal("reading the truncated response succeeded, want its original error")
	}
	if grants != 1 || calls != 1 {
		t.Errorf("grants=%d calls=%d, want one of each", grants, calls)
	}
}

func TestBufferedExpiredTokenInspectionDoesNotExpandCallerReadObligation(t *testing.T) {
	grants, calls := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			grants++
			fmt.Fprint(w, grantJSON("token"))
			return
		}
		calls++
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "x")
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: NewMemoryCache()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}

	resp, err := c.DoBufferedResponse(context.Background(), Request{Method: http.MethodGet, Path: "/api/v1/thing"}, 1)
	if err != nil {
		t.Fatalf("inspection error beyond the requested byte escaped: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden || string(resp.Body) != "x" {
		t.Errorf("response = %d %q, want 403 %q", resp.StatusCode, resp.Body, "x")
	}
	if grants != 1 || calls != 1 {
		t.Errorf("grants=%d calls=%d, want one of each with no retry", grants, calls)
	}
}

func TestReusedSecretServerExpiredTokenReplaysHead(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		name := "streaming"
		if buffered {
			name = "buffered"
		}
		t.Run(name, func(t *testing.T) {
			grants, heads, probes := 0, 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth2/token":
					grants++
					fmt.Fprint(w, grantJSON(fmt.Sprintf("tok-%d", grants)))
				case currentUserPath:
					probes++
					if r.Header.Get("Authorization") == "Bearer tok-1" {
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, expiredTokenJSON)
						return
					}
					fmt.Fprint(w, "ok")
				default:
					heads++
					if r.Method != http.MethodHead {
						t.Errorf("method = %s, want HEAD", r.Method)
					}
					if r.Header.Get("Authorization") == "Bearer tok-1" {
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, expiredTokenJSON) // net/http correctly omits this HEAD body
						return
					}
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer srv.Close()

			c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: NewMemoryCache()})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Token(context.Background()); err != nil {
				t.Fatal(err)
			}

			var status int
			if buffered {
				resp, err := c.DoBufferedResponse(context.Background(), Request{Method: http.MethodHead, Path: "/api/v1/thing"}, 0)
				if err != nil {
					t.Fatal(err)
				}
				status = resp.StatusCode
			} else {
				resp, err := c.Do(context.Background(), Request{Method: http.MethodHead, Path: "/api/v1/thing"})
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				status = resp.StatusCode
			}
			if status != http.StatusOK {
				t.Errorf("status = %d, want 200 after re-grant", status)
			}
			if grants != 2 || heads != 2 || probes != 1 {
				t.Errorf("grants=%d heads=%d probes=%d, want 2, 2, 1", grants, heads, probes)
			}
		})
	}
}

func TestOrdinarySecretServerHead403DoesNotEvictOrReplay(t *testing.T) {
	grants, heads, probes := 0, 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			grants++
			fmt.Fprint(w, grantJSON("token"))
		case currentUserPath:
			probes++
			fmt.Fprint(w, "ok")
		default:
			heads++
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: NewMemoryCache()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(context.Background(), Request{Method: http.MethodHead, Path: "/api/v1/denied"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want original 403", resp.StatusCode)
	}
	if grants != 1 || heads != 1 || probes != 1 {
		t.Errorf("grants=%d heads=%d probes=%d, want 1, 1, 1", grants, heads, probes)
	}
}

func TestHeadExpiredTokenConfirmationClosesResponseBeforeProbe(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		name := "streaming"
		if buffered {
			name = "buffered"
		}
		t.Run(name, func(t *testing.T) {
			gate := make(chan struct{}, 1)
			grants, heads, probes := 0, 0, 0
			rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				select {
				case gate <- struct{}{}:
				case <-r.Context().Done():
					return nil, r.Context().Err()
				}

				status, responseBody := http.StatusOK, ""
				switch r.URL.Path {
				case "/oauth2/token":
					grants++
					responseBody = grantJSON(fmt.Sprintf("tok-%d", grants))
				case currentUserPath:
					probes++
					status = http.StatusForbidden
					responseBody = expiredTokenJSON
				default:
					heads++
					if r.Header.Get("Authorization") == "Bearer tok-1" {
						status = http.StatusForbidden
					}
				}
				return &http.Response{
					StatusCode:    status,
					Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
					Proto:         "HTTP/1.1",
					Header:        make(http.Header),
					Body:          &closeReleaseBody{Reader: strings.NewReader(responseBody), release: func() { <-gate }},
					ContentLength: int64(len(responseBody)),
					Request:       r,
				}, nil
			})

			c, err := New(Config{
				URL: "https://example.com", Target: TargetSecretServer,
				Username: "u", Password: "p", Transport: rt,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Token(context.Background()); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var status int
			if buffered {
				resp, err := c.DoBufferedResponse(ctx, Request{Method: http.MethodHead, Path: "/api/v1/thing"}, 0)
				if err != nil {
					t.Fatal(err)
				}
				status = resp.StatusCode
			} else {
				resp, err := c.Do(ctx, Request{Method: http.MethodHead, Path: "/api/v1/thing"})
				if err != nil {
					t.Fatal(err)
				}
				status = resp.StatusCode
				resp.Body.Close()
			}
			if status != http.StatusOK {
				t.Errorf("status = %d, want 200 after confirmation and replay", status)
			}
			if grants != 2 || heads != 2 || probes != 1 {
				t.Errorf("grants=%d heads=%d probes=%d, want 2, 2, 1", grants, heads, probes)
			}
		})
	}
}
