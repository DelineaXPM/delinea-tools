package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitForFlightWaiters polls until the in-flight grant for c has
// at least n waiters, making the concurrency tests deterministic instead of
// sleep-based.
func waitForFlightWaiters(t *testing.T, c *Client, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	fk := flightKey{cacheID: c.flightID, key: c.key}
	for time.Now().Before(deadline) {
		sharedGrantsMu.Lock()
		f, ok := sharedGrants[fk]
		sharedGrantsMu.Unlock()
		if ok && f.waiters.Load() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("flight never gathered %d waiters", n)
}

// Concurrent cold misses from separately constructed clients sharing one
// cache collapse onto one grant: the cache shares completed grants, and the
// flight layer shares the in-flight one.
func TestConcurrentColdClientsShareOneGrant(t *testing.T) {
	const clients = 4
	var grants atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants.Add(1)
		<-release
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()

	shared := NewMemoryCache()
	built := make([]*Client, clients)
	for i := range built {
		c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: shared})
		if err != nil {
			t.Fatal(err)
		}
		built[i] = c
	}
	var wg sync.WaitGroup
	for _, c := range built {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := c.Token(context.Background())
			if err != nil || tok != "test-token" {
				t.Errorf("token: got %q, %v", tok, err)
			}
		}()
	}
	waitForFlightWaiters(t, built[0], clients-1)
	close(release)
	wg.Wait()
	if got := grants.Load(); got != 1 {
		t.Errorf("grants: got %d, want 1 (concurrent cold clients must share one grant)", got)
	}
}

// The failure case is the point: a wrong credential under concurrent load
// costs one failed authentication attempt, not one per caller racing the
// account toward lockout.
func TestConcurrentColdClientsShareOneDenial(t *testing.T) {
	const clients = 4
	var grants atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grants.Add(1)
		<-release
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
	}))
	defer srv.Close()

	shared := NewMemoryCache()
	built := make([]*Client, clients)
	for i := range built {
		c, err := New(Config{URL: srv.URL, Username: "u", Password: "rotated", Retries: 1, Cache: shared})
		if err != nil {
			t.Fatal(err)
		}
		built[i] = c
	}
	errs := make(chan error, clients)
	for _, c := range built {
		go func() {
			_, err := c.Token(context.Background())
			errs <- err
		}()
	}
	waitForFlightWaiters(t, built[0], clients-1)
	close(release)
	for range clients {
		if err := <-errs; !errors.Is(err, ErrAccessDenied) {
			t.Errorf("got %v, want ErrAccessDenied", err)
		}
	}
	if got := grants.Load(); got != 1 {
		t.Errorf("grants: got %d, want 1 (a denial must be shared, not repeated per client)", got)
	}
}

// A failure the leading client owns — its own context cancelled mid-grant —
// is not an answer about the credential, so a waiter from another client
// takes its own attempt instead of inheriting it.
func TestSharedGrantLeaderCancelWaiterRetries(t *testing.T) {
	var grants atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if grants.Add(1) == 1 {
			// Drain the body first: the server cannot observe the client's
			// disconnect while an unread request body pends.
			io.Copy(io.Discard, r.Body) //nolint:errcheck
			<-r.Context().Done()        // hold the leader until its caller cancels
			return
		}
		fmt.Fprint(w, grantJSON("second-token"))
	}))
	defer srv.Close()

	shared := NewMemoryCache()
	leader, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 1, Cache: shared})
	if err != nil {
		t.Fatal(err)
	}
	waiter, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Retries: 1, Cache: shared})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := leader.Token(ctx)
		leaderErr <- err
	}()
	// The leader must own the flight before the waiter starts, or the roles
	// race and the cancel hits the wrong side.
	deadline := time.Now().Add(5 * time.Second)
	for grants.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("leader never reached the server")
		}
		time.Sleep(time.Millisecond)
	}
	waiterTok := make(chan string, 1)
	go func() {
		tok, err := waiter.Token(context.Background())
		if err != nil {
			t.Errorf("waiter must retry past a leader-local failure, got %v", err)
		}
		waiterTok <- tok
	}()

	waitForFlightWaiters(t, leader, 1)
	cancel()
	if err := <-leaderErr; err == nil {
		t.Error("cancelled leader should report its own error")
	}
	if tok := <-waiterTok; tok != "second-token" {
		t.Errorf("waiter token: got %q, want second-token", tok)
	}
	if got := grants.Load(); got != 2 {
		t.Errorf("grants: got %d, want 2 (leader's aborted attempt, then the waiter's own)", got)
	}
}

// Flights are scoped to the cache instance: clients with deliberately
// separate caches — or with caching disabled — never share one.
func TestIsolatedClientsDoNotShareFlights(t *testing.T) {
	cases := []struct {
		name string
		cfg  func(url string) Config
	}{
		{"separate caches", func(url string) Config {
			return Config{URL: url, Username: "u", Password: "p", Cache: NewMemoryCache()}
		}},
		{"caching disabled", func(url string) Config {
			return Config{URL: url, Username: "u", Password: "p", DisableCache: true}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var grants atomic.Int32
			arrived := make(chan struct{}, 2)
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				grants.Add(1)
				arrived <- struct{}{}
				<-release
				fmt.Fprint(w, grantJSON("test-token"))
			}))
			defer srv.Close()

			var wg sync.WaitGroup
			for range 2 {
				c, err := New(tc.cfg(srv.URL))
				if err != nil {
					t.Fatal(err)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := c.Token(context.Background()); err != nil {
						t.Errorf("token: %v", err)
					}
				}()
			}
			for range 2 {
				select {
				case <-arrived:
				case <-time.After(5 * time.Second):
					t.Fatal("both isolated clients must grant concurrently; one is waiting on the other's flight")
				}
			}
			close(release)
			wg.Wait()
			if got := grants.Load(); got != 2 {
				t.Errorf("grants: got %d, want 2", got)
			}
		})
	}
}

// uncomparableCache is a valid TokenCache whose dynamic type cannot be a map
// key; New must degrade such a client to per-client coalescing, not panic.
type uncomparableCache struct {
	f  func()
	mc TokenCache
}

func (u uncomparableCache) Load(k CacheKey) (CachedToken, bool) { return u.mc.Load(k) }
func (u uncomparableCache) Store(k CacheKey, t CachedToken)     { u.mc.Store(k, t) }
func (u uncomparableCache) Evict(k CacheKey)                    { u.mc.Evict(k) }

func TestUncomparableCacheDegradesToPerClientCoalescing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p",
		Cache: uncomparableCache{f: func() {}, mc: NewMemoryCache()}})
	if err != nil {
		t.Fatal(err)
	}
	if c.flightID.valid() {
		t.Error("an uncomparable cache type must not enroll in cross-client flights")
	}
	if tok, err := c.Token(context.Background()); err != nil || tok != "test-token" {
		t.Errorf("token: got %q, %v", tok, err)
	}
}

// interfaceFieldCache has a comparable static type, but hashing it as an
// interface panics when value holds a slice. New must never map arbitrary
// cache values directly.
type interfaceFieldCache struct {
	value any
	mc    *memoryCache
}

func (c interfaceFieldCache) Load(k CacheKey) (CachedToken, bool) { return c.mc.Load(k) }
func (c interfaceFieldCache) Store(k CacheKey, t CachedToken)     { c.mc.Store(k, t) }
func (c interfaceFieldCache) Evict(k CacheKey)                    { c.mc.Evict(k) }

func TestCacheWithUnhashableInterfaceFieldDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, grantJSON("test-token"))
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, Username: "u", Password: "p", Cache: interfaceFieldCache{
		value: []string{"not hashable"}, mc: NewMemoryCache().(*memoryCache),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if c.flightID.valid() {
		t.Error("a value cache must degrade to per-client coalescing")
	}
	if tok, err := c.Token(context.Background()); err != nil || tok != "test-token" {
		t.Errorf("token: got %q, %v", tok, err)
	}
}

// Every allocation of a zero-size type shares one address, so pointer
// identity cannot distinguish two deliberately separate zero-size caches;
// such clients must not enroll in cross-client flights at all.
func TestZeroSizeCacheDoesNotEnrollInFlights(t *testing.T) {
	if id := cacheFlightID(nopTokenCache{}); id.valid() {
		t.Error("value cache must not enroll")
	}
	if id := cacheFlightID(&nopPtrCache{}); id.valid() {
		t.Error("zero-size pointee must not enroll: all such pointers share one address")
	}
}

type nopTokenCache struct{}

func (nopTokenCache) Load(CacheKey) (CachedToken, bool) { return CachedToken{}, false }
func (nopTokenCache) Store(CacheKey, CachedToken)       {}
func (nopTokenCache) Evict(CacheKey)                    {}

type nopPtrCache struct{}

func (*nopPtrCache) Load(CacheKey) (CachedToken, bool) { return CachedToken{}, false }
func (*nopPtrCache) Store(CacheKey, CachedToken)       {}
func (*nopPtrCache) Evict(CacheKey)                    {}
