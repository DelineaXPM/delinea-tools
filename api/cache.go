package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TokenCache stores bearer tokens outside a single Client, so several Clients
// for the same identity can share the result of one grant: when a Client's own
// token expires, it loads a token another already obtained rather than granting
// afresh. Clients with equivalent grant settings sharing the same pointer-valued
// cache also coalesce concurrent grants; a value-valued custom cache shares
// completed entries but cannot safely identify an instance for a cross-client
// in-flight grant. An opaque custom transport disables grant caching.
// NewMemoryCache is the provided implementation; callers may supply their own.
// Implementations must be process-local, must not persist CacheKey or
// CachedToken values, and must be safe for concurrent use. Store is best-effort;
// implementations must contain their own failures because a failing cache must
// never fail the call.
type TokenCache interface {
	Load(key CacheKey) (CachedToken, bool)
	Store(key CacheKey, tok CachedToken)
	Evict(key CacheKey)
}

// CompareEvicter is a TokenCache that can evict a key atomically — only while
// its stored token still equals a given value. When a Client discards a token
// a server rejected, it drops that token from the cache; doing so with a plain
// Load then Evict can race with another Client that stored a fresh token in
// the gap and delete the fresh one, forcing a needless re-grant. A cache that
// implements CompareEvicter closes that race; one that does not gets the
// best-effort two step. The built-in NewMemoryCache implements it, so a custom
// cache only needs to when several Clients share it concurrently and the
// occasional redundant grant matters.
type CompareEvicter interface {
	TokenCache
	// EvictMatching removes key if and only if its currently stored token
	// equals token, as one atomic step.
	EvictMatching(key CacheKey, token string)
}

// CacheKey identifies one credential's token. CredentialDigest is an HMAC of
// the credential secret under a process-random key: a credential change
// invalidates in-memory entries, and the digest is meaningless outside this
// process. CacheKey and CachedToken values must not be persisted: the former
// carries credential identity metadata and the latter contains a live bearer
// credential.
type CacheKey struct {
	URL              string
	Kind             Target
	Identity         string
	CredentialDigest string
}

// CachedToken is one stored grant. Client validates AccessToken again when an
// entry is loaded, so malformed data from a custom cache is never admitted as a
// bearer credential.
type CachedToken struct {
	AccessToken string
	TokenType   string
	ObtainedAt  time.Time
	ExpiresAt   time.Time
}

// withRedactedToken returns a copy with the live AccessToken masked, so String
// and MarshalJSON share one redaction just as Config does.
func (t CachedToken) withRedactedToken() CachedToken {
	if t.AccessToken != "" {
		t.AccessToken = "[REDACTED]"
	}
	return t
}

// String and GoString redact the AccessToken so a CachedToken logged through the
// fmt verbs never emits the bearer. CachedToken crosses the public TokenCache
// boundary into consumer code, which may format it while debugging a cache.
func (t CachedToken) String() string {
	type plain CachedToken
	return fmt.Sprintf("%+v", plain(t.withRedactedToken()))
}

// GoString makes %#v redact exactly as String does.
func (t CachedToken) GoString() string { return t.String() }

// MarshalJSON redacts the AccessToken, mirroring Config: a CachedToken cannot
// round-trip a live bearer onto disk through a JSON encoder (structured loggers
// included). A cache that legitimately needs the value reads the field directly.
func (t CachedToken) MarshalJSON() ([]byte, error) {
	type plain CachedToken
	return json.Marshal(plain(t.withRedactedToken()))
}

// Fresh reports whether the token is safely reusable at now: inside 90% of
// its lifetime and clear of expiry by a minute — or by a tenth of the
// lifetime when that is shorter, so a token living less than ten minutes
// (a 60-second expires_in is a real Secret Server configuration) is still
// reusable rather than stale the instant it is stored.
func (t CachedToken) Fresh(now time.Time) bool {
	lifetime := t.ExpiresAt.Sub(t.ObtainedAt)
	if t.AccessToken == "" || lifetime <= 0 {
		return false
	}
	margin := min(time.Minute, lifetime/10)
	return now.Before(t.ObtainedAt.Add(lifetime/10*9)) && now.Before(t.ExpiresAt.Add(-margin))
}

var (
	hmacKeyOnce sync.Once
	hmacKey     []byte
)

func credentialDigest(secret string, context ...string) string {
	if secret == "" {
		return ""
	}
	hmacKeyOnce.Do(func() {
		hmacKey = make([]byte, 32)
		if _, err := rand.Read(hmacKey); err != nil {
			panic(err)
		}
	})
	mac := hmac.New(sha256.New, hmacKey)
	parts := []string{secret}
	for _, part := range context {
		if part != "" {
			parts = append(parts, part)
		}
	}
	for _, part := range parts {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(part))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// grantContext returns a deterministic description of request properties
// that can change a grant's meaning — non-Authorization headers a gateway
// may read, and the TLS-trust settings that decide which endpoints a grant
// could have been performed against. It is fed only into the process-keyed
// credential HMAC, never exposed through CacheKey in plaintext.
func grantContext(header http.Header, skipTLSVerify bool, caCert []byte) string {
	keys := make([]string, 0, len(header))
	for key := range header {
		if !strings.EqualFold(key, "Authorization") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if !skipTLSVerify && len(caCert) == 0 && len(keys) == 0 {
		return ""
	}
	var b strings.Builder
	writePart := func(value string) {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(value)))
		b.WriteByte(':')
		b.WriteString(value)
	}
	if skipTLSVerify {
		writePart("tls-skip-verify")
	}
	if len(caCert) > 0 {
		sum := sha256.Sum256(caCert)
		writePart("ca-cert")
		writePart(hex.EncodeToString(sum[:]))
	}
	for _, key := range keys {
		writePart("header")
		writePart(key)
		writePart(strconv.Itoa(len(header[key])))
		for _, value := range header[key] {
			writePart(value)
		}
	}
	return b.String()
}

const maxMemoryCacheEntries = 1024

type memoryCache struct {
	mu      sync.Mutex
	entries map[CacheKey]CachedToken
}

// NewMemoryCache returns a process-lifetime TokenCache for sharing across
// Clients, capped at 1024 entries with stale entries purged on overflow.
func NewMemoryCache() TokenCache {
	return &memoryCache{entries: map[CacheKey]CachedToken{}}
}

func (m *memoryCache) Load(key CacheKey) (CachedToken, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.entries[key]
	return t, ok
}

func (m *memoryCache) Store(key CacheKey, tok CachedToken) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[key]; !exists && len(m.entries) >= maxMemoryCacheEntries {
		now := time.Now()
		for k, t := range m.entries {
			if !t.Fresh(now) {
				delete(m.entries, k)
			}
		}
		if len(m.entries) >= maxMemoryCacheEntries {
			// Every entry is still fresh; evict the one nearest expiry rather
			// than a random one, so an actively-used token is the least likely
			// to be dropped (and forced into a needless re-grant).
			var victim CacheKey
			first := true
			for k, t := range m.entries {
				if first || t.ExpiresAt.Before(m.entries[victim].ExpiresAt) {
					victim, first = k, false
				}
			}
			delete(m.entries, victim)
		}
	}
	m.entries[key] = tok
}

func (m *memoryCache) Evict(key CacheKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
}

// EvictMatching implements CompareEvicter: it removes key only if its stored
// token still equals token, in one locked compare-and-delete — so a fresh
// token another client stored between a separate Load and Evict is not
// clobbered. evictToken decides when this atomic path is taken.
func (m *memoryCache) EvictMatching(key CacheKey, token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.entries[key]; ok && t.AccessToken == token {
		delete(m.entries, key)
	}
}
