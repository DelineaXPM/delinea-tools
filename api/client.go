// Package api makes authenticated REST calls against Delinea Secret Server
// (on-prem or cloud) or the Delinea Platform. It performs the OAuth2 token
// grants itself with net/http — no SDK dependency — and exposes the raw
// request and response so callers can reach any API endpoint. It is the
// shared authentication and transport engine behind the delinea-util CLI (its
// raw verbs, check, and the secrets subcommand group) and can be embedded
// directly by other Go programs.
//
// # Long-running services
//
// Construct one Client per distinct credential at startup and share it — a
// Client is safe for concurrent use, and constructing one per request
// rebuilds the transport (and its TLS session state and connection pool) on
// every call. Token grants are guarded even when this advice is ignored:
// clients built without Config.Cache share a process-wide token cache, and
// clients with equivalent grant settings sharing a pointer-valued cache
// coalesce concurrent grants per credential. Successful grants are reused by
// later calls while the token remains fresh. A failed grant is shared only by
// callers waiting on that same in-flight attempt; it is not cached, so a later
// call tries again. This keeps one concurrent burst from racing an account
// toward lockout without suppressing recovery after credentials are repaired.
// Custom transports isolate grants per client. The same startup-constructed
// shape is what makes tests against secrets/secretstest natural — the two land
// together.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"weak"
)

// Sentinel errors, matched with errors.Is. A completed HTTP response is never
// an error: Do returns a Response for any status code, and these cover only
// configuration, authentication, vault-discovery, and transport failures.
var (
	ErrConfig       = errors.New("invalid configuration")
	ErrAuth         = errors.New("authentication failed")
	ErrAccessDenied = errors.New("access denied")
	ErrVault        = errors.New("vault discovery failed")
	ErrTransport    = errors.New("transport error")
	ErrTimeout      = errors.New("timed out")
)

// Target selects which token grant to perform against URL.
type Target string

const (
	TargetAuto         Target = ""         // infer from which credential pair is set
	TargetSecretServer Target = "ss"       // POST {URL}/oauth2/token, grant_type=password
	TargetPlatform     Target = "platform" // POST {URL}/identity/api/oauth2/token/xpmplatform
)

// Config holds connection and credential settings. A pre-obtained Token takes
// precedence over the grant credential fields; when Token is empty, exactly one
// grant style applies: Username/Password for Secret Server or
// ClientID/ClientSecret for the Delinea Platform. Token must be at least four
// bytes; shorter values are rejected as configuration errors.
type Config struct {
	URL    string
	Target Target
	// AllowInsecureHTTP permits plaintext HTTP to a non-loopback host. Leave it
	// false unless an operator has explicitly accepted that the credential and
	// every API response will cross the network without TLS protection.
	AllowInsecureHTTP bool

	Username string
	Password string
	Domain   string // optional AD domain (on-prem Secret Server only)

	ClientID     string
	ClientSecret string

	Token string // pre-obtained bearer token; when set no grant is performed

	CACert []byte // optional PEM bundle of trusted roots, added to the system trust store rather than replacing it
	// SkipTLSVerify disables TLS verification for this client's transport only.
	// Unlike the CLIs, embedding this package emits no warning when it is set —
	// the caller is responsible for confining it to a context where a
	// machine-in-the-middle is not a concern.
	SkipTLSVerify bool
	Timeout       time.Duration // header deadline and body idle limit per request (default 30s)
	Retries       int           // attempts, on transport errors/timeouts and 408/429/500/502/503/504, for GET/HEAD and the token grant (a completed grant answer is never replayed); default 3

	// Transport, when set, is the base RoundTripper for this client's requests
	// — an escape hatch for a client TLS certificate (mTLS), a custom dialer, or
	// bespoke proxy logic. Setting it hands TLS entirely to the caller: this
	// package no longer configures roots or verification, so a transport with
	// InsecureSkipVerify or an empty root pool is used as-is. It is therefore an
	// error to combine Transport with CACert or SkipTLSVerify. The cross-origin
	// redirect refusal still applies (it lives on the http.Client).
	//
	// Sharing one Transport across clients also shares its connection pool —
	// what a service holding many credentials against one server wants. The
	// combination rule above bounds that: because a shared Transport owns TLS,
	// clients whose servers need different private CAs cannot share one; give
	// each its own CACert (and accept a pool per client) instead.
	// A custom Transport disables token caching because its authentication
	// behavior is opaque to the package.
	//
	// Clients without Transport clone the process default as it existed when
	// this package initialized. Later in-place changes to http.DefaultTransport
	// are deliberately ignored; pass the changed transport here explicitly so
	// its opaque grant boundary is enforced.
	Transport http.RoundTripper `json:"-"`

	// Header is merged into every request sent to the primary target's origin.
	// It is deliberately NOT sent to a vault discovered on a different host, so
	// a header meant for a gateway in front of the platform cannot leak to a
	// third-party vault; use Request.Header to target a vault call. A
	// per-request Request.Header value for the same key wins, and an
	// Authorization entry here is ignored — the client always sets it last.
	Header http.Header

	// Backoff overrides the retry backoff (attempt is 0-based). Nil uses an
	// exponential default.
	Backoff func(attempt int) time.Duration `json:"-"`

	// Cache shares bearer tokens across Clients. Nil means a process-wide
	// shared memory cache (see NewMemoryCache), so code that constructs a
	// Client per operation does not also perform a token grant per operation —
	// the zero value is the safe value. Clients with equivalent grant settings
	// sharing one cache instance also coalesce concurrent grants per credential.
	// Cross-client coalescing requires a pointer-valued custom cache so instances
	// have an unambiguous identity; value-valued caches still share completed
	// entries but degrade to per-client coalescing. An opaque transport, whether
	// supplied in Config or installed as http.DefaultTransport, disables caching;
	// combining one with an explicit Cache is an error. Set DisableCache to opt
	// out explicitly. A custom implementation must remain process-local and must
	// not persist entries; see TokenCache.
	Cache TokenCache `json:"-"`

	// DisableCache turns off token caching for this client: every client
	// grants its own token and nothing is shared or reused across clients.
	// Combining it with an explicit Cache is a configuration error.
	DisableCache bool

	// Logger, when set, receives operational events: token grant outcomes,
	// request retries, vault discovery, and discarded cache entries. Nil is
	// silent — the default a CLI wants; a long-running service passes its own
	// handler to see why a call was slow or a credential refused. Events
	// carry metadata and, on a failed grant, the bounded credential-redacted
	// snippet of the token endpoint's error response; never a credential, a
	// request body, a successful response body, or a URL query string. Error
	// details from an opaque caller-supplied transport are suppressed because
	// arbitrary transport code may derive them from a request or response body.
	Logger *slog.Logger `json:"-"`

	// AllowedVaultHosts lists extra hosts trusted for discovered vault URLs.
	// A hostname without a port trusts only HTTPS port 443; trust an alternate
	// port by listing the exact host:port.
	AllowedVaultHosts []string
}

// defaultTokenCache backs Config.Cache == nil. One process-wide cache keyed
// by URL, target kind, identity, and a credential digest, so distinct
// tenants, identities, and rotated credentials never share an entry.
var defaultTokenCache = NewMemoryCache()

// redactedPlaceholder replaces a non-empty credential in formatted output. An
// empty credential stays empty, so formatted output still shows which
// credentials are configured.
func redactedPlaceholder(s string) string {
	if s == "" {
		return ""
	}
	return "[REDACTED]"
}

// withRedactedCredentials returns a copy with every credential field replaced
// by a placeholder.
func (c Config) withRedactedCredentials() Config {
	c.URL = RedactConfigURL(c.URL)
	c.Password = redactedPlaceholder(c.Password)
	c.ClientSecret = redactedPlaceholder(c.ClientSecret)
	c.Token = redactedPlaceholder(c.Token)
	if c.Header != nil {
		c.Header = c.Header.Clone()
		for name, values := range c.Header {
			for i, value := range values {
				values[i] = redactedPlaceholder(value)
			}
			c.Header[name] = values
		}
	}
	// These extension points can contain credentials in arbitrary caller
	// implementations. Omitting them is the only generally safe rendering.
	c.Transport = nil
	c.Backoff = nil
	c.Cache = nil
	c.Logger = nil
	return c
}

// RedactConfigURL preserves a valid origin while hiding components that
// commonly carry credentials (userinfo, query, fragment). A URL that cannot be
// parsed safely is hidden in full. It is the one redactor both api.Config and
// secrets.Config format through, so their safe-logging guarantee cannot drift.
func RedactConfigURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return redactedPlaceholder(raw)
	}
	if u.Host == "" || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) {
		return redactedPlaceholder(raw)
	}
	if u.User != nil {
		u.User = url.User("[REDACTED]")
	}
	if u.RawQuery != "" {
		u.RawQuery = "[REDACTED]"
	}
	if u.Fragment != "" {
		u.Fragment = "[REDACTED]"
	}
	return u.String()
}

// String renders credential-bearing fields safely, so a Config logged through
// the fmt verbs — including %+v of a struct that embeds one — never emits a
// credential. Header values are redacted and opaque extension points omitted.
func (c Config) String() string {
	type plain Config
	return fmt.Sprintf("%+v", plain(c.withRedactedCredentials()))
}

// GoString makes %#v redact exactly as String does.
func (c Config) GoString() string { return c.String() }

// MarshalJSON emits the Config with credentials and header values replaced by
// "[REDACTED]". JSON encoders (structured loggers included) never see those
// values, and a marshaled Config cannot round-trip them onto disk by design.
// Decoding a configuration file into Config is unaffected; Transport, Backoff,
// Cache, and Logger are not serializable and are skipped.
func (c Config) MarshalJSON() ([]byte, error) {
	type plain Config
	return json.Marshal(plain(c.withRedactedCredentials()))
}

// Request is one API call. Path is absolute on the target and may carry a
// query string. UseVault routes the call to the platform's default vault,
// discovered through the vault broker, with the same bearer token; setting
// VaultID alongside it routes to that specific vault instead of the default.
type Request struct {
	Method string
	Path   string
	Header http.Header
	// Body is read fully into memory before the call (so a GET/HEAD can be
	// replayed on retry), so it is not suited to streaming a very large upload.
	// A Body whose Read can block must also implement io.Closer: cancellation
	// closes it to unblock preparation. A non-closable Body must return from Read
	// promptly for the request context to bound the whole call.
	Body     io.Reader
	UseVault bool
	VaultID  string
}

// Response is the completed HTTP response. Body is streamed; the caller must
// close it.
type Response struct {
	StatusCode int
	Status     string
	Proto      string
	Header     http.Header
	Body       io.ReadCloser
}

// DiagnosticSnippet returns body as a bounded, single-line diagnostic with
// the exact request bearer token redacted. It is intended for bytes read from
// this response's streamed Body. Call it on the Response pointer returned by
// Do; a copied Response value has no binding and fails closed.
func (r *Response) DiagnosticSnippet(body []byte) string {
	return responseBindings.snippet(r, body)
}

// The binding registries keep exact request credentials associated with the
// response values Do and DoBufferedResponse return, without adding fields to
// their public layouts (the exported fields are source-compatibility surface
// for positional literals, and reflection-based formatting of a field holding
// a credential would leak it) and without hiding context inside the
// reassignable Body. Keys are weak, so a registry entry never keeps its
// response reachable; the value holds only credential snapshots and a weak
// client reference; runtime cleanup removes the snapshots once the response
// dies. Lookups are lock-free (sync.Map), so the per-request cost on the hot
// path is one Store and one AddCleanup registration.
type diagnosticBindings[T any] struct{ m sync.Map }

func (b *diagnosticBindings[T]) bind(r *T, c *Client, responseToken string, requestHeaderValues ...string) {
	key := weak.Make(r)
	b.m.Store(key, responseDiagnosticBinding{
		responseToken:          responseToken,
		configuredToken:        c.cfg.Token,
		password:               c.cfg.Password,
		clientSecret:           c.cfg.ClientSecret,
		configuredHeaderValues: headerValues(c.cfg.Header),
		requestHeaderValues:    slices.Clone(requestHeaderValues),
		client:                 weak.Make(c),
	})
	runtime.AddCleanup(r, func(key weak.Pointer[T]) { b.m.Delete(key) }, key)
}

func (b *diagnosticBindings[T]) snippet(r *T, body []byte) string {
	if r == nil {
		return diagnosticUnavailable
	}
	v, ok := b.m.Load(weak.Make(r))
	runtime.KeepAlive(r)
	if !ok {
		return diagnosticUnavailable
	}
	return v.(responseDiagnosticBinding).diagnosticSnippet(body)
}

var (
	responseBindings diagnosticBindings[Response]
	bufferedBindings diagnosticBindings[BufferedResponse]
)

type responseDiagnosticBinding struct {
	responseToken          string
	configuredToken        string
	password               string
	clientSecret           string
	configuredHeaderValues []string
	requestHeaderValues    []string
	client                 weak.Pointer[Client]
}

// diagnosticSnippet prefers the live client's formatter, so there is exactly
// one secret-classification policy; the credential snapshots serve only the
// fallback where the client has been collected but the response still lives.
func (b responseDiagnosticBinding) diagnosticSnippet(body []byte) string {
	if c := b.client.Value(); c != nil {
		requestSecrets := append([]string{b.responseToken}, b.requestHeaderValues...)
		out := c.diagnosticFormatter(requestSecrets...)(body)
		runtime.KeepAlive(c)
		return out
	}
	values := []string{b.configuredToken, b.responseToken}
	values = append(values, b.configuredHeaderValues...)
	values = append(values, b.requestHeaderValues...)
	redact := buildRedactor(append(values, b.password, b.clientSecret))
	return snippet([]byte(redact(string(body))))
}

// BufferedResponse is a completed response whose body has been read and
// closed. DiagnosticSnippet binds redaction to the bearer token actually sent
// on this response, so later token rotations cannot expose it.
type BufferedResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	// The redaction context lives in the weak binding registry, exactly as for
	// Response: a field holding the request token would leak it through
	// reflection-based formatting (%+v in a caller's debug log).
}

// DiagnosticSnippet returns this response body as a bounded, single-line
// diagnostic with the exact request bearer token redacted. Call it on the
// pointer DoBufferedResponse returned; a copied value has no binding and
// fails closed.
func (r *BufferedResponse) DiagnosticSnippet() string {
	if r == nil {
		return diagnosticUnavailable
	}
	return r.diagnosticSnippet(r.Body)
}

// diagnosticSnippet applies this response's exact request-bound redaction to
// related server-controlled fields as well as to Body.
func (r *BufferedResponse) diagnosticSnippet(text []byte) string {
	if r == nil {
		return diagnosticUnavailable
	}
	return bufferedBindings.snippet(r, text)
}

// diagnosticUnavailable is the shared fail-closed rendering for a response
// value that carries no redaction context (a zero value or a copy): with no
// client to redact through, emitting the raw body could leak a reflected
// credential.
const diagnosticUnavailable = "(diagnostic unavailable)"

// Client authenticates against one Delinea target and performs API calls.
// It is safe for concurrent use.
type Client struct {
	cfg             Config
	target          Target
	base            *url.URL
	hc              *http.Client
	opaqueTransport bool
	timeout         time.Duration
	retries         int
	backoff         func(attempt int) time.Duration
	now             func() time.Time
	log             *slog.Logger // never nil; a discard handler when Config.Logger is unset
	// flightID enrolls this client in cross-client grant coalescing, scoped to
	// its pointer-valued cache instance (see flight.go). Zero disables it.
	flightID flightIdentity
	// oobPollInterval is the minimum gap between interactive-login out-of-band
	// polls, so an auto-polling Prompter cannot hammer the Identity endpoint.
	// Defaulted in New; tests set it to zero to poll without delay.
	oobPollInterval time.Duration

	cache TokenCache
	key   CacheKey

	mu    sync.Mutex
	token CachedToken
	// tokenFromCache distinguishes a token loaded while this call was blocked
	// from one a peer granted during the call. Both are fresh locally, but only
	// the cached token may be stale and worth evicting/replaying after a 401 or
	// Secret Server's authoritative expired-token 403 response.
	tokenFromCache bool
	granting       *inflightGrant // non-nil while a grant is in flight, so peers coalesce onto it and share its outcome

	vaultMu       sync.Mutex
	vaultByID     map[string]cachedVaultURL       // memoized vault URLs by vaultId; the default under ""
	vaultDiscover map[string]*inflightVaultLookup // concurrent discoveries coalesce independently by vaultId
}

// String and GoString render the Client through Config's redaction. Config is
// held in the unexported cfg field, so fmt cannot invoke Config.String on it and
// would otherwise format the struct reflectively — printing Password,
// ClientSecret, and Token verbatim. A Client is the value an embedder is most
// likely to log (%+v), so it carries the same redaction guarantee as Config.
func (c *Client) String() string   { return "api.Client(" + c.cfg.String() + ")" }
func (c *Client) GoString() string { return "api.Client(" + c.cfg.GoString() + ")" }

// defaultBackoff doubles from 200ms; the shift is capped so a large attempt
// number cannot overflow into a negative duration (waits are further bounded
// by clampBackoff at the sleep sites).
func defaultBackoff(attempt int) time.Duration {
	return time.Duration(200*(1<<min(attempt, 8))) * time.Millisecond
}

// New validates cfg and builds a client with its own transport; it never
// mutates http.DefaultTransport and performs no network I/O. Header, CACert,
// and AllowedVaultHosts are copied, so mutating them after New returns has no
// effect on the client (a per-request header belongs in Request.Header);
// Transport, Backoff, and Cache are retained by reference and must stay valid
// for the client's lifetime.
func New(cfg Config) (*Client, error) {
	// Config is retained for the lifetime of the client. Snapshot its mutable
	// members before validation so caller mutation cannot change validated
	// headers, CA material, or the vault-host trust boundary after New returns.
	cfg.Header = cfg.Header.Clone()
	cfg.CACert = bytes.Clone(cfg.CACert)
	cfg.AllowedVaultHosts = slices.Clone(cfg.AllowedVaultHosts)

	base, err := parseBaseURL(cfg.URL, cfg.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	if cfg.Token != "" {
		if err := validateAccessToken(cfg.Token); err != nil {
			return nil, fmt.Errorf("%w: invalid Token: %v", ErrConfig, err)
		}
	}
	if err := ValidateHeaders(cfg.Header); err != nil {
		return nil, fmt.Errorf("%w: Config.Header: %v", ErrConfig, err)
	}
	target, err := resolveTarget(cfg)
	if err != nil {
		return nil, err
	}
	transport, opaqueTransport, err := newTransport(cfg)
	if err != nil {
		return nil, err
	}
	backoff := cfg.Backoff
	if backoff == nil {
		backoff = defaultBackoff
	}
	retries := cfg.Retries
	if retries < 1 {
		retries = 3
	}
	identity, secret := cfg.Username, cfg.Password
	if target == TargetPlatform {
		identity, secret = cfg.ClientID, cfg.ClientSecret
	} else if cfg.Domain != "" {
		identity = cfg.Domain + `\` + cfg.Username
	}
	cache := cfg.Cache
	switch {
	case cfg.DisableCache:
		if cache != nil {
			return nil, fmt.Errorf("%w: DisableCache with an explicit Cache is contradictory — drop one", ErrConfig)
		}
	case opaqueTransport:
		// An opaque Transport can change what a grant means in arbitrary ways,
		// so its tokens are never interchangeable with another client's; a
		// cache entry for one would either leak across that boundary or (under
		// a per-client key) be dead weight evicting live tokens. Such clients
		// do not participate in caching at all: an explicit Cache alongside an
		// opaque transport is contradictory and refused.
		if cache != nil {
			if cfg.Transport != nil {
				return nil, fmt.Errorf("%w: Cache with a custom Transport is contradictory — a transport's grants are not interchangeable across clients, so nothing could ever be shared; drop one", ErrConfig)
			}
			return nil, fmt.Errorf("%w: Cache cannot be used while http.DefaultTransport is replaced (%T) — grants made over a replaced default are not interchangeable across clients; drop Cache, or restore the default transport", ErrConfig, http.DefaultTransport)
		}
	case cache == nil:
		cache = defaultTokenCache
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Client{
		cfg:      cfg,
		target:   target,
		base:     base,
		log:      logger,
		cache:    cache,
		flightID: cacheFlightID(cache),
		key: CacheKey{
			URL:              base.String(),
			Kind:             target,
			Identity:         identity,
			CredentialDigest: credentialDigest(secret, grantContext(cfg.Header, cfg.SkipTLSVerify, cfg.CACert)),
		},
		hc: &http.Client{
			Transport:     transport,
			CheckRedirect: checkRedirect,
		},
		opaqueTransport: opaqueTransport,
		timeout:         effectiveTimeout(cfg),
		retries:         retries,
		backoff:         backoff,
		now:             time.Now,
		oobPollInterval: 2 * time.Second,
	}, nil
}

// parseBaseURL validates the primary origin without ever echoing raw back in an
// error: URL userinfo can contain a password. Paths are allowed for deployments
// mounted below an origin, but endpoint construction cannot safely preserve a
// base query or fragment.
func parseBaseURL(raw string, allowInsecureHTTP bool) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: URL is required", ErrConfig)
	}
	base, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("%w: URL must be an absolute http(s) URL", ErrConfig)
	}
	switch {
	case strings.EqualFold(base.Scheme, "https"):
		base.Scheme = "https"
	case strings.EqualFold(base.Scheme, "http"):
		base.Scheme = "http"
		if !allowInsecureHTTP && !loopbackHost(base.Hostname()) {
			return nil, fmt.Errorf("%w: URL uses plaintext http, which would expose the credential on the first request; use https, or set AllowInsecureHTTP only after accepting that risk", ErrConfig)
		}
	default:
		return nil, fmt.Errorf("%w: URL must be an absolute http(s) URL", ErrConfig)
	}
	if base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" {
		return nil, fmt.Errorf("%w: URL must not contain userinfo, a query, or a fragment", ErrConfig)
	}
	return base, nil
}

// effectiveTimeout is cfg.Timeout with the package's 30s default applied,
// shared by New and ProbeBackend so the two cannot default differently.
func effectiveTimeout(cfg Config) time.Duration {
	if cfg.Timeout <= 0 {
		return 30 * time.Second
	}
	return cfg.Timeout
}

// initialDefaultTransport is http.DefaultTransport as this package first saw
// it. A process that later replaces the default — with a tracing wrapper or
// even another *http.Transport routed differently — changes the network path
// every subsequent client would grant over, so those clients are treated as
// opaquely-transported exactly like an explicit Config.Transport: their
// grants never enter the shared cache.
var initialDefaultTransport = http.DefaultTransport

// initialDefaultHTTPTransport is an immutable configuration snapshot. Keeping
// only initialDefaultTransport's pointer would let an in-place mutation change
// the proxy, dialer, or TLS path while still looking non-opaque to the cache.
var initialDefaultHTTPTransport = func() *http.Transport {
	dt, ok := initialDefaultTransport.(*http.Transport)
	if !ok {
		return nil
	}
	return dt.Clone()
}()

// sameRoundTripperIdentity compares only values Go can compare safely. An
// unusual non-comparable RoundTripper (for example a function adapter) is
// conservatively opaque rather than triggering an interface-comparison panic.
func sameRoundTripperIdentity(a, b http.RoundTripper) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if va.Type() != vb.Type() || !va.Comparable() || !vb.Comparable() {
		return false
	}
	return va.Interface() == vb.Interface()
}

// newTransport builds the RoundTripper cfg describes: the caller's Transport
// verbatim, or a clone of the pristine http.DefaultTransport (which keeps
// proxy-environment handling) with cfg's TLS settings applied. ProbeBackend
// uses it too, so a probe observes the same network path as the client it
// validates. The bool reports whether the effective transport is opaque to
// cache-key construction and owned outside this call; false is returned only
// for the private *http.Transport clone created here.
func newTransport(cfg Config) (http.RoundTripper, bool, error) {
	if cfg.Transport != nil {
		if cfg.SkipTLSVerify || len(cfg.CACert) > 0 {
			return nil, false, fmt.Errorf("%w: Transport cannot be combined with CACert or SkipTLSVerify (a custom transport owns its own TLS)", ErrConfig)
		}
		return cfg.Transport, true, nil
	}
	// A replaced http.DefaultTransport (otelhttp, a proxy-routing
	// *http.Transport) is supported and common, but which replacement was in
	// force when a client was built decides which network path its grant
	// used — two different replacements must not share cached grants, so any
	// replacement is opaque, whatever its type.
	if !sameRoundTripperIdentity(http.DefaultTransport, initialDefaultTransport) {
		if cfg.SkipTLSVerify || len(cfg.CACert) > 0 {
			return nil, false, fmt.Errorf("%w: http.DefaultTransport has been replaced (%T); CACert/SkipTLSVerify need the pristine default — set Config.Transport with your own TLS instead", ErrConfig, http.DefaultTransport)
		}
		return http.DefaultTransport, true, nil
	}
	if _, ok := initialDefaultTransport.(*http.Transport); !ok || initialDefaultHTTPTransport == nil {
		// The default this package started under is itself not *http.Transport
		// (replaced before our init ran): same opacity rules apply.
		if cfg.SkipTLSVerify || len(cfg.CACert) > 0 {
			return nil, false, fmt.Errorf("%w: http.DefaultTransport is not *http.Transport (%T); CACert/SkipTLSVerify need the default transport — set Config.Transport with your own TLS instead", ErrConfig, http.DefaultTransport)
		}
		return http.DefaultTransport, true, nil
	}
	// Clone the startup snapshot, not the still-pointer-identical global. A
	// caller that mutates http.DefaultTransport in place after package init must
	// not silently move grants onto a different route while retaining the same
	// shared-cache identity.
	tr := initialDefaultHTTPTransport.Clone()
	if cfg.SkipTLSVerify || len(cfg.CACert) > 0 {
		tc := &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify} //nolint:gosec // opt-in, CLI-warned
		if len(cfg.CACert) > 0 {
			pool, err := rootPool(cfg.CACert)
			if err != nil {
				return nil, false, err
			}
			tc.RootCAs = pool
		}
		tr.TLSClientConfig = tc
	}
	return tr, false, nil
}

// Target reports the resolved token grant for this client (ss, platform, or
// empty when only a pre-obtained Token was supplied).
func (c *Client) Target() Target { return c.target }

// CloseIdleConnections closes connections held idle by the underlying
// transport. It does not interrupt active requests, and the Client remains
// usable. If Config.Transport is shared, this affects every client using that
// transport's idle connection pool.
func (c *Client) CloseIdleConnections() { c.hc.CloseIdleConnections() }

// rootPool returns the system trust store with the caller's PEM added, so a
// private CA supplements the public roots instead of replacing them. Replacing
// them would break the Delinea Platform flow, which reaches the Platform host
// and then a broker-supplied vault URL that may chain to a public CA. A system
// store that cannot be loaded is not fatal: the supplied roots may be all that
// is needed.
func rootPool(pem []byte) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%w: parsing CA certificate PEM: no certificates found", ErrConfig)
	}
	return pool, nil
}

func resolveTarget(cfg Config) (Target, error) {
	ss := cfg.Username != "" || cfg.Password != ""
	platform := cfg.ClientID != "" || cfg.ClientSecret != ""
	switch cfg.Target {
	case TargetSecretServer:
		if cfg.Token == "" && (cfg.Username == "" || cfg.Password == "") {
			return "", fmt.Errorf("%w: target ss requires Username and Password (or Token)", ErrConfig)
		}
		return TargetSecretServer, nil
	case TargetPlatform:
		// Username/Password is a valid platform credential set for the interactive
		// Identity API login (InteractiveLogin), which the automatic
		// client-credentials grant cannot serve. Accept it here; grantForm rejects
		// an automatic grant that lacks ClientID/ClientSecret with a message that
		// points at interactive login.
		hasClientCreds := cfg.ClientID != "" && cfg.ClientSecret != ""
		hasUserPass := cfg.Username != "" && cfg.Password != ""
		if cfg.Token == "" && !hasClientCreds && !hasUserPass {
			return "", fmt.Errorf("%w: target platform requires ClientID and ClientSecret, Username and Password (for interactive login), or Token", ErrConfig)
		}
		return TargetPlatform, nil
	case TargetAuto:
		// A bearer token is self-contained. Stale identity variables commonly
		// remain exported in a shell, but they neither select a grant nor change
		// the destination of a raw request.
		if cfg.Token != "" {
			return TargetAuto, nil
		}
		switch {
		case ss && platform:
			return "", fmt.Errorf("%w: both Username/Password and ClientID/ClientSecret are set; pass an explicit Target", ErrConfig)
		case platform:
			if cfg.ClientID == "" || cfg.ClientSecret == "" {
				return "", fmt.Errorf("%w: platform credentials require both ClientID and ClientSecret", ErrConfig)
			}
			return TargetPlatform, nil
		case ss:
			if cfg.Username == "" || cfg.Password == "" {
				return "", fmt.Errorf("%w: secret server credentials require both Username and Password", ErrConfig)
			}
			return TargetSecretServer, nil
		default:
			return "", fmt.Errorf("%w: no credentials: set Username/Password, ClientID/ClientSecret, or Token", ErrConfig)
		}
	default:
		return "", fmt.Errorf("%w: unknown target %q (want %q or %q)", ErrConfig, cfg.Target, TargetSecretServer, TargetPlatform)
	}
}

type noRedirectsKey struct{}

// errRefusedRedirect marks a redirect the client refused (cross-origin, or
// any redirect on a no-redirect request). It is a permanent configuration
// problem — the base URL points somewhere that bounces the call elsewhere —
// not a transient transport failure, so classifyTransport must not label it
// ErrTransport and have the resolver retry a doomed request.
var errRefusedRedirect = errors.New("redirect refused")

// checkRedirect refuses cross-origin redirects, so a bearer token is never
// replayed to another host, refuses all redirects on token grants, and refuses
// redirects for methods the client does not otherwise replay. A 307 or 308
// preserves a request body, while a 301, 302, or 303 can issue a second request
// after the first mutation was accepted; either behavior would violate the
// guarantee that writes are transmitted only once.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if req.Context().Value(noRedirectsKey{}) != nil {
		return http.ErrUseLastResponse
	}
	if len(via) == 0 {
		return fmt.Errorf("%w: redirect history is empty", errRefusedRedirect)
	}
	if method := via[0].Method; method != http.MethodGet && method != http.MethodHead {
		return fmt.Errorf("%w: refusing to redirect %s because the request may have mutated server state", errRefusedRedirect, method)
	}
	if len(via) >= 10 {
		return fmt.Errorf("%w: stopped after 10 redirects", errRefusedRedirect)
	}
	first := via[0].URL
	if !sameOrigin(first, req.URL) {
		return fmt.Errorf("%w: cross-origin redirect from %s to %s", errRefusedRedirect, first.Host, req.URL.Host)
	}
	return nil
}

// classifyTransport labels a transport failure while keeping the underlying
// error in the wrap chain: a caller distinguishing its own cancellation from
// a network outage must still match errors.Is(err, context.Canceled). A
// refused redirect is a permanent misconfiguration, not a transient failure,
// so it is labeled ErrConfig and never retried.
func classifyTransport(err error) error {
	if errors.Is(err, errRefusedRedirect) {
		return fmt.Errorf("%w: %v", ErrConfig, transportDiagnostic(err))
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return fmt.Errorf("%w: %w", ErrTimeout, transportDiagnostic(err))
	}
	return fmt.Errorf("%w: %w", ErrTransport, transportDiagnostic(err))
}

// transportDiagnostic suppresses net/http's full request URL while preserving
// the original error in the unwrap chain. Request paths may carry sensitive
// query values, and url.Error otherwise repeats them in returned errors and
// retry logs despite send's deliberately query-free structured path field.
func transportDiagnostic(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	cause := ue.Err.Error()
	if ue.URL != "" {
		cause = strings.ReplaceAll(cause, ue.URL, "(request URL)")
	}
	op := strings.TrimSpace(ue.Op)
	if op == "" {
		op = "HTTP"
	}
	message := op + " request: " + cause
	// Wrap prefixes name the failing operation ("requesting token: ",
	// "identity request: ") and carry no request values; losing them left the
	// operator unable to tell a failed grant from a failed API call.
	if prefix, ok := strings.CutSuffix(err.Error(), ue.Error()); ok && prefix != "" {
		message = prefix + message
	}
	return &safeTransportDiagnostic{message: message, err: err}
}

type safeTransportDiagnostic struct {
	message string
	err     error
}

func (e *safeTransportDiagnostic) Error() string { return e.message }
func (e *safeTransportDiagnostic) Unwrap() error { return e.err }

// opaqueTransportDiagnostic exposes only facts established by this package.
// Error text from a caller-supplied transport is untrusted: it can contain an
// arbitrary request or response body. Keep that error in the unwrap chain, but
// never render it into a returned error or logger attribute.
func opaqueTransportDiagnostic(operation string, err error) error {
	classified := classifyTransport(err)
	kind := ErrTransport.Error()
	switch {
	case errors.Is(classified, ErrConfig):
		kind = ErrConfig.Error()
	case errors.Is(classified, ErrTimeout):
		kind = ErrTimeout.Error()
	}
	if errors.Is(classified, context.Canceled) {
		kind = "request canceled"
	}
	return &safeTransportDiagnostic{
		message: kind + ": " + operation + " (opaque transport details suppressed)",
		err:     classified,
	}
}

// Do performs one authenticated API call. It returns a Response for any HTTP
// status code; errors are reserved for configuration, authentication, vault
// discovery, and transport failures.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	method, base, body, tok, reused, err := c.prepare(ctx, r)
	if err != nil {
		return nil, err
	}
	var resp *http.Response
	var staleAuthentication bool
	// The streaming finish only captures the response and never reads the body,
	// except for the small, bounded inspection needed to distinguish Secret
	// Server's expired-token 403 from ordinary resource authorization. A HEAD 403,
	// whose body HTTP omits, is confirmed by one read-only current-user request.
	// Inspected bytes are restored before the response reaches the caller. It
	// closes any previously captured response, so a stale-authentication body is
	// released before the re-auth replay overwrites it.
	stream := func(response *http.Response) error {
		if resp != nil {
			resp.Body.Close()
		}
		resp = response
		staleAuthentication = response.StatusCode == http.StatusUnauthorized
		if reused && c.target == TargetSecretServer && response.StatusCode == http.StatusForbidden {
			if method == http.MethodHead {
				// A HEAD body is always empty. Release the first exchange before the
				// confirmation request so a transport that serializes until Close
				// cannot deadlock, then leave the caller a normal bodyless response.
				response.Body.Close()
				response.Body = http.NoBody
				staleAuthentication = c.secretServerHeadTokenExpired(ctx, r, tok)
			} else {
				staleAuthentication = secretServerExpiredTokenStream(response)
			}
		}
		return nil
	}
	if err := c.deliver(ctx, method, base, r, body, tok, reused, stream, func() bool { return staleAuthentication }); err != nil {
		// A stale-authentication response the stream closure captured is still
		// open if the re-auth replay then failed at the transport level (finish
		// never ran to swap it), so close it here rather than leak the connection
		// until the watchdog fires.
		if resp != nil {
			resp.Body.Close()
		}
		return nil, err
	}
	result := &Response{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Proto:      resp.Proto,
		Header:     resp.Header,
		Body:       resp.Body,
	}
	responseBindings.bind(result, c, responseBearerToken(resp), headerValues(r.Header)...)
	return result, nil
}

func responseBearerToken(resp *http.Response) string {
	if resp == nil || resp.Request == nil {
		return ""
	}
	return strings.TrimPrefix(resp.Request.Header.Get("Authorization"), "Bearer ")
}

// deliver runs send once and, when a reused token drew an authoritative stale
// authentication response, refreshes the token and runs it once more. That
// response is either a 401, Secret Server's exact expired-token 403 body, or a
// HEAD 403 confirmed through the read-only current-user endpoint; ordinary 403
// resource authorization is left untouched. The classification is supplied by
// finish so Do can inspect and restore a streamed body while DoBufferedResponse
// can inspect the bytes it already read. Like every other automatic replay,
// stale-token recovery is limited to GET and HEAD. A mutation rejected for
// stale authentication still evicts the token so the next call can recover, but
// this call is never transmitted twice.
func (c *Client) deliver(ctx context.Context, method string, base *url.URL, r Request, body []byte, tok string, reused bool, finish func(*http.Response) error, staleAuthentication func() bool) error {
	err := c.send(ctx, method, base, r, tok, body, finish)
	if !reused || !staleAuthentication() {
		return err
	}
	c.evictToken(tok)
	idempotent := method == http.MethodGet || method == http.MethodHead
	if !idempotent {
		return err
	}
	fresh, _, gerr := c.accessToken(ctx)
	if gerr != nil {
		return gerr
	}
	return c.send(ctx, method, base, r, fresh, body, finish)
}

const (
	secretServerExpiredTokenMessage   = "Authentication failed or expired token."
	secretServerExpiredTokenBodyLimit = 1024
)

// secretServerExpiredTokenBody recognizes the bounded response Secret Server
// returns after POST /api/v1/oauth-expiration invalidates a token. Requiring a
// 403, a Secret Server target (at the call sites), one exact JSON field, and the
// exact observed message keeps unrelated authorization failures from causing
// a grant and replay.
func secretServerExpiredTokenBody(body []byte) bool {
	if len(body) == 0 || len(body) > secretServerExpiredTokenBodyLimit {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	open, err := decoder.Token()
	if err != nil || open != json.Delim('{') || !decoder.More() {
		return false
	}
	name, err := decoder.Token()
	if err != nil || name != "message" {
		return false
	}
	var message string
	if decoder.Decode(&message) != nil || message != secretServerExpiredTokenMessage || decoder.More() {
		return false
	}
	close, err := decoder.Token()
	if err != nil || close != json.Delim('}') {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

// restoredResponseBody replays bytes consumed for stale-authentication
// classification before continuing with the original stream. If inspection
// encountered a read error, the caller observes that error after the prefix,
// just as it would have without inspection.
type restoredResponseBody struct {
	prefix  *bytes.Reader
	readErr error
	body    io.ReadCloser
}

func (b *restoredResponseBody) Read(p []byte) (int, error) {
	if b.prefix.Len() > 0 {
		return b.prefix.Read(p)
	}
	if b.readErr != nil {
		err := b.readErr
		b.readErr = nil
		return 0, err
	}
	return b.body.Read(p)
}

func (b *restoredResponseBody) Close() error { return b.body.Close() }

// secretServerExpiredTokenStream inspects at most one byte beyond the accepted
// diagnostic size and restores every consumed byte before returning. Oversized,
// malformed, or unreadable bodies cannot trigger re-authentication.
func secretServerExpiredTokenStream(resp *http.Response) bool {
	original := resp.Body
	body, err := io.ReadAll(io.LimitReader(original, secretServerExpiredTokenBodyLimit+1))
	resp.Body = &restoredResponseBody{prefix: bytes.NewReader(body), readErr: err, body: original}
	return err == nil && secretServerExpiredTokenBody(body)
}

// secretServerHeadTokenExpired confirms a reused token after a HEAD receives
// 403. HTTP deliberately omits HEAD response bodies, so the exact Secret Server
// diagnostic cannot be classified from that response. A single read-only
// current-user request with the same token supplies an authoritative 401 or the
// bounded expired-token 403 without treating every HEAD authorization failure
// as stale authentication. Probe failures leave the original 403 untouched.
func (c *Client) secretServerHeadTokenExpired(ctx context.Context, original Request, tok string) bool {
	probe := Request{Method: http.MethodGet, Path: currentUserPath, Header: original.Header}
	resp, err := c.attempt(ctx, http.MethodGet, c.base, probe, tok, nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return true
	}
	if resp.StatusCode != http.StatusForbidden {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, secretServerExpiredTokenBodyLimit+1))
	return err == nil && secretServerExpiredTokenBody(body)
}

// DoBufferedResponse performs the request like Do but returns at most limit
// response-body bytes, read within the retry loop, so a body read that fails
// before that limit is retried on the same budget as a transport or status
// failure — one loop, Retry-After honored once, no outer retry to compound
// with. To classify Secret Server's bounded expired-token 403, the engine may
// inspect up to secretServerExpiredTokenBodyLimit+1 bytes independently of the
// returned limit; an error encountered only in that extra inspection does not
// change the caller's completed bounded response. A Secret Server HEAD receiving
// 403 may make one read-only current-user request to confirm that bodyless
// response before recovery. The body is returned already read and the connection
// released. The response keeps credential-redaction context bound to the exact
// request token, so rendering its body in a diagnostic cannot leak another
// call's token. Callers that stream a large body use Do instead; the secrets
// resolver and vault discovery use this.
func (c *Client) DoBufferedResponse(ctx context.Context, r Request, limit int64) (*BufferedResponse, error) {
	method, base, reqBody, tok, reused, err := c.prepare(ctx, r)
	if err != nil {
		return nil, err
	}
	var status int
	var header http.Header
	var body []byte
	var responseToken string
	var staleAuthentication bool
	read := func(resp *http.Response) error {
		bodyClosed := false
		defer func() {
			if !bodyClosed {
				resp.Body.Close()
			}
		}()
		// Capture the status before the body read, so a 401 whose body read
		// then fails still surfaces status 401 for deliver's re-auth decision
		// rather than being lost as a bare transport error.
		status, header = resp.StatusCode, resp.Header
		staleAuthentication = status == http.StatusUnauthorized
		responseToken = responseBearerToken(resp)
		readLimit := limit
		inspectExpiredToken := reused && c.target == TargetSecretServer && status == http.StatusForbidden && method != http.MethodHead
		if inspectExpiredToken && readLimit < secretServerExpiredTokenBodyLimit+1 {
			readLimit = secretServerExpiredTokenBodyLimit + 1
		}
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, readLimit))
		// Reading beyond limit is an internal, best-effort inspection. Once the
		// caller's requested prefix is complete, a failure in that extra read must
		// not turn an otherwise complete bounded response into a transport error.
		callerReadComplete := limit <= 0 || int64(len(b)) >= limit
		if rerr != nil && (!inspectExpiredToken || !callerReadComplete) {
			// A body read that dies mid-stream is transport-class; returning it
			// as such lets send retry it in place.
			return classifyTransport(rerr)
		}
		body = b
		if limit < 0 {
			body = nil
		} else if int64(len(body)) > limit {
			body = body[:limit]
		}
		staleAuthentication = staleAuthentication ||
			(inspectExpiredToken && rerr == nil && secretServerExpiredTokenBody(b))
		if reused && c.target == TargetSecretServer && status == http.StatusForbidden && method == http.MethodHead {
			resp.Body.Close()
			bodyClosed = true
			staleAuthentication = c.secretServerHeadTokenExpired(ctx, r, tok)
		}
		return nil
	}
	if err := c.deliver(ctx, method, base, r, reqBody, tok, reused, read, func() bool { return staleAuthentication }); err != nil {
		return nil, err
	}
	resp := &BufferedResponse{
		StatusCode: status,
		Header:     header,
		Body:       body,
	}
	bufferedBindings.bind(resp, c, responseToken, headerValues(r.Header)...)
	return resp, nil
}

// prepare validates a request and resolves the credentials and target base URL
// it needs, shared by Do and DoBufferedResponse. reused reports that the token
// predates the call, which is what makes an evict-and-replay worthwhile on a
// 401 or Secret Server's authoritative expired-token 403 response.
func (c *Client) prepare(ctx context.Context, r Request) (method string, base *url.URL, body []byte, tok string, reused bool, err error) {
	method = strings.ToUpper(strings.TrimSpace(r.Method))
	if method == "" {
		return "", nil, nil, "", false, fmt.Errorf("%w: method is required", ErrConfig)
	}
	if !strings.HasPrefix(r.Path, "/") {
		return "", nil, nil, "", false, fmt.Errorf("%w: Path must be absolute on the target, without scheme or host", ErrConfig)
	}
	if r.UseVault && c.target == TargetSecretServer {
		return "", nil, nil, "", false, fmt.Errorf("%w: vault routing requires a platform target", ErrConfig)
	}
	if r.VaultID != "" && !r.UseVault {
		return "", nil, nil, "", false, fmt.Errorf("%w: VaultID is set but UseVault is not; set UseVault to route the call to that vault", ErrConfig)
	}
	if err := ValidateHeaders(r.Header); err != nil {
		return "", nil, nil, "", false, fmt.Errorf("%w: Request.Header: %v", ErrConfig, err)
	}
	if r.Body != nil {
		if body, err = readRequestBody(ctx, r.Body); err != nil {
			return "", nil, nil, "", false, err
		}
	}
	tok, reused, err = c.accessToken(ctx)
	if err != nil {
		return "", nil, nil, "", false, err
	}
	base = c.base
	if r.UseVault {
		if base, err = c.vaultURLFor(ctx, r.VaultID); err != nil {
			return "", nil, nil, "", false, err
		}
	}
	return method, base, body, tok, reused, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// readRequestBody cooperates with cancellation without abandoning a reader in
// a worker goroutine. Closing a blocking pipe/socket is the only generic way to
// interrupt its Read; non-closable readers retain the documented obligation to
// return promptly.
func readRequestBody(ctx context.Context, r io.Reader) ([]byte, error) {
	closer, canClose := r.(io.Closer)
	if err := ctx.Err(); err != nil {
		if canClose {
			_ = closer.Close()
		}
		return nil, classifyTransport(err)
	}
	if canClose {
		stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
		defer stop()
	}
	body, err := io.ReadAll(contextReader{ctx: ctx, r: r})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, classifyTransport(ctxErr)
	}
	if err != nil {
		return nil, &safeTransportDiagnostic{
			message: "reading request body failed (details suppressed)",
			err:     err,
		}
	}
	return body, nil
}

// maxRetryAfterWait bounds how long a Retry-After header is honored; a server
// asking for more gets its 429/503 returned to the caller instead. The same
// bound clamps the fallback backoff (see clampBackoff), where it limits the
// wait rather than skipping the retry.
const maxRetryAfterWait = 30 * time.Second

// clampBackoff bounds a backoff delay to [0, maxRetryAfterWait]: a generous
// custom Backoff (or an overflowed exponential) must not stretch one wait to
// hours, and a negative overflow must not become a zero-delay hot loop.
func clampBackoff(d time.Duration) time.Duration {
	return min(max(d, 0), maxRetryAfterWait)
}

// backoffAt returns the clamped backoff for attempt a, or zero when no backoff
// is configured (tests disable it to avoid real sleeps).
func (c *Client) backoffAt(a int) time.Duration {
	if c.backoff == nil {
		return 0
	}
	return clampBackoff(c.backoff(a))
}

// retriableStatus reports a response worth retrying on an idempotent request:
// a request timeout (408), rate limiting (429), and the transient server
// failures a gateway emits during a restart or brief outage (500/502/503/504).
func retriableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retriableErr reports a failure worth another attempt on an idempotent
// request: a transport error, or a timeout (a connection that accepted but
// never answered is transient, and both CLIs' taxonomy files timeout under
// "transport error"). It covers a buffered finish's body-read failure too,
// since that is classified transport.
func retriableErr(err error) bool {
	return errors.Is(err, ErrTransport) || errors.Is(err, ErrTimeout)
}

// leaderLocalFailure reports that a coalesced operation's failure is the
// leader's own, so a waiter holding its own context should retry rather than
// share it. It holds only when the leader's context is done (ctxErr) and the
// operation error IS that context error: the failure was caused by the
// leader's own cancellation or deadline, which says nothing about whether a
// waiter can complete the token grant or vault lookup.
//
// Matching the error against the context — not merely testing ctxErr != nil —
// is deliberate, and settles a decision this predicate has circled:
//
//   - A denial (a rejected credential) that arrives just before the leader's
//     context cancels does not wrap the context sentinel, so it is shared, not
//     relabelled leader-local. Every waiter sees the denial and none retries a
//     rejected credential toward account lockout.
//   - A genuine endpoint transient (a 503, a refused connection) coinciding
//     with a late cancellation likewise does not wrap the sentinel, so it is
//     shared rather than re-granted per waiter against a degraded endpoint.
//   - A real leader cancellation or deadline does wrap it: grantOnce runs under
//     context.WithTimeout(ctx, ...) and net/http surfaces ctx.Err() when that
//     fires, which classifyTransport preserves. So the case a waiter must retry
//     is caught.
//
// The one case this misses — a leader-context failure surfacing as a bare net
// error not wrapping the sentinel — needs an independent transport-layer
// timeout to fire at the instant the leader's context does; it is
// astronomically narrow, and even then the waiter inherits a retriable error
// that its own caller's retry loop re-attempts. Sharing when the cause is
// ambiguous is the safe default: it never re-grants against a struggling
// endpoint and never retries a denial.
func leaderLocalFailure(ctxErr, operationErr error) bool {
	return ctxErr != nil && errors.Is(operationErr, ctxErr)
}

// send runs the token-authenticated attempt/retry loop for one call and hands
// each successful response to finish. A finish that returns a retriable error
// — a buffered caller's body read that died mid-stream — is retried under the
// same budget as a transport failure, so a whole-response read needs no
// second, compounding loop. GET and HEAD are the only methods retried.
func (c *Client) send(ctx context.Context, method string, base *url.URL, r Request, tok string, body []byte, finish func(*http.Response) error) error {
	attempts := 1
	retriable := method == http.MethodGet || method == http.MethodHead
	if retriable {
		attempts = c.retries
	}
	logPath := r.Path
	if i := strings.IndexAny(logPath, "?#"); i >= 0 {
		logPath = logPath[:i] // query and fragment can carry caller data
	}
	requestSecrets := append([]string{tok}, headerValues(r.Header)...)
	logPath = c.diagnosticFormatter(requestSecrets...)([]byte(logPath))
	var last error
	for a := range attempts {
		resp, err := c.attempt(ctx, method, base, r, tok, body)
		if err == nil {
			if retriable && a < attempts-1 && retriableStatus(resp.StatusCode) {
				wait, retry := retryWait(resp.Header.Get("Retry-After"), a, c.backoff, c.now())
				if retry {
					c.log.WarnContext(ctx, "retrying request",
						"method", method, "path", logPath, "attempt", a+1,
						"status", resp.StatusCode, "wait", wait)
					io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck // drain for reuse
					resp.Body.Close()
					if err := sleep(ctx, wait); err != nil {
						return err
					}
					continue
				}
			}
			if err = finish(resp); err == nil {
				return nil
			}
		}
		last = err
		if !retriable || !retriableErr(err) || a == attempts-1 {
			return last
		}
		c.log.WarnContext(ctx, "retrying request",
			"method", method, "path", logPath, "attempt", a+1, "err", err)
		if err := sleep(ctx, c.backoffAt(a)); err != nil {
			return err
		}
	}
	return last
}

// retryWait decides whether a retriable status is retried and after how long.
// A server-supplied Retry-After is honored up to maxRetryAfterWait — beyond
// that the response goes back to the caller, per the header's contract. The
// fallback backoff carries no server demand, so it is clamped to the same
// bound instead: a custom Backoff longer than the bound must slow retries
// down, not silently disable them.
func retryWait(header string, attempt int, backoff func(int) time.Duration, now time.Time) (time.Duration, bool) {
	wait, fromHeader := retryDelay(header, attempt, backoff, now)
	if fromHeader {
		return wait, wait <= maxRetryAfterWait
	}
	return clampBackoff(wait), true
}

// sleep waits for d, or returns the context's error if it is cancelled or its
// deadline passes first, so a retry backoff never outlives the caller.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		if ctx.Err() != nil {
			return classifyTransport(ctx.Err())
		}
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return classifyTransport(ctx.Err())
	}
}

// attempt performs one HTTP exchange. The configured timeout bounds three
// waits independently: for the response headers, for the first body read to
// begin (a response abandoned without ever being read must not pin its
// connection past Timeout), and then for each individual body read. A stalled
// connection is cut off; a large response that keeps flowing is not, and once
// reading has begun a consumer that pauses between reads is not penalized.
func (c *Client) attempt(ctx context.Context, method string, base *url.URL, r Request, tok string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	attemptCtx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(attemptCtx, method, strings.TrimRight(base.String(), "/")+r.Path, rd)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%w: Method and Path do not form a valid HTTP request", ErrConfig)
	}
	// Config.Header sets defaults, but only on requests to the primary target's
	// origin — never on a call routed to a vault on a different host, so a
	// gateway header meant for the platform cannot leak cross-origin to a
	// (possibly third-party) vault. A per-request Request.Header for the same
	// key replaces the default; Authorization is set last and is never
	// overridable from either.
	if sameOrigin(base, c.base) {
		c.applyConfigHeader(req)
	}
	for k, vs := range r.Header {
		req.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
	setHostFromHeader(req)
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	var timedOut atomic.Bool
	watchdog := time.AfterFunc(c.timeout, func() {
		timedOut.Store(true)
		cancel()
	})
	requestSecrets := append([]string{tok}, headerValues(r.Header)...)
	classify := c.transportErrorClassifier("API request", requestSecrets)
	resp, err := c.hc.Do(req)
	if err != nil {
		watchdog.Stop()
		cancel()
		if timedOut.Load() {
			return nil, fmt.Errorf("%w: no response headers within %s", ErrTimeout, c.timeout)
		}
		return nil, classify(err)
	}
	// The watchdog stays armed until the first Read, so a response whose body
	// is never read or closed is still torn down within Timeout instead of
	// pinning its context and pooled connection.
	watchdog.Reset(c.timeout)
	ib := &idleBody{rc: resp.Body, timer: watchdog, idle: c.timeout, cancel: cancel, timedOut: &timedOut, classify: classify}
	// A body read from and then dropped without Close leaves the timer
	// stopped, so nothing else would ever release the connection; cancelling
	// on unreachability is the backstop (cancel is idempotent, so a normal
	// Close beating the cleanup is harmless).
	runtime.AddCleanup(ib, func(cancel context.CancelFunc) { cancel() }, context.CancelFunc(cancel))
	resp.Body = ib
	return resp, nil
}

// applyConfigHeader merges Config.Header into a request bound for the primary
// origin — API calls, token grants, and Identity API posts alike, per the
// Config.Header contract. Authorization is skipped: the client always sets it
// itself, and a grant request must never carry a stray bearer.
func (c *Client) applyConfigHeader(req *http.Request) {
	applyConfiguredHeader(req, c.cfg.Header)
}

// applyConfiguredHeader is shared with the Delinea-credential-free backend
// probe so gateway and virtual-host routing behave the same before and after
// New.
func applyConfiguredHeader(req *http.Request, header http.Header) {
	for k, vs := range header {
		ck := http.CanonicalHeaderKey(k)
		if ck == "Authorization" {
			continue
		}
		req.Header[ck] = append([]string(nil), vs...)
	}
}

// headerValues returns a snapshot of every non-empty header value. Header
// values are an authentication boundary in practice (gateway API keys and
// routing tokens), so diagnostics treat all of them as secrets rather than
// trying to maintain an incomplete list of sensitive header names.
func headerValues(header http.Header) []string {
	var values []string
	for _, vv := range header {
		for _, value := range vv {
			if value != "" {
				values = append(values, value)
			}
		}
	}
	return values
}

// setHostFromHeader honors a Host entry in the header map: net/http writes
// only req.Host to the wire and silently ignores the map entry, so a Host set
// through Config.Header or Request.Header (curl semantics, vhost routing)
// must be moved. TLS SNI and the connection still use the URL's host. Applied
// to API calls, token grants, and Identity API posts alike.
func setHostFromHeader(req *http.Request) {
	if h := req.Header.Get("Host"); h != "" {
		req.Host = h
		req.Header.Del("Host")
	}
}

// ValidateHeaders applies the same wire-level rules Config.Header and
// Request.Header must satisfy. Returned errors identify a rejected header by
// name but never reproduce its values, which may contain gateway credentials.
func ValidateHeaders(h http.Header) error { return validateHTTPHeaders(h) }

// validateHTTPHeaders applies net/http's wire-level header rules and rejects
// names that collide after case-insensitive canonicalization before any
// credential grant or request is attempted. Otherwise net/http reports a bad
// caller-supplied header from RoundTrip, which looks like a transient transport
// failure and can be retried despite being deterministic configuration.
func validateHTTPHeaders(h http.Header) error {
	seen := make(map[string]struct{}, len(h))
	for name, values := range h {
		if !validHeaderFieldName(name) {
			return fmt.Errorf("invalid header name %q", name)
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, duplicate := seen[canonical]; duplicate {
			return fmt.Errorf("header %q is specified more than once with different casing", canonical)
		}
		seen[canonical] = struct{}{}
		for _, value := range values {
			if !validHeaderFieldValue(value) {
				return fmt.Errorf("header %q contains an invalid control character", name)
			}
			if strings.EqualFold(name, "Host") && !validHostHeader(value) {
				return fmt.Errorf("header %q contains an invalid host", name)
			}
		}
	}
	return nil
}

func validHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		b := name[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			continue
		}
		switch b {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}

func validHeaderFieldValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if b := value[i]; (b < ' ' && b != '\t') || b == 0x7f {
			return false
		}
	}
	return true
}

func validHostHeader(host string) bool {
	for i := 0; i < len(host); i++ {
		b := host[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			continue
		}
		switch b {
		case '!', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', ':', ';', '=', '[', ']', '_', '~':
			continue
		}
		return false
	}
	return true
}

// idleBody bounds how long any single Read may wait on the connection and
// releases the request context on Close. After the first Read begins, the
// timer runs only while a Read is blocked, so it measures a stalled server,
// never a consumer that is slow to come back for the next read (a blocked
// downstream pipe must not kill a healthy download).
type idleBody struct {
	rc       io.ReadCloser
	timer    *time.Timer
	idle     time.Duration
	cancel   context.CancelFunc
	timedOut *atomic.Bool
	classify func(error) error
}

func (b *idleBody) Read(p []byte) (int, error) {
	b.timer.Reset(b.idle)
	n, err := b.rc.Read(p)
	b.timer.Stop()
	if err != nil && b.timedOut.Load() {
		return n, fmt.Errorf("%w: response body stalled for %s", ErrTimeout, b.idle)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		if b.classify != nil {
			return n, b.classify(err)
		}
		return n, classifyTransport(err)
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	err := b.rc.Close()
	b.cancel()
	if err == nil {
		return nil
	}
	if b.classify != nil {
		return b.classify(err)
	}
	return classifyTransport(err)
}

// retryDelay parses a Retry-After header (seconds or HTTP-date) into the wait
// the server asked for; fromHeader reports whether the header supplied it, so
// the caller can distinguish a server demand from the fallback backoff.
func retryDelay(header string, attempt int, backoff func(int) time.Duration, now time.Time) (wait time.Duration, fromHeader bool) {
	fallback := func() time.Duration {
		if backoff == nil {
			return 0
		}
		return backoff(attempt)
	}
	header = strings.TrimSpace(header)
	if header == "" {
		return fallback(), false
	}
	if secs, err := strconv.Atoi(header); err == nil {
		if secs <= 0 {
			return 0, true
		}
		// Capped above maxRetryAfterWait rather than multiplied: a huge value
		// would overflow time.Duration's int64 nanoseconds and wrap to a zero
		// wait, and the caller returns the response for any wait this long.
		if secs > int(maxRetryAfterWait/time.Second) {
			return maxRetryAfterWait + time.Second, true
		}
		return time.Duration(secs) * time.Second, true
	} else if errors.Is(err, strconv.ErrRange) {
		// All digits but too large for int: still a numeric server demand,
		// clearly beyond the honor limit — it must not slip into the fallback
		// path and be retried after a short backoff.
		if strings.HasPrefix(header, "-") {
			return 0, true
		}
		return maxRetryAfterWait + time.Second, true
	}
	if t, err := http.ParseTime(header); err == nil {
		return max(t.Sub(now), 0), true
	}
	return fallback(), false
}
