// Package secrets fetches secrets from Delinea Secret Server, Secret Server
// Cloud, or the Delinea Platform and resolves field references into ordered
// name/value pairs. It is the engine behind the "delinea-util secrets"
// subcommand group and can be embedded directly by Go CI integrations.
// Authentication and transport come from the sibling api package.
//
// Clients constructed by New or NewWithClient are safe for concurrent use.
// A Client constructed by NewWithFetcher is safe for concurrent use only when
// its caller-supplied Fetcher (including CloseIdleConnections, when provided)
// is also safe for concurrent calls. Returned Secrets and other mutable values
// belong to the caller and must not be mutated concurrently without its own
// synchronization.
package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DelineaXPM/delinea-tools/api"
)

// Sentinel errors returned by Resolve, matched with errors.Is. Secret Server
// deliberately returns an identical "access denied" for a missing secret and
// an unauthorized one, so those cases collapse into ErrAccessDenied;
// ErrNotFound is only returned for a field absent on a secret that was
// successfully fetched.
var (
	ErrNotFound     = errors.New("field not found on secret")
	ErrAccessDenied = errors.New("access denied: secret missing or not permitted")
	ErrTransport    = errors.New("transport error")
	ErrTimeout      = errors.New("timed out")
)

// Config holds connection and credential settings. It deliberately has no
// ClientID/ClientSecret fields (unlike api.Config): for the Delinea Platform,
// pass the OAuth client_id/client_secret in Username/Password and set Target to
// api.TargetPlatform, and the secret calls are routed to the platform's vault.
// Carrying both backends' credentials in one pair is what lets WithProbedTarget
// resolve a single id/secret against either backend without the caller
// pre-declaring which — the one-credential-pair shape a CI integration carries.
// Use api.Config directly if you want the explicit ClientID/ClientSecret fields.
// Domain applies only to Active Directory users on on-prem Secret Server.
type Config struct {
	URL               string
	Target            api.Target // default treats Username/Password as Secret Server credentials
	AllowInsecureHTTP bool       // permit plaintext HTTP to a non-loopback host only after explicitly accepting credential exposure
	Username          string
	Password          string
	Domain            string
	Token             string // pre-obtained bearer token, at least four bytes; when set, callers skip Username/Password
	CACert            []byte // optional PEM bundle of trusted roots, added to the system trust store rather than replacing it
	SkipTLSVerify     bool   // skip TLS certificate verification (MITM risk); scoped to this client's transport, so other connections in the process are unaffected
	Timeout           time.Duration
	Retries           int // attempts per fetch on transport errors, body-read failures, and 408/429/500/502/503/504 responses, honoring Retry-After; default 1 (api.Config defaults to 3 — the resolver is deliberately less aggressive per fetch)

	Cache        api.TokenCache                  `json:"-"` // token cache shared across clients; nil means the api package's process-wide default (see api.Config.Cache)
	DisableCache bool                            // turn off token caching for this client entirely (contradictory with an explicit Cache)
	Logger       *slog.Logger                    `json:"-"` // operational events (grants, retries, vault discovery); nil is silent — see api.Config.Logger
	Backoff      func(attempt int) time.Duration `json:"-"` // optional backoff between the engine's retry attempts; nil uses an exponential default

	// AllowedVaultHosts lists extra hosts trusted for a platform-discovered
	// vault URL, for an on-premises vault that is neither same-origin with the
	// platform nor on a Delinea cloud vault domain. A hostname without a port
	// trusts only HTTPS port 443; list the exact host:port for another port.
	AllowedVaultHosts []string
}

// withRedactedCredentials returns a copy with every credential field replaced
// by a placeholder; an empty credential stays empty so formatted output still
// shows which credentials are configured.
func (c Config) withRedactedCredentials() Config {
	c.URL = api.RedactConfigURL(c.URL)
	if c.Password != "" {
		c.Password = "[REDACTED]"
	}
	if c.Token != "" {
		c.Token = "[REDACTED]"
	}
	// Caller implementations can contain credentials in arbitrary fields.
	// Omit opaque extension points from all formatted representations.
	c.Cache = nil
	c.Logger = nil
	c.Backoff = nil
	return c
}

// String renders Password and Token as "[REDACTED]" and omits opaque extension
// points, so a Config logged through the fmt verbs — including %+v of a struct
// that embeds one, the common consumer shape — never emits a credential.
func (c Config) String() string {
	type plain Config
	return fmt.Sprintf("%+v", plain(c.withRedactedCredentials()))
}

// GoString makes %#v redact exactly as String does.
func (c Config) GoString() string { return c.String() }

// MarshalJSON emits the Config with credentials replaced by "[REDACTED]" —
// JSON encoders (structured loggers included) never see a credential, and a
// marshaled Config cannot round-trip one onto disk by design. Decoding a
// configuration file into Config is unaffected; Backoff, Cache, and Logger are
// not serializable and are skipped.
func (c Config) MarshalJSON() ([]byte, error) {
	type plain Config
	return json.Marshal(plain(c.withRedactedCredentials()))
}

// Var is a resolved secret field, ready to expose as an environment variable.
type Var struct {
	Name  string
	Value string
}

// Secret is one fetched secret; Fields carries its items with file
// attachments already downloaded into ItemValue.
type Secret struct {
	Name     string
	ID       int
	FolderID int
	Fields   []SecretField `json:"items"`
}

// SecretField is one item on a secret.
type SecretField struct {
	ItemID           int
	FieldID          int
	FileAttachmentID int
	FieldName        string
	Slug             string
	Filename         string
	ItemValue        string
	IsFile           bool
	IsNotes          bool
	IsPassword       bool
}

// Field returns the value of the field matching name by field name or slug.
func (s *Secret) Field(name string) (string, bool) {
	for _, f := range s.Fields {
		if name == f.FieldName || name == f.Slug {
			return f.ItemValue, true
		}
	}
	return "", false
}

// Fetcher retrieves secrets by id or folder path. Implementations used by a
// Client shared between goroutines must be safe for concurrent calls. They must
// also stop promptly when ctx is cancelled: Client calls Fetcher methods
// synchronously, because abandoning a non-cooperative call in a worker
// goroutine would leak that goroutine and everything it retains. A successful
// call must return a non-nil Secret; Client rejects a nil result rather than
// allowing it to panic later during field resolution.
type Fetcher interface {
	Secret(ctx context.Context, id int) (*Secret, error)
	SecretByPath(ctx context.Context, path string) (*Secret, error)
}

// Client resolves mappings against a Fetcher. It is safe for concurrent use
// when its Fetcher is safe for concurrent calls. Retries live in the Fetcher —
// the api engine, which alone sees the HTTP response and can honor a server's
// Retry-After — so this layer performs one attempt per fetch and only bounds
// the whole call with timeout.
type Client struct {
	f         Fetcher
	timeout   time.Duration
	closeIdle func()
}

// String and GoString keep a logged Client (%+v) from leaking the credentials
// its underlying api.Client holds: without them fmt would format the unexported
// fetcher reflectively and reach the Config's secret fields. Delegation goes
// through the Stringer interface (never reflection) so a fetcher that is not a
// Stringer contributes nothing to leak.
func (c *Client) String() string {
	if s, ok := c.f.(fmt.Stringer); ok {
		return "secrets.Client(" + s.String() + ")"
	}
	return "secrets.Client"
}

// GoString makes %#v redact exactly as String does.
func (c *Client) GoString() string { return c.String() }

// EngineConfig is the api engine configuration this Config resolves to: the
// Username/Password pair is routed to ClientID/ClientSecret for a Platform
// target, and retries live in the engine — the only layer that sees the HTTP
// response and can honor a server's Retry-After on 429/503; the resolver above
// it performs a single attempt so the two layers cannot compound. (A
// resolver-level retry loop here once replaced the engine's, and silently
// ignored Retry-After.) New builds its client from it, and diagnostic callers
// (delinea-util check) reuse it so the authentication they perform cannot
// drift from the resolver's.
func (c Config) EngineConfig() api.Config {
	apiCfg := api.Config{
		URL:               c.URL,
		Target:            c.Target,
		AllowInsecureHTTP: c.AllowInsecureHTTP,
		Domain:            c.Domain,
		Token:             c.Token,
		CACert:            c.CACert,
		SkipTLSVerify:     c.SkipTLSVerify,
		Timeout:           c.Timeout,
		Cache:             c.Cache,
		DisableCache:      c.DisableCache,
		Logger:            c.Logger,
		AllowedVaultHosts: c.AllowedVaultHosts,
		Backoff:           c.Backoff,
		Retries:           max(c.Retries, 1),
	}
	if c.Target == api.TargetPlatform {
		apiCfg.ClientID = c.Username
		apiCfg.ClientSecret = c.Password
	} else {
		apiCfg.Username = c.Username
		apiCfg.Password = c.Password
	}
	return apiCfg
}

// WithProbedTarget resolves an unset Target by asking the server what it is
// (see api.Config.WithProbedTarget): the single Username/Password pair then
// routes to the grant the probed backend uses. An explicit Target returns
// the Config unchanged. The probe sends no credential.
func (c Config) WithProbedTarget(ctx context.Context) (Config, error) {
	if c.Target != api.TargetAuto {
		return c, nil
	}
	probed, err := c.EngineConfig().WithProbedTarget(ctx)
	if err != nil {
		return Config{}, err
	}
	c.Target = probed.Target
	return c, nil
}

// New connects to Delinea using cfg.
func New(cfg Config) (*Client, error) {
	c, err := api.New(cfg.EngineConfig())
	if err != nil {
		return nil, fmt.Errorf("configuring Delinea client: %w", err)
	}
	return newClient(&apiFetcher{c: c, vault: cfg.Target == api.TargetPlatform}, cfg.Timeout), nil
}

// NewWithClient builds a resolver over an already-configured api.Client, so an
// embedder can share one authenticated client — and its token cache — between
// raw api calls and secret resolution. Secret fetches route through the
// platform vault when the client's Target is platform.
//
// The injected client is the single source of retry and per-request timeout
// policy — its api.Config.Retries drives all retries, since the engine is the
// only layer that sees the HTTP response and can honor Retry-After. Configure
// Retries and Timeout on the client, and pass a context with a deadline to
// Resolve or Verify to bound the whole call.
func NewWithClient(c *api.Client) *Client {
	return newClient(&apiFetcher{c: c, vault: c.Target() == api.TargetPlatform}, 0)
}

// NewWithFetcher wraps an arbitrary Fetcher, primarily for testing. It
// performs a single attempt per fetch and applies no whole-call timeout;
// bound calls with a context deadline, make the Fetcher honor cancellation,
// and let the Fetcher own any retries. When the returned Client is shared
// between goroutines, the Fetcher must be safe for concurrent calls too.
func NewWithFetcher(f Fetcher) *Client { return newClient(f, 0) }

func newClient(f Fetcher, timeout time.Duration) *Client {
	c := &Client{f: f, timeout: timeout}
	if closer, ok := f.(interface{ CloseIdleConnections() }); ok {
		c.closeIdle = closer.CloseIdleConnections
	}
	return c
}

// CloseIdleConnections closes connections held idle by the underlying
// Fetcher when it supports that lifecycle operation. It does not interrupt
// active requests, and the Client remains usable. A client created with
// NewWithClient shares that api.Client's pool, so closing it affects every
// user of the injected client.
func (c *Client) CloseIdleConnections() {
	if c.closeIdle != nil {
		c.closeIdle()
	}
}

// Secret fetches one secret by id, with its file attachments downloaded. It is
// the typed read for callers that want the whole secret rather than resolved
// variables; use Field to read a value from it.
func (c *Client) Secret(ctx context.Context, id int) (*Secret, error) {
	return run(ctx, c.timeout, func(ctx context.Context) (*Secret, error) {
		return c.fetch(ctx, Mapping{SecretID: id})
	})
}

// SecretByPath fetches one secret by folder path, with its file attachments
// downloaded.
func (c *Client) SecretByPath(ctx context.Context, path string) (*Secret, error) {
	return run(ctx, c.timeout, func(ctx context.Context) (*Secret, error) {
		return c.fetch(ctx, Mapping{ByPath: true, Path: path})
	})
}

// diagnoses map a distinctive substring of a Delinea error to a specific cause.
// Secret Server and the Platform surface these as opaque HTTP failures, so the
// substring is the only signal available. All are permanent misconfigurations:
// retrying re-runs the password grant, and repeated password failures suspend
// the account.
var diagnoses = []struct{ match, cause string }{
	{"No internal user found for mapping the external user",
		"authenticated, but this Platform identity has no mapped Secret Server user (Secret Server Administration > Platform Integration > User Mappings)"},
	{"DuplicateUserNotMapped",
		"this Platform identity is unmapped or maps to a duplicate Secret Server username (Platform Integration > Reset User Mappings)"},
	{"invalid_client",
		"the Platform rejected the client credentials; for a Platform target, the username must be an OAuth client_id and the password its client_secret"},
	{"invalid_grant",
		"the username and password were rejected"},
}

// denials are error fragments that mean authorization failed without naming a
// cause. Secret Server returns an identical denial for a missing secret and an
// unauthorized one.
var denials = []string{"API_AccessDenied", "Access denied", "Access Denied", "access_denied"}

// containsDenialStatus reports whether s names a standalone embedded 401 or
// 403: preceded by whitespace, as a status is in prose ("returned 401"), and
// not followed by a letter, digit, or underscore. Requiring whitespace before
// the digits keeps punctuation-adjacent numbers — a path segment "/403/", an
// "id=401" — from reading as denials, and the strict trailing boundary keeps
// units such as "403ms" out.
func containsDenialStatus(s string) bool {
	for _, status := range []string{"401", "403"} {
		for offset := 0; offset < len(s); {
			i := strings.Index(s[offset:], status)
			if i < 0 {
				break
			}
			start := offset + i
			end := start + len(status)
			if denialStatusBoundary(s, start, end) {
				return true
			}
			offset = end
		}
	}
	return false
}

func denialStatusBoundary(s string, start, end int) bool {
	if start == 0 {
		// A leading status is httpStatus's business; an embedded one needs
		// the prose shape.
		return false
	}
	before, _ := utf8.DecodeLastRuneInString(s[:start])
	if !unicode.IsSpace(before) {
		return false
	}
	if end < len(s) {
		after, _ := utf8.DecodeRuneInString(s[end:])
		if unicode.IsLetter(after) || unicode.IsDigit(after) || after == '_' {
			return false
		}
	}
	return true
}

// httpStatus returns the HTTP status code an error begins with, or 0. The
// fetcher formats a non-2xx response as "<code> <text>: <body>", so the code
// appears only at the very front.
func httpStatus(s string) int {
	if len(s) < 3 {
		return 0
	}
	n, err := strconv.Atoi(s[:3])
	if err != nil || n < 100 || n > 599 {
		return 0
	}
	return n
}

// diagnose decides the sentinel reported to the caller, any named cause, and
// whether another attempt could help. Config and vault-discovery errors return
// a nil sentinel: they pass through unchanged.
func diagnose(err error) (cause string, sentinel error) {
	s := err.Error()
	code := httpStatus(s)
	// Transient wins over every substring and named cause: a 408/429/5xx, or
	// an engine transport/timeout, is retried even when its body happens to
	// contain "Access denied", "invalid_grant", or another denial fragment (a
	// WAF block page, an SSO error). Ordering the substring scans after this
	// is what stops a temporary outage from being frozen into a permanent
	// denial. Caller cancellation passes through untouched — not the server's
	// fault — and a deadline is a timeout, not a denial. The ErrTransport
	// sentinel is what marks a cause as retriable; the engine owns the retry.
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, api.ErrConfig), errors.Is(err, api.ErrVault):
		return "", nil
	case errors.Is(err, api.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return "", ErrTimeout
	case errors.Is(err, api.ErrTransport),
		code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500:
		return "", ErrTransport
	}
	// Named causes for the opaque HTTP denials Delinea returns, so a mapping
	// or credential misconfiguration is explained rather than left cryptic.
	for _, d := range diagnoses {
		if strings.Contains(s, d.match) {
			return d.cause, ErrAccessDenied
		}
	}
	// A bare 401/403, the access-denied sentinel, or a denial marker in the
	// body (Secret Server answers a missing/denied secret as 400
	// API_AccessDenied) is a genuine, non-retriable denial: the engine already
	// replayed once with a fresh grant, and re-running it risks suspension.
	if code == 401 || code == 403 || errors.Is(err, api.ErrAccessDenied) || errors.Is(err, api.ErrAuth) {
		return "", ErrAccessDenied
	}
	for _, d := range denials {
		if strings.Contains(s, d) {
			return "", ErrAccessDenied
		}
	}
	if containsDenialStatus(s) {
		return "", ErrAccessDenied
	}
	// A leading 4xx with no denial marker is a completed non-denial response
	// (a 404 from a wrong base path), passed through rather than reported as a
	// network problem.
	if code != 0 {
		return "", nil
	}
	if errors.Is(err, errTooLarge) || errors.Is(err, errBadResponse) {
		return "", nil
	}
	return "", ErrTransport
}

func classify(err error) error {
	cause, sentinel := diagnose(err)
	if sentinel == nil {
		return err
	}
	if cause != "" {
		return fmt.Errorf("%w: %s: %v", sentinel, cause, err)
	}
	return fmt.Errorf("%w: %v", sentinel, err)
}

// Resolve fetches every mapping and returns the resulting variables in order. A
// secret referenced by multiple mappings is fetched only once. Transient
// transport errors are retried; ctx bounds the whole call, and when Timeout is
// set it applies as an additional deadline.
func (c *Client) Resolve(ctx context.Context, mappings []Mapping) ([]Var, error) {
	return run(ctx, c.timeout, func(ctx context.Context) ([]Var, error) { return c.resolve(ctx, mappings) })
}

// run bounds fn with the caller's context plus the configured timeout. fn runs
// synchronously: every Fetcher accepts this context and must honor cancellation,
// while abandoning a non-cooperative call in a worker would leak the goroutine.
func run[T any](ctx context.Context, timeout time.Duration, fn func(context.Context) (T, error)) (T, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if err := contextError(ctx); err != nil {
		var zero T
		return zero, err
	}
	v, err := fn(ctx)
	if ctxErr := contextError(ctx); ctxErr != nil {
		var zero T
		return zero, ctxErr
	}
	return v, err
}

func contextError(ctx context.Context) error {
	err := ctx.Err()
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	}
	return err
}

// varsFor returns the variables a mapping defines against an already-fetched
// secret. Expansion skips file attachments and fields with no slug, since neither
// yields a usable variable name.
func varsFor(m Mapping, secret *Secret) ([]Var, error) {
	if m.Expand {
		// ParseMapping refuses an expansion with an empty prefix, but a
		// directly-constructed Mapping never went through it; the same rule
		// must hold here, or a vault-controlled slug names a top-level
		// variable (envify("ld-preload") is LD_PRELOAD) on the library path.
		if m.Prefix == "" {
			return nil, fmt.Errorf("secret %s: an expansion needs a non-empty Prefix, so its generated names are namespaced rather than chosen by the vault", m.Ref())
		}
		var out []Var
		for _, fld := range secret.Fields {
			if fld.Slug == "" || fld.IsFile {
				continue
			}
			out = append(out, Var{Name: m.Prefix + envify(fld.Slug), Value: fld.ItemValue})
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("secret %s: %w: expansion defines no variables (every field is a file attachment or has no slug)", m.Ref(), ErrNotFound)
		}
		return out, nil
	}
	value, ok := secret.Field(m.Field)
	if !ok {
		return nil, fmt.Errorf("secret %s: %w: field %q", m.Ref(), ErrNotFound, m.Field)
	}
	return []Var{{Name: m.EnvName, Value: value}}, nil
}

// validateMapping enforces every ParseMapping invariant for callers that use
// the documented struct-literal form. A malformed mapping must fail before a
// credential is spent fetching a secret, and contradictory fields must never
// be silently ignored.
func validateMapping(m Mapping) error {
	switch {
	case m.ByPath && m.Path == "":
		return fmt.Errorf("mapping path must not be empty")
	case m.ByPath && m.SecretID != 0:
		return fmt.Errorf("path mapping must not also set SecretID")
	case !m.ByPath && m.SecretID <= 0:
		return fmt.Errorf("mapping SecretID must be positive")
	case !m.ByPath && m.Path != "":
		return fmt.Errorf("id mapping must not also set Path")
	}
	if m.Expand {
		if m.EnvName != "" {
			return fmt.Errorf("an expansion must not also set EnvName")
		}
		if m.Field != "" {
			return fmt.Errorf("an expansion must not set Field")
		}
		if m.Prefix == "" {
			return fmt.Errorf("an expansion needs a non-empty Prefix, so its generated names are namespaced rather than chosen by the vault")
		}
		if !validEnvName(m.Prefix) {
			return fmt.Errorf("mapping Prefix %q is not a valid variable-name prefix (%s)", m.Prefix, envNameRule)
		}
		return nil
	}
	if m.Prefix != "" {
		return fmt.Errorf("a single-field mapping must not also set Prefix")
	}
	if !validEnvName(m.EnvName) {
		return fmt.Errorf("mapping EnvName %q is not a valid variable name (%s)", m.EnvName, envNameRule)
	}
	if m.Field == "" {
		return fmt.Errorf("a single-field mapping needs a non-empty Field")
	}
	return nil
}

func (c *Client) resolve(ctx context.Context, mappings []Mapping) ([]Var, error) {
	// Validate the whole batch before the first fetch. Callers can construct
	// Mapping values directly, and a malformed later entry must not spend a
	// credential or disclose the existence of an earlier referenced secret.
	for _, m := range mappings {
		if err := validateMapping(m); err != nil {
			return nil, err
		}
	}
	cache := map[string]*Secret{}
	var out []Var
	for _, m := range mappings {
		secret, ok := cache[m.cacheKey()]
		if !ok {
			s, err := c.fetch(ctx, m)
			if err != nil {
				return nil, err
			}
			cache[m.cacheKey()], secret = s, s
		}
		vars, err := varsFor(m, secret)
		if err != nil {
			return nil, err
		}
		out = append(out, vars...)
	}
	return out, nil
}

// Field is one variable a mapping would define. Bytes is the length of the
// resolved value, so an empty or truncated secret is visible; the value itself is
// deliberately not returned, so a diagnostic caller cannot disclose it.
type Field struct {
	Name  string
	Bytes int
}

// Result is the outcome of resolving one mapping. Err is nil when the mapping
// resolved; Fields is nil when it did not.
type Result struct {
	Mapping Mapping
	Fields  []Field
	Err     error
}

// Verify resolves every mapping and reports each outcome instead of stopping at
// the first failure as Resolve does, so a configuration with several bad
// references can be corrected in one pass. It returns names and value lengths,
// never values. The returned error is non-nil only if the whole call timed out
// or ctx was cancelled; per-mapping failures are in Result.Err.
func (c *Client) Verify(ctx context.Context, mappings []Mapping) ([]Result, error) {
	return run(ctx, c.timeout, func(ctx context.Context) ([]Result, error) { return c.verify(ctx, mappings) })
}

func (c *Client) verify(ctx context.Context, mappings []Mapping) ([]Result, error) {
	type fetched struct {
		secret *Secret
		err    error
	}
	// Failures are cached alongside successes: without that, every mapping naming
	// one unreachable secret would re-authenticate, and repeated password failures
	// suspend the account.
	cache := map[string]fetched{}
	out := make([]Result, 0, len(mappings))
	for _, m := range mappings {
		r := Result{Mapping: m}
		if err := validateMapping(m); err != nil {
			r.Err = err
			out = append(out, r)
			continue
		}
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		f, ok := cache[m.cacheKey()]
		if !ok {
			s, err := c.fetch(ctx, m)
			f = fetched{s, err}
			cache[m.cacheKey()] = f
		}
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if f.err != nil {
			r.Err = f.err
			out = append(out, r)
			continue
		}
		vars, err := varsFor(m, f.secret)
		if err != nil {
			r.Err = err
			out = append(out, r)
			continue
		}
		for _, v := range vars {
			r.Fields = append(r.Fields, Field{Name: v.Name, Bytes: len(v.Value)})
		}
		out = append(out, r)
	}
	return out, nil
}

// fetch performs one fetch of m; retries live in the Fetcher (the api engine),
// so this is a single attempt whose errors are classified for the caller.
func (c *Client) fetch(ctx context.Context, m Mapping) (*Secret, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fetching secret %s: %w", m.Ref(), classify(err))
	}
	if m.ByPath && m.Path == "" {
		return nil, fmt.Errorf("fetching secret: path must not be empty")
	}
	if !m.ByPath && m.SecretID <= 0 {
		return nil, fmt.Errorf("fetching secret: id must be positive")
	}
	var (
		s   *Secret
		err error
	)
	if m.ByPath {
		s, err = c.f.SecretByPath(ctx, m.Path)
	} else {
		s, err = c.f.Secret(ctx, m.SecretID)
	}
	if err != nil {
		return nil, fmt.Errorf("fetching secret %s: %w", m.Ref(), classify(err))
	}
	if s == nil {
		return nil, fmt.Errorf("fetching secret %s: %w: fetcher returned nil without an error", m.Ref(), errBadResponse)
	}
	return s, nil
}
