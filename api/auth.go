package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxAuthResponseBytes = 1 << 20
	maxTokenLifetime     = 365 * 24 * time.Hour
)

// The read-only endpoints Authenticate validates a pre-obtained token against;
// vault discovery (vault.go) shares the broker path so the two cannot drift.
const (
	currentUserPath       = "/api/v1/users/current"
	vaultBrokerVaultsPath = "/vaultbroker/api/vaults"
)

type grantResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// inflightGrant is one in-progress token grant that concurrent callers
// coalesce onto: done closes when the grant finishes, and tok/err then hold
// its shared outcome. Sharing the outcome — the failure as well as the
// success — is what makes a wave of concurrent refreshes cost one grant, so a
// revoked credential under load does not become one failing grant per
// goroutine.
type inflightGrant struct {
	done chan struct{}
	tok  string
	err  error
	// waiters counts callers that have coalesced onto this grant — observability
	// and deterministic tests, mirroring sharedGrant.waiters. Incremented each
	// time a caller parks on done; never decremented.
	waiters atomic.Int32
	// leaderLocal records that the grant failure is the leader's own, so a
	// coalesced waiter holding its own context retries rather than sharing it.
	// It is not simply "the leader's context was done": see leaderLocalFailure
	// for the exact test, and note the panic path sets it true independently.
	leaderLocal bool
}

// Token returns the bearer token for this client, performing the configured
// grant (or loading the configured cache) on first use. A token near expiry
// is replaced with a fresh grant, so a long-lived client keeps working past
// its first token's lifetime.
func (c *Client) Token(ctx context.Context) (string, error) {
	tok, _, err := c.accessToken(ctx)
	return tok, err
}

// Authenticate verifies that this client's credential is accepted and returns
// the bearer token for reuse. Username/password and client credentials are
// verified by a token grant performed during this call (and shared by callers
// in the same concurrent wave) — a fresh, memoized, or cached token from an
// earlier call is deliberately not enough, since it may have been granted under
// a credential that has since been rotated or revoked. A pre-obtained
// token requires one additional, read-only request because returning the
// configured string proves nothing: Secret Server uses the current-user
// endpoint and Platform uses the vault inventory endpoint. A configured token
// therefore needs an explicit target.
func (c *Client) Authenticate(ctx context.Context) (string, error) {
	if c.cfg.Token == "" {
		return c.forceGrant(ctx)
	}
	tok, err := c.Token(ctx)
	if err != nil {
		return tok, err
	}

	var path string
	switch c.target {
	case TargetSecretServer:
		path = currentUserPath
	case TargetPlatform:
		path = vaultBrokerVaultsPath
	default:
		return "", fmt.Errorf("%w: validating a pre-obtained token requires Target %q or %q", ErrConfig, TargetSecretServer, TargetPlatform)
	}
	resp, err := c.DoBufferedResponse(ctx, Request{Method: http.MethodGet, Path: path}, 1)
	if err != nil {
		return "", err
	}
	status := resp.StatusCode
	if status >= 200 && status < 300 {
		return tok, nil
	}
	statusText := fmt.Sprintf("%d %s", status, http.StatusText(status))
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return "", fmt.Errorf("%w: credential validation returned HTTP %s", ErrAccessDenied, strings.TrimSpace(statusText))
	}
	if retriableStatus(status) {
		return "", fmt.Errorf("%w: credential validation returned HTTP %s", ErrTransport, strings.TrimSpace(statusText))
	}
	if status >= 300 && status <= 399 {
		return "", fmt.Errorf("%w: credential validation returned HTTP %s", ErrConfig, strings.TrimSpace(statusText))
	}
	return "", fmt.Errorf("%w: credential validation returned HTTP %s", ErrAuth, strings.TrimSpace(statusText))
}

// forceGrant performs a genuine grant with the configured credential,
// bypassing the memoized token and the shared cache — Authenticate's contract
// is to exercise the credential, which a token granted earlier cannot do. It
// still respects the coalescing invariants: callers arriving during the same
// in-flight grant share its outcome. Config is immutable, so that grant is
// exercising the same credential; repeating it once per waiter would only
// amplify a denial toward account lockout.
func (c *Client) forceGrant(ctx context.Context) (string, error) {
	for {
		c.mu.Lock()
		if g := c.granting; g != nil {
			g.waiters.Add(1)
			c.mu.Unlock()
			select {
			case <-g.done:
				if g.err != nil && g.leaderLocal {
					continue
				}
				return g.tok, g.err
			case <-ctx.Done():
				return "", classifyTransport(ctx.Err())
			}
		}
		g := &inflightGrant{done: make(chan struct{})}
		c.granting = g
		c.mu.Unlock()
		c.runGrant(ctx, g)
		return g.tok, g.err
	}
}

// accessToken returns the bearer token to send. reused reports that the token
// predates this call — memoized from an earlier grant or loaded from the
// cache — which is what makes an evict-and-replay worthwhile on an
// authoritative stale-authentication response: a token granted within the
// same call cannot be stale.
//
// The mutex is never held across the grant's network I/O and backoff sleeps:
// concurrent callers coalesce onto one in-flight grant through c.granting,
// so a token expiry under load costs a single grant rather than one per
// goroutine, and a waiter whose context expires returns promptly instead of
// blocking on a lock that ignores deadlines.
func (c *Client) accessToken(ctx context.Context) (tok string, reused bool, err error) {
	if c.cfg.Token != "" {
		return c.cfg.Token, false, nil
	}
	for {
		c.mu.Lock()
		if c.token.Fresh(c.now()) {
			t := c.token.AccessToken
			c.mu.Unlock()
			return t, true, nil
		}
		c.mu.Unlock()
		// The cache Load runs with c.mu released, like runGrant's Store and
		// evictToken's calls: a caller-supplied cache that blocks on I/O,
		// re-enters the Client, or panics must not stall, deadlock, or leave
		// locked the mutex every other caller waits on. c.cache and c.key are
		// set once in New, so they are safe to read here without it.
		if c.cache != nil {
			if t, ok := c.cache.Load(c.key); ok && t.Fresh(c.now()) {
				if validateAccessToken(t.AccessToken) != nil {
					// A cache is an external admission boundary just like a grant
					// response. Discard malformed data and grant normally: cache
					// failures are best-effort and must not fail or weaken the call.
					c.log.Warn("discarding malformed cached token", "identity", c.key.Identity)
					c.evictToken(t.AccessToken)
				} else {
					c.mu.Lock()
					// A peer may have granted a newer token while Load ran; installing
					// the loaded one unconditionally would clobber it. Keep whichever
					// is fresh — the local token if a peer already set one, else the
					// loaded token — and return that.
					if !c.token.Fresh(c.now()) {
						c.token = t
						c.tokenFromCache = true
					}
					tok := c.token.AccessToken
					reused := c.tokenFromCache
					c.mu.Unlock()
					return tok, reused, nil
				}
			}
		}
		c.mu.Lock()
		// A peer may have granted while the cache Load ran; re-check before
		// starting our own grant so the wave still collapses onto one.
		if c.token.Fresh(c.now()) {
			t := c.token.AccessToken
			reused := c.tokenFromCache
			c.mu.Unlock()
			return t, reused, nil
		}
		if g := c.granting; g != nil {
			// A grant is already in flight: wait for it and share its outcome.
			// Almost every outcome is shared — a denial (so a concurrent wave
			// does not become one doomed grant per goroutine racing the account
			// toward lockout) and a server transient alike (so a struggling
			// endpoint is not hit with one grant sequence per waiter). Recovery
			// from a transient is the leader grant's own internal retry budget
			// (grant() loops c.retries honoring Retry-After), shared through the
			// coalesced result; giving each waiter a fresh grant on top of that
			// is the per-waiter storm, not extra safety — no waiter ends up worse
			// off than a solo caller whose grant exhausted the same budget. Only
			// a failure the leader owns (g.leaderLocal) makes this waiter take its
			// own attempt. A shared success is a token this call did not hold
			// beforehand, so reused is false (a 401 on it is a genuine denial,
			// not staleness).
			g.waiters.Add(1)
			c.mu.Unlock()
			select {
			case <-g.done:
				if g.err != nil {
					if g.leaderLocal {
						continue
					}
					return "", false, g.err
				}
				return g.tok, false, nil
			case <-ctx.Done():
				return "", false, classifyTransport(ctx.Err())
			}
		}
		g := &inflightGrant{done: make(chan struct{})}
		c.granting = g
		c.mu.Unlock()
		c.runGrant(ctx, g)
		return g.tok, false, g.err
	}
}

// runGrant performs the grant and publishes its outcome to g, always clearing
// c.granting and closing g.done — even if grant() or the cache Store panics.
// Without that guarantee a recovered panic (an embedder's custom Transport or
// TokenCache faulting on one request, inside its own recover) would leave
// c.granting set and g.done unclosed, wedging every later call on this shared
// client forever. The finalizer runs with c.mu unheld, so it is invoked only
// at points where the lock is not held. A panic aborts with a transient error
// so waiters retry rather than inherit a spurious failure.
func (c *Client) runGrant(ctx context.Context, g *inflightGrant) {
	done := false
	finish := func(tok string, err error, leaderLocal bool) {
		c.mu.Lock()
		g.tok, g.err, g.leaderLocal = tok, err, leaderLocal
		c.granting = nil
		close(g.done)
		c.mu.Unlock()
		done = true
	}
	defer func() {
		if !done {
			// A panic is spurious to this leader alone (an embedder's Transport
			// or TokenCache faulting on one request); let waiters take their
			// own attempt rather than share it.
			finish("", fmt.Errorf("%w: token grant aborted", ErrTransport), true)
		}
	}()

	gr, gerr := c.coalescedGrant(ctx)
	if gerr != nil {
		finish("", gerr, leaderLocalFailure(ctx.Err(), gerr))
		return
	}
	now := c.now()
	tok := CachedToken{
		AccessToken: gr.AccessToken,
		TokenType:   "Bearer",
		ObtainedAt:  now,
		ExpiresAt:   now.Add(time.Duration(gr.ExpiresIn) * time.Second),
	}
	c.mu.Lock()
	c.token = tok
	c.tokenFromCache = false
	c.mu.Unlock()
	if c.cache != nil {
		c.cache.Store(c.key, tok) // outside the lock: a panicking cache must not deadlock the finalizer
	}
	finish(tok.AccessToken, nil, false)
}

// evictToken discards a malformed cache entry or server-rejected token only if
// it is still the same value: under concurrent refreshes a peer may already have
// installed a newer token, and wiping that would force a redundant grant. The
// shared cache is likewise evicted only when its stored token still matches, so
// one client cannot blindly evict a fresh token another already stored. Grant
// coalescing spans clients sharing a pointer-valued cache, but eviction can race
// with a later, separate flight and still needs this compare-and-delete.
func (c *Client) evictToken(rejected string) {
	c.mu.Lock()
	if c.token.AccessToken == rejected {
		c.token = CachedToken{}
		c.tokenFromCache = false
	}
	c.mu.Unlock()
	if c.cache == nil {
		return
	}
	// The shared-cache calls run with c.mu released, exactly as runGrant's
	// cache.Store does: a caller-supplied cache that blocks on I/O or re-enters
	// the Client must not stall or deadlock every other Token() caller waiting
	// on the lock. c.cache and c.key are set once in New and never mutated, so
	// they are safe to read here without it.
	//
	// A cache that implements CompareEvicter (the built-in one does) evicts
	// atomically; any other TokenCache gets the best-effort Load-then-Evict,
	// which can race a peer's fresh Store but at worst forces a redundant grant.
	if ce, ok := c.cache.(CompareEvicter); ok {
		ce.EvictMatching(c.key, rejected)
		return
	}
	if t, ok := c.cache.Load(c.key); ok && t.AccessToken == rejected {
		c.cache.Evict(c.key)
	}
}

// grant performs the OAuth2 token grant, retrying only failures that carry
// no authentication answer: transport errors (the request may never have
// reached the server) and the same transient statuses roundTrip retries,
// honoring Retry-After. A completed response outside that set is never
// retried — repeated credential failures suspend accounts, and one
// authoritative answer is enough. (The narrow case of a response lost after
// the server counted a failed attempt is accepted; it is how every OAuth
// client retries.)
func (c *Client) grant(ctx context.Context) (grantResponse, error) {
	endpoint, form, err := c.grantForm()
	if err != nil {
		return grantResponse{}, err
	}
	start := c.now()
	var last error
	for a := range c.retries {
		g, status, retryAfter, err := c.grantOnce(ctx, endpoint, form)
		if err == nil {
			c.log.DebugContext(ctx, "token grant succeeded",
				"target", string(c.target), "identity", c.key.Identity,
				"attempt", a+1, "duration", c.now().Sub(start), "expires_in_s", g.ExpiresIn)
			return g, nil
		}
		c.log.WarnContext(ctx, "token grant attempt failed",
			"target", string(c.target), "identity", c.key.Identity,
			"attempt", a+1, "status", status, "err", err)
		last = err
		if a == c.retries-1 {
			break
		}
		var wait time.Duration
		switch {
		case status != 0 && retriableStatus(status):
			w, retry := retryWait(retryAfter, a, c.backoff, c.now())
			if !retry {
				return grantResponse{}, err
			}
			wait = w
		case status == 0 && retriableErr(err):
			wait = c.backoffAt(a)
		default:
			return grantResponse{}, err
		}
		if serr := sleep(ctx, wait); serr != nil {
			return grantResponse{}, serr
		}
	}
	return grantResponse{}, last
}

func (c *Client) grantForm() (string, url.Values, error) {
	switch c.target {
	case TargetPlatform:
		// A platform config carrying only Username/Password is valid for
		// interactive login (InteractiveLogin) but not for this automatic
		// client-credentials grant. Fail with direction rather than sending an
		// empty client_id/secret and surfacing the server's opaque "Login failed".
		if c.cfg.ClientID == "" || c.cfg.ClientSecret == "" {
			return "", nil, fmt.Errorf("%w: target platform with Username/Password requires interactive login (InteractiveLogin) to obtain a token; an automatic grant needs ClientID and ClientSecret", ErrConfig)
		}
		return c.base.String() + "/identity/api/oauth2/token/xpmplatform", url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {c.cfg.ClientID},
			"client_secret": {c.cfg.ClientSecret},
			"scope":         {"xpmheadless"},
		}, nil
	case TargetSecretServer:
		form := url.Values{
			"grant_type": {"password"},
			"username":   {c.cfg.Username},
			"password":   {c.cfg.Password},
		}
		if c.cfg.Domain != "" {
			form.Set("domain", c.cfg.Domain)
		}
		return c.base.String() + "/oauth2/token", form, nil
	default:
		return "", nil, fmt.Errorf("%w: no credentials available to obtain a token", ErrConfig)
	}
}

// grantOnce performs one grant exchange. status is the completed HTTP status
// (0 when no response arrived), and retryAfter its Retry-After header, so the
// caller can distinguish a transient the server asked to be retried from an
// authentication answer.
func (c *Client) grantOnce(ctx context.Context, endpoint string, form url.Values) (grantResponse, int, string, error) {
	gctx, cancel := context.WithTimeout(context.WithValue(ctx, noRedirectsKey{}, true), c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(gctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return grantResponse{}, 0, "", fmt.Errorf("%w: %v", ErrConfig, err)
	}
	c.applyConfigHeader(req)
	setHostFromHeader(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.hc.Do(req)
	if err != nil {
		return grantResponse{}, 0, "", c.transportErrorClassifier("requesting token", nil)(fmt.Errorf("requesting token: %w", err))
	}
	defer resp.Body.Close()
	body, oversized, err := readAuthResponse(resp.Body)
	if err != nil {
		// Headers are already an authoritative authentication answer even when
		// its explanatory body is lost. Preserve a completed non-2xx status so
		// grant does not mistake a rejected credential for a pre-response
		// transport failure and replay it toward account lockout. A successful
		// response whose body cannot be read still has no usable answer and is
		// safe to retry as transport failure.
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return grantResponse{}, resp.StatusCode, resp.Header.Get("Retry-After"),
				c.grantStatusError(resp.StatusCode, resp.Status, nil)
		}
		return grantResponse{}, 0, "", c.transportErrorClassifier("reading token response", nil)(fmt.Errorf("reading token response: %w", err))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return grantResponse{}, resp.StatusCode, resp.Header.Get("Retry-After"),
			c.grantStatusError(resp.StatusCode, resp.Status, body)
	}
	if oversized {
		return grantResponse{}, resp.StatusCode, "", fmt.Errorf("%w: token response exceeds %d bytes", ErrAuth, maxAuthResponseBytes)
	}
	var g grantResponse
	if err := json.Unmarshal(body, &g); err != nil {
		return grantResponse{}, resp.StatusCode, "", fmt.Errorf("%w: parsing token response: %v", ErrAuth, err)
	}
	if err := validateGrant(g); err != nil {
		return grantResponse{}, resp.StatusCode, "", fmt.Errorf("%w: %v", ErrAuth, err)
	}
	return g, 0, "", nil
}

// grantStatusError classifies a completed token-endpoint response. A transient
// status is transport-class, not an authentication answer: labeling it ErrAuth
// would make the secrets resolver report rate limiting as access denied. A 3xx
// (the grant never follows redirects) means the URL points at a front door that
// bounces the grant elsewhere, which is a permanent misconfiguration.
func (c *Client) grantStatusError(statusCode int, status string, body []byte) error {
	kind := ErrAuth
	switch {
	case statusCode >= 300 && statusCode <= 399:
		kind = ErrConfig
	case statusCode == http.StatusBadRequest || statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
		kind = ErrAccessDenied
	case retriableStatus(statusCode):
		kind = ErrTransport
	}
	return fmt.Errorf("%w: token endpoint returned %s: %s", kind, c.authSnippet([]byte(status)), c.authSnippet(body))
}

// minAccessTokenLen is enforced at every token admission boundary: configured
// tokens, grant responses, interactive-login responses, and cache loads. A
// one- to three-byte value is a typo or hostile response, and accepting it
// would shred diagnostics through unconditional bearer-token redaction.
const minAccessTokenLen = 4

// validateAccessToken rejects a token that is empty, too short, or carries
// whitespace or control characters. It is placed in an Authorization header
// and may be printed, so a hostile endpoint must not be able to smuggle bytes
// through it or return a value the client would reject when configured later.
func validateAccessToken(tok string) error {
	if tok == "" || strings.IndexFunc(tok, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("access_token is missing or contains whitespace or control characters")
	}
	if len(tok) < minAccessTokenLen {
		return fmt.Errorf("access_token is %d bytes; a bearer token must be at least %d", len(tok), minAccessTokenLen)
	}
	return nil
}

func validateGrant(g grantResponse) error {
	if err := validateAccessToken(g.AccessToken); err != nil {
		return err
	}
	if g.TokenType != "" && !strings.EqualFold(g.TokenType, "Bearer") {
		// token_type is endpoint-controlled and can reflect a submitted
		// credential or the newly issued token. Its value is not needed to
		// diagnose the protocol violation, so never put it in an error.
		return fmt.Errorf("unsupported token_type (want Bearer)")
	}
	if g.ExpiresIn <= 0 {
		return fmt.Errorf("expires_in must be greater than zero")
	}
	if g.ExpiresIn > int(maxTokenLifetime/time.Second) {
		return fmt.Errorf("expires_in exceeds the supported maximum of %s", maxTokenLifetime)
	}
	return nil
}

func readAuthResponse(r io.Reader) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxAuthResponseBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > maxAuthResponseBytes {
		return body[:maxAuthResponseBytes], true, nil
	}
	return body, false, nil
}

// DiagnosticSnippet renders server-controlled diagnostic text without allowing
// it to reflect this client's configured credentials or current bearer token
// into a terminal or CI log. For a body returned by Do or DoBufferedResponse,
// prefer the response's DiagnosticSnippet method: it also covers the exact token
// sent on that request after any number of later rotations. The client
// deliberately does not retain obsolete tokens: without a response identity,
// arbitrary bytes cannot be attributed to the old request that produced them.
func (c *Client) DiagnosticSnippet(body []byte) string {
	return c.diagnosticFormatter()(body)
}

func (c *Client) diagnosticFormatter(requestSecrets ...string) func([]byte) string {
	redact := c.redactor(requestSecrets)
	return func(body []byte) string {
		return snippet([]byte(redact(string(body))))
	}
}

// authSnippet also includes grant credentials and caller-supplied values such
// as MFA answers.
func (c *Client) authSnippet(body []byte, extra ...string) string {
	return snippet([]byte(c.redactor(nil, extra...)(string(body))))
}

// redactText redacts like authSnippet but preserves the text otherwise: no
// whitespace collapse and no truncation, only control characters neutralized.
// Prompter-bound challenge prompts use it — a multi-line security question
// must reach the user intact, but must never carry an escape sequence or an
// earlier answer.
func (c *Client) redactText(s string, extra ...string) string {
	redacted := c.redactor(nil, extra...)(s)
	return strings.Map(func(r rune) rune {
		if r != '\n' && r != '\t' && unicode.IsControl(r) {
			return '?'
		}
		return r
	}, redacted)
}

// redactor builds one replacement pass in the encodings the wire formats use.
// Every known credential is redacted regardless of length. A short credential
// may also hide matching ordinary text, but confidentiality takes precedence
// over preserving that diagnostic word.
func (c *Client) redactor(requestSecrets []string, extra ...string) func(string) string {
	return buildRedactor(c.redactionValues(requestSecrets, extra...))
}

// redactionValues snapshots the secrets known to this client and request. It is
// separate from building the replacement table so the transport classifier can
// defer the more expensive encoded-variant construction until an error occurs.
func (c *Client) redactionValues(requestSecrets []string, extra ...string) []string {
	c.mu.Lock()
	currentToken := c.token.AccessToken
	c.mu.Unlock()
	// Every accepted credential is an authentication secret regardless of length.
	// Admission accepts bearer tokens from four bytes upward and passwords,
	// client secrets, and answer-like values may be shorter, so the redactor
	// cannot infer that any configured value is disposable.
	values := []string{c.cfg.Token, currentToken, c.cfg.Password, c.cfg.ClientSecret}
	values = append(values, headerValues(c.cfg.Header)...)
	values = append(values, requestSecrets...)
	return append(values, extra...)
}

// transportErrorClassifier binds credential redaction to one request while
// preserving the classified error's unwrap chain. An opaque RoundTripper or
// response Body is arbitrary caller code and may derive its error text from a
// request or response body, which cannot be redacted reliably. Its printable
// diagnostic is therefore reduced to a stable operation and error class; the
// original remains available through errors.Is/errors.As.
func (c *Client) transportErrorClassifier(operation string, requestSecrets []string, extra ...string) func(error) error {
	if c.opaqueTransport {
		return func(err error) error { return opaqueTransportDiagnostic(operation, err) }
	}
	values := c.redactionValues(requestSecrets, extra...)
	redactor := sync.OnceValue(func() func(string) string {
		return buildRedactor(values)
	})
	return func(err error) error {
		classified := classifyTransport(err)
		return &safeTransportDiagnostic{message: redactor()(classified.Error()), err: classified}
	}
}

func buildRedactor(secrets []string) func(string) string {
	variants := make(map[string]struct{})
	addVariants := func(secret string) {
		if secret == "" {
			return
		}
		variants[secret] = struct{}{}
		variants[url.QueryEscape(secret)] = struct{}{}
		if encoded, err := json.Marshal(secret); err == nil && len(encoded) >= 2 {
			variants[string(encoded[1:len(encoded)-1])] = struct{}{}
		}
	}
	for _, secret := range secrets {
		addVariants(secret)
	}
	ordered := make([]string, 0, len(variants))
	for value := range variants {
		ordered = append(ordered, value)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) != len(ordered[j]) {
			return len(ordered[i]) > len(ordered[j])
		}
		return ordered[i] < ordered[j]
	})
	if len(ordered) == 0 {
		return func(s string) string { return s }
	}
	pairs := make([]string, 0, len(ordered)*2)
	for _, value := range ordered {
		pairs = append(pairs, value, "[REDACTED]")
	}
	// Replacer performs one pass and does not scan replacement text. Sequential
	// ReplaceAll calls would let a later one-byte secret such as "R" repeatedly
	// expand the marker inserted for an earlier secret, turning a bounded
	// diagnostic into an attacker-amplified allocation.
	return strings.NewReplacer(pairs...).Replace
}

// snippet reduces a server response body to one bounded, single-line string
// suitable for an error message. Whitespace is collapsed and the result capped;
// control characters are replaced, because the body comes from the server and
// error text reaches terminals, so a hostile endpoint must not be able to embed
// escape sequences in it. snippet does not redact credentials: a caller
// rendering a response body should prefer Response.DiagnosticSnippet or
// BufferedResponse.DiagnosticSnippet, which bind redaction to the exact bearer
// token the request was sent with; a caller rendering other authenticated text
// uses Client.DiagnosticSnippet, which covers the configured and current
// bearer tokens.
func snippet(body []byte) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if len(s) > 200 {
		// Truncate on a rune boundary: a byte slice at 200 could split a
		// multi-byte rune and emit invalid UTF-8 into the error text.
		cut := 200
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	if s == "" {
		s = "(empty body)"
	}
	return s
}
