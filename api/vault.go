package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

const maxVaultResponseBytes = 4 << 20

// vaultURLFreshness bounds how long routing learned from the Platform broker
// can remain unobservably stale. Discovery is synchronous after this window:
// a broker failure is returned rather than sending a request to an expired
// route that an operator may have deactivated or replaced.
const vaultURLFreshness = 5 * time.Minute

type cachedVaultURL struct {
	url          *url.URL
	discoveredAt time.Time
}

type inflightVaultLookup struct {
	done        chan struct{}
	url         *url.URL
	err         error
	leaderLocal bool
	waiters     atomic.Int32 // observability and deterministic cancellation tests
}

// Vault is one entry from the platform vault broker's inventory.
type Vault struct {
	VaultID         string          `json:"vaultId"`
	Name            string          `json:"name"`
	Type            string          `json:"type"`
	IsDefault       bool            `json:"isDefault"`
	IsGlobalDefault bool            `json:"isGlobalDefault"`
	IsActive        bool            `json:"isActive"`
	Connection      VaultConnection `json:"connection"`
}

// VaultConnection carries the vault's Secret Server base URL.
type VaultConnection struct {
	URL string `json:"url"`
}

// Vaults lists the platform's vaults from the vault broker.
// DoBufferedResponse reads the whole response inside the engine's retry loop,
// so transport failures, transient statuses (with Retry-After), and a body
// read that dies after the headers are all retried on one budget.
func (c *Client) Vaults(ctx context.Context) ([]Vault, error) {
	vaults, _, err := c.vaults(ctx)
	return vaults, err
}

func (c *Client) vaults(ctx context.Context) ([]Vault, *BufferedResponse, error) {
	// Read one byte past the cap so an over-length inventory is reported as a
	// size error rather than silently truncated and then misread as malformed
	// JSON (the fetcher reads its own cap the same way).
	resp, err := c.DoBufferedResponse(ctx, Request{Method: http.MethodGet, Path: vaultBrokerVaultsPath}, maxVaultResponseBytes+1)
	if err != nil {
		return nil, nil, err
	}
	status, body := resp.StatusCode, resp.Body
	// Status is classified before the size cap: a 401/403 or transient 5xx
	// with an oversized (e.g. verbose WAF) body is an access or transport
	// answer, not a size error.
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return nil, nil, fmt.Errorf("%w: vault broker returned %d", ErrAccessDenied, status)
	}
	if status < 200 || status > 299 {
		// DoBufferedResponse already retried the retriable statuses; one that persists
		// past that is still transport-class, not a verdict about discovery,
		// so an embedder matching ErrTransport requeues it rather than
		// treating a broker outage as a permanent vault-discovery failure.
		kind := ErrVault
		if retriableStatus(status) {
			kind = ErrTransport
		}
		return nil, nil, fmt.Errorf("%w: vault broker returned %d: %s", kind, status, resp.DiagnosticSnippet())
	}
	if len(body) > maxVaultResponseBytes {
		return nil, nil, fmt.Errorf("%w: vault broker inventory exceeds %d bytes", ErrVault, maxVaultResponseBytes)
	}
	var vr struct {
		Vaults []Vault `json:"vaults"`
	}
	if err := json.Unmarshal(body, &vr); err != nil {
		return nil, nil, fmt.Errorf("%w: parsing vault broker response: %v", ErrVault, err)
	}
	return vr.Vaults, resp, nil
}

// VaultURLByID discovers, validates, and memoizes the URL of a specific vault
// by its vaultId for five minutes, for callers that must reach a non-default
// vault. The URL is held to the same refresh and trust policy as the default.
// An empty id is refused rather than read as "the default": a caller passing
// through an unset configured ID must learn the configuration is incomplete,
// not silently route to the wrong vault (VaultURL is the way to ask for the
// default).
func (c *Client) VaultURLByID(ctx context.Context, id string) (*url.URL, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: vault id is required; use VaultURL for the default vault", ErrConfig)
	}
	return c.vaultURLFor(ctx, id)
}

// VaultURL discovers, validates, and memoizes the platform's default active
// vault URL for five minutes. After that it synchronously refreshes the route;
// a refresh failure is returned rather than using expired routing data.
func (c *Client) VaultURL(ctx context.Context) (*url.URL, error) {
	return c.vaultURLFor(ctx, "")
}

// vaultURLFor returns a fresh cached route or coalesces onto one broker lookup
// for this vault id. Network work runs without vaultMu held, so lookups for
// different ids proceed independently and canceled waiters return promptly.
func (c *Client) vaultURLFor(ctx context.Context, id string) (*url.URL, error) {
	for {
		now := c.now()
		c.vaultMu.Lock()
		if cached, ok := c.vaultByID[id]; ok && now.Before(cached.discoveredAt.Add(vaultURLFreshness)) {
			u := *cached.url
			c.vaultMu.Unlock()
			return &u, nil
		}
		if lookup := c.vaultDiscover[id]; lookup != nil {
			lookup.waiters.Add(1)
			c.vaultMu.Unlock()
			select {
			case <-lookup.done:
				if lookup.err != nil && lookup.leaderLocal {
					continue
				}
				if lookup.err != nil {
					return nil, lookup.err
				}
				u := *lookup.url
				return &u, nil
			case <-ctx.Done():
				return nil, classifyTransport(ctx.Err())
			}
		}
		if c.vaultDiscover == nil {
			c.vaultDiscover = make(map[string]*inflightVaultLookup)
		}
		lookup := &inflightVaultLookup{done: make(chan struct{})}
		c.vaultDiscover[id] = lookup
		c.vaultMu.Unlock()
		return c.runVaultLookup(ctx, id, lookup)
	}
}

// runVaultLookup publishes every outcome and always releases coalesced waiters,
// including when caller-provided transport code panics. A failure owned by the
// leader's context is not shared: waiters retry with their own live contexts.
func (c *Client) runVaultLookup(ctx context.Context, id string, lookup *inflightVaultLookup) (*url.URL, error) {
	completed := false
	finish := func(vu *url.URL, err error, leaderLocal bool) {
		c.vaultMu.Lock()
		lookup.url, lookup.err, lookup.leaderLocal = vu, err, leaderLocal
		delete(c.vaultDiscover, id)
		if err == nil {
			if c.vaultByID == nil {
				c.vaultByID = make(map[string]cachedVaultURL)
			}
			c.vaultByID[id] = cachedVaultURL{url: vu, discoveredAt: c.now()}
		}
		close(lookup.done)
		c.vaultMu.Unlock()
		completed = true
	}
	defer func() {
		if !completed {
			finish(nil, fmt.Errorf("%w: vault discovery aborted", ErrTransport), true)
		}
	}()

	vu, err := c.discoverVaultURL(ctx, id)
	if err != nil {
		finish(nil, err, leaderLocalFailure(ctx.Err(), err))
		return nil, err
	}
	finish(vu, nil, false)
	u := *vu
	return &u, nil
}

func (c *Client) discoverVaultURL(ctx context.Context, id string) (*url.URL, error) {
	vaults, resp, err := c.vaults(ctx)
	if err != nil {
		return nil, err
	}
	diagnostic := func(text string) string {
		if text == "" {
			return ""
		}
		return resp.diagnosticSnippet([]byte(text))
	}
	for _, v := range vaults {
		switch {
		case id == "" && (!v.IsDefault || !v.IsActive):
			continue
		case id != "" && v.VaultID != id:
			continue
		case id != "" && !v.IsActive:
			return nil, fmt.Errorf("%w: vault %q is not active", ErrVault, id)
		}
		vu, err := validateVaultURL(c.base, v.Connection.URL, c.cfg.AllowedVaultHosts)
		if err != nil {
			// Validation errors can include the broker-controlled host. Bind them
			// to the exact request redactor before they reach a terminal or log.
			detail := strings.TrimPrefix(err.Error(), ErrVault.Error()+": ")
			return nil, fmt.Errorf("%w: %s", ErrVault, diagnostic(detail))
		}
		c.log.DebugContext(ctx, "vault selected", "vault_id", diagnostic(v.VaultID), "name", diagnostic(v.Name), "host", diagnostic(vu.Host))
		return vu, nil
	}
	if id == "" {
		return nil, fmt.Errorf("%w: no default active vault configured", ErrVault)
	}
	return nil, fmt.Errorf("%w: no vault with id %q", ErrVault, id)
}

var delineaCloudVaultDomains = []string{
	"devsecretservercloud.com",
	"secretservercloud.com",
	"secretservercloud.eu",
	"secretservercloud.com.au",
	"secretservercloud.com.sg",
	"secretservercloud.ca",
	"secretservercloud.co.uk",
	"secretservercloud.ae",
}

// CloudURL builds the base URL of a Secret Server Cloud tenant —
// https://{tenant}.secretservercloud.{tld} — from the tenant name and
// top-level domain that tss-sdk-go configurations carry as Tenant and TLD,
// so those configurations migrate mechanically. An empty tld means "com"
// (the SDK's default). The tld must name a Delinea cloud region (the same
// set the vault trust policy accepts): com, eu, com.au, com.sg, ca, co.uk,
// ae. The tenant must be a bare DNS label, not a URL or hostname.
func CloudURL(tenant, tld string) (string, error) {
	tenant = strings.ToLower(strings.TrimSpace(tenant))
	if !validDNSLabel(tenant) {
		return "", fmt.Errorf("%w: tenant %q must be a bare DNS label (letters, digits, hyphens; not a URL)", ErrConfig, tenant)
	}
	tld = strings.ToLower(strings.TrimSpace(tld))
	if tld == "" {
		tld = "com"
	}
	domain := "secretservercloud." + tld
	if !slices.Contains(delineaCloudVaultDomains, domain) {
		return "", fmt.Errorf("%w: %q is not a Delinea cloud region TLD (use one of com, eu, com.au, com.sg, ca, co.uk, ae, or give the full URL via Config.URL)", ErrConfig, tld)
	}
	return "https://" + tenant + "." + domain, nil
}

// validDNSLabel reports whether s is a plausible single DNS label: 1-63
// bytes of letters, digits, and interior hyphens.
func validDNSLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// validateVaultURL treats the broker's connection URL as untrusted input: it
// must be https without userinfo, query, or fragment, and its host must be
// same-origin with the platform, a Delinea cloud vault domain, or explicitly
// allow-listed.
func validateVaultURL(platform *url.URL, raw string, allowed []string) (*url.URL, error) {
	vu, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || vu.Scheme == "" || vu.Host == "" {
		return nil, fmt.Errorf("%w: platform returned an invalid vault URL", ErrVault)
	}
	if !strings.EqualFold(vu.Scheme, "https") {
		return nil, fmt.Errorf("%w: platform returned a vault URL that does not use HTTPS", ErrVault)
	}
	if vu.User != nil {
		return nil, fmt.Errorf("%w: platform returned a vault URL containing user information", ErrVault)
	}
	if vu.RawQuery != "" || vu.ForceQuery || vu.Fragment != "" {
		return nil, fmt.Errorf("%w: platform returned a vault URL containing a query or fragment", ErrVault)
	}
	if sameOrigin(platform, vu) || isDelineaCloudVaultURL(vu) || isAllowedVaultHost(vu, allowed) {
		return vu, nil
	}
	return nil, fmt.Errorf("%w: untrusted vault host %q; if this on-premises deployment is expected, allow it explicitly (AllowedVaultHosts; delinea-util --vault-allow or DELINEA_TOOLS_VAULT_ALLOW)", ErrVault, vu.Host)
}

func isDelineaCloudVaultURL(vu *url.URL) bool {
	return effectivePort(vu) == "443" && isDelineaCloudVaultHost(vu.Hostname())
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func isDelineaCloudVaultHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, domain := range delineaCloudVaultDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func isAllowedVaultHost(vu *url.URL, allowed []string) bool {
	host := strings.ToLower(strings.TrimSuffix(vu.Host, "."))
	hostname := strings.ToLower(strings.TrimSuffix(vu.Hostname(), "."))
	for _, configured := range allowed {
		a := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(configured), "."))
		if a != "" && (a == host || (a == hostname && effectivePort(vu) == "443")) {
			return true
		}
	}
	return false
}
