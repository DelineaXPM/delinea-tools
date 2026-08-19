package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Backend is which Delinea service answers at a URL. It is what Target must
// agree with -- Target decides which token grant is performed and how the
// credentials are interpreted -- so it is the first thing to establish when
// authentication fails against the wrong kind of host.
type Backend string

const (
	BackendUnknown      Backend = ""
	BackendSecretServer Backend = "Secret Server"
	BackendPlatform     Backend = "Delinea Platform"
)

// maxHealthBody bounds a health response read; these bodies are a few hundred
// bytes and come from an endpoint that receives no Delinea credential, so they
// are untrusted and may be anything at all.
const maxHealthBody = 64 * 1024

// ProbeBackend reports which service answers at cfg.URL: the Secret Server
// health endpoint is tried first, then the Platform one. It sends configured
// same-origin routing headers except Authorization, but ignores every
// Delinea credential field on cfg. Config.Header may itself authenticate to a
// same-origin gateway; it is the routing layer needed to reach the health
// endpoint, not the Delinea credential the probe is intended to withhold.
func ProbeBackend(ctx context.Context, cfg Config) (Backend, error) {
	baseURL, err := parseBaseURL(cfg.URL, cfg.AllowInsecureHTTP)
	if err != nil {
		return BackendUnknown, err
	}
	if err := ValidateHeaders(cfg.Header); err != nil {
		return BackendUnknown, fmt.Errorf("%w: Config.Header: %v", ErrConfig, err)
	}
	client, cleanup, opaque, err := probeClient(cfg)
	if err != nil {
		return BackendUnknown, err
	}
	defer cleanup()
	base := baseURL.String()
	probes := []struct {
		path    string
		backend Backend
	}{
		{"api/v1/healthcheck", BackendSecretServer},
		{"health", BackendPlatform},
	}
	var firstErr error
	reachable := false
	for _, p := range probes {
		ok, err := probeHealthy(ctx, client, base+"/"+p.path, cfg.Header)
		switch {
		case ok:
			return p.backend, nil
		case err == nil:
			// The host answered (any status) — it is reachable, just not this
			// backend's healthy shape.
			reachable = true
		case firstErr == nil:
			firstErr = err
		}
	}
	if reachable {
		// One endpoint answered, so this is not a reachability failure even if
		// a later probe's transport errored; report an unrecognized backend,
		// not a misleading network error.
		return BackendUnknown, nil
	}
	// Route the probe's transport failure through the same classifier every
	// other network path uses, so WithProbedTarget honors the ErrTransport /
	// ErrTimeout contract (and the URL sanitizer). firstErr is non-nil here:
	// reachable stays false only when every probe returned an error.
	return BackendUnknown, classifyProbeTransport(firstErr, cfg.Header, opaque)
}

// probeClient builds the same transport New would — proxy environment, TLS
// settings, and Config.Transport included, so the probe observes the network
// path the real client will use rather than a bare direct connection.
// It refuses to follow redirects: the probe must observe only the origin it was
// pointed at, so a hostile endpoint cannot redirect it to an internal host (a
// Delinea-credential-free SSRF oracle) or to a service that answers "Healthy"
// and thereby flip the reported backend — which is what decides where the
// real credential is later sent.
func probeClient(cfg Config) (*http.Client, func(), bool, error) {
	tr, opaque, err := newTransport(cfg)
	if err != nil {
		return nil, nil, false, err
	}
	client := &http.Client{
		Transport:     tr,
		Timeout:       effectiveTimeout(cfg),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	// newTransport returns opaque=false only for the *http.Transport clone this
	// call owns. Close that clone's idle pool when the short probe is done, but
	// never disturb a caller-supplied or process-wide opaque transport.
	if !opaque {
		return client, client.CloseIdleConnections, false, nil
	}
	return client, func() {}, true, nil
}

// probeHealthy accepts a JSON object whose healthy field is true, or the exact
// trimmed legacy plain-text value Healthy (case-insensitively). Valid JSON is
// authoritative: a body without a healthy boolean is not a health verdict.
func probeHealthy(ctx context.Context, client *http.Client, url string, header http.Header) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	applyConfiguredHeader(req, header)
	setHostFromHeader(req)
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	// A healthy endpoint answers 2xx. Ignoring the status would let an error
	// page, a redirect body, or a WAF block that happens to contain the word
	// "Healthy" be read as a healthy backend — flipping which service the
	// probe reports and, with it, where the real credential is later sent.
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return false, nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxHealthBody))
	if err != nil {
		return false, err
	}
	return recognizedHealthyBody(body), nil
}

func recognizedHealthyBody(body []byte) bool {
	var parsed struct {
		Healthy *bool `json:"healthy"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		return parsed.Healthy != nil && *parsed.Healthy
	}
	return strings.EqualFold(strings.TrimSpace(string(body)), "Healthy")
}

// classifyProbeTransport preserves the engine's sentinel and underlying error
// chain. Errors from an opaque transport are suppressed in full because its
// arbitrary code may derive them from headers or response bodies; otherwise
// configured routing-header values are removed from the printable diagnostic.
func classifyProbeTransport(err error, header http.Header, opaque bool) error {
	if opaque {
		return opaqueTransportDiagnostic("probing backend", err)
	}
	classified := classifyTransport(err)
	values := make([]string, 0, len(header))
	for _, vv := range header {
		values = append(values, vv...)
	}
	redact := buildRedactor(values)
	return &safeTransportDiagnostic{
		message: redact(classified.Error()),
		err:     classified,
	}
}

// WithProbedTarget resolves TargetAuto by asking the server what it is, for
// the one-credential-pair shape CI integrations carry: an id/secret that is a
// Secret Server username/password on one tenant and a Platform
// client_id/client_secret on another. Give the pair in either field pair;
// the probe decides which grant it is, and the returned Config carries the
// pair in the fields that grant reads. An explicit Target returns the Config
// unchanged, so this is safe to call unconditionally; setting both pairs is
// ambiguous and refused, exactly as New would. The probe sends no Delinea
// credential, but does send configured same-origin gateway headers. One probe
// per constructed Config — cache the result, not the call.
func (c Config) WithProbedTarget(ctx context.Context) (Config, error) {
	if c.Target != TargetAuto {
		return c, nil
	}
	hasUserPair := c.Username != "" || c.Password != ""
	hasClientPair := c.ClientID != "" || c.ClientSecret != ""
	if hasUserPair && hasClientPair {
		return Config{}, fmt.Errorf("%w: both Username/Password and ClientID/ClientSecret are set; the probe cannot choose between two credential pairs", ErrConfig)
	}
	backend, err := ProbeBackend(ctx, c)
	if err != nil {
		return Config{}, err
	}
	switch backend {
	case BackendSecretServer:
		c.Target = TargetSecretServer
		if hasClientPair {
			c.Username, c.Password = c.ClientID, c.ClientSecret
			c.ClientID, c.ClientSecret = "", ""
		}
	case BackendPlatform:
		c.Target = TargetPlatform
		if hasUserPair {
			c.ClientID, c.ClientSecret = c.Username, c.Password
			c.Username, c.Password = "", ""
		}
	default:
		return Config{}, fmt.Errorf("%w: %s did not answer as Secret Server or the Delinea Platform; set Target explicitly", ErrConfig, c.URL)
	}
	return c, nil
}
