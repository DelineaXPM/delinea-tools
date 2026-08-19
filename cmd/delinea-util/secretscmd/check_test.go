package secretscmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DelineaXPM/delinea-common/api"
	ds "github.com/DelineaXPM/delinea-common/secrets"
	"github.com/DelineaXPM/delinea-tools/internal/cli"
)

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "check-test-ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// verifyFake serves one secret with a populated field and an empty one, so
// checkSecrets can be exercised over its three outcomes.
type verifyFake struct{}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("write failed") }

func (verifyFake) Secret(_ context.Context, id int) (*ds.Secret, error) {
	if id != 1 {
		return nil, fmt.Errorf("403 Forbidden: ")
	}
	return &ds.Secret{Fields: []ds.SecretField{
		{Slug: "password", FieldName: "password", ItemValue: "s3cr3t"},
		{Slug: "blank", FieldName: "blank", ItemValue: ""},
	}}, nil
}

func (verifyFake) SecretByPath(context.Context, string) (*ds.Secret, error) {
	return nil, fmt.Errorf("403 Forbidden: ")
}

func TestProbeConfig(t *testing.T) {
	clearDelineaEnv(t)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, testCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DELINEA_TOOLS_CA_CERT", ca)
	t.Setenv("DELINEA_TOOLS_TLS_SKIP_VERIFY", "1")
	t.Setenv("DELINEA_TOOLS_TIMEOUT", "45s")

	// probeConfig now takes the parsed flags-over-env cliConfig; build it from
	// the environment set above and supply the URL the way a flag or env would.
	cc := configFromEnv()
	cc.URL = "https://vault.example.com"
	cfg, err := probeConfig(cc)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://vault.example.com" {
		t.Errorf("URL: got %q", cfg.URL)
	}
	if !cfg.SkipTLSVerify {
		t.Errorf("SkipTLSVerify not carried")
	}
	if len(cfg.CACert) == 0 {
		t.Errorf("CACert not loaded")
	}
	if cfg.Timeout != 45*time.Second {
		t.Errorf("Timeout: got %v, want 45s", cfg.Timeout)
	}
	// A probe never carries a credential, whatever else is set.
	if cfg.Username != "" || cfg.Password != "" || cfg.Token != "" {
		t.Errorf("probeConfig carried a credential: %+v", cfg)
	}
}

func TestCheckConfigGatewayHeaderErrorsHideValues(t *testing.T) {
	clearDelineaEnv(t)
	const secret = "do-not-repeat-gateway-secret"
	for name, content := range map[string]string{
		"syntax": "malformed " + secret + "\n",
		"wire":   "Bad Name: " + secret + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gateway.headers")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cc := cliConfig{URL: "https://vault.example.com", GatewayHeaderFiles: []string{path}}
			f := findingFor(t, checkConfig(cc), "DELINEA_TOOLS_GATEWAY_HEADER_FILE")
			if f.status != statusFail || strings.Contains(f.detail, secret) {
				t.Errorf("got %+v, want a failure without the header value", f)
			}
			if _, err := probeConfig(cc); err == nil || strings.Contains(err.Error(), secret) {
				t.Errorf("probeConfig error = %v, want a refusal without the header value", err)
			}
		})
	}
}

func TestWidthFrom(t *testing.T) {
	const fallback = 100
	cases := []struct {
		isTTY   bool
		columns string
		want    int
	}{
		{false, "", fallback},
		{false, "200", fallback}, // not a terminal: COLUMNS ignored
		{true, "", fallback},     // COLUMNS unset
		{true, "not-a-number", fallback},
		{true, "20", fallback}, // too narrow
		{true, "80", 80},
		{true, "500", 110}, // capped
	}
	for _, c := range cases {
		if got := widthFrom(c.isTTY, c.columns); got != c.want {
			t.Errorf("widthFrom(%v, %q): got %d, want %d", c.isTTY, c.columns, got, c.want)
		}
	}
}

func TestWriteCheckOutputReturnsWriteErrors(t *testing.T) {
	sections := []section{{title: "configuration", findings: []finding{ok("URL", "configured")}}}
	tests := []struct {
		name          string
		asJSON, quiet bool
	}{
		{name: "text"},
		{name: "json", asJSON: true},
		{name: "quiet with findings", quiet: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := writeCheckOutput(failingWriter{}, sections, sections, tt.asJSON, tt.quiet); err == nil || !strings.Contains(err.Error(), "write failed") {
				t.Fatalf("got %v, want the output write error", err)
			}
		})
	}
	if err := writeCheckOutput(failingWriter{}, sections, nil, false, true); err != nil {
		t.Fatalf("quiet output with nothing to write returned %v", err)
	}
}

func TestCountCertsSkipsUnparseable(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var bundle bytes.Buffer
	pem.Encode(&bundle, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	pem.Encode(&bundle, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	loaded, skipped := countCerts(bundle.Bytes())
	if loaded != 1 || skipped != 1 {
		t.Errorf("got (%d loaded, %d skipped), want (1, 1): a PEM-framed block whose DER does not parse is not in the pool", loaded, skipped)
	}
}

func TestReadCredentialVetting(t *testing.T) {
	cred, present, err := cli.ReadCredential(strings.NewReader("pw\r\n"))
	if err != nil || cred != "pw" || !present {
		t.Errorf("got (%q, %v, %v), want (\"pw\", true, nil)", cred, present, err)
	}
	if _, _, err := cli.ReadCredential(strings.NewReader(strings.Repeat("a", cli.MaxCredentialBytes+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("over-length credential: got %v, want an exceeds error", err)
	}
	if _, _, err := cli.ReadCredential(strings.NewReader("\xEF\xBB\xBFa")); err == nil || !strings.Contains(err.Error(), "byte-order mark") {
		t.Errorf("BOM credential: got %v, want a byte-order mark error", err)
	}
	if _, present, err := cli.ReadCredential(strings.NewReader("")); err != nil || present {
		t.Errorf("empty stdin: got (present %v, %v), want (false, nil)", present, err)
	}
	oversizedBOM := "\xFF\xFE" + strings.Repeat("a\x00", cli.MaxCredentialBytes)
	if _, _, err := cli.ReadCredential(strings.NewReader(oversizedBOM)); err == nil || !strings.Contains(err.Error(), "byte-order mark") {
		t.Errorf("over-length re-encoded credential: got %v, want the re-encoding diagnosis, not a size complaint", err)
	}
}

func TestCheckSecretsReportsCollision(t *testing.T) {
	client := ds.NewWithFetcher(verifyFake{})
	got := checkSecrets(client, []ds.Mapping{
		{EnvName: "A", SecretID: 1, Field: "password"},
		{EnvName: "A", SecretID: 1, Field: "blank"},
	})
	for _, f := range got {
		if f.label == "A" && f.status == statusFail {
			if !strings.Contains(f.detail, "defined 2 times") {
				t.Errorf("collision detail = %q, want it to say defined 2 times", f.detail)
			}
			return
		}
	}
	t.Errorf("no FAIL finding for the collision on A, got %+v", got)
}

func TestCheckConfigReportsQualifiedUsername(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://vault.example.com")
	t.Setenv("DELINEA_TOOLS_USERNAME", `CORP\svc-ci`)
	if f := findingFor(t, checkConfig(configFromEnv()), "DELINEA_TOOLS_USERNAME"); f.status != statusFail {
		t.Errorf("got %v, want statusFail", f.status)
	}
}

func findingFor(t *testing.T, findings []finding, label string) finding {
	t.Helper()
	for _, f := range findings {
		if f.label == label {
			return f
		}
	}
	t.Fatalf("no finding labelled %q in %+v", label, findings)
	return finding{}
}

// credCC builds a cliConfig from a target, principal, and domain. The Platform
// principal is a client_id (DELINEA_TOOLS_CLIENT_ID); every other target's
// principal is a Secret Server username (DELINEA_TOOLS_USERNAME).
func credCC(target api.Target, principal, domain string) cliConfig {
	cc := cliConfig{Domain: domain}
	if target == api.TargetPlatform {
		cc.ClientID = principal
	} else {
		cc.Username = principal
	}
	return cc
}

// credFindings exercises structural credential resolution for the rendering
// tests. End-to-end tests cover cmdCheck's network authentication separately.
func credFindings(t *testing.T, cc cliConfig, stdinCred string) []finding {
	t.Helper()
	// A URL is orthogonal to the credential; supply one so ds.New validates the
	// credential (its own concern) rather than failing on a missing URL, which a
	// real check reports in the configuration section.
	if cc.URL == "" {
		cc.URL = "https://vault.example.com"
	}
	if stdinCred != "" {
		cc.SecretStdin = true
	}
	cfg, cfgErr := buildConfig(cc, strings.NewReader(stdinCred))
	var credValidErr error
	if cfgErr == nil {
		_, credValidErr = ds.New(cfg)
	}
	attempted := cc.Username != "" || cc.ClientID != "" || cc.Token != "" ||
		cc.Password != "" || cc.ClientSecret != "" || cc.SecretStdin || stdinCred != ""
	return credentialFindings(cc, cfg, cfgErr, credValidErr, nil, attempted, "")
}

func TestCountFailures(t *testing.T) {
	mixed := []section{{findings: []finding{fail("a", ""), ok("b", ""), warn("c", ""), fail("d", ""), skip("e", "")}}}
	if got := countFailures(mixed); got != 2 {
		t.Errorf("got %d failures, want 2", got)
	}
	if got := countFailures([]section{{findings: []finding{ok("a", ""), warn("b", ""), skip("c", "")}}}); got != 0 {
		t.Errorf("warnings and skips must not count as failures, got %d", got)
	}
}

func TestRenderSkipsEmptySections(t *testing.T) {
	out := render([]section{
		{title: "kept", findings: []finding{ok("label", "detail")}},
		{title: "dropped"},
	}, 100)
	if !strings.Contains(out, "kept") || !strings.Contains(out, "detail") {
		t.Errorf("render dropped content: %q", out)
	}
	if strings.Contains(out, "dropped") {
		t.Errorf("render kept an empty section: %q", out)
	}
}

func TestCheckConfigReportsEachSettingIndependently(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "http://vault.example.com")
	t.Setenv("DELINEA_TOOLS_TIMEOUT", "not-a-duration")
	t.Setenv("DELINEA_TOOLS_CA_CERT", filepath.Join(t.TempDir(), "absent.pem"))
	t.Setenv("DELINEA_TOOLS_TLS_SKIP_VERIFY", "1")

	got := checkConfig(configFromEnv())
	// A bad URL must not hide the later problems, which is the whole point of
	// check over configFromEnv.
	for _, label := range []string{"DELINEA_TOOLS_URL", "DELINEA_TOOLS_TIMEOUT", "DELINEA_TOOLS_CA_CERT"} {
		if f := findingFor(t, got, label); f.status != statusFail {
			t.Errorf("%s: got %v, want statusFail", label, f.status)
		}
	}
	if f := findingFor(t, got, "DELINEA_TOOLS_TLS_SKIP_VERIFY"); f.status != statusWarn {
		t.Errorf("skip-verify: got %v, want statusWarn", f.status)
	}
}

func TestCheckConfigCleanAndDefaults(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://vault.example.com")
	got := checkConfig(configFromEnv())
	if f := findingFor(t, got, "DELINEA_TOOLS_URL"); f.status != statusOK {
		t.Errorf("URL: got %v, want statusOK", f.status)
	}
	if f := findingFor(t, got, "DELINEA_TOOLS_TIMEOUT"); f.status != statusOK || !strings.Contains(f.detail, "default") {
		t.Errorf("Timeout: got %v %q, want ok and 'default'", f.status, f.detail)
	}
	if f := findingFor(t, got, "DELINEA_TOOLS_TARGET"); f.status != statusInfo || !strings.Contains(f.detail, "ss") {
		t.Errorf("Target: got %v %q, want info naming ss", f.status, f.detail)
	}
	if n := countFailures([]section{{findings: got}}); n != 0 {
		t.Errorf("clean config reported %d failures: %+v", n, got)
	}
}

func TestCheckConfigTarget(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://vault.example.com")
	t.Setenv("DELINEA_TOOLS_TARGET", "platform")
	// The target finding describes routing only; the credential kind (client_id/
	// client_secret vs a bearer token) is the credential section's job.
	if f := findingFor(t, checkConfig(configFromEnv()), "DELINEA_TOOLS_TARGET"); f.status != statusInfo || !strings.Contains(f.detail, "vault") {
		t.Errorf("platform: got %v %q, want info describing vault routing", f.status, f.detail)
	}
	t.Setenv("DELINEA_TOOLS_TARGET", "bogus")
	if f := findingFor(t, checkConfig(configFromEnv()), "DELINEA_TOOLS_TARGET"); f.status != statusFail {
		t.Errorf("bogus: got %v, want statusFail", f.status)
	}
}

func TestTargetMismatch(t *testing.T) {
	if got := targetMismatch(api.TargetPlatform, api.BackendSecretServer); !strings.Contains(got, "Secret Server answered") {
		t.Errorf("platform vs SS: got %q, want a mismatch naming Secret Server", got)
	}
	if got := targetMismatch(api.TargetSecretServer, api.BackendPlatform); !strings.Contains(got, "DELINEA_TOOLS_TARGET=platform") {
		t.Errorf("ss vs Platform: got %q, want the fix named", got)
	}
	if got := targetMismatch(api.TargetSecretServer, api.BackendSecretServer); got != "" {
		t.Errorf("ss vs SS: got %q, want no mismatch", got)
	}
	if got := targetMismatch(api.TargetPlatform, api.BackendPlatform); got != "" {
		t.Errorf("platform vs Platform: got %q, want no mismatch", got)
	}
	// The default (auto resolves to ss) against a Platform backend IS a
	// mismatch: run/print route every non-platform target to Secret Server
	// paths, so a later run would fail — check must pre-explain that, as the
	// README promises, rather than silently passing.
	if got := targetMismatch(api.TargetSecretServer, api.BackendPlatform); !strings.Contains(got, "DELINEA_TOOLS_TARGET=platform") {
		t.Errorf("default vs Platform: got %q, want the mismatch naming the fix", got)
	}
}

func TestCheckConfigMissingURL(t *testing.T) {
	clearDelineaEnv(t)
	if f := findingFor(t, checkConfig(configFromEnv()), "DELINEA_TOOLS_URL"); f.status != statusFail {
		t.Errorf("got %v, want statusFail", f.status)
	}
}

func TestCheckConfigValidCACert(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://vault.example.com")
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, testCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DELINEA_TOOLS_CA_CERT", path)
	if f := findingFor(t, checkConfig(configFromEnv()), "DELINEA_TOOLS_CA_CERT"); f.status != statusOK {
		t.Errorf("got %v (%s), want statusOK", f.status, f.detail)
	}
}

func TestCheckConfigGarbageCACert(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://vault.example.com")
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DELINEA_TOOLS_CA_CERT", path)
	f := findingFor(t, checkConfig(configFromEnv()), "DELINEA_TOOLS_CA_CERT")
	if f.status != statusFail || !strings.Contains(f.detail, "no certificates") {
		t.Errorf("got %v %q, want a PEM failure", f.status, f.detail)
	}
}

// With a client-id and no explicit target, check infers the Platform: the
// target is reported as inferred, a Platform backend is not a mismatch, and the
// credential is described as a client_secret under DELINEA_TOOLS_CLIENT_ID rather
// than a Secret Server username or a stdin bearer token.
func TestCheckInfersPlatformFromClientID(t *testing.T) {
	cc := cliConfig{ClientID: "svc-ci"} // no DELINEA_TOOLS_TARGET

	if got := effectiveTarget(cc); got != api.TargetPlatform {
		t.Errorf("effectiveTarget = %q, want platform inferred from the client-id", got)
	}
	if m := targetMismatch(effectiveTarget(cc), api.BackendPlatform); m != "" {
		t.Errorf("targetMismatch = %q, want none for an inferred platform vs a Platform backend", m)
	}

	tf := findingFor(t, checkConfig(cc), "DELINEA_TOOLS_TARGET")
	if tf.status != statusInfo || !strings.Contains(tf.detail, "platform is inferred") {
		t.Errorf("target finding: got %v %q, want info saying platform is inferred", tf.status, tf.detail)
	}

	got := credFindings(t, cc, "cs") // the client_secret makes the platform config valid
	cid := findingFor(t, got, "DELINEA_TOOLS_CLIENT_ID")
	if !strings.Contains(cid.detail, "client_secret") {
		t.Errorf("got %q, want the credential described as a client_secret", cid.detail)
	}
	for _, f := range got {
		if f.label == "DELINEA_TOOLS_USERNAME" {
			t.Errorf("inferred platform must not report a Secret Server Username: %+v", f)
		}
	}
}

// The target decides whether the credential is described as a Secret Server
// password, a Platform client_secret, or a bearer token — the distinction check
// exists to surface, now read from the resolved config run/print use.
func TestCredentialSectionExplainsInterpretation(t *testing.T) {
	ss := credFindings(t, cliConfig{Username: "svc-ci"}, "pw")
	if !strings.Contains(ss[0].detail, "Secret Server username") {
		t.Errorf("got %q, want a Secret Server reading", ss[0].detail)
	}
	plat := credFindings(t, cliConfig{Target: "platform", ClientID: "svc-ci"}, "cs")
	if !strings.Contains(plat[0].detail, "client_id") {
		t.Errorf("got %q, want a Platform client_id reading", plat[0].detail)
	}
	token := credFindings(t, cliConfig{}, "test-token")
	if !strings.Contains(token[0].detail, "bearer token") {
		t.Errorf("got %q, want a bearer-token reading", token[0].detail)
	}
}

// A Platform target with a user-shaped client_id is the documented trap: a
// Platform user's password is not valid for vault access.
func TestCredentialSectionWarnsOnPlatformUser(t *testing.T) {
	got := credFindings(t, cliConfig{Target: "platform", ClientID: "someone@tenant"}, "cs")
	found := false
	for _, f := range got {
		if f.status == statusWarn && strings.Contains(f.detail, "not a service-user") {
			found = true
		}
	}
	if !found {
		t.Errorf("got %+v, want a warning about a Platform user", got)
	}
}

// The domain is mandatory for an Active Directory user -- Secret Server answers
// "400 Login Failed" without it -- and must be absent for a local account, so
// check states the consequence whichever way it is set.
func TestCredentialSectionReportsDomain(t *testing.T) {
	withDomain := findingFor(t, credFindings(t, cliConfig{Username: "svc-ci", Domain: "CORP"}, "pw"), "DELINEA_TOOLS_DOMAIN")
	if !strings.Contains(withDomain.detail, "Active Directory") {
		t.Errorf("got %q, want it to name Active Directory", withDomain.detail)
	}
	without := findingFor(t, credFindings(t, cliConfig{Username: "svc-ci"}, "pw"), "DELINEA_TOOLS_DOMAIN")
	if !strings.Contains(without.detail, "local Secret Server account") {
		t.Errorf("got %q, want it to name a local account", without.detail)
	}
	if !strings.Contains(without.detail, "requires its domain") {
		t.Errorf("got %q, want it to say a domain user needs the domain", without.detail)
	}
}

// A domain is silently unused on the Platform and with a bearer token, so setting
// one there is worth flagging rather than passing over.
func TestCredentialSectionWarnsDomainIsIgnored(t *testing.T) {
	for _, c := range []struct {
		name   string
		cc     cliConfig
		secret string
	}{
		{"platform", cliConfig{Target: "platform", ClientID: "svc-ci", Domain: "CORP"}, "cs"},
		{"bearer token", cliConfig{Domain: "CORP"}, "test-token"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := findingFor(t, credFindings(t, c.cc, c.secret), "DELINEA_TOOLS_DOMAIN")
			if f.status != statusWarn || !strings.Contains(f.detail, "ignored") {
				t.Errorf("got %v %q, want a warning that it is ignored", f.status, f.detail)
			}
			if c.name == "bearer token" && strings.Contains(f.detail, "client credentials") {
				t.Errorf("a bearer token must not be told it uses client credentials: %q", f.detail)
			}
		})
	}
}

// Finding #3b: a bearer token with target=platform is a bearer token, so the
// domain finding must not tell it it uses client credentials — the token
// carries its own identity, and the credential section reports a bearer token.
func TestCredentialSectionBearerTokenPlatformDomain(t *testing.T) {
	got := credFindings(t, cliConfig{Target: "platform", Token: "test-token", Domain: "CORP"}, "")
	tok := findingFor(t, got, "DELINEA_TOOLS_TOKEN")
	if !strings.Contains(tok.detail, "bearer token") {
		t.Errorf("credential: got %q, want a bearer-token reading", tok.detail)
	}
	dom := findingFor(t, got, "DELINEA_TOOLS_DOMAIN")
	if strings.Contains(dom.detail, "client credentials") {
		t.Errorf("a bearer token must not be told it uses client credentials: %q", dom.detail)
	}
	if !strings.Contains(dom.detail, "bearer token") {
		t.Errorf("domain finding should name the bearer token, got %q", dom.detail)
	}
}

// A missing credential is what run/print reject, so check must fail it too
// (matching run/print) rather than pass. The domain is still reported.
// Nothing supplied at all is check's reachability-only mode: a skip, not a
// failure, and the domain is still reported. run/print require a credential,
// but verifying reachability without one is a deliberate check mode.
func TestCheckNoCredentialIsReachabilityMode(t *testing.T) {
	got := credFindings(t, cliConfig{URL: "https://vault.example.com"}, "")
	f := findingFor(t, got, "credential")
	if f.status != statusSkip {
		t.Errorf("no credential supplied: got %v, want a skip (reachability-only mode)", f.status)
	}
	if !strings.Contains(f.detail, "--secret-stdin") {
		t.Errorf("stdin remedy must name the required flag: %q", f.detail)
	}
	findingFor(t, got, "DELINEA_TOOLS_DOMAIN") // always reported (#3a)
}

// A half-configured identity (a username with no password) is not reachability
// mode: run/print reject it, so check must fail it too.
func TestCheckPartialIdentityFails(t *testing.T) {
	got := credFindings(t, cliConfig{URL: "https://vault.example.com", Username: "svc"}, "")
	f := findingFor(t, got, "credential")
	if f.status != statusFail {
		t.Errorf("username with no Password: got %v, want a FAIL matching run/print", f.status)
	}
}

func TestCheckChildEnvReportsPassedAndWithheld(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "unrelated")
	t.Setenv("JAVA_HOME", "/opt/java")

	got := checkChildEnv([]string{"JAVA_HOME"})
	passed := findingFor(t, got, "passed to child")
	for _, want := range []string{"PATH", "JAVA_HOME"} {
		if !strings.Contains(passed.detail, want) {
			t.Errorf("passed list %q missing %s", passed.detail, want)
		}
	}
	if strings.Contains(passed.detail, "AWS_SECRET_ACCESS_KEY") {
		t.Errorf("passed list names a withheld secret: %q", passed.detail)
	}
	if f := findingFor(t, got, "withheld"); !strings.Contains(f.detail, "withheld") {
		t.Errorf("withheld: got %q", f.detail)
	}
}

func TestCheckChildEnvWarnsOnUnpassedProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example:8080")
	if f := findingFor(t, checkChildEnv(nil), "HTTPS_PROXY"); f.status != statusWarn {
		t.Errorf("got %v, want statusWarn", f.status)
	}
	for _, f := range checkChildEnv([]string{"HTTPS_PROXY"}) {
		if f.label == "HTTPS_PROXY" {
			t.Errorf("passing the proxy should silence the warning, got %+v", f)
		}
	}
}

func TestCheckChildEnvReportsBadPassEnv(t *testing.T) {
	os.Unsetenv("NOT_SET_FOR_CHECK_XYZ")
	got := checkChildEnv([]string{"NOT_SET_FOR_CHECK_XYZ"})
	if len(got) != 1 || got[0].status != statusFail {
		t.Errorf("got %+v, want a single failure", got)
	}
}

func TestCheckSecretsReportsPerMapping(t *testing.T) {
	client := ds.NewWithFetcher(verifyFake{})
	got := checkSecrets(client, []ds.Mapping{
		{EnvName: "A", SecretID: 1, Field: "password"},
		{EnvName: "B", SecretID: 1, Field: "blank"},
		{EnvName: "C", SecretID: 1, Field: "absent"},
	})
	if f := findingFor(t, got, "A"); f.status != statusOK || !strings.Contains(f.detail, "6 bytes") {
		t.Errorf("A: got %v %q, want ok with a byte count", f.status, f.detail)
	}
	// An empty value is a warning, not a pass: it reaches the child as NAME=.
	if f := findingFor(t, got, "B"); f.status != statusWarn || !strings.Contains(f.detail, "empty value") {
		t.Errorf("B: got %v %q, want a warning about an empty value", f.status, f.detail)
	}
	if f := findingFor(t, got, "C"); f.status != statusFail {
		t.Errorf("C: got %v, want statusFail", f.status)
	}
	for _, f := range got {
		if strings.Contains(f.detail, "s3cr3t") {
			t.Errorf("check printed a secret value: %q", f.detail)
		}
	}
}

func TestPlural(t *testing.T) {
	for n, want := range map[int]string{0: "problems", 1: "problem", 2: "problems"} {
		if got := plural(n, "problem"); got != want {
			t.Errorf("plural(%d): got %q, want %q", n, got, want)
		}
	}
}

func TestStatusLabels(t *testing.T) {
	for s, want := range map[status]string{
		statusOK: "ok", statusWarn: "warn", statusFail: "FAIL", statusSkip: "skip",
	} {
		if got := s.label(); got != want {
			t.Errorf("label: got %q, want %q", got, want)
		}
	}
}

// A skipped check must say which condition caused it, not that something is
// vaguely "unusable" -- the reader has to know whether to set a variable or fix one.
func TestSkipReasonsAreSpecific(t *testing.T) {
	src, err := os.ReadFile("check.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "unusable") {
		t.Errorf("check.go describes a state as \"unusable\"")
	}
}

// The baseline withholds six proxy names, so all six must be reported.
func TestCheckChildEnvWarnsOnEveryProxyName(t *testing.T) {
	// Environment-variable names fold case on Windows, so a finding's label can
	// come back in a different case than the name was set with (https_proxy ->
	// HTTPS_PROXY). Match case-insensitively so the test asserts the real
	// behavior on both platforms rather than a Unix-only exact case.
	warned := func(findings []finding, name string) (finding, bool) {
		for _, f := range findings {
			if strings.EqualFold(f.label, name) {
				return f, true
			}
		}
		return finding{}, false
	}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "http://proxy.example:8080")
			if f, ok := warned(checkChildEnv(nil), name); !ok || f.status != statusWarn {
				t.Errorf("got %+v ok=%v, want a statusWarn finding", f, ok)
			}
			if _, ok := warned(checkChildEnv([]string{name}), name); ok {
				t.Errorf("passing it should silence the warning")
			}
		})
	}
}

// A count of one must not read "1 bytes" or "1 variables".
func TestCountsAgreeWithTheirNouns(t *testing.T) {
	got := checkSecrets(ds.NewWithFetcher(oneBytePasswordFake{}), []ds.Mapping{{EnvName: "A", SecretID: 1, Field: "password"}})
	if len(got) != 1 || !strings.Contains(got[0].detail, "1 byte)") {
		t.Errorf("got %+v, want a singular byte", got)
	}
	if strings.Contains(got[0].detail, "1 bytes") {
		t.Errorf("got %q, want singular", got[0].detail)
	}
}

type oneBytePasswordFake struct{}

func (oneBytePasswordFake) Secret(context.Context, int) (*ds.Secret, error) {
	return &ds.Secret{Fields: []ds.SecretField{{Slug: "password", FieldName: "password", ItemValue: "x"}}}, nil
}
func (oneBytePasswordFake) SecretByPath(context.Context, string) (*ds.Secret, error) {
	return nil, fmt.Errorf("unused")
}

// Anything sourced from the environment must be named, so a reader knows what to
// set. When no credential is supplied, the finding names every source it can
// come from, so a reader knows where to put one.
// check must fail the ambiguous both-username-and-client-id-no-target config
// that run/print reject, rather than passing it silently.
func TestCheckConfigFailsAmbiguousIdentity(t *testing.T) {
	cc := cliConfig{URL: "https://vault.example.com", Username: "u", ClientID: "c"}
	failed := false
	for _, f := range checkConfig(cc) {
		if f.label == "DELINEA_TOOLS_TARGET" && f.status == statusFail {
			failed = true
		}
	}
	if !failed {
		t.Error("checkConfig must fail DELINEA_TOOLS_TARGET when both a username and a client-id are set with no target (run/print reject it as ambiguous)")
	}
}

// A bearer token wins even with a stale client-id and target=platform: it is
// reported as a bearer token, never as client credentials / a client_secret.
func TestCredentialSectionTokenOnlyPlatform(t *testing.T) {
	var joined string
	for _, f := range credFindings(t, cliConfig{Token: "test-token", ClientID: "stale", Target: "platform"}, "") {
		joined += f.label + " " + f.detail + "\n"
	}
	if !strings.Contains(joined, "bearer token") {
		t.Errorf("token config should be described as a bearer token, got:\n%s", joined)
	}
	if strings.Contains(joined, "client_secret") || strings.Contains(joined, "client credentials") {
		t.Errorf("a token config must not claim client credentials are used, got:\n%s", joined)
	}
}

// A password with no username is what run/print reject (Secret Server needs
// both); check must fail it too, via the authoritative ds.New validation.
func TestCredentialSectionPasswordWithoutUsername(t *testing.T) {
	// target=ss routes the stdin secret into the password slot; with no username
	// resolveTarget rejects it, exactly as run/print do.
	got := credFindings(t, cliConfig{Target: "ss"}, "pw")
	f := findingFor(t, got, "credential")
	if f.status != statusFail || !strings.Contains(f.detail, "Username and Password") {
		t.Errorf("a password with no username must fail with the Username/Password requirement, got %v %q", f.status, f.detail)
	}
	// The domain line must not contradict that failure by claiming a bearer
	// token: a password was supplied, so it is a Secret Server credential.
	dom := findingFor(t, got, "DELINEA_TOOLS_DOMAIN")
	if strings.Contains(dom.detail, "bearer token") {
		t.Errorf("a password (not a token) must not get the bearer-token domain line: %q", dom.detail)
	}
	if !strings.Contains(dom.detail, "Secret Server") {
		t.Errorf("domain line should name Secret Server for a password credential: %q", dom.detail)
	}
}

// A bearer token with a stale client-id: the token wins and the client-id is
// reported as ignored, not used as a client_secret principal.
func TestCredentialSectionTokenBeatsStaleClientID(t *testing.T) {
	var joined string
	for _, f := range credFindings(t, cliConfig{Token: "test-token", ClientID: "stale"}, "") {
		joined += f.label + " " + f.detail + "\n"
	}
	if !strings.Contains(joined, "bearer token") || !strings.Contains(joined, "ignored") {
		t.Errorf("token with stale client-id should report a bearer token with the client-id ignored, got:\n%s", joined)
	}
}

// Each valid credential names its source variable, so a reader knows what to set.
func TestFindingsNameTheirSource(t *testing.T) {
	for _, c := range []struct {
		cc     cliConfig
		secret string
		want   string
	}{
		{cliConfig{Username: "svc"}, "pw", "DELINEA_TOOLS_USERNAME"},
		{cliConfig{Target: "platform", ClientID: "svc"}, "cs", "DELINEA_TOOLS_CLIENT_ID"},
		{cliConfig{}, "test-token", "DELINEA_TOOLS_TOKEN"},
	} {
		named := false
		for _, f := range credFindings(t, c.cc, c.secret) {
			if strings.Contains(f.label+" "+f.detail, c.want) {
				named = true
			}
		}
		if !named {
			t.Errorf("cc=%+v: no finding names %s", c.cc, c.want)
		}
	}
}

func TestWrapText(t *testing.T) {
	if got := wrapText("one two three four", 9); !reflect.DeepEqual(got, []string{"one two", "three", "four"}) {
		t.Errorf("got %q", got)
	}
	if got := wrapText("", 10); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("empty: got %q", got)
	}
	// A word longer than the width overflows rather than being broken: a split
	// URL or folder path cannot be copied out of the output.
	long := "\\\\ci\\\\database\\\\a-very-long-secret-name-that-exceeds-the-column"
	got := wrapText(long, 20)
	if len(got) != 1 || got[0] != long {
		t.Errorf("long word: got %q, want it intact on one line", got)
	}
}

// Every text line shares one indent, which is what makes wrapping trivial: there
// is no first line to treat differently and no column to hang under.
func TestRenderPutsTextOnItsOwnLines(t *testing.T) {
	detail := "this detail is deliberately much longer than the available width so that it must wrap onto several lines"
	out := render([]section{{title: "s", findings: []finding{ok("label", detail)}}}, 60)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	at := -1
	for i, l := range lines {
		if l == "  ok    label" {
			at = i
		}
	}
	if at < 0 {
		t.Fatalf("no label line in:\n%s", out)
	}
	text := 0
	for _, l := range lines[at+1:] {
		if l == "" {
			continue
		}
		text++
		if got := len(l) - len(strings.TrimLeft(l, " ")); got != detailIndent {
			t.Errorf("text indent: got %d, want %d in %q", got, detailIndent, l)
		}
		if len(l) > 60 {
			t.Errorf("line exceeds width: %d chars in %q", len(l), l)
		}
	}
	if text < 2 {
		t.Errorf("expected the detail to wrap, got %d text lines:\n%s", text, out)
	}
}

func TestOutputWidthFallsBackWhenNotATerminal(t *testing.T) {
	// go test redirects stdout, so this exercises the non-terminal path.
	if got := outputWidth(); got < 40 || got > 110 {
		t.Errorf("got %d, want a sane fallback width", got)
	}
}

// "ok" means a check ran and passed. Describing how a credential will be read
// verifies nothing, so those findings must not claim it -- with an unreachable
// vault and no attempt made, an "ok" invites the reader to conclude the
// credential works.
func TestInterpretationIsNotReportedAsPassing(t *testing.T) {
	for _, c := range []struct {
		target   api.Target
		username string
	}{
		{api.TargetSecretServer, "svc"}, {api.TargetPlatform, "svc"},
		{api.TargetSecretServer, ""}, {api.TargetPlatform, ""},
	} {
		for _, f := range credFindings(t, credCC(c.target, c.username, "CORP"), "s") {
			if f.status == statusOK {
				t.Errorf("target=%q username=%q: %q claims to have passed a check", c.target, c.username, f.detail)
			}
		}
	}
	if got := statusInfo.label(); got != "info" {
		t.Errorf("label: got %q, want info", got)
	}
	if n := countFailures([]section{{findings: []finding{info("a", "")}}}); n != 0 {
		t.Errorf("info must not count as a failure, got %d", n)
	}
}

// Findings in the credential section are labelled by where the value comes from,
// so the column has a single axis a reader can scan.
func TestCredentialFindingsAreLabelledBySource(t *testing.T) {
	allowed := map[string]bool{"DELINEA_TOOLS_USERNAME": true, "DELINEA_TOOLS_DOMAIN": true}
	for _, f := range credFindings(t, cliConfig{Username: "svc@tenant", Domain: "CORP"}, "pw") {
		if !allowed[f.label] {
			t.Errorf("label %q is not a source; want one of DELINEA_TOOLS_USERNAME, DELINEA_TOOLS_DOMAIN", f.label)
		}
	}
}

// The domain must be reported in every combination. Omitting it when unset hides
// a variable the reader may need to set.
func TestDomainIsAlwaysReported(t *testing.T) {
	for _, target := range []api.Target{api.TargetSecretServer, api.TargetPlatform} {
		for _, username := range []string{"svc", ""} {
			for _, domain := range []string{"CORP", ""} {
				got := credFindings(t, credCC(target, username, domain), "s")
				f := findingFor(t, got, "DELINEA_TOOLS_DOMAIN")
				if f.detail == "" {
					t.Errorf("target=%q username=%q domain=%q: empty detail", target, username, domain)
				}
				// Unset domain is reported as not set (ss) or not used (token/platform).
				if domain == "" && !strings.Contains(f.detail, "not set") && !strings.Contains(f.detail, "not used") {
					t.Errorf("target=%q username=%q: %q does not say the domain is unused", target, username, f.detail)
				}
			}
		}
	}
}

// The list of recognised settings must not drift from the ones actually read, or
// a new variable starts being reported as unrecognised.
func TestKnownEnvCoversEveryVariableRead(t *testing.T) {
	re := regexp.MustCompile(`os\.(?:Getenv|LookupEnv)\("(DELINEA_TOOLS_[A-Z_]+)"\)`)
	// The connection-setting reads live in the shared internal/cli config,
	// which this group consumes; scan both so a variable added there cannot
	// escape checkUnknownEnv's knowledge.
	dirs := []string{".", "../../../internal/cli"}
	seen := map[string]string{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			src, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range re.FindAllStringSubmatch(string(src), -1) {
				seen[m[1]] = e.Name()
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no DELINEA_TOOLS_ reads; the scan is broken")
	}
	for name, file := range seen {
		if !slices.Contains(knownEnv, name) {
			t.Errorf("%s reads %s, which is missing from knownEnv", file, name)
		}
	}
	for _, name := range knownEnv {
		if _, ok := seen[name]; !ok {
			t.Errorf("knownEnv lists %s, which nothing reads", name)
		}
	}
}

func TestCheckUnknownEnv(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://vault.example.com")
	t.Setenv("DELINEA_TOOLS_TIMEOUTS", "hunter2")
	t.Setenv("DELINEA_TOOLS_FROBNICATOR", "x")

	got := checkUnknownEnv()
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	// Never print a value: an unrecognised variable may hold the password its
	// author believed was in use.
	for _, f := range got {
		if strings.Contains(f.label+" "+f.detail, "hunter2") {
			t.Errorf("finding exposes a value: %+v", f)
		}
		if f.status != statusWarn {
			t.Errorf("%s: got %v, want statusWarn", f.label, f.status)
		}
	}
	if f := findingFor(t, got, "DELINEA_TOOLS_TIMEOUTS"); !strings.Contains(f.detail, "did you mean DELINEA_TOOLS_TIMEOUT?") {
		t.Errorf("got %q, want the near-miss suggested", f.detail)
	}
	if f := findingFor(t, got, "DELINEA_TOOLS_FROBNICATOR"); strings.Contains(f.detail, "did you mean") {
		t.Errorf("got %q, want no guess for a name nothing resembles", f.detail)
	}
}

func TestCheckUnknownEnvIsSilentWhenClean(t *testing.T) {
	clearDelineaEnv(t)
	for _, name := range knownEnv {
		t.Setenv(name, "x")
	}
	if got := checkUnknownEnv(); len(got) != 0 {
		t.Errorf("recognised settings must not be reported: %+v", got)
	}
}

func TestEditDistance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"", "", 0}, {"abc", "abc", 0}, {"abc", "abd", 1}, {"abc", "", 3}, {"TIMEOUTS", "TIMEOUT", 1}} {
		if got := editDistance(c.a, c.b); got != c.want {
			t.Errorf("editDistance(%q,%q): got %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestKeepProblems(t *testing.T) {
	in := []section{
		{title: "a", findings: []finding{ok("o", ""), info("i", ""), skip("s", ""), warn("w", ""), fail("f", "")}},
		{title: "b", findings: []finding{ok("o", ""), info("i", "")}},
	}
	got := keepProblems(in)
	if len(got[0].findings) != 2 {
		t.Errorf("section a: got %+v, want only the warn and the fail", got[0].findings)
	}
	if len(got[1].findings) != 0 {
		t.Errorf("section b: got %+v, want nothing kept", got[1].findings)
	}
	// A healthy run must render to nothing at all, so it can gate a pipeline
	// without filling its log.
	clean := keepProblems([]section{{title: "a", findings: []finding{ok("o", ""), info("i", ""), skip("s", "")}}})
	if out := render(clean, 100); strings.TrimSpace(out) != "" {
		t.Errorf("got %q, want empty output", out)
	}
}

func TestRenderJSON(t *testing.T) {
	sections := []section{
		{title: "configuration", findings: []finding{fail("DELINEA_TOOLS_URL", "not set; required"), ok("X", "")}},
		{title: "empty"},
	}
	out, err := renderJSON(sections, sections)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Summary  map[string]int `json:"summary"`
		Sections []struct {
			Title    string `json:"title"`
			Findings []struct{ Status, Label, Detail string }
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(doc.Sections) != 1 {
		t.Errorf("empty sections must be dropped, got %+v", doc.Sections)
	}
	if doc.Summary["FAIL"] != 1 || doc.Summary["ok"] != 1 {
		t.Errorf("summary: got %+v", doc.Summary)
	}
	// Every status must be present so a consumer can rely on the key existing.
	for _, k := range []string{"ok", "info", "warn", "FAIL", "skip"} {
		if _, ok := doc.Summary[k]; !ok {
			t.Errorf("summary is missing %q", k)
		}
	}
	f := doc.Sections[0].Findings[0]
	if f.Status != "FAIL" || f.Label != "DELINEA_TOOLS_URL" || f.Detail != "not set; required" {
		t.Errorf("finding: got %+v", f)
	}
	// Nothing is wrapped, so a consumer never has to rejoin lines.
	if strings.Contains(f.Detail, "\n") {
		t.Errorf("detail contains a newline: %q", f.Detail)
	}
}
