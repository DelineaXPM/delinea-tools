package secretscmd

import (
	"regexp"
	"strings"
	"testing"

	"github.com/DelineaXPM/delinea-common/api"
	ds "github.com/DelineaXPM/delinea-common/secrets"
)

// everyFinding gathers findings from every producer in check, with adversarial
// values: an unbreakable token longer than the column, an error carrying embedded
// newlines and JSON as a server returns, and a pathologically long label.
func everyFinding(t *testing.T) []section {
	t.Helper()
	longURL := "https://a-very-long-tenant-name-that-will-not-fit.secretservercloud.example.com/SecretServer"
	fetchErr := "fetching secret id 999: access denied: secret missing or not permitted: 403 Forbidden: {\n  \"errorCode\": \"API_AccessDenied\",\n  \"message\": \"Access denied\"\n}"

	// Exercise the credential section across its branches — valid ss/platform/
	// token, a domain-ignored warning, a client-id-looks-like-a-user warning, and
	// the missing/invalid failures — all through the same resolution cmdCheck
	// uses, so the layout corpus stays in step with the real output.
	// Reuse the one credential-resolution harness (credFindings) so this
	// layout corpus and the credential-branch tests cannot drift.
	resolve := func(cc cliConfig, secret string) []finding { return credFindings(t, cc, secret) }
	var out []section
	for _, c := range []struct {
		cc     cliConfig
		secret string
	}{
		{cliConfig{Username: "svc", Domain: "CORP"}, "pw"},
		{cliConfig{Username: "svc"}, "pw"},
		{cliConfig{Target: "platform", ClientID: "someone@tenant", Domain: "CORP"}, "cs"},
		{cliConfig{}, "tok"},
		{cliConfig{Domain: "CORP"}, "tok"},
		{cliConfig{URL: "https://vault.example.com"}, ""},
		{cliConfig{Target: "platform", ClientID: "c"}, ""},
	} {
		out = append(out, section{title: "credential", findings: resolve(c.cc, c.secret)})
	}
	out = append(out, section{title: "misc", findings: []finding{
		fail("DELINEA_TOOLS_URL", "not set; required"),
		ok("DELINEA_TOOLS_URL", longURL),
		fail("DELINEA_TOOLS_URL", "DELINEA_TOOLS_URL must use https (got scheme \"http\"); the bootstrap credential is sent on the first request and http would expose it"),
		fail("DELINEA_TOOLS_TIMEOUT", "\"nope\" is not a duration: time: invalid duration \"nope\""),
		ok("DELINEA_TOOLS_CA_CERT", "/etc/ssl/certs/a/very/long/path/to/a/corporate/root/bundle.pem: 3 certificates, added to the system trust store"),
		warn("DELINEA_TOOLS_TLS_SKIP_VERIFY", "set: the vault's TLS certificate is not verified, so the connection can be intercepted"),
		warn("DELINEA_TOOLS_PASWORD", "not read by delinea-util secrets; did you mean DELINEA_TOOLS_PASSWORD?"),
		warn("DELINEA_TOOLS_TIMEOUTS", "not read by delinea-util secrets; did you mean DELINEA_TOOLS_TIMEOUT?"),
		fail("DELINEA_TOOLS_TARGET", targetMismatch(api.TargetSecretServer, api.BackendPlatform)),
		skip("reachability", "not probed: DELINEA_TOOLS_URL is not set"),
		skip("reachability", "not probed: DELINEA_TOOLS_URL was rejected, see configuration above"),
		ok("backend", "Secret Server answered the health probe (no Delinea credential sent)"),
		fail("reachability", "Get \""+longURL+"/api/v1/healthcheck\": dial tcp: lookup host: no such host"),
		fail("backend", "reachable, but neither the Secret Server nor the Platform health endpoint reported healthy; check the URL path"),
		fail("stdin", "credential on stdin begins with a UTF-16LE byte-order mark, so it was re-encoded in transit; PowerShell encodes a pipeline to a native command using the console output encoding. Run [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) first, use PowerShell 7, or pipe from a byte-clean source"),
		skip("secrets", "none given; pass mappings to check that each resolves"),
		fail("secrets", fetchErr),
		fail("A_VERY_LONG_ENVIRONMENT_VARIABLE_NAME_CHOSEN_BY_A_USER", fetchErr),
		fail("--pass-env", "--pass-env: not set in the environment: NOPE_ONE, NOPE_TWO (a shell variable must be exported before it is one)"),
		ok("empty detail", ""),
	}})
	out = append(out, section{title: "child environment (run)", findings: checkChildEnv(nil)})
	out = append(out, section{title: "secrets", findings: checkSecrets(ds.NewWithFetcher(verifyFake{}), []ds.Mapping{
		{EnvName: "A", SecretID: 1, Field: "password"},
		{EnvName: "B", SecretID: 1, Field: "blank"},
		{EnvName: "C", SecretID: 9, Field: "password"},
		{Prefix: "ALL_", SecretID: 1, Expand: true},
		{EnvName: "D", ByPath: true, Path: `\a\deeply\nested\folder\path\that\keeps\going\and\going\Secret Name`, Field: "password"},
	})})
	return out
}

// TestCheckOutputLayout renders every message check can produce, at several
// widths. The layout is two levels and nothing is aligned to anything else, so
// the invariants are simple: a line is either a section title, a label line, or a
// text line at exactly detailIndent.
func TestCheckOutputLayout(t *testing.T) {
	labelLine := regexp.MustCompile(`^ {2}(ok|info|warn|FAIL|skip) {2,}\S`)
	for _, width := range []int{60, 80, 100, 110} {
		out := render(everyFinding(t), width)
		t.Logf("\n=== width %d ===\n%s", width, out)

		text := 0
		for line := range strings.SplitSeq(strings.TrimRight(out, "\n"), "\n") {
			if line != strings.TrimRight(line, " ") {
				t.Errorf("width %d: trailing whitespace: %q", width, line)
			}
			if strings.Contains(line, "\t") {
				t.Errorf("width %d: tab in output: %q", width, line)
			}
			switch {
			case line == "" || !strings.HasPrefix(line, " "):
			case labelLine.MatchString(line):
			default:
				text++
				if got := len(line) - len(strings.TrimLeft(line, " ")); got != detailIndent {
					t.Errorf("width %d: text line at column %d, want %d: %q", width, got, detailIndent, line)
				}
				if len(line) > width && strings.Contains(strings.TrimSpace(line), " ") && detailIndent+minDetailWidth <= width {
					t.Errorf("width %d: line could have wrapped but did not: %q", width, line)
				}
			}
		}
		if text == 0 {
			t.Fatalf("width %d: no text lines, so the corpus is not exercising the layout", width)
		}
	}
}

// A caller-named variable can be any length. Nothing is aligned to it, so it
// cannot affect another finding, and it is never truncated.
func TestLongLabelAffectsOnlyItsOwnFinding(t *testing.T) {
	long := strings.Repeat("X", 80)
	withLong := render([]section{{title: "s", findings: []finding{
		ok("SHORT", "a detail"),
		fail(long, "another detail"),
	}}}, 80)
	if !strings.Contains(withLong, "  ok    SHORT\n        a detail\n") {
		t.Errorf("the long label changed how SHORT renders:\n%s", withLong)
	}
	if !strings.Contains(withLong, "  FAIL  "+long+"\n") {
		t.Errorf("the label should appear intact on its own line:\n%s", withLong)
	}
}

// A detail must not repeat the label it is rendered after.
func TestNoFindingRepeatsItsLabel(t *testing.T) {
	for _, s := range everyFinding(t) {
		for _, f := range s.findings {
			if f.label == "" || f.detail == "" {
				continue
			}
			if strings.HasPrefix(f.detail, f.label) {
				t.Errorf("%q: detail repeats the label: %q", f.label, f.detail)
			}
		}
	}
	// The trimming must not swallow a detail that is only the label.
	if got := newFinding(statusOK, "X", "X"); got.detail != "X" {
		t.Errorf("got %q, want the detail preserved", got.detail)
	}
	if got := newFinding(statusOK, "PATH", "PATH_EXTRA is unset"); got.detail != "PATH_EXTRA is unset" {
		t.Errorf("got %q, want an unrelated detail untouched", got.detail)
	}
}

// Informational output is framed by a blank line at each end, as help and
// --readme are. JSON is machine output and gets no such decoration.
func TestTextOutputIsFramedByBlankLines(t *testing.T) {
	out := render(everyFinding(t), 100)
	if !strings.HasPrefix(out, "\n") {
		t.Errorf("output should open with a blank line, starts %q", out[:min(20, len(out))])
	}
	// render ends with a newline and cmdCheck prints it with Fprintln, which
	// supplies the closing blank line.
	if !strings.HasSuffix(out, "\n") || strings.HasSuffix(out, "\n\n") {
		t.Errorf("output should end with exactly one newline, ends %q", out[max(0, len(out)-20):])
	}
	sections := everyFinding(t)
	doc, err := renderJSON(sections, sections)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(doc, "\n") || strings.HasSuffix(doc, "\n") {
		t.Errorf("JSON must not be padded with blank lines")
	}
}
