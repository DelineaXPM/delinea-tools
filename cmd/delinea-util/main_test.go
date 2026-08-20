package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DelineaXPM/delinea-tools/internal/cli"

	da "github.com/DelineaXPM/delinea-common/api"
)

// The top-level page lists the commands and only the flags that work at the top
// level (meta + the shared Global Flags), plus the required URL and credential
// sources. It must NOT list any command-specific flag.
func TestTopLevelHelp(t *testing.T) {
	h := topLevelHelp()
	for _, want := range []string{
		"Usage:\n  delinea-util METHOD PATH [flags]",
		"Available Commands:",
		"Additional help topics:",
		"\nFlags:\n",
		"\nGlobal Flags:\n",
		"(required) target base URL",
		"Delinea credentials (never a flag",
		"DELINEA_TOOLS_PASSWORD",
		"check may run in reachability-only mode without one",
		"check --no-auth additionally ignores any ambient Delinea credential",
		"Use \"delinea-util COMMAND --help\"",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("top-level help missing %q", want)
		}
	}
	// Command-specific flags belong on each command's own help, never here.
	for _, unwanted := range []string{"-d, --data", "--json", "--via", "--out FILE", "--allow-terminal", "--pass-env"} {
		if strings.Contains(h, unwanted) {
			t.Errorf("top-level help must not list command-specific flag %q", unwanted)
		}
	}
}

// Each command's help lists only its own flags, plus the shared Global Flags and
// Credentials, and states what it requires.
func TestPerCommandHelp(t *testing.T) {
	req := requestHelp()
	for _, want := range []string{"-d, --data", "-H, --header", "@FILE reads one per line", "--vault-id", "-i, --include", "Requires: DELINEA_TOOLS_URL", "Delinea credentials (never a flag"} {
		if !strings.Contains(req, want) {
			t.Errorf("request help missing %q", want)
		}
	}
	if strings.Contains(req, "--interactive") || strings.Contains(req, "--allow-terminal") {
		t.Error("request help must not list token-only flags")
	}
	tok := tokenHelp()
	for _, want := range []string{
		"--interactive", "--allow-terminal", "Requires: DELINEA_TOOLS_URL",
		"--interactive requires a username (--username or DELINEA_TOOLS_USERNAME)",
		"DELINEA_TOOLS_PASSWORD from the environment", "stdin carries MFA answers",
		"Delinea credentials (never a flag",
	} {
		if !strings.Contains(tok, want) {
			t.Errorf("token help missing %q", want)
		}
	}
	if strings.Contains(tok, "-d, --data") || strings.Contains(tok, "--vault-id") || strings.Contains(tok, "--vault-allow") {
		t.Error("token help must not list request flags")
	}
}

func TestReadmeContainsTree(t *testing.T) {
	if !strings.Contains(readmeText, commandTree()) {
		t.Error("README.txt does not contain the command tree verbatim")
	}
}

func TestCommandTreeShape(t *testing.T) {
	tree := commandTree()
	// check is a top-level verb, listed after token and before the secrets group;
	// there is no "secrets check".
	if !strings.Contains(tree, "├── check  —") {
		t.Errorf("tree missing a top-level check item:\n%s", tree)
	}
	if strings.Contains(tree, "secrets check") {
		t.Errorf("tree still lists a secrets check subcommand:\n%s", tree)
	}
	for _, want := range []string{"secrets run", "secrets print", "secrets template"} {
		if !strings.Contains(tree, want) {
			t.Errorf("tree missing %q:\n%s", want, tree)
		}
	}
}

// The unified README documents the whole tool: the raw verbs, the top-level
// check verb, and the secrets subtree. This guards against silently regressing
// to a raw-API-only document.
func TestReadmeIsUnified(t *testing.T) {
	for _, want := range []string{
		"delinea-util check", // the top-level check verb
		"SECRETS SUBCOMMANDS",
		"secrets run", "secrets print", "secrets template",
		"MAPPING", "--via", "CHILD ENVIRONMENT",
	} {
		if !strings.Contains(readmeText, want) {
			t.Errorf("unified README missing %q", want)
		}
	}
	if strings.Contains(readmeText, "delinea-secrets") || strings.Contains(readmeText, "DELINEA_SECRETS_") {
		t.Error("README references a retired standalone delinea-secrets binary / DELINEA_SECRETS_ var")
	}
}

// check is a top-level verb; `delinea-util secrets check` is no longer a thing.
func TestCheckIsTopLevel(t *testing.T) {
	if err := dispatch([]string{"check", "--help"}); err != nil {
		t.Errorf("delinea-util check --help: got %v, want nil (check must be a real top-level verb)", err)
	}
	err := dispatch([]string{"secrets", "check"})
	if _, ok := err.(*cli.UsageError); !ok {
		t.Errorf("delinea-util secrets check: got %T (%v), want an unknown-subcommand usage error", err, err)
	}
}

func TestLeadingFlagsRouteTopLevelCommands(t *testing.T) {
	for _, tc := range []struct {
		args      []string
		wantIndex int
		want      string
	}{
		{[]string{"--secret-stdin", "check", "--json"}, 1, "check"},
		{[]string{"--url", "https://vault.example.com", "check"}, 2, "check"},
		{[]string{"--url=https://vault.example.com", "secrets", "run"}, 1, "secrets"},
		{[]string{"--target", "check", "GET", "/x"}, 2, "GET"},
	} {
		index, got, err := topLevelCommand(tc.args)
		if err != nil || index != tc.wantIndex || got != tc.want {
			t.Errorf("topLevelCommand(%v) = %d, %q, %v; want %d, %q", tc.args, index, got, err, tc.wantIndex, tc.want)
		}
	}

	// A flag the router does not know has unknowable arity: guessing would
	// either swallow the command as the flag's value or promote the value to
	// the command, so it must be a clear error instead. The unknown long token
	// is not repeated because it has no safe name/value boundary.
	for _, args := range [][]string{
		{"--pass-env", "HTTPS_PROXY", "check"},
		{"--pass-env", "check", "DB=password#128"},
	} {
		_, _, err := topLevelCommand(args)
		if err == nil || !strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), "HTTPS_PROXY") {
			t.Errorf("topLevelCommand(%v) = %v, want a redacted unknown-leading-flag error", args, err)
		}
	}

	if err := dispatch([]string{"--url=https://vault.example.com", "check", "--help"}); err != nil {
		t.Errorf("leading flag before check: %v", err)
	}
	if err := dispatch([]string{"--secret-stdin", "secrets", "--help"}); err != nil {
		t.Errorf("leading flag before secrets: %v", err)
	}
	err := dispatch([]string{"--secret-stdin", "secrets", "run", "not-a-mapping", "--", "true"})
	if err == nil || !strings.Contains(err.Error(), "invalid mapping") {
		t.Errorf("leading flag was not delegated to secrets run: %v", err)
	}
}

func TestRootValueFlagArityStaysCoherent(t *testing.T) {
	check := func(t *testing.T, args []string) {
		t.Helper()
		index, command, err := topLevelCommand(args)
		if err != nil || index != len(args)-1 || command != "GET" {
			t.Fatalf("topLevelCommand(%v) = %d, %q, %v; want the final GET positional", args, index, command, err)
		}
		cc := cliConfig{}
		o, err := parseArgs(args, &cc)
		if err != nil {
			t.Fatalf("parseArgs(%v): %v", args, err)
		}
		if !reflect.DeepEqual(o.positionals, []string{"GET"}) {
			t.Fatalf("parseArgs(%v) positionals = %v, want [GET]", args, o.positionals)
		}
	}

	for flag, spec := range rootValueFlags {
		t.Run(flag+" separate", func(t *testing.T) {
			check(t, []string{flag, "check", "GET"})
		})
		if spec.inline {
			t.Run(flag+" inline", func(t *testing.T) {
				check(t, []string{flag + "=check", "GET"})
			})
		}
	}
}

func TestRootBoolFlagArityStaysCoherent(t *testing.T) {
	for flag := range rootBoolFlags {
		t.Run(flag, func(t *testing.T) {
			args := []string{flag, "GET"}
			index, command, err := topLevelCommand(args)
			if err != nil || index != 1 || command != "GET" {
				t.Fatalf("topLevelCommand(%v) = %d, %q, %v; want 1, GET", args, index, command, err)
			}
			cc := cliConfig{}
			o, err := parseArgs(args, &cc)
			if err != nil {
				t.Fatalf("parseArgs(%v): %v", args, err)
			}
			if !reflect.DeepEqual(o.positionals, []string{"GET"}) {
				t.Fatalf("parseArgs(%v) positionals = %v, want [GET]", args, o.positionals)
			}
		})
	}
}

// help is hierarchical: no-args and -h show the top-level page, and every
// command's help is reachable via "help COMMAND", "COMMAND -h", and (for the raw
// call) "METHOD -h". An unknown topic is a usage error, not a silent top page.
func TestHelpRouting(t *testing.T) {
	cases := []struct {
		args []string
		want string // substring the printed help must contain
	}{
		{nil, "Available Commands:"},
		{[]string{"-h"}, "Available Commands:"},
		{[]string{"help"}, "Available Commands:"},
		{[]string{"help", "token"}, "--interactive"},
		{[]string{"help", "request"}, "-d, --data"},
		{[]string{"help", "GET"}, "-d, --data"},
		{[]string{"help", "check"}, "delinea-util check [flags]"},
		{[]string{"help", "secrets"}, "Available Commands:"},
		{[]string{"token", "-h"}, "--interactive"},
		{[]string{"token", "--help"}, "--interactive"},
		{[]string{"GET", "-h"}, "-d, --data"},
		{[]string{"secrets", "print", "--out", "help", "--help", "DB=password#1"}, "delinea-util secrets print"},
		{[]string{"check", "--url", "help", "--help"}, "delinea-util check"},
	}
	for _, tc := range cases {
		out, code := runCapture(t, tc.args...)
		if code != 0 {
			t.Errorf("%v: exit %d, want 0", tc.args, code)
		}
		if !strings.Contains(out, tc.want) {
			t.Errorf("%v: help missing %q\n%s", tc.args, tc.want, out)
		}
	}
	if _, ok := errors.AsType[*cli.UsageError](dispatch([]string{"help", "frobnicate"})); !ok {
		t.Error("help frobnicate: want *cli.UsageError")
	}
}

func TestUsageForSecretsLeaf(t *testing.T) {
	for _, leaf := range []string{"run", "print", "template"} {
		name, usage := usageFor([]string{"--url", "https://vault.example.com", "secrets", leaf, "--unknown"})
		if name != "delinea-util secrets "+leaf {
			t.Errorf("%s: usage name = %q", leaf, name)
		}
		if !strings.Contains(usage, "Usage:\n  delinea-util secrets "+leaf) || strings.Contains(usage, "Available Commands:") {
			t.Errorf("%s: got group help instead of leaf help:\n%s", leaf, usage)
		}
	}
}

func TestParseArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    options
		wantErr bool
	}{
		{
			"method and path",
			[]string{"GET", "/api/v1/x"},
			options{positionals: []string{"GET", "/api/v1/x"}},
			false,
		},
		{
			"flags interleaved",
			[]string{"-i", "GET", "/x", "-v", "--vault"},
			options{include: true, verbose: true, useVault: true, positionals: []string{"GET", "/x"}},
			false,
		},
		{
			"allow terminal",
			[]string{"token", "--allow-terminal"},
			options{allowTerminal: true, positionals: []string{"token"}},
			false,
		},
		{
			"secret stdin",
			[]string{"token", "--secret-stdin"},
			options{secretStdin: true, positionals: []string{"token"}},
			false,
		},
		{
			"data separate",
			[]string{"POST", "/x", "-d", `{"a":1}`},
			options{data: `{"a":1}`, dataSet: true, positionals: []string{"POST", "/x"}},
			false,
		},
		{
			"data inline",
			[]string{"POST", "/x", `--data={"a":1}`},
			options{data: `{"a":1}`, dataSet: true, positionals: []string{"POST", "/x"}},
			false,
		},
		{
			"headers repeat",
			[]string{"GET", "/x", "-H", "A: 1", "--header", "B: 2", "--header=C: 3"},
			options{headers: []string{"A: 1", "B: 2", "C: 3"}, positionals: []string{"GET", "/x"}},
			false,
		},
		{
			"unknown flag",
			[]string{"GET", "/x", "--bogus"},
			options{},
			true,
		},
		{
			"missing value",
			[]string{"GET", "/x", "--url"},
			options{},
			true,
		},
	}
	for _, tc := range cases {
		cc := cliConfig{}
		got, err := parseArgs(tc.args, &cc)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: got err %v, wantErr %v", tc.name, err, tc.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if !reflect.DeepEqual(*got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", tc.name, *got, tc.want)
		}
	}
}

func TestParseArgsConfigFlags(t *testing.T) {
	cc := cliConfig{}
	_, err := parseArgs([]string{
		"--url", "https://x.example.com",
		"--target=platform",
		"--client-id", "cid",
		"--timeout", "5s",
		"--tls-skip-verify",
		"--vault-allow", "a.example.com,b.example.com",
		"--vault-allow=c.example.com",
		"--gateway-header-file", "first.headers",
		"--gateway-header-file=second.headers",
		"GET", "/x",
	}, &cc)
	if err != nil {
		t.Fatal(err)
	}
	// The secret flags (--password/--client-secret/--token) are intentionally
	// not parseable: the credential never comes from argv.
	want := cliConfig{
		URL: "https://x.example.com", Target: "platform",
		ClientID: "cid", Timeout: "5s",
		TLSSkipVerify:      true,
		VaultAllow:         []string{"a.example.com,b.example.com", "c.example.com"},
		GatewayHeaderFiles: []string{"first.headers", "second.headers"},
	}
	if !reflect.DeepEqual(cc, want) {
		t.Errorf("got %+v, want %+v", cc, want)
	}
}

func TestFlagsOverrideEnv(t *testing.T) {
	t.Setenv("DELINEA_TOOLS_URL", "https://env.example.com")
	t.Setenv("DELINEA_TOOLS_USERNAME", "env-user")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "env-pass")
	cc := configFromEnv()
	if _, err := parseArgs([]string{"--url", "https://flag.example.com", "GET", "/x"}, &cc); err != nil {
		t.Fatal(err)
	}
	if cc.URL != "https://flag.example.com" {
		t.Errorf("URL: got %q, want the flag value", cc.URL)
	}
	if cc.Username != "env-user" || cc.Password != "env-pass" {
		t.Errorf("credentials should still come from env: %+v", cc)
	}
}

func TestGatewayHeaderFileFlagsReplaceEnvironmentFile(t *testing.T) {
	t.Setenv("DELINEA_TOOLS_GATEWAY_HEADER_FILE", "ambient.headers")
	cc := configFromEnv()
	if _, err := parseArgs([]string{"--gateway-header-file", "first.headers", "--gateway-header-file=second.headers", "GET", "/x"}, &cc); err != nil {
		t.Fatal(err)
	}
	if got, want := cc.GatewayHeaderPaths(), []string{"first.headers", "second.headers"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want flag files to replace the environment file %v", got, want)
	}
}

func TestConfigFromEnvAll(t *testing.T) {
	env := map[string]string{
		"DELINEA_TOOLS_URL":                 "https://x.example.com",
		"DELINEA_TOOLS_TARGET":              "ss",
		"DELINEA_TOOLS_USERNAME":            "u",
		"DELINEA_TOOLS_PASSWORD":            "p",
		"DELINEA_TOOLS_DOMAIN":              "d",
		"DELINEA_TOOLS_CLIENT_ID":           "cid",
		"DELINEA_TOOLS_CLIENT_SECRET":       "cs",
		"DELINEA_TOOLS_TOKEN":               "tok",
		"DELINEA_TOOLS_CA_CERT":             "/tmp/ca.pem",
		"DELINEA_TOOLS_TIMEOUT":             "45s",
		"DELINEA_TOOLS_TLS_SKIP_VERIFY":     "yes",
		"DELINEA_TOOLS_VAULT_ALLOW":         "a.example.com",
		"DELINEA_TOOLS_GATEWAY_HEADER_FILE": "/tmp/gateway.headers",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	got := configFromEnv()
	want := cliConfig{
		URL: "https://x.example.com", Target: "ss",
		Username: "u", Password: "p", Domain: "d",
		ClientID: "cid", ClientSecret: "cs", Token: "tok",
		CACert: "/tmp/ca.pem", Timeout: "45s",
		TLSSkipVerify: true,
		VaultAllowEnv: "a.example.com", GatewayHeaderFileEnv: "/tmp/gateway.headers",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestBuildConfig(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte("PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	headerFile := filepath.Join(t.TempDir(), "gateway.headers")
	if err := os.WriteFile(headerFile, []byte("X-Gateway-Key: gateway-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cc := cliConfig{
		URL: "https://x.example.com", Target: "platform",
		ClientID: "cid", ClientSecret: "cs",
		CACert: caFile, Timeout: "45s",
		VaultAllow: []string{"a.example.com, b.example.com", "c.example.com"}, GatewayHeaderFiles: []string{headerFile},
	}
	cfg, err := buildConfig(cc)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target != da.TargetPlatform {
		t.Errorf("Target: got %q", cfg.Target)
	}
	if string(cfg.CACert) != "PEM" {
		t.Errorf("ca cert: got %q", cfg.CACert)
	}
	if cfg.Timeout != 45*time.Second {
		t.Errorf("Timeout: got %v", cfg.Timeout)
	}
	wantAllow := []string{"a.example.com", "b.example.com", "c.example.com"}
	if !reflect.DeepEqual(cfg.AllowedVaultHosts, wantAllow) {
		t.Errorf("vault allow: got %v, want %v", cfg.AllowedVaultHosts, wantAllow)
	}
	if got := cfg.Header.Get("X-Gateway-Key"); got != "gateway-secret" {
		t.Errorf("gateway header: got %q", got)
	}
}

func TestBuildConfigRetries(t *testing.T) {
	cfg, err := buildConfig(cliConfig{URL: "https://x.example.com", Retries: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Retries != 1 {
		t.Errorf("Retries: got %d, want 1", cfg.Retries)
	}
	cfg, err = buildConfig(cliConfig{URL: "https://x.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Retries != 0 {
		t.Errorf("unset Retries: got %d, want 0 (the engine owns the default of 3)", cfg.Retries)
	}
}

func TestBuildConfigVaultAllowFlagWins(t *testing.T) {
	cfg, err := buildConfig(cliConfig{URL: "https://x.example.com", VaultAllow: []string{"new.corp"}, VaultAllowEnv: "old.corp"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.AllowedVaultHosts, []string{"new.corp"}) {
		t.Errorf("got %v, want the flag to replace the env list entirely", cfg.AllowedVaultHosts)
	}
	cfg, err = buildConfig(cliConfig{URL: "https://x.example.com", VaultAllowEnv: "old.corp, other.corp"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.AllowedVaultHosts, []string{"old.corp", "other.corp"}) {
		t.Errorf("got %v, want the env list when no flag is given", cfg.AllowedVaultHosts)
	}
}

func TestFprintResponseSummary(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Add("X-Multi", "1")
	h.Add("X-Multi", "2")
	_, resp := newDiagnosticResponse(t, "configured-token-value", nil, nil)
	resp.Proto = "HTTP/1.1"
	resp.Status = "200 OK"
	resp.Header = h
	var b strings.Builder
	fprintResponseSummary(&b, resp)
	want := "< HTTP/1.1 200 OK\n< Content-Type: application/json\n< X-Multi: 1\n< X-Multi: 2\n"
	if b.String() != want {
		t.Errorf("summary:\ngot  %q\nwant %q", b.String(), want)
	}
}

func newDiagnosticResponse(t *testing.T, token string, configuredHeaders, requestHeaders http.Header) (*da.Client, *da.Response) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	client, err := da.New(da.Config{
		URL:          srv.URL,
		Target:       da.TargetPlatform,
		Token:        token,
		Header:       configuredHeaders,
		DisableCache: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(context.Background(), da.Request{Method: http.MethodGet, Path: "/", Header: requestHeaders})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return client, resp
}

type responseWriteFailure struct{}

func (responseWriteFailure) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestWriteResponseHead(t *testing.T) {
	h := http.Header{"X-Multi": {"1", "2"}}
	var b strings.Builder
	if err := writeResponseHead(&b, "HTTP/1.1", "200 OK", h); err != nil {
		t.Fatal(err)
	}
	want := "HTTP/1.1 200 OK\r\nX-Multi: 1\r\nX-Multi: 2\r\n\r\n"
	if b.String() != want {
		t.Errorf("response head:\ngot  %q\nwant %q", b.String(), want)
	}
	if err := writeResponseHead(responseWriteFailure{}, "HTTP/1.1", "204 No Content", nil); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("got %v, want the output write error", err)
	}
}

func TestBuildConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		cc   cliConfig
	}{
		{"no url", cliConfig{}},
		{"bad target", cliConfig{URL: "https://x.example.com", Target: "weird"}},
		{"bad timeout", cliConfig{URL: "https://x.example.com", Timeout: "banana"}},
		{"negative timeout", cliConfig{URL: "https://x.example.com", Timeout: "-30s"}},
		{"zero timeout", cliConfig{URL: "https://x.example.com", Timeout: "0s"}},
		{"missing ca file", cliConfig{URL: "https://x.example.com", CACert: "/nonexistent/ca.pem"}},
		{"retries zero", cliConfig{URL: "https://x.example.com", Retries: "0"}},
		{"retries negative", cliConfig{URL: "https://x.example.com", Retries: "-2"}},
		{"retries garbage", cliConfig{URL: "https://x.example.com", Retries: "many"}},
		{"domain-qualified username", cliConfig{URL: "https://x.example.com", Username: `CORP\svc-ci`}},
	}
	for _, tc := range cases {
		if _, err := buildConfig(tc.cc); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestDispatchUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown subcommand", []string{"frobnicate"}},
		{"method without path", []string{"GET"}},
		{"method with two paths", []string{"GET", "/a", "/b"}},
		{"token with extra arg", []string{"token", "x"}},
		{"token with body", []string{"token", "-d", "x"}},
		{"token interactive with extra arg", []string{"token", "--interactive", "x"}},
		{"token interactive with body", []string{"token", "--interactive", "-d", "x"}},
		{"token interactive with secret stdin", []string{"token", "--interactive", "--secret-stdin"}},
		{"token interactive with ss target", []string{"--target", "ss", "token", "--interactive"}},
		{"interactive on non-token", []string{"GET", "/x", "--interactive"}},
		{"removed login verb", []string{"login"}},
		{"secret stdin with stdin body", []string{"POST", "/x", "-d", "@-", "--secret-stdin"}},
		{"token with vault", []string{"token", "--vault"}},
		{"token interactive with vault id", []string{"token", "--interactive", "--vault-id", "2"}},
		{"token with header", []string{"token", "-H", "X-Test: value"}},
		{"token with include", []string{"--include", "token"}},
		{"token with verbose", []string{"token", "--verbose"}},
		{"token with vault allow", []string{"--vault-allow", "vault.example.com", "token"}},
		{"request with allow terminal", []string{"--allow-terminal", "GET", "/x"}},
		{"secret server request with vault", []string{"--target", "ss", "GET", "/x", "--vault"}},
		{"request with unused vault allow", []string{"GET", "/x", "--vault-allow", "vault.example.com"}},
		{"request with empty vault id", []string{"GET", "/x", "--vault", "--vault-id="}},
		{"removed vaults verb", []string{"vaults"}},
	}
	for _, tc := range cases {
		err := dispatch(tc.args)
		if _, ok := errors.AsType[*cli.UsageError](err); !ok {
			t.Errorf("%s: got %v, want *cli.UsageError", tc.name, err)
		}
	}
}

func TestNoOpFlagsHaveExplicitUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"token header after", []string{"token", "--header", "X-Test: value"}, "use --gateway-header-file"},
		{"token header before", []string{"-H", "X-Test: value", "token"}, "use --gateway-header-file"},
		{"token include after", []string{"token", "--include"}, "raw METHOD PATH requests"},
		{"token include before", []string{"-i", "token"}, "raw METHOD PATH requests"},
		{"token verbose after", []string{"token", "--verbose"}, "raw METHOD PATH requests"},
		{"token verbose before", []string{"-v", "token"}, "raw METHOD PATH requests"},
		{"request allow terminal after", []string{"GET", "/x", "--allow-terminal"}, "only valid with token"},
		{"request allow terminal before", []string{"--allow-terminal", "GET", "/x"}, "only valid with token"},
		{"secret server vault before credential stdin", []string{"--target", "ss", "--secret-stdin", "GET", "/x", "--vault"}, "only supported for the platform target"},
		{"token vault allow", []string{"token", "--vault-allow", "vault.example.com"}, "performs no vault request"},
		{"request vault allow", []string{"GET", "/x", "--vault-allow", "vault.example.com"}, "requires --vault"},
		{"empty vault id", []string{"GET", "/x", "--vault", "--vault-id="}, "non-empty ID"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := dispatch(tc.args)
			if _, ok := errors.AsType[*cli.UsageError](err); !ok {
				t.Fatalf("got %v, want *cli.UsageError", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestInteractiveSecretServerTargetErrorIsExplicit(t *testing.T) {
	err := dispatch([]string{"--target", "ss", "token", "--interactive"})
	if _, ok := errors.AsType[*cli.UsageError](err); !ok {
		t.Fatalf("got %v, want *cli.UsageError", err)
	}
	if !strings.Contains(err.Error(), "only supported for the platform target") {
		t.Errorf("got %q, want an explicit Platform-only diagnostic", err)
	}
}

func TestDispatchMethodIsCaseInsensitive(t *testing.T) {
	t.Setenv("DELINEA_TOOLS_URL", "")
	err := dispatch([]string{"get", "/a"})
	if _, ok := errors.AsType[*cli.UsageError](err); !ok {
		t.Errorf("got %v, want *cli.UsageError for the missing URL, not an unknown-subcommand error", err)
	}
	if err != nil && !strings.Contains(err.Error(), "required") {
		t.Errorf("expected the missing-URL error, got: %v", err)
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{&httpErr{status: "403 Forbidden"}, 4},
		{fmt.Errorf("x: %w", da.ErrAccessDenied), 2},
		{fmt.Errorf("x: %w", da.ErrAuth), 2},
		{fmt.Errorf("x: %w", da.ErrVault), 2},
		{fmt.Errorf("x: %w", da.ErrTimeout), 3},
		{fmt.Errorf("x: %w", da.ErrTransport), 3},
		{fmt.Errorf("x: %w", da.ErrConfig), 1},
		{errors.New("other"), 1},
	}
	for _, tc := range cases {
		if got := exitCode(tc.err); got != tc.want {
			t.Errorf("exitCode(%v): got %d, want %d", tc.err, got, tc.want)
		}
	}
}

func TestParseHeaders(t *testing.T) {
	h, err := parseHeaders([]string{"Content-Type: text/plain", "X-Two:  spaced  "})
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Get("Content-Type"); got != "text/plain" {
		t.Errorf("content type: got %q", got)
	}
	if got := h.Get("X-Two"); got != "spaced" {
		t.Errorf("x-two: got %q", got)
	}
	if _, err := parseHeaders([]string{"no colon"}); err == nil {
		t.Error("header without colon should error")
	}
	const secret = "do-not-repeat-this-secret"
	if _, err := parseHeaders([]string{"malformed " + secret}); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("malformed header error must not echo its value: %v", err)
	}
	if _, err := parseHeaders([]string{"Authorization: Bearer " + secret}); err == nil ||
		!strings.Contains(err.Error(), "Authorization") || strings.Contains(err.Error(), secret) {
		t.Errorf("Authorization header should be rejected without echoing its value: %v", err)
	}
	if h, err := parseHeaders(nil); h != nil || err != nil {
		t.Errorf("nil input: got %v/%v", h, err)
	}
}

func TestRequestHeadersFromFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "headers")
	if err := os.WriteFile(file, []byte("X-Gateway-Key: file-secret\r\n\nX-Route: west\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := requestHeaders([]string{"Content-Type: application/json", "@" + file, "X-Route: east"})
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Get("X-Gateway-Key"); got != "file-secret" {
		t.Errorf("gateway key: got %q", got)
	}
	if got, want := h.Values("X-Route"), []string{"west", "east"}; !reflect.DeepEqual(got, want) {
		t.Errorf("route values: got %v, want %v", got, want)
	}
	if got := h.Get("Content-Type"); got != "application/json" {
		t.Errorf("content type: got %q", got)
	}

	const secret = "do-not-repeat-file-secret"
	bad := filepath.Join(t.TempDir(), "bad-headers")
	if err := os.WriteFile(bad, []byte("malformed "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := requestHeaders([]string{"@" + bad}); err == nil ||
		!strings.Contains(err.Error(), "line 1") || strings.Contains(err.Error(), secret) {
		t.Errorf("malformed header file error must name the line without its value: %v", err)
	}

	if _, err := requestHeaders([]string{"@"}); err == nil || !strings.Contains(err.Error(), "empty @FILE") {
		t.Errorf("empty header-file path: got %v", err)
	}
	if h, err := requestHeaders(nil); h != nil || err != nil {
		t.Errorf("nil input: got %v/%v", h, err)
	}
}

func TestRequestBody(t *testing.T) {
	f := filepath.Join(t.TempDir(), "body.json")
	if err := os.WriteFile(f, []byte(`{"file":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		o    options
		want string
	}{
		{"none", options{}, ""},
		{"literal", options{data: "abc", dataSet: true}, "abc"},
		{"file", options{data: "@" + f, dataSet: true}, `{"file":true}`},
	}
	for _, tc := range cases {
		r, err := requestBody(&tc.o)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if tc.want == "" {
			if r != nil {
				t.Errorf("%s: expected nil reader", tc.name)
			}
			continue
		}
		b := new(strings.Builder)
		if _, err := io.Copy(b, r); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if b.String() != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, b.String(), tc.want)
		}
	}
	if _, err := requestBody(&options{data: "@/nonexistent/file", dataSet: true}); err == nil {
		t.Error("missing body file should error")
	}
}

func TestReadSecretStdin(t *testing.T) {
	got, err := readSecretStdin(strings.NewReader("s3cret\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cret" {
		t.Errorf("secret: got %q", got)
	}
	if _, err := readSecretStdin(strings.NewReader("")); err == nil {
		t.Error("empty stdin should error")
	}
	if _, err := readSecretStdin(strings.NewReader("\n")); err == nil {
		t.Error("newline-only stdin should error")
	}
}

func TestApplyStdinSecret(t *testing.T) {
	cases := []struct {
		name string
		cc   cliConfig
		want cliConfig
	}{
		{"username gets password", cliConfig{Username: "u"}, cliConfig{Username: "u", Password: "s"}},
		{"client id gets secret", cliConfig{ClientID: "c"}, cliConfig{ClientID: "c", ClientSecret: "s"}},
		{"neither gets token", cliConfig{}, cliConfig{Token: "s"}},
		{"target ss names the password slot", cliConfig{Target: "ss", Username: "u", ClientID: "c"}, cliConfig{Target: "ss", Username: "u", ClientID: "c", Password: "s"}},
		{"target platform names the client secret slot", cliConfig{Target: "platform", Username: "u", ClientID: "c"}, cliConfig{Target: "platform", Username: "u", ClientID: "c", ClientSecret: "s"}},
		{"stale token cleared when the secret is a password", cliConfig{Username: "u", Token: "stale"}, cliConfig{Username: "u", Password: "s"}},
		{"stale token cleared when the secret is a client secret", cliConfig{Target: "platform", ClientID: "c", Token: "stale"}, cliConfig{Target: "platform", ClientID: "c", ClientSecret: "s"}},
	}
	for _, tc := range cases {
		cc := tc.cc
		if err := applyStdinSecret(&cc, "s"); err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
			continue
		}
		if !reflect.DeepEqual(cc, tc.want) {
			t.Errorf("%s: got %+v, want %+v", tc.name, cc, tc.want)
		}
	}

	cc := cliConfig{Username: "u", ClientID: "c"}
	err := applyStdinSecret(&cc, "s")
	if err == nil {
		t.Fatal("both username and client-id without a target should error")
	}
	if !strings.Contains(err.Error(), "--target") {
		t.Errorf("error should point at --target, got %q", err)
	}
	if cc.Password != "" || cc.ClientSecret != "" || cc.Token != "" {
		t.Errorf("no credential slot should be filled on error, got %+v", cc)
	}
}

func TestStdioPrompterChooseMechanism(t *testing.T) {
	mechs := []da.Mechanism{
		{Name: "EMAIL", PromptSelectMech: "Email me"},
		{Name: "OTP"},
	}
	p := &stdioPrompter{in: bufio.NewReader(strings.NewReader("9\nx\n2\n"))}
	got, err := p.ChooseMechanism(mechs)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("choice: got %d, want 1", got)
	}
	p = &stdioPrompter{in: bufio.NewReader(strings.NewReader(""))}
	if _, err := p.ChooseMechanism(mechs); err == nil {
		t.Error("closed stdin should error, not loop")
	}
}

func TestStdioPrompterReadAnswer(t *testing.T) {
	p := &stdioPrompter{in: bufio.NewReader(strings.NewReader("  12345678  \n"))}
	got, err := p.ReadAnswer("code")
	if err != nil {
		t.Fatal(err)
	}
	if got != "12345678" {
		t.Errorf("answer: got %q", got)
	}
	p = &stdioPrompter{in: bufio.NewReader(strings.NewReader(""))}
	if _, err := p.ReadAnswer("code"); err == nil {
		t.Error("closed stdin should error, not poll forever")
	}
}

func TestCheckOutputSink(t *testing.T) {
	cases := []struct {
		isTTY, allow bool
		wantErr      bool
	}{
		{true, false, true},
		{true, true, false},
		{false, false, false},
		{false, true, false},
	}
	for _, tc := range cases {
		err := checkOutputSink(tc.isTTY, tc.allow)
		if (err != nil) != tc.wantErr {
			t.Errorf("isTTY=%v allow=%v: got err %v, wantErr %v", tc.isTTY, tc.allow, err, tc.wantErr)
		}
	}
}
