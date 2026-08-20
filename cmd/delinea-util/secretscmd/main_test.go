package secretscmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	ds "github.com/DelineaXPM/delinea-common/secrets"
	"github.com/DelineaXPM/delinea-tools/internal/cli"
)

// unifiedREADME loads the single authoritative README that package main embeds
// and passes in, so secretscmd tests scrape the same text the binary renders.
func unifiedREADME(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../README.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The secrets-group page is the Cobra-style command listing: its subcommands,
// the required URL, and the credential sources. check is the top-level verb, so
// it is not listed here.
func TestUsageText(t *testing.T) {
	u := UsageText(unifiedREADME(t))
	for _, want := range []string{
		"Usage:\n  delinea-util secrets COMMAND",
		"Available Commands:",
		"\n  print ", "\n  run ", "\n  template ",
		"\nGlobal Flags:\n",
		"(required) target base URL",
		"Delinea credentials (never a flag",
		`Use "delinea-util secrets COMMAND --help"`,
	} {
		if !strings.Contains(u, want) {
			t.Errorf("secrets group help missing %q", want)
		}
	}
	if strings.Contains(u, "secrets check") {
		t.Errorf("secrets group help still lists check, which is now the top-level verb")
	}
}

// The mapping forms shown in a subcommand's help come from the README and must
// all parse.
func TestMappingFormsParse(t *testing.T) {
	rm := unifiedREADME(t)
	block := readmeMappingBlock(rm)
	if block == "" || !strings.Contains(subHelpText("run", rm), block) {
		t.Error("secrets run help does not contain the README mapping block")
	}
	for _, stale := range []string{"NAME=id", "id/field", "@path/field"} {
		if strings.Contains(block, stale) {
			t.Errorf("mapping block still describes the old syntax: %q", stale)
		}
	}
	for l := range strings.SplitSeq(block, "\n") {
		form := strings.Fields(l)[0]
		example := strings.NewReplacer("field", "password", "id", "1", "path", `\f\s`, "PREFIX_", "P_").Replace(form)
		if _, err := ds.ParseMapping(example); err != nil {
			t.Errorf("help shows form %q, but its instance %q does not parse: %v", form, example, err)
		}
	}
}

func TestWriteSecretFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s")
	if err := writeSecretFile(p, []byte("val")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "val" {
		t.Errorf("content: got %q, want val", b)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode: got %o, want 600", fi.Mode().Perm())
		}
	}
}

func TestWriteSecretFileReplacesExistingPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFile(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new" {
		t.Errorf("content: got %q, want new", b)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode: got %o, want 600", fi.Mode().Perm())
		}
	}
}

func TestRemoveFailedTempReportsCleanupFailure(t *testing.T) {
	cause := errors.New("install failed")
	missing := filepath.Join(t.TempDir(), "residual-secret")
	err := removeFailedTemp(missing, cause)
	if err != cause {
		t.Fatalf("removeFailedTemp() = %v, want only the original error when the temporary file is already gone", err)
	}

	residual := filepath.Join(t.TempDir(), "residual-secret")
	if err := os.Mkdir(residual, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(residual, "secret"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = removeFailedTemp(residual, cause)
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), residual) || !strings.Contains(err.Error(), "removing temporary secret file") {
		t.Fatalf("removeFailedTemp() = %v, want the original and cleanup errors with the residual path", err)
	}

	existing := filepath.Join(t.TempDir(), "temporary-secret")
	if err := os.WriteFile(existing, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = removeFailedTemp(existing, cause)
	if !errors.Is(err, cause) {
		t.Fatalf("removeFailedTemp() = %v, want the original error", err)
	}
	if _, err := os.Stat(existing); !os.IsNotExist(err) {
		t.Fatalf("temporary file still exists after successful cleanup: %v", err)
	}
}

func TestWriteSecretFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeSecretFile(link, []byte("val")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("got %v, want a symlink refusal", err)
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 0 {
		t.Errorf("target written through symlink: %q", b)
	}
}

func TestAppendSecretFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := appendSecretFile(link, []byte("secret")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("got %v, want a symlink refusal", err)
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old" {
		t.Errorf("target written through symlink: %q", b)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("stdin boom") }

func stdinConfigFromEnv() cliConfig {
	cc := configFromEnv()
	cc.SecretStdin = true
	return cc
}

func TestConfigFromEnvIgnoresStdinWithoutFlag(t *testing.T) {
	clearDelineaEnv(t)
	cfg, err := buildConfig(configFromEnv(), errReader{})
	if err != nil {
		t.Errorf("stdin must not be read without --secret-stdin: %v", err)
	}
	if cfg.Token != "" || cfg.Password != "" {
		t.Errorf("stdin unexpectedly populated a credential: %+v", cfg)
	}
}

func TestConfigFromEnvStdinError(t *testing.T) {
	clearDelineaEnv(t)
	if _, err := buildConfig(stdinConfigFromEnv(), errReader{}); err == nil {
		t.Errorf("explicit stdin read error: want error")
	}
}

func TestConfigFromEnvCredentialTooLarge(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_USERNAME", "u")
	if _, err := buildConfig(stdinConfigFromEnv(), strings.NewReader(strings.Repeat("a", cli.MaxCredentialBytes+1))); err == nil {
		t.Errorf("over-length credential: want error")
	}
}

func TestConfigFromEnvCredentialAtLimit(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_USERNAME", "u")
	cfg, err := buildConfig(stdinConfigFromEnv(), strings.NewReader(strings.Repeat("a", cli.MaxCredentialBytes)))
	if err != nil {
		t.Fatalf("credential at limit: got %v, want nil", err)
	}
	if len(cfg.Password) != cli.MaxCredentialBytes {
		t.Errorf("password length: got %d, want %d", len(cfg.Password), cli.MaxCredentialBytes)
	}
}

func TestConfigFromEnvRejectsQualifiedUsername(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://vault.example.com")
	t.Setenv("DELINEA_TOOLS_USERNAME", `CORP\svc-ci`)
	if _, err := buildConfig(configFromEnv(), strings.NewReader("pw")); err == nil {
		t.Errorf("got nil error, want a rejection")
	}
}

func TestConfigFromEnvTarget(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://vault.example.com")
	t.Setenv("DELINEA_TOOLS_USERNAME", "cid")
	t.Setenv("DELINEA_TOOLS_TARGET", "platform")
	cfg, err := buildConfig(stdinConfigFromEnv(), strings.NewReader("cs"))
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if cfg.Target != "platform" {
		t.Errorf("Target: got %q, want platform", cfg.Target)
	}
	t.Setenv("DELINEA_TOOLS_TARGET", "bogus")
	if _, err := buildConfig(configFromEnv(), strings.NewReader("cs")); err == nil {
		t.Errorf("invalid Target: want error")
	}
}

func clearDelineaEnv(t *testing.T) {
	t.Helper()
	for _, n := range []string{
		"DELINEA_TOOLS_URL", "DELINEA_TOOLS_TARGET", "DELINEA_TOOLS_USERNAME",
		"DELINEA_TOOLS_PASSWORD", "DELINEA_TOOLS_DOMAIN", "DELINEA_TOOLS_CLIENT_ID",
		"DELINEA_TOOLS_CLIENT_SECRET", "DELINEA_TOOLS_TOKEN", "DELINEA_TOOLS_CA_CERT",
		"DELINEA_TOOLS_TLS_SKIP_VERIFY", "DELINEA_TOOLS_TIMEOUT", "DELINEA_TOOLS_RETRIES",
		"DELINEA_TOOLS_VAULT_ALLOW",
		"DELINEA_TOOLS_GATEWAY_HEADER_FILE",
	} {
		t.Setenv(n, "")
		os.Unsetenv(n)
	}
}

func TestParseArgs(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		defaultMode string
		wantCommand bool
		wantMode    string
		wantMaps    []ds.Mapping
		wantCmd     []string
		wantHasCmd  bool
		wantPassEnv []string
		wantErr     bool
	}{
		{
			name: "pass-env repeated, both forms", args: []string{"--pass-env", "JAVA_HOME", "--pass-env=KUBECONFIG", "A=password#1", "--", "app"},
			defaultMode: "env", wantCommand: true,
			wantMode: "env", wantMaps: []ds.Mapping{{EnvName: "A", SecretID: 1, Field: "password"}},
			wantCmd: []string{"app"}, wantHasCmd: true,
			wantPassEnv: []string{"JAVA_HOME", "KUBECONFIG"},
		},
		{name: "pass-env rejects assignment", args: []string{"--pass-env", "FOO=bar", "--", "app"}, defaultMode: "env", wantCommand: true, wantErr: true},
		{name: "pass-env rejects assignment (= form)", args: []string{"--pass-env=FOO=bar", "--", "app"}, defaultMode: "env", wantCommand: true, wantErr: true},
		{name: "pass-env missing value", args: []string{"--pass-env"}, defaultMode: "env", wantCommand: true, wantErr: true},
		{name: "pass-env empty name", args: []string{"--pass-env=", "--", "app"}, defaultMode: "env", wantCommand: true, wantErr: true},
		{
			name: "run stdin with command", args: []string{"--via", "stdin", "A=password#1", "--", "app", "x"},
			defaultMode: "env", wantCommand: true,
			wantMode: "stdin", wantMaps: []ds.Mapping{{EnvName: "A", SecretID: 1, Field: "password"}},
			wantCmd: []string{"app", "x"}, wantHasCmd: true,
		},
		{
			name: "run default env", args: []string{"A=password#1", "--", "app"},
			defaultMode: "env", wantCommand: true,
			wantMode: "env", wantMaps: []ds.Mapping{{EnvName: "A", SecretID: 1, Field: "password"}},
			wantCmd: []string{"app"}, wantHasCmd: true,
		},
		{
			name: "via equals form", args: []string{"--via=sh", "A=password#1", "--", "app"},
			defaultMode: "env", wantCommand: true,
			wantMode: "sh", wantMaps: []ds.Mapping{{EnvName: "A", SecretID: 1, Field: "password"}},
			wantCmd: []string{"app"}, wantHasCmd: true,
		},
		{
			name: "print sh no command", args: []string{"--via", "sh", "A=password#1"},
			defaultMode: "stdin", wantCommand: false,
			wantMode: "sh", wantMaps: []ds.Mapping{{EnvName: "A", SecretID: 1, Field: "password"}},
			wantHasCmd: false,
		},
		{name: "via missing value", args: []string{"--via"}, defaultMode: "env", wantCommand: true, wantErr: true},
		{name: "print rejects command", args: []string{"A=password#1", "--", "x"}, defaultMode: "stdin", wantCommand: false, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := "print"
			if c.wantCommand {
				cmd = "run"
			}
			p, err := parseArgs(cmd, c.args, c.defaultMode, c.wantCommand)
			if c.wantErr {
				if err == nil {
					t.Fatalf("got nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("got error %v, want nil", err)
			}
			if p.mode != c.wantMode {
				t.Errorf("mode: got %q, want %q", p.mode, c.wantMode)
			}
			if !reflect.DeepEqual(p.mappings, c.wantMaps) {
				t.Errorf("mappings: got %+v, want %+v", p.mappings, c.wantMaps)
			}
			if !reflect.DeepEqual(p.command, c.wantCmd) {
				t.Errorf("command: got %v, want %v", p.command, c.wantCmd)
			}
			if p.hasCommand != c.wantHasCmd {
				t.Errorf("hasCommand: got %v, want %v", p.hasCommand, c.wantHasCmd)
			}
			if !reflect.DeepEqual(p.passEnv, c.wantPassEnv) {
				t.Errorf("passEnv: got %v, want %v", p.passEnv, c.wantPassEnv)
			}
		})
	}
}

func TestNoCommandErrorNamesTheCommand(t *testing.T) {
	for _, cmd := range []string{"print", "template", "check"} {
		_, err := parseArgs(cmd, []string{"A=password#1", "--", "x"}, "stdin", false)
		if err == nil || !strings.Contains(err.Error(), cmd) {
			t.Errorf("%s: got %v, want an error naming %s", cmd, err, cmd)
		}
	}
}

// template and check have no delivery mode, so a --via must be an error rather
// than silently ignored. template goes through the secrets Dispatch; check is
// the top-level verb, so it goes through Check.
func TestTemplateAndCheckRejectVia(t *testing.T) {
	rm := unifiedREADME(t)
	if err := Dispatch([]string{"template", "--in", "x", "--via", "sh", "A=password#1"}, rm); err == nil || !strings.Contains(err.Error(), "--via applies only to run and print") {
		t.Errorf("template --via: got %v, want a --via rejection", err)
	}
	if err := Check([]string{"--via=sh"}, rm); err == nil || !strings.Contains(err.Error(), "--via applies only to run and print") {
		t.Errorf("check --via: got %v, want a --via rejection", err)
	}
}

func TestCheckCollisions(t *testing.T) {
	if err := checkCollisions([]ds.Var{{Name: "A"}, {Name: "B"}}); err != nil {
		t.Errorf("distinct names: got %v, want nil", err)
	}
	if err := checkCollisions([]ds.Var{{Name: "TOKEN"}, {Name: "token"}}); err != nil {
		t.Errorf("case-distinct sink-neutral names: got %v, want nil", err)
	}
	if err := checkCollisions(nil); err != nil {
		t.Errorf("no vars: got %v, want nil", err)
	}
	err := checkCollisions([]ds.Var{{Name: "A"}, {Name: "B"}, {Name: "A"}})
	if err == nil || !strings.Contains(err.Error(), "A is defined more than once") {
		t.Errorf("got %v, want a collision error naming A", err)
	}
}

func TestPassEnvAssignmentErrorDoesNotEchoValue(t *testing.T) {
	const secret = "do-not-repeat-this-secret"
	_, err := parseArgs("run", []string{"--pass-env", "FOO=" + secret, "--", "app"}, "env", true)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("assignment error must not echo its value: %v", err)
	}
}

func TestCheckPassEnvCollisions(t *testing.T) {
	if err := checkPassEnvCollisions([]ds.Var{{Name: "DB_PASS"}}, []string{"HTTP_PROXY"}); err != nil {
		t.Errorf("distinct names: got %v, want nil", err)
	}
	if err := checkPassEnvCollisions([]ds.Var{{Name: "DB_PASS"}}, nil); err != nil {
		t.Errorf("no pass-env: got %v, want nil", err)
	}
	err := checkPassEnvCollisions([]ds.Var{{Name: "DB_PASS"}}, []string{"DB_PASS"})
	if err == nil || !strings.Contains(err.Error(), "DB_PASS is both") {
		t.Errorf("got %v, want a collision error naming DB_PASS", err)
	}
}

func TestConfigFromEnvRejectsInsecureURL(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "http://vault.example.com")
	t.Setenv("DELINEA_TOOLS_USERNAME", "u")
	if _, err := buildConfig(configFromEnv(), strings.NewReader("pw")); err == nil {
		t.Errorf("http URL: want error")
	}
}

func TestConfigFromEnvCACert(t *testing.T) {
	clearDelineaEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, []byte("pem-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DELINEA_TOOLS_USERNAME", "u")
	t.Setenv("DELINEA_TOOLS_CA_CERT", path)
	cfg, err := buildConfig(configFromEnv(), strings.NewReader("pw"))
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if string(cfg.CACert) != "pem-bytes" {
		t.Errorf("CACert: got %q, want pem-bytes", cfg.CACert)
	}
}

func TestConfigFromEnvCACertMissing(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_CA_CERT", "/no/such/ca.pem")
	if _, err := buildConfig(configFromEnv(), strings.NewReader("pw")); err == nil {
		t.Errorf("missing CA file: want error")
	}
}

func TestConfigFromEnvBadTimeout(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_TIMEOUT", "not-a-duration")
	if _, err := buildConfig(configFromEnv(), strings.NewReader("pw")); err == nil {
		t.Errorf("bad Timeout: want error")
	}
	for _, v := range []string{"-30s", "0s"} {
		t.Setenv("DELINEA_TOOLS_TIMEOUT", v)
		if _, err := buildConfig(configFromEnv(), strings.NewReader("pw")); err == nil {
			t.Errorf("%s: want error, a non-positive timeout would disable the deadline", v)
		}
	}
}

func TestParseTemplateError(t *testing.T) {
	if _, err := parseTemplate("{{ .X"); err == nil {
		t.Errorf("unclosed action: want parse error")
	}
}

func TestCmdTemplateErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--in"},         // needs a value
		{"--out"},        // needs a value
		{"A=password#1"}, // no --in
	} {
		if err := cmdTemplate(args, unifiedREADME(t)); err == nil {
			t.Errorf("cmdTemplate(%v): want error", args)
		}
	}
}

func TestDeliveryCommandsRequireMappings(t *testing.T) {
	clearDelineaEnv(t)
	templatePath := filepath.Join(t.TempDir(), "template")
	if err := os.WriteFile(templatePath, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		call func() error
	}{
		{"run", func() error { return cmdRun([]string{"--", "true"}, unifiedREADME(t)) }},
		{"print", func() error { return cmdPrint(nil, unifiedREADME(t)) }},
		{"template", func() error { return cmdTemplate([]string{"--in", templatePath}, unifiedREADME(t)) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			var usage *cli.UsageError
			if !errors.As(err, &usage) || !strings.Contains(err.Error(), "requires at least one MAPPING") {
				t.Errorf("got %T (%v), want a mapping usage error", err, err)
			}
		})
	}
}

type closeTrackingFetcher struct {
	verifyFake
	closeCalls int
}

func (f *closeTrackingFetcher) CloseIdleConnections() { f.closeCalls++ }

func TestResolveMappingsClosesIdleConnections(t *testing.T) {
	for _, tt := range []struct {
		name    string
		id      int
		wantErr bool
	}{
		{"success", 1, false},
		{"resolution failure", 2, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fetcher := &closeTrackingFetcher{}
			client := ds.NewWithFetcher(fetcher)
			_, err := resolveMappings(client, []ds.Mapping{{EnvName: "A", SecretID: tt.id, Field: "password"}})
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveMappings() error = %v, wantErr %v", err, tt.wantErr)
			}
			if fetcher.closeCalls != 1 {
				t.Errorf("CloseIdleConnections called %d times, want 1", fetcher.closeCalls)
			}
		})
	}
}

func TestFormat(t *testing.T) {
	vars := []ds.Var{{Name: "A", Value: "multi\nline"}, {Name: "B", Value: "it's"}}

	stdinPayload := payloadFor("stdin", vars)
	if got, want := string(stdinPayload), "A=multi\nline\x00B=it's\x00"; got != want {
		t.Errorf("stdin payload: got %q, want %q", got, want)
	}

	shPayload := payloadFor("sh", vars)
	if got, want := string(shPayload), "export A='multi\nline'\nexport B='it'\\''s'\n"; got != want {
		t.Errorf("sh payload: got %q, want %q", got, want)
	}

	if payload := payloadFor("env", vars); payload != nil {
		t.Errorf("env payload: got %v, want nil", payload)
	}
}

func envMap(t *testing.T, kvs []string) map[string]string {
	t.Helper()
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		name, value, _ := strings.Cut(kv, "=")
		m[name] = value
	}
	return m
}

// Nothing outside the baseline reaches the child, including anything a
// dependency might park in this process's own environment while resolving.
func TestChildEnvWithholdsEverythingUnlisted(t *testing.T) {
	t.Setenv("DELINEA_TOOLS_USERNAME", "someone")
	t.Setenv("DELINEA_TOOLS_URL", "https://example")
	t.Setenv("SS_AT_https%3A%2F%2Fexample_someone", `{"access_token":"leaked"}`)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "unrelated-secret")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
	t.Setenv("LC_PAPER", "en_US")
	t.Setenv("JAVA_HOME", "/opt/java")
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("LC_CTYPE", "en_US.UTF-8")

	got, err := childEnv(nil)
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	m := envMap(t, got)
	for _, name := range []string{
		"DELINEA_TOOLS_USERNAME", "DELINEA_TOOLS_URL",
		"SS_AT_https%3A%2F%2Fexample_someone",
		"AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "LC_PAPER", "JAVA_HOME",
	} {
		if _, ok := m[name]; ok {
			t.Errorf("childEnv passed %s, want it withheld", name)
		}
	}
	if got, want := m["PATH"], "/usr/bin"; got != want {
		t.Errorf("PATH: got %q, want %q", got, want)
	}
	if got, want := m["LC_CTYPE"], "en_US.UTF-8"; got != want {
		t.Errorf("LC_CTYPE: got %q, want %q", got, want)
	}
}

func TestChildEnvPassEnv(t *testing.T) {
	t.Setenv("JAVA_HOME", "/opt/java")
	got, err := childEnv([]string{"JAVA_HOME"})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if got, want := envMap(t, got)["JAVA_HOME"], "/opt/java"; got != want {
		t.Errorf("JAVA_HOME: got %q, want %q", got, want)
	}
}

// The error must name every missing variable, and say why one the caller "set"
// can still be invisible: an unexported shell variable is not in the environment.
func TestChildEnvPassEnvUnsetIsAnError(t *testing.T) {
	os.Unsetenv("DEFINITELY_NOT_SET_XYZ")
	os.Unsetenv("ALSO_NOT_SET_XYZ")
	t.Setenv("IS_SET_XYZ", "here")
	_, err := childEnv([]string{"DEFINITELY_NOT_SET_XYZ", "IS_SET_XYZ", "ALSO_NOT_SET_XYZ"})
	if err == nil {
		t.Fatalf("got nil error, want error naming the unset variables")
	}
	for _, want := range []string{"DEFINITELY_NOT_SET_XYZ", "ALSO_NOT_SET_XYZ", "export"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "IS_SET_XYZ") {
		t.Errorf("error %q names a variable that was set", err)
	}
}

// A baseline variable named by --pass-env must appear once, not twice.
func TestChildEnvPassEnvNoDuplicate(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	got, err := childEnv([]string{"PATH"})
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	n := 0
	for _, kv := range got {
		if strings.HasPrefix(kv, "PATH=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("PATH appeared %d times, want 1", n)
	}
}

func TestUsageErrorError(t *testing.T) {
	if got := (&cli.UsageError{Msg: "boom"}).Error(); got != "boom" {
		t.Errorf("got %q, want boom", got)
	}
}

// Dispatch returns errors rather than rendering them; the parent renders. A
// usage error is a *cli.UsageError, an ordinary one is not.
func TestDispatchErrorKinds(t *testing.T) {
	rm := unifiedREADME(t)
	if err := Dispatch([]string{"help"}, rm); err != nil {
		t.Errorf("help: got %v, want nil", err)
	}
	err := Dispatch([]string{"bogus"}, rm)
	if _, ok := err.(*cli.UsageError); !ok {
		t.Errorf("unknown subcommand: got %T (%v), want *cli.UsageError", err, err)
	}
	if err := Dispatch([]string{"run", "not-a-mapping", "--", "true"}, rm); err == nil || !strings.Contains(err.Error(), "invalid mapping") {
		t.Errorf("bad mapping: got %v, want the mapping error", err)
	}
	// check is no longer a secrets subcommand — it is the top-level verb.
	if _, ok := Dispatch([]string{"check"}, rm).(*cli.UsageError); !ok {
		t.Errorf("`secrets check` must now be an unknown-subcommand usage error")
	}
}

func TestRefuseBaselineShadowing(t *testing.T) {
	if err := refuseUnsafeChildVars([]ds.Var{{Name: "APP_TOKEN", Value: "x"}, {Name: "DB_PASS", Value: "y"}}); err != nil {
		t.Errorf("non-baseline names: got %v, want nil", err)
	}
	err := refuseUnsafeChildVars([]ds.Var{{Name: "APP_TOKEN", Value: "x"}, {Name: "PATH", Value: "/evil"}})
	if err == nil || !strings.Contains(err.Error(), "PATH") {
		t.Errorf("got %v, want a refusal naming PATH", err)
	}
	if !strings.Contains(err.Error(), "--pass-env") {
		t.Errorf("error should point at --pass-env: %v", err)
	}
	// Interpreter/linker names are refused even though they are not baseline
	// variables — a secret must not steer how the child loads code.
	for _, name := range []string{
		"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "DYLD_FALLBACK_LIBRARY_PATH",
		"DYLD_FRAMEWORK_PATH", "DYLD_FALLBACK_FRAMEWORK_PATH", "BASH_ENV", "PROMPT_COMMAND", "ZDOTDIR",
		"GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_EDITOR", "GIT_ASKPASS",
		"PAGER", "MANPAGER", "SYSTEMD_PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS", "SUDO_ASKPASS",
		"LESSOPEN", "LESSCLOSE", "MAKEFLAGS", "BROWSER", "NODE_OPTIONS",
		"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
		"GCONV_PATH", "PYTHONHOME", "NODE_PATH", "RUBYLIB", "PERLLIB",
		"LUA_PATH", "LUA_CPATH", "DOTNET_STARTUP_HOOKS",
		"CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER", "CORECLR_PROFILER_PATH",
		"COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH",
	} {
		err := refuseUnsafeChildVars([]ds.Var{{Name: name, Value: "x"}})
		if err == nil || !strings.Contains(err.Error(), "load or execute code") {
			t.Errorf("%s: got %v, want a code-loading refusal", name, err)
		}
	}
}

// --via sh emits export lines a shell evals, so a code-loading name is as
// dangerous there as in --via env; refuseUnsafeExports guards both. It does
// not apply the baseline-shadow rule (that is the env model's declared
// environment), only the code-loading names.
// An empty --out= (or --out "") must be rejected, not silently treated as
// "no --out" and written to stdout — that would leak the secret to whatever
// stdout points at.
func TestExtractSinkFlagsRejectsEmptyValue(t *testing.T) {
	for _, args := range [][]string{
		{"--out=", "A=password#1"},
		{"--out", "", "A=password#1"},
		{"--in=", "A=password#1"},
	} {
		var out, in string
		allow := false
		if _, err := extractSinkFlags(args, map[string]*string{"--out": &out, "--in": &in}, &allow); err == nil {
			t.Errorf("%v: got nil error, want a rejection of the empty path", args)
		}
	}
	// A real value still works.
	var out string
	allow := false
	rest, err := extractSinkFlags([]string{"--out=/tmp/x", "A=password#1"}, map[string]*string{"--out": &out}, &allow)
	if err != nil || out != "/tmp/x" || len(rest) != 1 {
		t.Errorf("valid --out: got out=%q rest=%v err=%v", out, rest, err)
	}
}

func TestRefuseUnsafeExports(t *testing.T) {
	if err := refuseUnsafeExports([]ds.Var{{Name: "DB_PASS", Value: "y"}, {Name: "APP_TOKEN", Value: "z"}}); err != nil {
		t.Errorf("ordinary names: got %v, want nil", err)
	}
	// PATH (and other baseline names) must be refused: eval'ing export PATH=
	// from a secret redirects command resolution to an attacker directory. The
	// code-loading names are refused on every OS; PATH is a baseline name on
	// every OS.
	for _, name := range []string{
		"PATH", "LD_PRELOAD", "BASH_ENV", "PROMPT_COMMAND", "ZDOTDIR",
		"GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_EDITOR", "GIT_ASKPASS",
		"PAGER", "MANPAGER", "SYSTEMD_PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS", "SUDO_ASKPASS",
		"LESSOPEN", "LESSCLOSE", "MAKEFLAGS", "BROWSER", "NODE_OPTIONS",
		"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
		"GCONV_PATH", "PYTHONHOME", "NODE_PATH", "RUBYLIB", "PERLLIB",
		"LUA_PATH", "LUA_CPATH", "DOTNET_STARTUP_HOOKS",
		"CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER", "CORECLR_PROFILER_PATH",
		"COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH",
	} {
		if err := refuseUnsafeExports([]ds.Var{{Name: name, Value: "x"}}); err == nil {
			t.Errorf("%s: got nil, want a refusal", name)
		}
	}
	// HOME is a baseline name only where the OS uses it; Windows uses
	// USERPROFILE/HOMEDRIVE/HOMEPATH, so HOME is not shadow-refused there.
	if runtime.GOOS != "windows" {
		if err := refuseUnsafeExports([]ds.Var{{Name: "HOME", Value: "x"}}); err == nil {
			t.Errorf("HOME: got nil, want a refusal")
		}
	}
}

// exportsToEnvironment gates the refuseUnsafeExports guard in cmdPrint. Both sh
// and github-env inject into an environment that loads code; the inert sinks do
// not. A missing github-env case here previously let a secret define LD_PRELOAD
// or PATH into $GITHUB_ENV, executing in every later CI step.
func TestExportsToEnvironment(t *testing.T) {
	want := map[string]bool{
		"sh": true, "github-env": true,
		"stdin": false, "json": false, "raw": false, "github-output": false, "ado": false,
	}
	for mode, w := range want {
		if got := exportsToEnvironment(mode); got != w {
			t.Errorf("exportsToEnvironment(%q): got %v, want %v", mode, got, w)
		}
	}
}

// --out to a character device (a terminal) is refused unless --allow-terminal,
// the same guard the stdout path applies. /dev/null is a char device on Unix.
func TestCheckOutFileSinkCharDevice(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/null char device semantics on Windows")
	}
	if err := checkOutFileSink(os.DevNull, false); err == nil {
		t.Errorf("%s without --allow-terminal: got nil, want a refusal", os.DevNull)
	}
	if err := checkOutFileSink(os.DevNull, true); err != nil {
		t.Errorf("%s with --allow-terminal: got %v, want nil", os.DevNull, err)
	}
	// A regular file (and a nonexistent path) is always fine.
	p := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkOutFileSink(p, false); err != nil {
		t.Errorf("regular file: got %v, want nil", err)
	}
	if err := checkOutFileSink(filepath.Join(t.TempDir(), "absent"), false); err != nil {
		t.Errorf("absent path: got %v, want nil", err)
	}
}

func TestBaselineIsInert(t *testing.T) {
	for _, name := range []string{
		"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "SSH_AUTH_SOCK", "KRB5CCNAME",
		"XAUTHORITY", "DISPLAY", "PS1", "PROMPT_COMMAND",
	} {
		if inBaseline(name) {
			t.Errorf("%s is in the baseline; it can redirect traffic, change trust, or confer a capability", name)
		}
	}
}

func TestShellPayloadQuoting(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abc", "export X='abc'\n"},
		{"it's", "export X='it'\\''s'\n"},
		{"", "export X=''\n"},
		{"a b\tc", "export X='a b\tc'\n"},
	}
	for _, c := range cases {
		if got := string(payloadFor("sh", []ds.Var{{Name: "X", Value: c.in}})); got != c.want {
			t.Errorf("sh payload for %q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDispatch(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"no subcommand", nil, true},
		{"unknown subcommand", []string{"bogus"}, true},
		{"help", []string{"help"}, false},
		{"-h", []string{"-h"}, false},
		{"run without command", []string{"run", "A=password#1"}, true},
		{"run bad via", []string{"run", "--via", "bogus", "--", "true"}, true},
		{"print rejects env via", []string{"print", "--via", "env", "A=password#1"}, true},
		{"bad mapping", []string{"run", "nope", "--", "true"}, true},
		{"print --out needs value", []string{"print", "--out"}, true},
		{"readme flag is the parent's, not the group's", []string{"--readme"}, true},
		{"tree flag is the parent's", []string{"--tree"}, true},
		{"version flag is not handled here (parent owns it)", []string{"--version"}, true},
		{"check is the top-level verb, not a secrets subcommand", []string{"check"}, true},
		{"template no args", []string{"template"}, true},
		{"template without --in", []string{"template", "A=password#1"}, true},
	}
	rm := unifiedREADME(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Dispatch(c.args, rm)
			if c.wantErr && err == nil {
				t.Errorf("got nil error, want error")
			}
			if !c.wantErr && err != nil {
				t.Errorf("got error %v, want nil", err)
			}
		})
	}
}

func TestCheckOutputSink(t *testing.T) {
	if err := checkOutputSink(true, false); err == nil {
		t.Errorf("terminal without --allow-terminal: got nil error, want error")
	}
	if err := checkOutputSink(true, true); err != nil {
		t.Errorf("terminal with --allow-terminal: got %v, want nil", err)
	}
	if err := checkOutputSink(false, false); err != nil {
		t.Errorf("non-terminal: got %v, want nil", err)
	}
}

func TestConfigFromEnv(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://x")
	t.Setenv("DELINEA_TOOLS_USERNAME", "u")
	cfg, err := buildConfig(stdinConfigFromEnv(), strings.NewReader("s3cr3t\n"))
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if cfg.URL != "https://x" || cfg.Username != "u" || cfg.Password != "s3cr3t" {
		t.Errorf("cfg mismatch: %+v", cfg)
	}
	if cfg.Timeout == 0 {
		t.Errorf("default timeout not applied")
	}
	if cfg.Retries != 3 {
		t.Errorf("Retries: got %d, want 3", cfg.Retries)
	}
}

func TestConfigFromEnvInfersToken(t *testing.T) {
	clearDelineaEnv(t)
	cfg, err := buildConfig(stdinConfigFromEnv(), strings.NewReader("tok-value\n"))
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if cfg.Token != "tok-value" {
		t.Errorf("Token: got %q, want tok-value", cfg.Token)
	}
	if cfg.Password != "" {
		t.Errorf("no Username: password should be empty, got %q", cfg.Password)
	}
}

func TestConfigFromEnvInsecureAndTimeout(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_TLS_SKIP_VERIFY", "TRUE")
	t.Setenv("DELINEA_TOOLS_TIMEOUT", "45s")
	cfg, err := buildConfig(configFromEnv(), strings.NewReader(""))
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if !cfg.SkipTLSVerify {
		t.Errorf("skip-tls-verify not parsed")
	}
	if cfg.Timeout != 45*time.Second {
		t.Errorf("Timeout: got %v, want 45s", cfg.Timeout)
	}
}

func TestConfigGatewayHeaderFile(t *testing.T) {
	clearDelineaEnv(t)
	path := filepath.Join(t.TempDir(), "gateway.headers")
	if err := os.WriteFile(path, []byte("X-Gateway-Key: gateway-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DELINEA_TOOLS_GATEWAY_HEADER_FILE", path)
	cfg, err := buildConfig(configFromEnv(), strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Header.Get("X-Gateway-Key"); got != "gateway-secret" {
		t.Errorf("gateway header: got %q", got)
	}
}

func TestExtractConnFlagsGatewayHeaderFilesReplaceEnvironment(t *testing.T) {
	cc := cliConfig{GatewayHeaderFileEnv: "ambient.headers"}
	rest, err := extractConnFlags([]string{"--gateway-header-file", "first.headers", "--gateway-header-file=second.headers", "print", "DB=password#1"}, &cc)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cc.GatewayHeaderPaths(), []string{"first.headers", "second.headers"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got, want := rest, []string{"print", "DB=password#1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("rest: got %v, want %v", got, want)
	}
}

// The command tree and its README containment now live with package main, the
// owner of the single unified README; see cmd/delinea-util's TestReadmeContainsTree
// and TestCommandTree.

func TestValidModes(t *testing.T) {
	for _, m := range []string{"env", "stdin", "sh"} {
		if !validRunMode(m) {
			t.Errorf("validRunMode(%q) = false, want true", m)
		}
	}
	if validRunMode("json") {
		t.Errorf("validRunMode(json) = true; json is print-only")
	}
	for _, m := range []string{"stdin", "sh", "json", "raw", "github-env", "github-output", "ado"} {
		if !validPrintMode(m) {
			t.Errorf("validPrintMode(%q) = false, want true", m)
		}
	}
	if validPrintMode("env") {
		t.Errorf("validPrintMode(env) = true; env is run-only")
	}
}

func TestCheckRawCount(t *testing.T) {
	if err := checkRawCount("raw", 1); err != nil {
		t.Errorf("raw/1: got %v, want nil", err)
	}
	if err := checkRawCount("raw", 0); err == nil {
		t.Errorf("raw/0: want error")
	}
	if err := checkRawCount("raw", 2); err == nil {
		t.Errorf("raw/2: want error")
	}
	if err := checkRawCount("stdin", 3); err != nil {
		t.Errorf("stdin/3: got %v, want nil", err)
	}
}

func TestFormatJSONRaw(t *testing.T) {
	jsonPayload := payloadFor("json", []ds.Var{{Name: "TOKEN", Value: "upper"}, {Name: "token", Value: "lower"}})
	if got, want := string(jsonPayload), `{"TOKEN":"upper","token":"lower"}`; got != want {
		t.Errorf("json payload: got %q, want %q", got, want)
	}
	rawPayload := payloadFor("raw", []ds.Var{{Name: "A", Value: "the-value"}})
	if got, want := string(rawPayload), "the-value"; got != want {
		t.Errorf("raw payload: got %q, want %q", got, want)
	}
	adoPayload := payloadFor("ado", []ds.Var{{Name: "DB_PASS", Value: "s3cr3t"}})
	if got, want := string(adoPayload), "##vso[task.setsecret]s3cr3t\n##vso[task.setvariable variable=DB_PASS;issecret=true]s3cr3t\n"; got != want {
		t.Errorf("ado payload: got %q, want %q", got, want)
	}
	githubOutput := payloadFor("github-output", []ds.Var{{Name: "GITHUB_WORKSPACE", Value: "result"}})
	if got, want := string(githubOutput), "GITHUB_WORKSPACE<<DELINEA_EOF\nresult\nDELINEA_EOF\n"; got != want {
		t.Errorf("github-output payload: got %q, want %q", got, want)
	}
}

func TestRenderTemplate(t *testing.T) {
	tmpl, err := parseTemplate("password={{.DB}} upper={{.TOKEN}} lower={{.token}}")
	if err != nil {
		t.Fatal(err)
	}
	out, err := renderTemplate(tmpl, []ds.Var{{Name: "DB", Value: "s3cr3t"}, {Name: "TOKEN", Value: "one"}, {Name: "token", Value: "two"}})
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if got, want := string(out), "password=s3cr3t upper=one lower=two"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRenderTemplateMissingKey(t *testing.T) {
	tmpl, err := parseTemplate("{{.MISSING}}")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renderTemplate(tmpl, nil); err == nil {
		t.Errorf("missing key: want error")
	}
}

func TestConfigFromEnvRejectsMisencodedCredential(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://vault.example.com")
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")
	if _, err := buildConfig(stdinConfigFromEnv(), bytes.NewReader(append([]byte{0xFF, 0xFE}, "p\x00w\x00"...))); err == nil {
		t.Errorf("got nil error, want a rejection")
	}
	// A BOM must not simply be stripped and the rest used.
	cfg, err := buildConfig(stdinConfigFromEnv(), bytes.NewReader([]byte("plain-password")))
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if cfg.Password != "plain-password" {
		t.Errorf("Password: got %q, want plain-password", cfg.Password)
	}
}

// A NUL in a value corrupts --via stdin framing and cannot survive sh or execve.
// File attachments arrive as ordinary values, so this is reachable.
func TestCheckDeliverable(t *testing.T) {
	binary := []ds.Var{{Name: "OK", Value: "plain"}, {Name: "KEY", Value: "aa\x00bb"}}
	for _, mode := range []string{"env", "stdin", "sh"} {
		err := checkDeliverable("print", mode, binary)
		if err == nil {
			t.Errorf("--via %s: got nil error, want a rejection", mode)
			continue
		}
		if !strings.Contains(err.Error(), "KEY") {
			t.Errorf("--via %s: error %q should name the offending variable", mode, err)
		}
		if !strings.Contains(err.Error(), "raw") {
			t.Errorf("--via %s: error %q should point at a mode that works", mode, err)
		}
	}
	err := checkDeliverable("run", "env", binary)
	if err == nil || strings.Contains(err.Error(), "--via json") {
		t.Errorf("run remedy must not point at modes run rejects, got %v", err)
	}
	// raw and json carry NUL (json escapes it); only raw carries invalid UTF-8.
	for _, mode := range []string{"raw", "json"} {
		if err := checkDeliverable("print", mode, binary); err != nil {
			t.Errorf("--via %s: got %v, want nil", mode, err)
		}
	}
	notUTF8 := []ds.Var{{Name: "BLOB", Value: "\xff\xfe\x01"}}
	if err := checkDeliverable("print", "json", notUTF8); err == nil || !strings.Contains(err.Error(), "BLOB") {
		t.Errorf("json with invalid UTF-8: got %v, want a rejection naming BLOB (it would be silently corrupted)", err)
	}
	if err := checkDeliverable("print", "github-env", notUTF8); err == nil || !strings.Contains(err.Error(), "BLOB") || strings.Contains(err.Error(), "raw") {
		t.Errorf("github-env with invalid UTF-8: got %v, want a rejection naming BLOB without recommending unmasked raw output", err)
	}
	if err := checkDeliverable("print", "github-output", notUTF8); err == nil || !strings.Contains(err.Error(), "BLOB") || strings.Contains(err.Error(), "raw") {
		t.Errorf("github-output with invalid UTF-8: got %v, want a rejection naming BLOB without recommending unmasked raw output", err)
	}
	if err := checkDeliverable("print", "github-env", []ds.Var{{Name: "GITHUB_WORKSPACE", Value: "x"}}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Errorf("github-env reserved name: got %v, want a reserved-name refusal", err)
	}
	if err := checkDeliverable("print", "github-output", []ds.Var{{Name: "GITHUB_WORKSPACE", Value: "x"}}); err != nil {
		t.Errorf("github-output environment-reserved name: got %v, want nil", err)
	}
	if err := checkDeliverable("print", "github-output", []ds.Var{{Name: "TOKEN", Value: "a"}, {Name: "token", Value: "b"}}); err == nil || !strings.Contains(err.Error(), "case-insensitive") || strings.Contains(err.Error(), "raw") {
		t.Errorf("github-output case-insensitive duplicates: got %v, want a refusal without the inapplicable raw remedy", err)
	}
	if err := checkDeliverable("print", "github-env", []ds.Var{{Name: "TOKEN", Value: "a"}, {Name: "token", Value: "b"}}); err == nil || !strings.Contains(err.Error(), "case-insensitive") || strings.Contains(err.Error(), "raw") {
		t.Errorf("github-env case-insensitive duplicates: got %v, want a portable refusal without the inapplicable raw remedy", err)
	}
	if err := checkDeliverable("print", "ado", []ds.Var{{Name: "TOKEN", Value: "a"}, {Name: "token", Value: "b"}}); err == nil || !strings.Contains(err.Error(), "case-insensitive") {
		t.Errorf("ado case-insensitive duplicates: got %v, want a refusal", err)
	}
	if err := checkDeliverable("print", "ado", []ds.Var{{Name: "SECRET_VALUE", Value: "x"}}); err == nil || !strings.Contains(err.Error(), "reserved") || strings.Contains(err.Error(), "raw") {
		t.Errorf("ado reserved name: got %v, want a refusal without the inapplicable raw remedy", err)
	}
	if err := checkDeliverable("print", "ado", notUTF8); err == nil || !strings.Contains(err.Error(), "BLOB") || strings.Contains(err.Error(), "raw") {
		t.Errorf("ado with invalid UTF-8: got %v, want a rejection naming BLOB without recommending unmasked raw output", err)
	}
	if err := checkDeliverable("print", "ado", []ds.Var{{Name: "GOOD", Value: "x"}, {Name: "MULTI", Value: "a\nb"}}); err == nil || strings.Contains(err.Error(), "raw") {
		t.Errorf("ado batch with an unrepresentable value: got %v, want a refusal without a raw mode that cannot carry the batch", err)
	}
	if err := checkDeliverable("print", "ado", []ds.Var{{Name: "MULTI", Value: "a\nb"}}); err == nil || !strings.Contains(err.Error(), "multiline") {
		t.Errorf("ado with multiline value: got %v, want a multiline refusal", err)
	}
	for _, mode := range []string{"env", "stdin", "sh"} {
		if err := checkDeliverable("print", mode, []ds.Var{{Name: "DSS_private-key", Value: "x"}}); err == nil || !strings.Contains(err.Error(), "environment-variable name") {
			t.Errorf("%s with an ADO-only name: got %v, want an environment-name refusal", mode, err)
		}
	}
	if err := checkDeliverable("print", "ado", []ds.Var{{Name: "DSS_private-key", Value: "x"}}); err != nil {
		t.Errorf("ado with a hyphenated macro-variable name: got %v, want nil", err)
	}
	if err := checkDeliverable("print", "raw", notUTF8); err != nil {
		t.Errorf("raw with invalid UTF-8: got %v, want nil", err)
	}
	if err := checkDeliverable("run", "env", notUTF8); envRequiresUTF8 && (err == nil || !strings.Contains(err.Error(), "stdin")) {
		t.Errorf("Windows env with invalid UTF-8: got %v, want a rejection and stdin remedy", err)
	} else if !envRequiresUTF8 && err != nil {
		t.Errorf("Unix env with non-NUL bytes: got %v, want nil", err)
	}
	for _, mode := range []string{"env", "stdin", "sh", "raw", "json", "github-env", "github-output", "ado"} {
		if err := checkDeliverable("print", mode, []ds.Var{{Name: "A", Value: "no nul here"}}); err != nil {
			t.Errorf("--via %s clean value: got %v, want nil", mode, err)
		}
	}
}
