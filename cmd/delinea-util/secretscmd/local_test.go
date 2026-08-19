package secretscmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DelineaXPM/delinea-tools/internal/cli"
)

// These tests drive dispatch end to end — configFromEnv, the engine's grant,
// resolution, and delivery — against a loopback server, which is exactly what
// requireSecureURL's http-loopback exception exists for. Everything runs
// offline.

func loopbackSS(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("username") != "svc" || r.PostForm.Get("password") != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"test-token","token_type":"bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/api/v1/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"healthy":true}`)
	})
	mux.HandleFunc("/api/v1/users/current", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"id":1,"userName":"svc"}`)
	})
	mux.HandleFunc("/api/v1/secrets/128", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"id":128,"name":"db","items":[
			{"fieldName":"Username","slug":"username","itemValue":"svc-db"},
			{"fieldName":"Password","slug":"password","itemValue":"s3cr3t","isPassword":true},
			{"fieldName":"Notes","slug":"notes","itemValue":"line one\nline two"}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func loopbackPlatform(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"healthy":true}`)
	})
	mux.HandleFunc("/vaultbroker/api/vaults", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer platform-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"vaults":[]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func loopbackGatewaySS(t *testing.T, gatewaySecret string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	guard := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("X-Gateway-Key") == gatewaySecret {
			return true
		}
		w.WriteHeader(http.StatusForbidden)
		return false
	}
	mux.HandleFunc("/api/v1/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		if guard(w, r) {
			fmt.Fprint(w, `{"healthy":true}`)
		}
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if guard(w, r) {
			fmt.Fprint(w, `{"access_token":"test-token","token_type":"bearer","expires_in":3600}`)
		}
	})
	mux.HandleFunc("/api/v1/users/current", func(w http.ResponseWriter, r *http.Request) {
		if !guard(w, r) {
			return
		}
		if r.Header.Get("Authorization") == "Bearer test-token" {
			fmt.Fprint(w, `{"id":1,"userName":"svc"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/api/v1/secrets/128", func(w http.ResponseWriter, r *http.Request) {
		if !guard(w, r) {
			return
		}
		if r.Header.Get("Authorization") == "Bearer test-token" {
			fmt.Fprint(w, `{"id":128,"name":"db","items":[{"fieldName":"Password","slug":"password","itemValue":"s3cr3t"}]}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// runInProcess swaps os.Stdin and os.Stdout around dispatch, feeding stdin and
// capturing stdout, so the whole CLI wiring runs in-process.
func runInProcess(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	go func() {
		io.WriteString(inW, stdin)
		inW.Close()
	}()
	// Route exactly as main's dispatch does: check is the top-level verb handled
	// by Check; everything else is a secrets-group subcommand handled by Dispatch.
	rm := unifiedREADME(t)
	var dispatchErr error
	if len(args) > 0 && args[0] == "check" {
		dispatchErr = Check(args[1:], rm)
	} else {
		dispatchErr = Dispatch(args, rm)
	}
	os.Stdin, os.Stdout = oldIn, oldOut
	outW.Close()
	out, readErr := io.ReadAll(outR)
	inR.Close()
	outR.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(out), dispatchErr
}

func TestLocalPrintJSON(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")

	out, err := runInProcess(t, "pw\n", "print", "--secret-stdin", "--via", "json", "DB=password#128", "U=username#128")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if got["DB"] != "s3cr3t" || got["U"] != "svc-db" {
		t.Errorf("got %v, want both fields resolved", got)
	}
}

func TestLocalGatewayHeaderFileCoversCheckAndSecretResolution(t *testing.T) {
	const gatewaySecret = "gateway-secret"
	srv := loopbackGatewaySS(t, gatewaySecret)
	clearDelineaEnv(t)
	headerFile := filepath.Join(t.TempDir(), "gateway.headers")
	if err := os.WriteFile(headerFile, []byte("X-Gateway-Key: "+gatewaySecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "pw")
	t.Setenv("DELINEA_TOOLS_GATEWAY_HEADER_FILE", headerFile)

	out, err := runInProcess(t, "", "check", "--json", "DB=password#128")
	if err != nil {
		t.Fatalf("gateway check: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"label": "DB"`) || !strings.Contains(out, `"status": "ok"`) {
		t.Fatalf("gateway check did not resolve the mapping:\n%s", out)
	}
}

func TestLocalPrintGitHubEnv(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")
	outFile := filepath.Join(t.TempDir(), "github.env")
	if err := os.WriteFile(outFile, []byte("PREVIOUS=kept\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	masks, err := runInProcess(t, "pw\n", "print", "--secret-stdin", "--via", "github-env", "--out", outFile, "DB=password#128", "NOTES=notes#128")
	if err != nil {
		t.Fatal(err)
	}
	wantMasks := "::add-mask::s3cr3t\n::add-mask::line one\n::add-mask::line two\n"
	if masks != wantMasks {
		t.Errorf("masks on stdout: got %q, want %q", masks, wantMasks)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "PREVIOUS=kept\nDB<<DELINEA_EOF\ns3cr3t\nDELINEA_EOF\nNOTES<<DELINEA_EOF\nline one\nline two\nDELINEA_EOF\n"
	if string(data) != want {
		t.Errorf("env file: got %q, want %q", data, want)
	}
	if runtime.GOOS != "windows" {
		// The runner owns its command file: a pre-existing mode is preserved
		// (chmod by a guest fails with EPERM when the runner's UID differs).
		if fi, err := os.Stat(outFile); err != nil || fi.Mode().Perm() != 0o644 {
			t.Errorf("env file mode: got %v, %v; want the pre-existing 0644 preserved", fi, err)
		}
	}
}

func TestLocalPrintGitHubEnvCreatesPrivateFile(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")
	outFile := filepath.Join(t.TempDir(), "fresh.env")

	if _, err := runInProcess(t, "pw\n", "print", "--secret-stdin", "--via", "github-env", "--out", outFile, "DB=password#128"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(outFile); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("fresh env file mode: got %v, %v; want 0600", fi, err)
		}
	}
}

// Without --out the masks would have nowhere to go — mixing them into a
// redirected env file corrupts it, and omitting them leaves the secrets
// unmasked in job logs while the docs promise otherwise — so the mode
// refuses before any credential is spent.
func TestLocalPrintGitHubEnvRequiresOut(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")

	out, err := runInProcess(t, "pw\n", "print", "--via", "github-env", "DB=password#128")
	if err == nil || !strings.Contains(err.Error(), "--out") {
		t.Errorf("got %v, want a refusal naming --out", err)
	}
	if out != "" {
		t.Errorf("nothing may reach stdout on refusal, got %q", out)
	}
}

func TestLocalPrintGitHubModesApplySinkSpecificNameRules(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")

	envFile := filepath.Join(t.TempDir(), "github.env")
	out, err := runInProcess(t, "pw\n", "print", "--secret-stdin", "--via", "github-env", "--out", envFile, "GITHUB_WORKSPACE=password#128")
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("github-env: got output %q, error %v; want a reserved-name refusal", out, err)
	}
	if _, statErr := os.Stat(envFile); !os.IsNotExist(statErr) {
		t.Errorf("github-env created its output on validation failure: %v", statErr)
	}

	foldedFile := filepath.Join(t.TempDir(), "github-folded.env")
	out, err = runInProcess(t, "pw\n", "print", "--secret-stdin", "--via", "github-env", "--out", foldedFile,
		"TOKEN=password#128", "token=username#128")
	if err == nil {
		t.Fatalf("github-env case-folded collision: got output %q, want a refusal", out)
	}
	if out != "" {
		t.Errorf("github-env case-folded refusal reached stdout: %q", out)
	}
	if _, statErr := os.Stat(foldedFile); !os.IsNotExist(statErr) {
		t.Errorf("github-env created its output on case-folded validation failure: %v", statErr)
	}

	outputFile := filepath.Join(t.TempDir(), "github.output")
	masks, err := runInProcess(t, "pw\n", "print", "--secret-stdin", "--via", "github-output", "--out", outputFile, "GITHUB_WORKSPACE=password#128")
	if err != nil {
		t.Fatal(err)
	}
	if masks != "::add-mask::s3cr3t\n" {
		t.Errorf("github-output masks: got %q", masks)
	}
	data, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := "GITHUB_WORKSPACE<<DELINEA_EOF\ns3cr3t\nDELINEA_EOF\n"; string(data) != want {
		t.Errorf("github-output file: got %q, want %q", data, want)
	}
}

func TestLocalPrintGitHubOutputRequiresOut(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")

	out, err := runInProcess(t, "pw\n", "print", "--via", "github-output", "DB=password#128")
	if err == nil || !strings.Contains(err.Error(), "$GITHUB_OUTPUT") {
		t.Errorf("got %v, want a refusal naming $GITHUB_OUTPUT", err)
	}
	if out != "" {
		t.Errorf("nothing may reach stdout on refusal, got %q", out)
	}
}

func TestLocalPrintADO(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")

	out, err := runInProcess(t, "pw\n", "print", "--secret-stdin", "--via", "ado", "DB_PASS=password#128", "DB_USER=username#128")
	if err != nil {
		t.Fatal(err)
	}
	want := "##vso[task.setsecret]s3cr3t\n" +
		"##vso[task.setvariable variable=DB_PASS;issecret=true]s3cr3t\n" +
		"##vso[task.setsecret]svc-db\n" +
		"##vso[task.setvariable variable=DB_USER;issecret=true]svc-db\n"
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestLocalPrintADORefusesOutBeforeFetch(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")

	outFile := filepath.Join(t.TempDir(), "commands")
	out, err := runInProcess(t, "", "print", "--via", "ado", "--out", outFile, "DB_PASS=password#128")
	if err == nil || !strings.Contains(err.Error(), "stdout") || !strings.Contains(err.Error(), "--out") {
		t.Errorf("got %v, want a stdout-only usage error", err)
	}
	if out != "" {
		t.Errorf("nothing may reach stdout on refusal, got %q", out)
	}
	if _, statErr := os.Stat(outFile); !os.IsNotExist(statErr) {
		t.Errorf("--out refusal created %q: %v", outFile, statErr)
	}
}

func TestLocalPrintADORefusesMultilineWithoutOutput(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")

	out, err := runInProcess(t, "pw\n", "print", "--secret-stdin", "--via", "ado", "DB_PASS=password#128", "NOTES=notes#128")
	if err == nil || !strings.Contains(err.Error(), "multiline") {
		t.Errorf("got %v, want a multiline refusal", err)
	}
	if out != "" {
		t.Errorf("validation failure emitted partial commands: %q", out)
	}
}

func TestLocalPrintRawBearerToken(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	// No Username: stdin is a pre-obtained bearer token.
	out, err := runInProcess(t, "test-token", "print", "--secret-stdin", "--via", "raw", "DB=password#128")
	if err != nil {
		t.Fatal(err)
	}
	if out != "s3cr3t" {
		t.Errorf("got %q, want the raw value", out)
	}
}

// The credential now comes from the environment the same way delinea-util reads
// it: DELINEA_TOOLS_TOKEN alone, no username and nothing on stdin, resolves.
func TestLocalTokenFromEnv(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")
	out, err := runInProcess(t, "", "print", "--via", "raw", "DB=password#128")
	if err != nil {
		t.Fatal(err)
	}
	if out != "s3cr3t" {
		t.Errorf("got %q, want the value resolved with the env token", out)
	}
}

func TestLocalTokenFromEnvIgnoresStaleUsername(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")
	t.Setenv("DELINEA_TOOLS_USERNAME", "stale-user")
	out, err := runInProcess(t, "", "print", "--via", "raw", "DB=password#128")
	if err != nil || out != "s3cr3t" {
		t.Fatalf("targetless token did not ignore the stale Username: output=%q err=%v", out, err)
	}
}

// Without --secret-stdin, the environment secret is used and stdin is not read.
func TestLocalTokenEnvBeatsStdin(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")
	out, err := runInProcess(t, "wrong-token", "print", "--via", "raw", "DB=password#128")
	if err != nil {
		t.Fatalf("env token should be used and stdin ignored: %v", err)
	}
	if out != "s3cr3t" {
		t.Errorf("got %q, want the env token used and stdin ignored", out)
	}
}

// Without --secret-stdin, an unrelated pipe is not interpreted as a credential.
func TestLocalStdinIgnoredWithoutSecretStdin(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	out, err := runInProcess(t, "test-token", "print", "--via", "raw", "DB=password#128")
	if err == nil {
		t.Fatal("stdin credential unexpectedly accepted without --secret-stdin")
	}
	if out != "" {
		t.Errorf("got output %q, want none on credential failure", out)
	}
}

// The credential is never accepted as a command-line argument: --token,
// --password and --client-secret are rejected with a usage error before the
// command separator (argv is world-readable via ps and /proc).
func TestSecretFlagsRejected(t *testing.T) {
	for _, flag := range [][]string{
		{"--token", "t"}, {"--password", "p"}, {"--client-secret", "s"},
		{"--token=t"}, {"--password=p"}, {"--client-secret=s"},
	} {
		args := append([]string{"print", "--via", "raw"}, flag...)
		args = append(args, "DB=password#128", "--", "true")
		err := Dispatch(args, unifiedREADME(t))
		if _, ok := err.(*cli.UsageError); !ok {
			t.Errorf("%v: got %v (%T), want a usage error rejecting the secret flag", flag, err, err)
		}
	}
}

// --secret-stdin forces the credential from stdin, overriding an env secret:
// the env token would be rejected, but --secret-stdin makes the stdin token win.
func TestLocalSecretStdinOverridesEnv(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "wrong-token")
	out, err := runInProcess(t, "test-token", "print", "--secret-stdin", "--via", "raw", "DB=password#128")
	if err != nil {
		t.Fatalf("--secret-stdin should override the env Token: %v", err)
	}
	if out != "s3cr3t" {
		t.Errorf("got %q, want the stdin token used when --secret-stdin is set", out)
	}
}

// check honors connection FLAGS, not just the environment: with nothing in the
// environment, --url and --username supply the config, and check reaches and
// resolves the secret rather than reporting URL/username as unset.
func TestLocalCheckHonorsConnectionFlags(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t) // the flags, not env, must supply URL and username
	out, err := runInProcess(t, "pw", "check", "--secret-stdin", "--json", "--url", srv.URL, "--username", "svc", "DB=password#128")
	if err != nil {
		t.Fatalf("check with flag-provided config should pass: %v\n%s", err, out)
	}
	var doc struct {
		Summary  map[string]int `json:"summary"`
		Sections []struct {
			Title    string `json:"title"`
			Findings []struct{ Status, Label, Detail string }
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc.Summary["FAIL"] != 0 {
		t.Errorf("flag-provided config reported failures:\n%s", out)
	}
	urlSeen, resolvedSeen := false, false
	for _, s := range doc.Sections {
		for _, f := range s.Findings {
			if f.Label == "DELINEA_TOOLS_URL" {
				urlSeen = true
				if f.Status != "ok" || !strings.Contains(f.Detail, srv.URL) {
					t.Errorf("URL finding: got %s %q, want ok showing the flag URL, not 'not set'", f.Status, f.Detail)
				}
			}
			if f.Label == "DB" && strings.Contains(f.Detail, "6 bytes") {
				resolvedSeen = true
			}
		}
	}
	if !urlSeen {
		t.Errorf("no DELINEA_TOOLS_URL finding (the flag URL was ignored):\n%s", out)
	}
	if !resolvedSeen {
		t.Errorf("check did not reach/resolve the secret via flag config:\n%s", out)
	}
}

// check validates DELINEA_TOOLS_RETRIES with the same parser run uses: a bogus
// value is a configuration failure and makes cmdCheck exit nonzero.
func TestLocalCheckValidatesRetries(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_RETRIES", "bogus")

	out, err := runInProcess(t, "", "check", "--json")
	if err == nil {
		t.Fatalf("a bogus DELINEA_TOOLS_RETRIES must fail check\n%s", out)
	}
	var doc struct {
		Sections []struct {
			Title    string `json:"title"`
			Findings []struct{ Status, Label, Detail string }
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	found := false
	for _, s := range doc.Sections {
		for _, f := range s.Findings {
			if f.Label == "DELINEA_TOOLS_RETRIES" && f.Status == "FAIL" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no DELINEA_TOOLS_RETRIES failure in the configuration section:\n%s", out)
	}
}

func TestLocalCheckClassifiesInvalidGatewayHeaderAsConfiguration(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	const secret = "do-not-repeat-gateway-secret"
	path := filepath.Join(t.TempDir(), "gateway.headers")
	if err := os.WriteFile(path, []byte("Bad Name: "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DELINEA_TOOLS_GATEWAY_HEADER_FILE", path)

	out, err := runInProcess(t, "", "check", "--no-auth", "--json")
	if err == nil {
		t.Fatalf("a wire-invalid gateway header must fail check\n%s", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("check output exposed the gateway header value: %s", out)
	}
	sections := checkSections(t, out)
	if !hasFail(sections["configuration"], "DELINEA_TOOLS_GATEWAY_HEADER_FILE") {
		t.Errorf("invalid gateway header was not a configuration failure:\n%s", out)
	}
	for _, f := range sections["vault"] {
		if f.Label == "reachability" && f.Status == "FAIL" {
			t.Errorf("local header error was misclassified as reachability: %+v\n%s", f, out)
		}
	}
}

// checkSections parses the --json output into its sections.
func checkSections(t *testing.T, out string) map[string][]struct{ Status, Label, Detail string } {
	t.Helper()
	var doc struct {
		Sections []struct {
			Title    string `json:"title"`
			Findings []struct{ Status, Label, Detail string }
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	m := map[string][]struct{ Status, Label, Detail string }{}
	for _, s := range doc.Sections {
		m[s.Title] = s.Findings
	}
	return m
}

func hasFail(findings []struct{ Status, Label, Detail string }, label string) bool {
	for _, f := range findings {
		if f.Label == label && f.Status == "FAIL" {
			return true
		}
	}
	return false
}

// Finding #1: an irrelevant env secret must not be accepted as the credential.
// A Platform target (client-id) with only DELINEA_TOOLS_PASSWORD and no
// client_secret is rejected by run/print (platform needs client_secret); check
// must fail it too rather than call the client credentials OK and exit 0.
func TestLocalCheckRejectsIrrelevantEnvSecret(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_CLIENT_ID", "svc-ci")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "hunter2") // wrong slot for a platform target

	out, err := runInProcess(t, "", "check", "--json")
	if err == nil {
		t.Fatalf("platform target with only a password (no client_secret) must fail check\n%s", out)
	}
	if !hasFail(checkSections(t, out)["credential"], "credential") {
		t.Errorf("no credential FAIL; check accepted an irrelevant env secret:\n%s", out)
	}
}

// Finding #2: --secret-stdin with an empty pipe clears the credential exactly as
// run/print do (an empty forced stdin routes to an empty slot / clears the
// token), so an exported DELINEA_TOOLS_TOKEN must not rescue it. check must fail.
func TestLocalCheckSecretStdinEmptyPipeFails(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")

	out, err := runInProcess(t, "", "check", "--secret-stdin", "--json")
	if err == nil {
		t.Fatalf("--secret-stdin with an empty pipe must fail check\n%s", out)
	}
	// An empty forced pipe is a stdin-delivery failure (the same class as a
	// malformed one), reported as a stdin FAIL rather than silently clearing
	// the credential and misreporting a generic "no credentials".
	if !hasFail(checkSections(t, out)["credential"], "stdin") {
		t.Errorf("no stdin FAIL for the empty forced stdin:\n%s", out)
	}
}

// A supplied bearer token has no grant to validate it, so check must make its
// read-only authenticated request even when there are no secret mappings.
func TestLocalCheckRejectsWrongBearerWithoutMappings(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TARGET", "ss")
	t.Setenv("DELINEA_TOOLS_TOKEN", "wrong-token")

	out, err := runInProcess(t, "", "check", "--json")
	if err == nil {
		t.Fatalf("a rejected bearer token must fail check without mappings\n%s", out)
	}
	if !hasFail(checkSections(t, out)["credential"], "credential") {
		t.Errorf("no credential failure for the rejected bearer token:\n%s", out)
	}
}

// A Platform bearer token is validated against the vault broker when the
// target says platform, exactly where run/print would route.
func TestLocalCheckValidatesPlatformBearerWithoutMappings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"accepted", "platform-token", false},
		{"rejected", "wrong-token", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := loopbackPlatform(t)
			clearDelineaEnv(t)
			t.Setenv("DELINEA_TOOLS_URL", srv.URL)
			t.Setenv("DELINEA_TOOLS_TARGET", "platform")
			t.Setenv("DELINEA_TOOLS_TOKEN", tc.token)

			out, err := runInProcess(t, "", "check", "--json")
			if (err != nil) != tc.wantErr {
				t.Fatalf("check error = %v, wantErr %v\n%s", err, tc.wantErr, out)
			}
			if got := hasFail(checkSections(t, out)["credential"], "credential"); got != tc.wantErr {
				t.Errorf("credential failure = %v, want %v:\n%s", got, tc.wantErr, out)
			}
		})
	}
}

// A bearer token needs no target for raw API requests. check uses the
// Delinea-credential-free probe to select its read-only validation endpoint
// without changing how a later secrets mapping would be routed.
func TestLocalCheckBearerAutoAgainstPlatformValidates(t *testing.T) {
	srv := loopbackPlatform(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "platform-token")

	out, err := runInProcess(t, "", "check", "--json")
	if err != nil {
		t.Fatalf("auto target against a Platform backend should validate: %v\n%s", err, out)
	}
	sections := checkSections(t, out)
	if hasFail(sections["vault"], "DELINEA_TOOLS_TARGET") {
		t.Errorf("targetless bearer token was reported as a mismatch:\n%s", out)
	}
	if hasFail(sections["credential"], "credential") {
		t.Errorf("valid Platform bearer token was rejected:\n%s", out)
	}
}

// The mismatch guard must not fire when the backend matches the default:
// a bearer token with no target against Secret Server validates there.
func TestLocalCheckBearerAutoAgainstSSValidates(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")

	out, err := runInProcess(t, "", "check", "--json")
	if err != nil {
		t.Fatalf("bearer token with auto target against Secret Server should validate: %v\n%s", err, out)
	}
	if hasFail(checkSections(t, out)["credential"], "credential") {
		t.Errorf("credential section failed for a valid token:\n%s", out)
	}
}

// Credential-free reachability has no target to contradict: raw requests and a
// future bearer token can use either backend without selecting a grant type.
func TestLocalCheckCredentialFreePlatformNeedsNoTarget(t *testing.T) {
	srv := loopbackPlatform(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)

	out, err := runInProcess(t, "", "check", "--json")
	if err != nil {
		t.Fatalf("credential-free check against a Platform backend should pass: %v\n%s", err, out)
	}
	if hasFail(checkSections(t, out)["vault"], "DELINEA_TOOLS_TARGET") {
		t.Errorf("credential-free check invented a target mismatch:\n%s", out)
	}
}

// --no-auth keeps the Delinea credential out of every request while retaining
// a gateway header needed to reach the health endpoint. The grant endpoint must
// not be touched, the credential section reports the skip, and check passes on
// a healthy config — the mode a monitoring loop uses so a stale Delinea
// credential cannot burn failed-login attempts.
func TestLocalCheckNoAuthSkipsDelineaCredential(t *testing.T) {
	const gatewaySecret = "gateway-secret"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Gateway-Key") != gatewaySecret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"healthy":true}`)
	})
	var granted atomic.Bool
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		granted.Store(true)
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "stale-rotated-password")
	headerFile := filepath.Join(t.TempDir(), "gateway.headers")
	if err := os.WriteFile(headerFile, []byte("X-Gateway-Key: "+gatewaySecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DELINEA_TOOLS_GATEWAY_HEADER_FILE", headerFile)

	out, err := runInProcess(t, "", "check", "--no-auth", "--json")
	if err != nil {
		t.Fatalf("check --no-auth on a healthy config: %v\n%s", err, out)
	}
	if granted.Load() {
		t.Error("--no-auth still sent the credential to the token endpoint")
	}
	skipSeen := false
	for _, f := range checkSections(t, out)["credential"] {
		if f.Label == "credential" && f.Status == "skip" && strings.Contains(f.Detail, "--no-auth") {
			skipSeen = true
		}
	}
	if !skipSeen {
		t.Errorf("credential section should report the --no-auth skip:\n%s", out)
	}
}

func TestLocalCheckNoAuthDoesNotReadCredentialStdin(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)

	out, err := runInProcess(t, "\x00malformed", "check", "--no-auth", "--secret-stdin", "--json")
	if err != nil {
		t.Fatalf("--no-auth treated credential stdin as input: %v\n%s", err, out)
	}
	for _, f := range checkSections(t, out)["credential"] {
		if f.Label == "stdin" || strings.Contains(f.Detail, "NUL") {
			t.Fatalf("--no-auth inspected credential stdin: %+v", f)
		}
	}
}

// An unreachable host is one problem, not two: reachability fails, and the
// credential section skips (the grant is not burned against a dead host and
// the outage is not misattributed to the credential).
func TestLocalCheckUnreachableSkipsCredential(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://127.0.0.1:1")
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "pw")

	out, err := runInProcess(t, "", "check", "--json")
	if err == nil || !strings.Contains(err.Error(), "1 problem") {
		t.Fatalf("got %v, want exactly one problem (the reachability failure)\n%s", err, out)
	}
	sections := checkSections(t, out)
	if !hasFail(sections["vault"], "reachability") {
		t.Errorf("no reachability failure:\n%s", out)
	}
	credSkip := false
	for _, f := range sections["credential"] {
		if f.Label == "credential" && f.Status == "skip" && strings.Contains(f.Detail, "unreachable") {
			credSkip = true
		}
	}
	if !credSkip {
		t.Errorf("credential section should skip with the unreachable reason, not re-report the outage:\n%s", out)
	}
}

func TestLocalCheckUnreachableStillRejectsPartialCredential(t *testing.T) {
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", "https://127.0.0.1:1")
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")

	out, err := runInProcess(t, "", "check", "--json")
	if err == nil {
		t.Fatalf("partial credential must fail independently of reachability\n%s", out)
	}
	sections := checkSections(t, out)
	if !hasFail(sections["credential"], "credential") {
		t.Errorf("partial credential was hidden by the outage:\n%s", out)
	}
}

// Finding #3a: the credential-free path must still report DELINEA_TOOLS_DOMAIN.
func TestLocalCheckCredentialFreeReportsDomain(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)

	out, _ := runInProcess(t, "", "check", "--json")
	found := false
	for _, f := range checkSections(t, out)["credential"] {
		if f.Label == "DELINEA_TOOLS_DOMAIN" {
			found = true
		}
	}
	if !found {
		t.Errorf("credential-free check omitted DELINEA_TOOLS_DOMAIN:\n%s", out)
	}
}

func TestLocalPrintWrongPassword(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")
	_, err := runInProcess(t, "wrong", "print", "--secret-stdin", "--via", "json", "DB=password#128")
	if err == nil || !strings.Contains(err.Error(), "username and password were rejected") {
		t.Errorf("got %v, want the invalid_grant cause named", err)
	}
}

func TestLocalCheckJSON(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")

	out, err := runInProcess(t, "pw", "check", "--secret-stdin", "--json", "DB=password#128")
	if err != nil {
		t.Fatalf("got %v\n%s", err, out)
	}
	var doc struct {
		Summary  map[string]int `json:"summary"`
		Sections []struct {
			Title    string `json:"title"`
			Findings []struct{ Status, Label, Detail string }
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc.Summary["FAIL"] != 0 {
		t.Errorf("healthy loopback config reported failures:\n%s", out)
	}
	backendSeen, resolvedSeen := false, false
	for _, s := range doc.Sections {
		for _, f := range s.Findings {
			if f.Label == "backend" && strings.Contains(f.Detail, "Secret Server") {
				backendSeen = true
			}
			if f.Label == "DB" && strings.Contains(f.Detail, "6 bytes") {
				resolvedSeen = true
			}
			if strings.Contains(f.Detail, "s3cr3t") {
				t.Errorf("check printed a secret value: %+v", f)
			}
		}
	}
	if !backendSeen {
		t.Errorf("no backend finding naming Secret Server:\n%s", out)
	}
	if !resolvedSeen {
		t.Errorf("no resolution finding for DB with a byte count:\n%s", out)
	}
}

// A target that contradicts the probed backend must fail check: the loopback
// server answers as Secret Server while platform is configured.
func TestLocalCheckTargetMismatch(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TARGET", "platform")

	out, err := runInProcess(t, "", "check", "--json")
	if err == nil {
		t.Fatalf("want check to fail on the mismatch\n%s", out)
	}
	if !strings.Contains(out, "Secret Server answered") {
		t.Errorf("no mismatch finding in output:\n%s", out)
	}
}

// A secret whose resolved name collides with a baseline variable is refused
// before the child is launched, end to end through run --via env.
func TestLocalRunRefusesBaselineShadow(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")
	// The resolved name PATH collides with a baseline variable.
	_, err := runInProcess(t, "pw", "run", "--secret-stdin", "PATH=password#128", "--", "true")
	if err == nil || !strings.Contains(err.Error(), "baseline environment variable") {
		t.Errorf("got %v, want a baseline-shadowing refusal", err)
	}
}

func TestLocalTemplateOut(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")

	dir := t.TempDir()
	tmpl := dir + "/t.tmpl"
	outFile := dir + "/out.conf"
	if err := os.WriteFile(tmpl, []byte("user={{.U}} pass={{.DB}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runInProcess(t, "pw", "template", "--secret-stdin", "--in", tmpl, "--out", outFile, "U=username#128", "DB=password#128"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "user=svc-db pass=s3cr3t" {
		t.Errorf("rendered: got %q", b)
	}
}

// A raw-verb flag the router let through must be named as an unknown flag,
// not surfaced as a cryptic mapping-parse error.
func TestLocalUnknownForwardedFlagIsNamed(t *testing.T) {
	srv := loopbackSS(t)
	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token")

	_, err := runInProcess(t, "", "print", "-v", "DB=password#128")
	if err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("got %v, want an unknown-flag error for -v", err)
	}
	if err != nil && strings.Contains(err.Error(), "invalid mapping") {
		t.Errorf("-v must not be reported as a mapping error: %v", err)
	}
}

// The CLI opts every client out of the shared cross-client token cache
// (DisableCache), because a one-shot process never reads it. These two
// in-process invocations share this test process — and therefore the same
// package-wide default cache — so if the CLI participated in it, the second
// would reuse the first's token and the server would see one grant. It must
// see two: each invocation authenticates for itself, exactly as separate
// CLI processes would.
func TestCLIInvocationsDoNotShareTheProcessCache(t *testing.T) {
	var grants atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		grants.Add(1)
		fmt.Fprint(w, `{"access_token":"test-token","token_type":"bearer","expires_in":3600}`)
	})
	mux.HandleFunc("/api/v1/secrets/128", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"id":128,"name":"db","items":[{"fieldName":"Password","slug":"password","itemValue":"s3cr3t"}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	clearDelineaEnv(t)
	t.Setenv("DELINEA_TOOLS_URL", srv.URL)
	t.Setenv("DELINEA_TOOLS_USERNAME", "svc")
	t.Setenv("DELINEA_TOOLS_PASSWORD", "pw")

	for range 2 {
		if _, err := runInProcess(t, "", "print", "--via", "raw", "DB=password#128"); err != nil {
			t.Fatal(err)
		}
	}
	if got := grants.Load(); got != 2 {
		t.Errorf("grants: got %d, want 2 (each CLI invocation must authenticate for itself, not reuse a shared-cache token)", got)
	}
}
