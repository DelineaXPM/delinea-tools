//go:build e2e

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DelineaXPM/delinea-tools/internal/e2etest"
)

// binPath is the freshly-built CLI, compiled once in TestMain. These tests
// run only with `go test -tags e2e ./...`, skip when fixtures are absent, and
// never print secret values.
var binPath string

func TestMain(m *testing.M) {
	os.Exit(func() int {
		dir, err := os.MkdirTemp("", "da-e2e")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer os.RemoveAll(dir)
		binPath = filepath.Join(dir, "delinea-util")
		if runtime.GOOS == "windows" {
			binPath += ".exe"
		}
		build := exec.Command("go", "build", "-o", binPath, ".")
		build.Stderr = os.Stderr
		if err := build.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "building CLI:", err)
			return 1
		}
		return m.Run()
	}())
}

func baseEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DELINEA_TOOLS_") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func ssEnv(t *testing.T) []string {
	t.Helper()
	f := e2etest.Require(t, "DELINEA_TOOLS_TEST_SS_URL", "DELINEA_TOOLS_TEST_SS_USERNAME", "DELINEA_TOOLS_TEST_SS_PASSWORD")
	return append(baseEnv(),
		"DELINEA_TOOLS_URL="+f["DELINEA_TOOLS_TEST_SS_URL"],
		"DELINEA_TOOLS_USERNAME="+f["DELINEA_TOOLS_TEST_SS_USERNAME"],
		"DELINEA_TOOLS_PASSWORD="+f["DELINEA_TOOLS_TEST_SS_PASSWORD"],
	)
}

func platformEnv(t *testing.T) []string {
	t.Helper()
	f := e2etest.Require(t, "DELINEA_TOOLS_TEST_PLATFORM_URL", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_ID", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET")
	return append(baseEnv(),
		"DELINEA_TOOLS_URL="+f["DELINEA_TOOLS_TEST_PLATFORM_URL"],
		"DELINEA_TOOLS_CLIENT_ID="+f["DELINEA_TOOLS_TEST_PLATFORM_CLIENT_ID"],
		"DELINEA_TOOLS_CLIENT_SECRET="+f["DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET"],
	)
}

func runCLI(env []string, args ...string) (stdout, stderr string, code int) {
	return runCLIStdin(env, "", args...)
}

func runCLIStdin(env []string, stdin string, args ...string) (stdout, stderr string, code int) {
	cmd := exec.Command(binPath, args...)
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		code = -1
	}
	return out.String(), errb.String(), code
}

type checkReport struct {
	Summary  map[string]int `json:"summary"`
	Sections []struct {
		Findings []struct {
			Status string `json:"status"`
			Label  string `json:"label"`
		} `json:"findings"`
	} `json:"sections"`
}

func parseCheckReport(t *testing.T, stdout string) checkReport {
	t.Helper()
	var report checkReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("check output is not JSON: %v", err)
	}
	if len(report.Summary) == 0 || len(report.Sections) == 0 {
		t.Fatal("check returned an empty report")
	}
	if report.Summary["FAIL"] != 0 {
		t.Fatalf("check JSON reports %d failures despite a zero exit", report.Summary["FAIL"])
	}
	return report
}

func TestCLISecretServerCurrentUser(t *testing.T) {
	stdout, stderr, code := runCLI(ssEnv(t), "GET", "/api/v1/users/current")
	if code != 0 {
		t.Fatalf("exit: got %d, want 0 (stderr: %s)", code, stderr)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestCLINonexistentSecretExitCode(t *testing.T) {
	stdout, stderr, code := runCLI(ssEnv(t), "GET", "/api/v1/secrets/999999999")
	if code != 4 {
		t.Fatalf("exit: got %d, want 4 (stdout len %d, stderr: %s)", code, len(stdout), stderr)
	}
	if !strings.Contains(stderr, "HTTP") {
		t.Errorf("stderr should summarize the HTTP status: %s", stderr)
	}
}

func TestCLITokenReuse(t *testing.T) {
	stdout, stderr, code := runCLI(ssEnv(t), "token")
	if code != 0 {
		t.Fatalf("exit: got %d, want 0 (stderr: %s)", code, stderr)
	}
	tok := strings.TrimSpace(stdout)
	if len(tok) < 20 {
		t.Fatalf("token suspiciously short: len %d", len(tok))
	}
	url := e2etest.Require(t, "DELINEA_TOOLS_TEST_SS_URL")["DELINEA_TOOLS_TEST_SS_URL"]
	env := append(baseEnv(), "DELINEA_TOOLS_URL="+url, "DELINEA_TOOLS_TOKEN="+tok)
	stdout, stderr, code = runCLI(env, "GET", "/api/v1/users/current")
	if code != 0 {
		t.Fatalf("GET current user with reused Token: exit %d (stderr: %s)", code, stderr)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestCLISecretStdin(t *testing.T) {
	password := e2etest.Require(t, "DELINEA_TOOLS_TEST_SS_PASSWORD")["DELINEA_TOOLS_TEST_SS_PASSWORD"]
	var env []string
	for _, kv := range ssEnv(t) {
		if strings.HasPrefix(kv, "DELINEA_TOOLS_PASSWORD=") {
			continue
		}
		env = append(env, kv)
	}
	stdout, stderr, code := runCLIStdin(env, password+"\n", "--secret-stdin", "GET", "/api/v1/users/current")
	if code != 0 {
		t.Fatalf("exit: got %d, want 0 (stderr: %s)", code, stderr)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestCLIPlatformSecretStdin(t *testing.T) {
	f := e2etest.Require(t, "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET", "DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID")
	var env []string
	for _, kv := range platformEnv(t) {
		if !strings.HasPrefix(kv, "DELINEA_TOOLS_CLIENT_SECRET=") {
			env = append(env, kv)
		}
	}
	stdout, stderr, code := runCLIStdin(env, f["DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET"],
		"--secret-stdin", "--vault", "GET", "/api/v1/secrets/"+f["DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID"])
	if code != 0 {
		t.Fatalf("exit: got %d, want 0 (stderr: %s)", code, stderr)
	}
	var secret map[string]any
	if err := json.Unmarshal([]byte(stdout), &secret); err != nil || secret["id"] == nil {
		t.Fatalf("vault response has no id (parse error %v)", err)
	}
}

func TestCLIBadPasswordExitCode(t *testing.T) {
	env := ssEnv(t)
	for i, kv := range env {
		if strings.HasPrefix(kv, "DELINEA_TOOLS_PASSWORD=") {
			env[i] = "DELINEA_TOOLS_PASSWORD=definitely-wrong-password"
		}
	}
	stdout, _, code := runCLI(env, "GET", "/api/v1/users/current")
	if code != 2 {
		t.Fatalf("exit: got %d, want 2 (stdout len %d)", code, len(stdout))
	}
}

func TestCLIPlatformVaultSecret(t *testing.T) {
	id := e2etest.Require(t, "DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID")["DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID"]
	stdout, stderr, code := runCLI(platformEnv(t), "--vault", "GET", "/api/v1/secrets/"+id)
	if code != 0 {
		t.Fatalf("exit: got %d, want 0 (stderr: %s)", code, stderr)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if m["id"] == nil {
		t.Error("secret response has no id field")
	}
}

func createAndDeleteFolder(t *testing.T, env []string, parentID string, extraArgs ...string) {
	t.Helper()
	name := fmt.Sprintf("delinea-util-e2e-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"folderName":%q,"folderTypeId":1,"parentFolderId":%s,"inheritPermissions":true,"inheritSecretPolicy":true}`, name, parentID)
	stdout, stderr, code := runCLI(env, append(append([]string{}, extraArgs...), "POST", "/api/v1/folders", "-d", body)...)
	if code != 0 {
		t.Fatalf("create folder: exit %d (stderr: %s)", code, stderr)
	}
	var folder struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal([]byte(stdout), &folder); err != nil || folder.ID == 0 {
		t.Fatalf("create response has no id (err %v)", err)
	}
	path := fmt.Sprintf("/api/v1/folders/%d", folder.ID)
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			runCLI(env, append(append([]string{}, extraArgs...), "DELETE", path)...)
		}
	})
	_, stderr, code = runCLI(env, append(append([]string{}, extraArgs...), "DELETE", path)...)
	if code != 0 {
		t.Fatalf("delete folder %d: exit %d (stderr: %s)", folder.ID, code, stderr)
	}
	deleted = true
}

func createAndDeleteSecret(t *testing.T, env []string, folder, template, site string, extraArgs ...string) {
	t.Helper()
	args := func(tail ...string) []string {
		return append(append([]string{}, extraArgs...), tail...)
	}
	stdout, stderr, code := runCLI(env, args("GET", "/api/v1/secret-templates/"+template)...)
	if code != 0 {
		t.Fatalf("fetch template: exit %d (stderr: %s)", code, stderr)
	}
	var tpl struct {
		Fields []struct {
			FieldID    int  `json:"secretTemplateFieldId"`
			IsRequired bool `json:"isRequired"`
			IsFile     bool `json:"isFile"`
		} `json:"fields"`
	}
	if err := json.Unmarshal([]byte(stdout), &tpl); err != nil {
		t.Fatalf("template response: %v", err)
	}
	var items []string
	for _, f := range tpl.Fields {
		if f.IsRequired && !f.IsFile {
			items = append(items, fmt.Sprintf(`{"fieldId":%d,"itemValue":"e2e-%d"}`, f.FieldID, time.Now().UnixNano()))
		}
	}
	if len(items) == 0 {
		t.Fatalf("template %s has no required non-file fields", template)
	}

	name := fmt.Sprintf("delinea-util-e2e-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"name":%q,"secretTemplateId":%s,"folderId":%s,"siteId":%s,"items":[%s]}`,
		name, template, folder, site, strings.Join(items, ","))
	stdout, stderr, code = runCLI(env, args("POST", "/api/v1/secrets", "-d", body)...)
	if code != 0 {
		t.Fatalf("create secret: exit %d (stderr: %s)", code, stderr)
	}
	var secret struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal([]byte(stdout), &secret); err != nil || secret.ID == 0 {
		t.Fatalf("create response has no id (err %v)", err)
	}
	path := fmt.Sprintf("/api/v1/secrets/%d", secret.ID)
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			runCLI(env, args("DELETE", path)...)
		}
	})
	_, stderr, code = runCLI(env, args("DELETE", path)...)
	if code != 0 {
		t.Fatalf("delete secret %d: exit %d (stderr: %s)", secret.ID, code, stderr)
	}
	deleted = true
}

func TestCLISecretServerSecretCreateDelete(t *testing.T) {
	f := e2etest.Require(t, "DELINEA_TOOLS_TEST_SS_FOLDER_ID", "DELINEA_TOOLS_TEST_SS_TEMPLATE_ID", "DELINEA_TOOLS_TEST_SS_SITE_ID")
	createAndDeleteSecret(t, ssEnv(t), f["DELINEA_TOOLS_TEST_SS_FOLDER_ID"],
		f["DELINEA_TOOLS_TEST_SS_TEMPLATE_ID"], f["DELINEA_TOOLS_TEST_SS_SITE_ID"])
}

func TestCLIPlatformVaultSecretCreateDelete(t *testing.T) {
	f := e2etest.Require(t,
		"DELINEA_TOOLS_TEST_PLATFORM_FOLDER_ID", "DELINEA_TOOLS_TEST_PLATFORM_TEMPLATE_ID",
		"DELINEA_TOOLS_TEST_PLATFORM_SITE_ID")
	createAndDeleteSecret(t, platformEnv(t), f["DELINEA_TOOLS_TEST_PLATFORM_FOLDER_ID"],
		f["DELINEA_TOOLS_TEST_PLATFORM_TEMPLATE_ID"], f["DELINEA_TOOLS_TEST_PLATFORM_SITE_ID"], "--vault")
}

func TestCLIPlatformVaultFolderCreateDelete(t *testing.T) {
	env := platformEnv(t)
	parent := e2etest.Require(t, "DELINEA_TOOLS_TEST_PLATFORM_FOLDER_ID")["DELINEA_TOOLS_TEST_PLATFORM_FOLDER_ID"]
	createAndDeleteFolder(t, env, parent, "--vault")
}

func TestCLIPlatformTokenReuse(t *testing.T) {
	stdout, stderr, code := runCLI(platformEnv(t), "token")
	if code != 0 {
		t.Fatalf("token: exit %d (stderr: %s)", code, stderr)
	}
	token := strings.TrimSpace(stdout)
	if len(token) < 20 {
		t.Fatalf("token suspiciously short: len %d", len(token))
	}
	f := e2etest.Require(t, "DELINEA_TOOLS_TEST_PLATFORM_URL", "DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID")
	env := append(baseEnv(),
		"DELINEA_TOOLS_URL="+f["DELINEA_TOOLS_TEST_PLATFORM_URL"],
		"DELINEA_TOOLS_TARGET=platform",
		"DELINEA_TOOLS_TOKEN="+token,
	)
	stdout, stderr, code = runCLI(env, "--vault", "GET", "/api/v1/secrets/"+f["DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID"])
	if code != 0 {
		t.Fatalf("vault request with reused token: exit %d (stderr: %s)", code, stderr)
	}
	var secret map[string]any
	if err := json.Unmarshal([]byte(stdout), &secret); err != nil || secret["id"] == nil {
		t.Fatalf("vault response has no id (parse error %v)", err)
	}
}

func TestCLICheck(t *testing.T) {
	tests := []struct {
		name    string
		env     func(*testing.T) []string
		fixture []string
	}{
		{"secret-server", ssEnv, []string{"DELINEA_TOOLS_TEST_SS_SECRET_FIELD", "DELINEA_TOOLS_TEST_SS_SECRET_ID", "DELINEA_TOOLS_TEST_SS_SECRET_VALUE"}},
		{"platform", platformEnv, []string{"DELINEA_TOOLS_TEST_PLATFORM_SECRET_FIELD", "DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID", "DELINEA_TOOLS_TEST_PLATFORM_SECRET_VALUE"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := tt.env(t)
			stdout, stderr, code := runCLI(env, "check", "--json", "--no-auth")
			if code != 0 {
				t.Fatalf("reachability-only check: exit %d (stderr: %s)", code, stderr)
			}
			parseCheckReport(t, stdout)

			f := e2etest.Require(t, tt.fixture...)
			mapping := "E2E_VALUE=" + f[tt.fixture[0]] + "#" + f[tt.fixture[1]]
			stdout, stderr, code = runCLI(env, "check", "--json", mapping)
			if code != 0 {
				t.Fatalf("authenticated mapping check: exit %d (stderr: %s)", code, stderr)
			}
			if strings.Contains(stdout+stderr, f[tt.fixture[2]]) {
				t.Fatal("check output contains the resolved secret value")
			}
			report := parseCheckReport(t, stdout)
			found := false
			for _, section := range report.Sections {
				for _, finding := range section.Findings {
					if finding.Label == "E2E_VALUE" && finding.Status == "ok" {
						found = true
					}
				}
			}
			if !found {
				t.Fatal("check report has no successful E2E_VALUE mapping finding")
			}
		})
	}
}

// The vault-broker inventory is reached with the raw verb; the dedicated
// "vaults" subcommand was removed (it was sugar for exactly this call and its
// platform-only guard kept accreting complexity).
func TestCLIPlatformVaultBrokerList(t *testing.T) {
	stdout, stderr, code := runCLI(platformEnv(t), "GET", "/vaultbroker/api/vaults")
	if code != 0 {
		t.Fatalf("exit: got %d, want 0 (stderr: %s)", code, stderr)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if m["vaults"] == nil {
		t.Error("response has no vaults field")
	}
}
