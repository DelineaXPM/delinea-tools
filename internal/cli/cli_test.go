package cli

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

type partialCredentialReader struct{ read bool }

func (r *partialCredentialReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, errors.New("read failed")
	}
	r.read = true
	return copy(p, "partial"), nil
}

func TestReadCredential(t *testing.T) {
	secret, present, err := ReadCredential(strings.NewReader("secret\r\n"))
	if err != nil || !present || secret != "secret" {
		t.Fatalf("clean credential = %q, %v, %v", secret, present, err)
	}
	if secret, present, err = ReadCredential(strings.NewReader("")); err != nil || present || secret != "" {
		t.Fatalf("empty credential = %q, %v, %v", secret, present, err)
	}
	if _, present, err = ReadCredential(&partialCredentialReader{}); err == nil || !present || !strings.Contains(err.Error(), "reading credential") {
		t.Fatalf("partial read = present %v, error %v", present, err)
	}
	if _, present, err = ReadCredential(strings.NewReader(strings.Repeat("x", MaxCredentialBytes+1))); err == nil || !present || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized read = present %v, error %v", present, err)
	}
}

func TestArgumentHelpers(t *testing.T) {
	for _, tt := range []struct {
		arg            string
		name, value    string
		inline         bool
		wantFlagName   string
		wantCredential bool
	}{
		{"--url=https://example.com", "--url", "https://example.com", true, "--url", false},
		{"--url=", "--url", "", true, "--url", false},
		{"--url", "--url", "", false, "--url", false},
		{"-x=value", "-x=value", "", false, "-x", false},
		{"value=secret", "value=secret", "", false, "value", false},
		{"--token=secret", "--token", "secret", true, "--token", true},
	} {
		name, value, inline := SplitInlineFlag(tt.arg)
		if name != tt.name || value != tt.value || inline != tt.inline {
			t.Errorf("SplitInlineFlag(%q) = %q, %q, %v", tt.arg, name, value, inline)
		}
		if got := FlagName(tt.arg); got != tt.wantFlagName {
			t.Errorf("FlagName(%q) = %q, want %q", tt.arg, got, tt.wantFlagName)
		}
		if got := IsCredentialFlag(tt.wantFlagName); got != tt.wantCredential {
			t.Errorf("IsCredentialFlag(%q) = %v, want %v", tt.wantFlagName, got, tt.wantCredential)
		}
	}
	for _, name := range []string{"--password", "--client-secret"} {
		if !IsCredentialFlag(name) {
			t.Errorf("IsCredentialFlag(%q) = false", name)
		}
	}
}

func TestCredentialFlagErrorRedactsInlineValue(t *testing.T) {
	err := CredentialFlagError("--token=SUPERSECRET")
	var usage *UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("got %T, want *UsageError", err)
	}
	if strings.Contains(err.Error(), "SUPERSECRET") || !strings.Contains(err.Error(), "--token") {
		t.Errorf("unsafe or unclear error: %q", err)
	}
}

func TestDocumentationHelpers(t *testing.T) {
	if got := Tree("Commands", []TreeItem{{"one", "first"}, {"two", "last"}}); got != "Commands\n├── one  — first\n└── two  — last\n" {
		t.Errorf("Tree = %q", got)
	}
	var out bytes.Buffer
	PrintDoc(&out, "document\n\n")
	if got := out.String(); got != "\ndocument\n\n" {
		t.Errorf("PrintDoc = %q", got)
	}
}

func TestSplitHosts(t *testing.T) {
	got := SplitHosts(" one.example, ,two.example ,, three.example ")
	want := []string{"one.example", "two.example", "three.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SplitHosts = %v, want %v", got, want)
	}
}

func TestConnConfigFromEnv(t *testing.T) {
	values := map[string]string{
		"DELINEA_TOOLS_URL": "https://example.com", "DELINEA_TOOLS_TARGET": "platform",
		"DELINEA_TOOLS_USERNAME": "user", "DELINEA_TOOLS_PASSWORD": "password", "DELINEA_TOOLS_DOMAIN": "domain",
		"DELINEA_TOOLS_CLIENT_ID": "client", "DELINEA_TOOLS_CLIENT_SECRET": "client-secret", "DELINEA_TOOLS_TOKEN": "token",
		"DELINEA_TOOLS_CA_CERT": "ca.pem", "DELINEA_TOOLS_TIMEOUT": "12s", "DELINEA_TOOLS_RETRIES": "5",
		"DELINEA_TOOLS_TLS_SKIP_VERIFY": "yes", "DELINEA_TOOLS_VAULT_ALLOW": "vault.example.com",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
	want := ConnConfig{
		URL: "https://example.com", Target: "platform", Username: "user", Password: "password", Domain: "domain",
		ClientID: "client", ClientSecret: "client-secret", Token: "token", CACert: "ca.pem", Timeout: "12s", Retries: "5",
		TLSSkipVerify: true, VaultAllowEnv: "vault.example.com",
	}
	if got := ConnConfigFromEnv(); !reflect.DeepEqual(got, want) {
		t.Errorf("ConnConfigFromEnv = %#v, want %#v", got, want)
	}
}

func TestTruthy(t *testing.T) {
	for _, s := range []string{"1", "true", "TRUE", "yes", "on", " y "} {
		if !Truthy(s) {
			t.Errorf("Truthy(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "0", "false", "no", "maybe"} {
		if Truthy(s) {
			t.Errorf("Truthy(%q) = true, want false", s)
		}
	}
}

func TestSanitizeText(t *testing.T) {
	got := SanitizeText("a\x1b[31mred\u009b\rb\nc\td")
	want := "a?[31mred??b\nc\td"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWipe(t *testing.T) {
	b := []byte("s3cr3t")
	Wipe(b)
	for i, c := range b {
		if c != 0 {
			t.Errorf("byte %d not zeroed: %d", i, c)
		}
	}
}

func TestIsTerminalOnPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if IsTerminal(w) {
		t.Errorf("a pipe reported as a terminal")
	}
}

// A descriptor whose Stat fails (here, a closed file) is not a terminal: the
// error branch returns false rather than propagating.
func TestIsTerminalStatError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "f")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if IsTerminal(f) {
		t.Errorf("closed file reported as a terminal")
	}
}

func TestVersion(t *testing.T) {
	v := Version("delinea-thing")
	if !strings.HasPrefix(v, "delinea-thing ") {
		t.Errorf("got %q, want the name as prefix", v)
	}
	if !strings.Contains(v, runtime.GOOS+"/"+runtime.GOARCH) {
		t.Errorf("got %q, want the platform included", v)
	}
}

// versionFrom holds the VCS-stamp formatting that a test binary can't reach
// through Version, since it carries no vcs.* settings of its own.
func TestVersionFrom(t *testing.T) {
	plat := runtime.GOOS + "/" + runtime.GOARCH

	if got := versionFrom("t", nil, false); got != "t (unknown) "+plat {
		t.Errorf("no build info: got %q", got)
	}

	bi := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef0000"},
		{Key: "vcs.modified", Value: "true"},
	}}
	bi.Main.Version = "v1.2.3"
	got := versionFrom("t", bi, true)
	if want := "t v1.2.3 " + plat + " 0123456789ab+dirty"; got != want {
		t.Errorf("dirty revision: got %q, want %q", got, want)
	}

	clean := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "abcdef"},
		{Key: "vcs.modified", Value: "false"},
	}}
	clean.Main.Version = "v1.0.0"
	if got := versionFrom("t", clean, true); got != "t v1.0.0 "+plat+" abcdef" {
		t.Errorf("clean short revision: got %q", got)
	}
}

func TestRequireSecureURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://vault.example.com", false},
		{"HTTPS://vault.example.com", false},
		{"https://vault.example.com:8443/x", false},
		{"https://user:secret@vault.example.com", true},
		{"https://vault.example.com?tenant=one", true},
		{"https://vault.example.com?", true}, // bare '?' => RawQuery "" but ForceQuery true; must match the engine's parseBaseURL
		{"https://vault.example.com#fragment", true},
		{"", false},
		{"http://vault.example.com", true},
		{"http://localhost:8080", false},
		{"HTTP://LOCALHOST:8080", false},
		{"http://127.0.0.1:8080", false},
		{"http://[::1]:8080", false},
		{"ftp://vault.example.com", true},
		{"vault.example.com", true},
		{"https:not-an-absolute-url", true},
		{"http://[::1", true}, // malformed: url.Parse fails
	}
	for _, c := range cases {
		err := RequireSecureURL(c.url, "TEST_URL")
		if c.wantErr && err == nil {
			t.Errorf("RequireSecureURL(%q): got nil error, want error", c.url)
		}
		if !c.wantErr && err != nil {
			t.Errorf("RequireSecureURL(%q): got %v, want nil", c.url, err)
		}
		if err != nil && !strings.Contains(err.Error(), "TEST_URL") {
			t.Errorf("RequireSecureURL(%q): error %q should name the source", c.url, err)
		}
	}
	err := RequireSecureURL("https://user:supersecret@vault.example.com", "TEST_URL")
	if err == nil || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("userinfo error was not redacted: %v", err)
	}
}

func TestRequirePlainUsername(t *testing.T) {
	for _, user := range []string{`CORP\svc-ci`, `corp/svc-ci`} {
		if err := RequirePlainUsername(user); err == nil {
			t.Errorf("%q: got nil error, want a rejection", user)
		} else if !strings.Contains(err.Error(), "DELINEA_TOOLS_DOMAIN") {
			t.Errorf("%q: error %q should name DELINEA_TOOLS_DOMAIN", user, err)
		}
	}
	// A UPN is legitimate for the Platform and for some AD configurations.
	for _, user := range []string{"svc-ci", "someone@tenant", ""} {
		if err := RequirePlainUsername(user); err != nil {
			t.Errorf("%q: got %v, want nil", user, err)
		}
	}
}

// PowerShell re-encodes a pipeline to a native command, so a credential can
// arrive UTF-16 or BOM-prefixed. Those are rejected, never transcoded.
func TestRequireDecodedCredential(t *testing.T) {
	bad := map[string][]byte{
		"utf-8 bom":     append([]byte{0xEF, 0xBB, 0xBF}, "hunter2"...),
		"utf-16le bom":  append([]byte{0xFF, 0xFE}, "h\x00u\x00"...),
		"utf-16be bom":  append([]byte{0xFE, 0xFF}, "\x00h\x00u"...),
		"utf-16 no bom": []byte("h\x00u\x00n\x00t\x00"),
		"trailing nul":  []byte("hunter2\x00"),
	}
	for name, cred := range bad {
		err := RequireDecodedCredential(cred)
		if err == nil {
			t.Errorf("%s: got nil error, want a rejection", name)
			continue
		}
		// The remedy is the point: an opaque denial is what this replaces.
		if !strings.Contains(err.Error(), "OutputEncoding") {
			t.Errorf("%s: error %q should name the fix", name, err)
		}
	}
	for name, cred := range map[string][]byte{
		"plain ascii":   []byte("hunter2"),
		"utf-8 no bom":  []byte("hüntér2"),
		"trailing crlf": []byte("hunter2\r\n"),
		"empty":         {},
		"high bytes":    {0xFF, 0x01},
	} {
		if err := RequireDecodedCredential(cred); err != nil {
			t.Errorf("%s: got %v, want nil", name, err)
		}
	}
}
