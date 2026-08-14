package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/DelineaXPM/delinea-tools/internal/cli"
)

// The verbose (-v) summary is server-controlled and reaches a terminal, so its
// status line and header values must be sanitized.
func TestFprintResponseSummarySanitizes(t *testing.T) {
	var b strings.Builder
	h := http.Header{"X-\x1bEvil": {"a\x1b[31mb"}}
	fprintResponseSummary(&b, "HTTP/1.1", "200 O\x1bK", h)
	out := b.String()
	if strings.ContainsRune(out, '\x1b') {
		t.Errorf("escape survived sanitization: %q", out)
	}
	if !strings.Contains(out, "X-?Evil") {
		t.Errorf("header name dropped: %q", out)
	}
}

func TestSanitizedHeadersStopsWhenConsumerStops(t *testing.T) {
	h := http.Header{"A": {"1", "2"}, "B": {"3"}}
	count := 0
	for range sanitizedHeaders(h) {
		count++
		break
	}
	if count != 1 {
		t.Errorf("iterator yielded %d entries after an early stop, want 1", count)
	}
}

func TestVaultIDRequiresVault(t *testing.T) {
	// --vault-id without --vault is a usage error, before any network call.
	// No credential is needed to reach the check (and one could never be passed
	// as a flag anyway).
	err := dispatch([]string{"--url", "https://x", "--vault-id", "2", "GET", "/api/v1/secrets/9"})
	if _, ok := err.(*cli.UsageError); !ok {
		t.Errorf("got %v (%T), want a usageErr", err, err)
	}
}

// The credential is never accepted as a command-line argument: --token,
// --password and --client-secret are rejected with a usage error (argv is
// world-readable). This holds for the raw-API verbs.
func TestSecretFlagsRejected(t *testing.T) {
	const secret = "SUPERSECRET"
	for _, flag := range [][]string{
		{"--token", secret}, {"--password", secret}, {"--client-secret", secret},
		{"--token=" + secret}, {"--password=" + secret}, {"--client-secret=" + secret},
	} {
		for _, args := range [][]string{
			append(append([]string{"--url", "https://x"}, flag...), "GET", "/api/v1/secrets/9"),
			append(append([]string{}, flag...), "GET", "/api/v1/secrets/9"),
		} {
			err := dispatch(args)
			if _, ok := err.(*cli.UsageError); !ok {
				t.Errorf("%v: got %v (%T), want a usage error rejecting the secret flag", args, err, err)
				continue
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%v: rejected credential appeared in error %q", args, err)
			}
		}
	}
}

// No error path may echo a flag's inline value: a mistyped credential flag
// ("--pasword=SECRET"), a Go-style single dash ("-token=SECRET"), or a
// credential flag between "secrets" and its verb all carry the secret in the
// argument, and repeating the argument writes it into scrollback and CI logs.
func TestUnknownFlagErrorsNeverEchoInlineValues(t *testing.T) {
	const secret = "SUPERSECRET"
	for _, args := range [][]string{
		{"--pasword=" + secret, "GET", "/x"},              // typo of --password
		{"-token=" + secret, "GET", "/x"},                 // single-dash form
		{"--pasword=" + secret, "check"},                  // before a routed verb
		{"secrets", "--token=" + secret, "run", "M=a#1"},  // between secrets and its verb
		{"secrets", "--tokenn=" + secret, "run", "M=a#1"}, // typo'd, same slot
	} {
		err := dispatch(args)
		if err == nil {
			t.Errorf("%v: want an error", args)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%v: secret echoed in error %q", args, err)
		}
	}
	// The credential-flag rejection still names the flag so the remedy is clear.
	err := dispatch([]string{"secrets", "--token=" + secret, "run", "M=a#1"})
	if err == nil || !strings.Contains(err.Error(), "--token") || !strings.Contains(err.Error(), "never taken as a command-line argument") {
		t.Errorf("credential flag after secrets: got %v, want the name-only credential rejection", err)
	}
}

func TestParseArgsVaultID(t *testing.T) {
	cc := cliConfig{}
	o, err := parseArgs([]string{"--vault", "--vault-id", "7", "GET", "/x"}, &cc)
	if err != nil {
		t.Fatal(err)
	}
	if !o.useVault || o.vaultID != "7" {
		t.Errorf("got useVault=%v vaultID=%q, want true/7", o.useVault, o.vaultID)
	}
}

func TestBuildConfigRejectsInsecureURL(t *testing.T) {
	if _, err := buildConfig(cliConfig{URL: "http://vault.example.com", Token: "t"}); err == nil {
		t.Errorf("http URL: want error")
	}
	if _, err := buildConfig(cliConfig{URL: "http://127.0.0.1:8080", Token: "t"}); err != nil {
		t.Errorf("loopback http URL: got %v, want nil", err)
	}
}

// PowerShell re-encodes a pipeline to a native command, so a secret can arrive
// UTF-16 or BOM-prefixed. Those are rejected, never transcoded.
func TestReadSecretStdinRejectsMisencoded(t *testing.T) {
	bad := map[string][]byte{
		"utf-8 bom":     append([]byte{0xEF, 0xBB, 0xBF}, "hunter2"...),
		"utf-16le bom":  append([]byte{0xFF, 0xFE}, "h\x00u\x00"...),
		"utf-16be bom":  append([]byte{0xFE, 0xFF}, "\x00h\x00u"...),
		"utf-16 no bom": []byte("h\x00u\x00n\x00t\x00"),
	}
	for name, cred := range bad {
		_, err := readSecretStdin(strings.NewReader(string(cred)))
		if err == nil {
			t.Errorf("%s: got nil error, want a rejection", name)
			continue
		}
		// The remedy is the point: an opaque denial is what this replaces.
		if !strings.Contains(err.Error(), "OutputEncoding") {
			t.Errorf("%s: error %q should name the fix", name, err)
		}
	}
	if got, err := readSecretStdin(strings.NewReader("hüntér2\r\n")); err != nil || got != "hüntér2" {
		t.Errorf("clean utf-8: got (%q, %v), want it accepted", got, err)
	}
}

func TestReadSecretStdinTooLarge(t *testing.T) {
	if _, err := readSecretStdin(strings.NewReader(strings.Repeat("a", cli.MaxCredentialBytes+1))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("over-length secret: got %v, want an exceeds error", err)
	}
	got, err := readSecretStdin(strings.NewReader(strings.Repeat("a", cli.MaxCredentialBytes)))
	if err != nil || len(got) != cli.MaxCredentialBytes {
		t.Errorf("secret at limit: got (len %d, %v), want it accepted", len(got), err)
	}
}
