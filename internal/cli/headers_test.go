package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadHeaderFiles(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	if err := os.WriteFile(first, []byte("X-Gateway-Key: secret\r\n\nX-Route: west\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("X-Route: east\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := ReadHeaderFiles([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Get("X-Gateway-Key"); got != "secret" {
		t.Errorf("gateway key: got %q", got)
	}
	if got, want := h.Values("X-Route"), []string{"west", "east"}; !reflect.DeepEqual(got, want) {
		t.Errorf("route values: got %v, want %v", got, want)
	}
}

func TestReadHeaderFileErrorsDoNotEchoValues(t *testing.T) {
	dir := t.TempDir()
	const secret = "do-not-repeat-this-secret"
	for name, content := range map[string]string{
		"malformed":     "X-Okay: yes\nmalformed " + secret + "\n",
		"authorization": "\nAuthorization: Bearer " + secret + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := ReadHeaderFile(path)
			if err == nil || !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), secret) {
				t.Errorf("got %v, want a line-2 error without the header value", err)
			}
		})
	}
}

func TestReadHeaderFileBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(path, []byte("X: "+strings.Repeat("a", MaxHeaderFileBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadHeaderFile(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("got %v, want an over-size refusal", err)
	}
}
