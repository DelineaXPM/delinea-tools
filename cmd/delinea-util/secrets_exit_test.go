package main

import (
	"fmt"
	"testing"

	ds "github.com/DelineaXPM/delinea-common/secrets"
)

// End-to-end: a secrets fetch against an unreachable host must exit 3
// (transport), not the generic 1. This exercises the real resolve error path
// through run(), which the isolated exitCode test below does not.
func TestSecretsTransportFailureExits3(t *testing.T) {
	t.Setenv("DELINEA_TOOLS_URL", "https://127.0.0.1:1")
	t.Setenv("DELINEA_TOOLS_TOKEN", "test-token") // token set, so no stdin read
	if got := run([]string{"secrets", "print", "--via", "raw", "DB=password#128"}); got != 3 {
		t.Errorf("run exit = %d, want 3 (transport failure)", got)
	}
}

// exitCode maps the secrets resolver's sentinels to the same documented codes
// as the engine's, so a secrets failure from the "secrets" group does not fall
// through to the generic exit 1: a denial is 2, a transport/timeout is 3. The
// wrapped case proves errors.Is unwraps, which is how resolve surfaces them.
func TestExitCodeMapsSecretsSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"wrapped transport", fmt.Errorf("resolving DB: %w", ds.ErrTransport), 3},
		{"timeout", ds.ErrTimeout, 3},
		{"access denied", ds.ErrAccessDenied, 2},
	}
	for _, c := range cases {
		if got := exitCode(c.err); got != c.want {
			t.Errorf("%s: exitCode = %d, want %d", c.name, got, c.want)
		}
	}
}
