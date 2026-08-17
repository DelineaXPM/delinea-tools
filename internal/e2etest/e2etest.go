//go:build e2e

// Package e2etest holds fixture policy shared by the live test suites.
package e2etest

import (
	"os"
	"strings"
	"testing"
)

const requireEnv = "DELINEA_TOOLS_TEST_REQUIRE_E2E"

// Require returns the named environment fixtures. Missing fixtures skip a
// developer or fork run, but fail when the scheduled suite opts into strict
// fixture enforcement with DELINEA_TOOLS_TEST_REQUIRE_E2E.
func Require(t testing.TB, keys ...string) map[string]string {
	t.Helper()
	values := make(map[string]string, len(keys))
	var missing []string
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			values[key] = value
		} else {
			missing = append(missing, key)
		}
	}
	if len(missing) == 0 {
		return values
	}
	message := "missing e2e fixture(s): " + strings.Join(missing, ", ")
	if required() {
		t.Fatal(message)
	}
	t.Skip(message)
	return nil
}

func required() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(requireEnv))) {
	case "1", "true", "yes", "y", "on":
		return true
	}
	return false
}
