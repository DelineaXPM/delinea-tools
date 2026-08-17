//go:build e2e

package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/DelineaXPM/delinea-tools/api"
	"github.com/DelineaXPM/delinea-tools/internal/e2etest"
)

// These end-to-end tests hit a real Delinea instance using fixture environment
// variables. They are excluded from the default build and run only with:
//
//	go test -tags e2e ./...
//
// Each test skips when its fixtures are absent, and none print secret values.
// The fixture variables and their meanings are documented in docs/E2E.txt.

func requireEnv(t *testing.T, keys ...string) map[string]string {
	t.Helper()
	return e2etest.Require(t, keys...)
}

func e2eCheck(t *testing.T, cfg Config, mapping, want string) {
	t.Helper()
	m, err := ParseMapping(mapping)
	if err != nil {
		t.Fatalf("ParseMapping: %v", err)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	vars, err := c.Resolve(context.Background(), []Mapping{m})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(vars) != 1 {
		t.Fatalf("got %d vars, want 1", len(vars))
	}
	if vars[0].Value != want {
		t.Errorf("resolved value != expected fixture value (got len %d, want len %d)", len(vars[0].Value), len(want))
	}
}

func ssConfig(e map[string]string) Config {
	return Config{
		URL:      e["DELINEA_TOOLS_TEST_SS_URL"],
		Username: e["DELINEA_TOOLS_TEST_SS_USERNAME"],
		Password: e["DELINEA_TOOLS_TEST_SS_PASSWORD"],
		Timeout:  30 * time.Second,
		Retries:  3,
	}
}

func platformConfig(e map[string]string) Config {
	return Config{
		URL:      e["DELINEA_TOOLS_TEST_PLATFORM_URL"],
		Target:   api.TargetPlatform,
		Username: e["DELINEA_TOOLS_TEST_PLATFORM_CLIENT_ID"],
		Password: e["DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET"],
		Timeout:  30 * time.Second,
		Retries:  3,
	}
}

func TestE2ESecretServer(t *testing.T) {
	e := requireEnv(t,
		"DELINEA_TOOLS_TEST_SS_URL", "DELINEA_TOOLS_TEST_SS_USERNAME", "DELINEA_TOOLS_TEST_SS_PASSWORD",
		"DELINEA_TOOLS_TEST_SS_SECRET_ID", "DELINEA_TOOLS_TEST_SS_SECRET_FIELD", "DELINEA_TOOLS_TEST_SS_SECRET_VALUE")
	e2eCheck(t, ssConfig(e),
		"V="+e["DELINEA_TOOLS_TEST_SS_SECRET_FIELD"]+"#"+e["DELINEA_TOOLS_TEST_SS_SECRET_ID"], e["DELINEA_TOOLS_TEST_SS_SECRET_VALUE"])
}

// Resolving by path exercises the mapping syntax that no id-based fixture can:
// the path fixture must name the same secret as the id fixture, so both must
// yield the same value. Only ever referencing secrets by id is why a broken
// @path syntax went unnoticed.
func TestE2ESecretServerByPath(t *testing.T) {
	e := requireEnv(t,
		"DELINEA_TOOLS_TEST_SS_URL", "DELINEA_TOOLS_TEST_SS_USERNAME", "DELINEA_TOOLS_TEST_SS_PASSWORD",
		"DELINEA_TOOLS_TEST_SS_SECRET_PATH", "DELINEA_TOOLS_TEST_SS_SECRET_FIELD", "DELINEA_TOOLS_TEST_SS_SECRET_VALUE")
	e2eCheck(t, ssConfig(e),
		"V="+e["DELINEA_TOOLS_TEST_SS_SECRET_FIELD"]+"@"+e["DELINEA_TOOLS_TEST_SS_SECRET_PATH"], e["DELINEA_TOOLS_TEST_SS_SECRET_VALUE"])
}

func TestE2EPlatform(t *testing.T) {
	e := requireEnv(t,
		"DELINEA_TOOLS_TEST_PLATFORM_URL", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_ID", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET",
		"DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID", "DELINEA_TOOLS_TEST_PLATFORM_SECRET_FIELD", "DELINEA_TOOLS_TEST_PLATFORM_SECRET_VALUE")
	e2eCheck(t, platformConfig(e),
		"V="+e["DELINEA_TOOLS_TEST_PLATFORM_SECRET_FIELD"]+"#"+e["DELINEA_TOOLS_TEST_PLATFORM_SECRET_ID"], e["DELINEA_TOOLS_TEST_PLATFORM_SECRET_VALUE"])
}

func TestE2EPlatformByPath(t *testing.T) {
	e := requireEnv(t,
		"DELINEA_TOOLS_TEST_PLATFORM_URL", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_ID", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET",
		"DELINEA_TOOLS_TEST_PLATFORM_SECRET_PATH", "DELINEA_TOOLS_TEST_PLATFORM_SECRET_FIELD", "DELINEA_TOOLS_TEST_PLATFORM_SECRET_VALUE")
	e2eCheck(t, platformConfig(e),
		"V="+e["DELINEA_TOOLS_TEST_PLATFORM_SECRET_FIELD"]+"@"+e["DELINEA_TOOLS_TEST_PLATFORM_SECRET_PATH"], e["DELINEA_TOOLS_TEST_PLATFORM_SECRET_VALUE"])
}

func e2eAttachment(t *testing.T, cfg Config, id, field, wantDigest string) {
	t.Helper()
	mapping, err := ParseMapping("FILE=" + field + "#" + id)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	vars, err := client.Resolve(context.Background(), []Mapping{mapping})
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 1 {
		t.Fatalf("got %d attachment values, want 1", len(vars))
	}
	want, err := hex.DecodeString(wantDigest)
	if err != nil || len(want) != sha256.Size {
		t.Fatalf("attachment SHA-256 fixture must be 64 hexadecimal characters")
	}
	got := sha256.Sum256([]byte(vars[0].Value))
	if !bytes.Equal(got[:], want) {
		t.Fatal("downloaded attachment digest does not match the fixture")
	}
}

func TestE2ESecretServerAttachment(t *testing.T) {
	base := requireEnv(t, "DELINEA_TOOLS_TEST_SS_URL", "DELINEA_TOOLS_TEST_SS_USERNAME", "DELINEA_TOOLS_TEST_SS_PASSWORD")
	f := e2etest.Require(t,
		"DELINEA_TOOLS_TEST_SS_FILE_SECRET_ID", "DELINEA_TOOLS_TEST_SS_FILE_SECRET_FIELD",
		"DELINEA_TOOLS_TEST_SS_FILE_SHA256")
	e2eAttachment(t, ssConfig(base), f["DELINEA_TOOLS_TEST_SS_FILE_SECRET_ID"],
		f["DELINEA_TOOLS_TEST_SS_FILE_SECRET_FIELD"], f["DELINEA_TOOLS_TEST_SS_FILE_SHA256"])
}

func TestE2EPlatformAttachment(t *testing.T) {
	base := requireEnv(t, "DELINEA_TOOLS_TEST_PLATFORM_URL", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_ID", "DELINEA_TOOLS_TEST_PLATFORM_CLIENT_SECRET")
	f := e2etest.Require(t,
		"DELINEA_TOOLS_TEST_PLATFORM_FILE_SECRET_ID", "DELINEA_TOOLS_TEST_PLATFORM_FILE_SECRET_FIELD",
		"DELINEA_TOOLS_TEST_PLATFORM_FILE_SHA256")
	e2eAttachment(t, platformConfig(base), f["DELINEA_TOOLS_TEST_PLATFORM_FILE_SECRET_ID"],
		f["DELINEA_TOOLS_TEST_PLATFORM_FILE_SECRET_FIELD"], f["DELINEA_TOOLS_TEST_PLATFORM_FILE_SHA256"])
}
