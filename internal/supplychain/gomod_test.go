package supplychain

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestGoModDeclaresOnlyCommon(t *testing.T) {
	root := moduleRoot(t)
	parsed, err := declaredModuleFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	want := []moduleRequirement{{Path: "github.com/DelineaXPM/delinea-common", Version: "v1.0.0"}}
	if !slices.Equal(parsed.Require, want) {
		got := make([]string, len(parsed.Require))
		for i, requirement := range parsed.Require {
			got[i] = requirement.String()
		}
		t.Fatalf("go.mod must declare exactly one direct dependency: github.com/DelineaXPM/delinea-common v1.0.0.\n"+
			"actual require directive(s):\n\t%s",
			strings.Join(got, "\n\t"))
	}
	if len(parsed.Replace) != 0 || len(parsed.Exclude) != 0 || len(parsed.Retract) != 0 {
		t.Fatalf("go.mod must not contain replace, exclude, or retract directives (got replace=%d exclude=%d retract=%d)",
			len(parsed.Replace), len(parsed.Exclude), len(parsed.Retract))
	}
}

func TestDeclaredRequirementsUsesGoParser(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []moduleRequirement
	}{
		{"clean", "module x\n\ngo 1.26.6\n", nil},
		{"single", "module x\n\ngo 1.26\n\nrequire golang.org/x/text v0.14.0\n", []moduleRequirement{{Path: "golang.org/x/text", Version: "v0.14.0"}}},
		{"compact block", "module x\n\nrequire(\n\tgolang.org/x/text v0.14.0\n\tgolang.org/x/sys v0.5.0\n)\n", []moduleRequirement{{Path: "golang.org/x/text", Version: "v0.14.0"}, {Path: "golang.org/x/sys", Version: "v0.5.0"}}},
		{"indirect", "module x\n\nrequire golang.org/x/net v0.1.0 // indirect\n", []moduleRequirement{{Path: "golang.org/x/net", Version: "v0.1.0", Indirect: true}}},
		{"require in comment", "module x\n\n// require golang.org/x/text v0.14.0 would break the build\n", nil},
		{"empty compact block", "module x\n\nrequire()\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "go.mod")
			if err := os.WriteFile(path, []byte(tc.in), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := declaredRequirements(path)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("declaredRequirements() = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found in any parent of the test working directory")
		}
		dir = parent
	}
}

type moduleRequirement struct {
	Path     string
	Version  string
	Indirect bool
}

func (r moduleRequirement) String() string {
	s := r.Path + " " + r.Version
	if r.Indirect {
		s += " // indirect"
	}
	return s
}

// declaredRequirements delegates to the Go command's own go.mod parser. The
// -json operation only reads the named file and performs no module resolution
// or network access, while still accepting every syntax the active toolchain
// accepts.
func declaredRequirements(gomod string) ([]moduleRequirement, error) {
	parsed, err := declaredModuleFile(gomod)
	return parsed.Require, err
}

type moduleFile struct {
	Require []moduleRequirement
	Replace []json.RawMessage
	Exclude []moduleRequirement
	Retract []json.RawMessage
}

func declaredModuleFile(gomod string) (moduleFile, error) {
	cmd := exec.Command("go", "mod", "edit", "-json", gomod)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return moduleFile{}, fmt.Errorf("go mod edit: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return moduleFile{}, fmt.Errorf("go mod edit: %w", err)
	}
	var parsed moduleFile
	if err := json.Unmarshal(out, &parsed); err != nil {
		return moduleFile{}, fmt.Errorf("decode go mod edit output: %w", err)
	}
	return parsed, nil
}
