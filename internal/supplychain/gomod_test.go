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

func TestGoModDeclaresNoDependencies(t *testing.T) {
	root := moduleRoot(t)
	requirements, err := declaredRequirements(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	if len(requirements) != 0 {
		got := make([]string, len(requirements))
		for i, requirement := range requirements {
			got[i] = requirement.String()
		}
		t.Fatalf("go.mod declares third-party dependencies, but delinea-tools must import only the Go standard library.\n"+
			"offending require directive(s):\n\t%s\nremove the dependency, or the `go get` that introduced it",
			strings.Join(got, "\n\t"))
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
	cmd := exec.Command("go", "mod", "edit", "-json", gomod)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("go mod edit: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("go mod edit: %w", err)
	}
	var parsed struct {
		Require []moduleRequirement
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("decode go mod edit output: %w", err)
	}
	return parsed.Require, nil
}
