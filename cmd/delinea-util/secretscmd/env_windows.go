//go:build windows

package secretscmd

import "strings"

// baseline is the set of variables a child inherits. See env_unix.go for the
// rule that decides membership; the Windows list adds the directory and machine
// variables a process needs to start correctly, and omits the proxy and trust
// variables for the same reason.
var baseline = []string{
	"PATH", "PATHEXT", "COMSPEC",
	"SystemRoot", "windir", "SystemDrive",
	"TEMP", "TMP",
	"USERPROFILE", "HOMEDRIVE", "HOMEPATH",
	"APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
	"ProgramFiles", "ProgramFiles(x86)",
	"USERNAME", "USERDOMAIN", "COMPUTERNAME",
	"NUMBER_OF_PROCESSORS", "OS", "PROCESSOR_ARCHITECTURE",
	// Usually unset on Windows, but a Git-Bash, MSYS or WSL-interop child reads
	// them, and LC_CTYPE decides how it interprets bytes.
	"TZ", "LANG", "LC_ALL", "LC_CTYPE",
}

// inBaseline folds case: Windows environment names are case-insensitive, and
// os.Environ reports the system's own casing (commonly "Path", not "PATH").
func inBaseline(name string) bool {
	for _, b := range baseline {
		if strings.EqualFold(b, name) {
			return true
		}
	}
	return false
}

// envNameKey folds to upper case for the same reason inBaseline folds: the
// child's environment is case-insensitive, so every guard keyed by variable
// name (collisions, unsafeChildVars) must treat Node_Options as NODE_OPTIONS.
func envNameKey(name string) string { return strings.ToUpper(name) }

// Windows process environments are UTF-16; Go converts values from UTF-8.
const envRequiresUTF8 = true
