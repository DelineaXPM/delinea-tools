package cli

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// MaxHeaderFileBytes bounds local header configuration. HTTP header sets are
// small; accepting an unbounded file would turn a typo into an avoidable OOM.
const MaxHeaderFileBytes = 1 << 20

// ParseHeaders parses Name: value lines without reproducing a rejected line in
// an error. Header values are an authentication boundary in practice, so every
// value is treated as potentially secret. Authorization remains owned by the
// engine and cannot be supplied through either CLI header mechanism.
func ParseHeaders(raw []string) (http.Header, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	h := http.Header{}
	for i, line := range raw {
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, &UsageError{Msg: fmt.Sprintf("invalid header argument %d (want 'Name: value')", i+1)}
		}
		if strings.EqualFold(name, "Authorization") {
			return nil, &UsageError{Msg: "Authorization cannot be supplied with a header option; use DELINEA_TOOLS_TOKEN or --secret-stdin for a bearer token"}
		}
		h.Add(name, strings.TrimSpace(value))
	}
	return h, nil
}

// ReadHeaderFile reads one Name: value header per non-empty line. It accepts
// LF or CRLF and identifies malformed lines without echoing their contents.
func ReadHeaderFile(path string) (http.Header, error) {
	if path == "" {
		return nil, &UsageError{Msg: "header file path is empty"}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening header file %q: %w", path, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(f, MaxHeaderFileBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, fmt.Errorf("reading header file %q: %w", path, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("closing header file %q: %w", path, closeErr)
	}
	if len(data) > MaxHeaderFileBytes {
		return nil, fmt.Errorf("header file %q exceeds %d bytes", path, MaxHeaderFileBytes)
	}

	h := http.Header{}
	for lineNo, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		part, err := ParseHeaders([]string{line})
		if err != nil {
			return nil, &UsageError{Msg: fmt.Sprintf("header file %q line %d: %s", path, lineNo+1, err.Error())}
		}
		mergeHeaders(h, part)
	}
	if len(h) == 0 {
		return nil, nil
	}
	return h, nil
}

// ReadHeaderFiles merges header files in order. Repeated names retain their
// value order, matching repeated -H arguments.
func ReadHeaderFiles(paths []string) (http.Header, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	h := http.Header{}
	for _, path := range paths {
		part, err := ReadHeaderFile(path)
		if err != nil {
			return nil, err
		}
		mergeHeaders(h, part)
	}
	if len(h) == 0 {
		return nil, nil
	}
	return h, nil
}

func mergeHeaders(dst, src http.Header) {
	for name, values := range src {
		dst[name] = append(dst[name], values...)
	}
}
