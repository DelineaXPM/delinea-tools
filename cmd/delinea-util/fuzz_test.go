package main

import (
	"strings"
	"testing"
)

func FuzzParseArgs(f *testing.F) {
	f.Add("GET", "/api/v1/x", "-d")
	f.Add("--url", "https://x.example.com", "token")
	f.Add("--header=A: 1", "-H", "")
	f.Add("--", "-", "--=x")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		cc := cliConfig{}
		parseArgs([]string{a, b, c}, &cc)
	})
}

func FuzzParseHeaders(f *testing.F) {
	f.Add("Content-Type: application/json")
	f.Add("no colon")
	f.Add(": empty name")
	f.Add("A:")
	f.Add("A: b: c")
	f.Fuzz(func(t *testing.T, raw string) {
		h, err := parseHeaders([]string{raw})
		if err != nil {
			return
		}
		for k := range h {
			if strings.TrimSpace(k) == "" {
				t.Errorf("parseHeaders(%q) accepted an empty header name", raw)
			}
		}
	})
}

func FuzzReadSecretStdin(f *testing.F) {
	f.Add("secret\n")
	f.Add("\r\n")
	f.Add("")
	f.Add("a\nb\r\n")
	f.Fuzz(func(t *testing.T, in string) {
		secret, err := readSecretStdin(strings.NewReader(in))
		if err == nil && secret == "" {
			t.Errorf("readSecretStdin(%q) returned an empty secret without error", in)
		}
	})
}
