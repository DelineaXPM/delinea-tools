package api

import (
	"net"
	"strings"
)

// NormalizeURL turns the base-URL spellings integration configs actually
// contain into the canonical form Config.URL wants, and rejects the unsafe
// ones. A bare host gains https://; trailing slashes and surrounding space
// are dropped; userinfo, query, and fragment are refused. The scheme is
// compared case-insensitively, so HTTP:// cannot slip past the check that
// http:// fails — plaintext http discloses the credential on the first
// request and is allowed only for a loopback host or when allowInsecureHTTP
// says the operator accepted that risk explicitly.
func NormalizeURL(raw string, allowInsecureHTTP bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" && !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	// Delegate to the one validator New uses, so the scheme, plaintext-http
	// opt-in, and userinfo/query/fragment rules cannot diverge between the
	// public normalizer and the constructor — a URL NormalizeURL accepts is
	// one New accepts, and neither gate can be looser than the other.
	base, err := parseBaseURL(raw, allowInsecureHTTP)
	if err != nil {
		return "", err
	}
	return base.String(), nil
}

// loopbackHost reports whether host is localhost or a loopback address,
// where plaintext http cannot cross a network.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
