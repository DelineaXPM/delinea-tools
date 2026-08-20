package secretscmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/DelineaXPM/delinea-common/api"
	ds "github.com/DelineaXPM/delinea-common/secrets"
	"github.com/DelineaXPM/delinea-tools/internal/cli"
)

type status int

const (
	statusOK   status = iota // a check ran and passed
	statusInfo               // a statement of how something will be interpreted; nothing was verified
	statusWarn
	statusFail
	statusSkip
)

func (s status) label() string {
	switch s {
	case statusOK:
		return "ok"
	case statusInfo:
		return "info"
	case statusWarn:
		return "warn"
	case statusFail:
		return "FAIL"
	}
	return "skip"
}

type finding struct {
	status status
	label  string
	detail string
}

type section struct {
	title    string
	findings []finding
}

func ok(label, detail string) finding   { return newFinding(statusOK, label, detail) }
func info(label, detail string) finding { return newFinding(statusInfo, label, detail) }
func warn(label, detail string) finding { return newFinding(statusWarn, label, detail) }
func fail(label, detail string) finding { return newFinding(statusFail, label, detail) }
func skip(label, detail string) finding { return newFinding(statusSkip, label, detail) }

// newFinding drops a label the detail repeats. Several details come from errors
// that name the variable because they are also printed on their own, where the
// name is all the context there is; rendered after the label they would read
// "DELINEA_TOOLS_URL: DELINEA_TOOLS_URL must use https". The detail is
// sanitized because it can carry a server response body, which must not be able
// to write terminal escape sequences into the report.
func newFinding(s status, label, detail string) finding {
	// Both are sanitized: the detail can carry a server response body, and the
	// label can be a mapping-derived variable name that in CI may come from
	// untrusted input — neither may write terminal escape sequences.
	label = cli.SanitizeText(label)
	detail = cli.SanitizeText(detail)
	if rest, found := strings.CutPrefix(detail, label); found && (strings.HasPrefix(rest, ":") || strings.HasPrefix(rest, " ")) {
		if trimmed := strings.TrimLeft(rest, ": "); trimmed != "" {
			detail = trimmed
		}
	}
	return finding{s, label, detail}
}

// plural avoids the "1 problem(s)" that a bare count produces.
func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func countFailures(sections []section) int {
	n := 0
	for _, s := range sections {
		for _, f := range s.findings {
			if f.status == statusFail {
				n++
			}
		}
	}
	return n
}

// outputWidth is the column budget for rendering. A pipe or file gets a fixed
// width so output is reproducible rather than depending on whoever happens to
// be watching; a terminal gets COLUMNS when the shell exports it. Very wide
// terminals are capped, since a 200-column line is no easier to read than a
// wrapped one.
func outputWidth() int {
	return widthFrom(cli.IsTerminal(os.Stdout), os.Getenv("COLUMNS"))
}

// widthFrom is the pure core of outputWidth, split out so its branches are
// testable without a real terminal. A pipe or file gets a fixed width so output
// is reproducible; a terminal gets COLUMNS when the shell exports it, capped so
// a 200-column line is not left unwrapped.
func widthFrom(isTTY bool, columns string) int {
	const fallback, maxWidth = 100, 110
	if !isTTY {
		return fallback
	}
	w, err := strconv.Atoi(columns)
	if err != nil || w < 40 {
		return fallback
	}
	return min(w, maxWidth)
}

// wrapText greedily wraps on spaces. A single word longer than the width -- a URL
// or a folder path -- is left to overflow rather than broken, since a broken one
// cannot be copied.
func wrapText(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	lines := []string{words[0]}
	for _, w := range words[1:] {
		last := len(lines) - 1
		if len(lines[last])+1+len(w) <= width {
			lines[last] += " " + w
			continue
		}
		lines = append(lines, w)
	}
	return lines
}

// A finding is two levels: its status and label on one line, its text on the
// lines beneath. Nothing is aligned to anything else, so no label width has to be
// computed, no continuation has to hang under a column, and one long label cannot
// affect another finding. Every text line shares detailIndent, which is what
// makes wrapping trivial: there is no first line to treat differently.
const (
	labelIndent = 2
	// The text sits under the label, not under the status, so a finding reads as
	// one block: the status stays out at the margin where it can be scanned.
	detailIndent = labelIndent + 4 + 2
)

// minDetailWidth is the narrowest the text may become. On a very narrow terminal
// it overflows instead: unreadable wrapping helps no one.
const minDetailWidth = 30

func render(sections []section, width int) string {
	textWidth := max(width-detailIndent, minDetailWidth)
	labelPad := strings.Repeat(" ", labelIndent)
	detailPad := strings.Repeat(" ", detailIndent)

	var b strings.Builder
	line := func(s string) { b.WriteString(strings.TrimRight(s, " ") + "\n") }
	first := true
	for _, s := range sections {
		if len(s.findings) == 0 {
			continue
		}
		// A blank line opens the output, as help and --readme do. After that two
		// blank lines start a section and one separates findings within it, so
		// the two boundaries cannot be mistaken for each other.
		line("")
		if !first {
			line("")
		}
		first = false
		line(s.title + ":")
		line("")
		for i, f := range s.findings {
			if i > 0 {
				line("")
			}
			line(fmt.Sprintf("%s%-4s  %s", labelPad, f.status.label(), f.label))
			if f.detail == "" {
				continue
			}
			for _, l := range wrapText(f.detail, textWidth) {
				line(detailPad + l)
			}
		}
	}
	return b.String()
}

// keepProblems drops everything a healthy run would report, leaving the findings
// that need attention. Sections emptied by the filter are dropped by render.
func keepProblems(sections []section) []section {
	out := make([]section, 0, len(sections))
	for _, s := range sections {
		kept := section{title: s.title}
		for _, f := range s.findings {
			if f.status == statusWarn || f.status == statusFail {
				kept.findings = append(kept.findings, f)
			}
		}
		out = append(out, kept)
	}
	return out
}

// renderJSON emits findings structurally. The summary counts every finding
// (from all), while the rendered sections are the possibly-filtered shown set:
// under --quiet, shown drops the healthy findings, but the summary must still
// report them, or a healthy config reads as "ok": 0. The text layout wraps, so
// a consumer parsing it would have to rejoin continuations by counting
// indentation; this has no width and nothing to reassemble.
func renderJSON(all, shown []section) (string, error) {
	type jsonFinding struct {
		Status string `json:"status"`
		Label  string `json:"label"`
		Detail string `json:"detail,omitempty"`
	}
	type jsonSection struct {
		Title    string        `json:"title"`
		Findings []jsonFinding `json:"findings"`
	}
	doc := struct {
		Summary  map[string]int `json:"summary"`
		Sections []jsonSection  `json:"sections"`
	}{Summary: map[string]int{}, Sections: []jsonSection{}}

	for s := statusOK; s <= statusSkip; s++ {
		doc.Summary[s.label()] = 0
	}
	for _, s := range all {
		for _, f := range s.findings {
			doc.Summary[f.status.label()]++
		}
	}
	for _, s := range shown {
		if len(s.findings) == 0 {
			continue
		}
		js := jsonSection{Title: s.title, Findings: []jsonFinding{}}
		for _, f := range s.findings {
			js.Findings = append(js.Findings, jsonFinding{Status: f.status.label(), Label: f.label, Detail: f.detail})
		}
		doc.Sections = append(doc.Sections, js)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	return string(out), err
}

// effectiveTarget resolves the target check reports and probes against from the
// parsed flags-over-env in cc, exactly as buildConfig does: an explicit target
// wins, otherwise a bearer token remains targetless, a client-id infers the
// Platform, and a username infers Secret Server.
// An invalid target value is reported by checkConfig and treated as the default
// here.
func effectiveTarget(cc cliConfig) api.Target {
	t, _ := parseTarget(cc.Target)
	if t == api.TargetAuto && cc.Token != "" {
		return api.TargetAuto
	}
	if t == api.TargetAuto && cc.Username == "" && cc.ClientID == "" {
		return api.TargetAuto
	}
	if platform, _ := resolvePlatform(cc, t); platform {
		return api.TargetPlatform
	}
	return api.TargetSecretServer
}

// checkConfig reports each connection setting independently, rather than failing
// on the first bad one as configFromEnv does.
func checkConfig(cc cliConfig) []finding {
	var out []finding

	url := cc.URL
	switch {
	case url == "":
		out = append(out, fail("DELINEA_TOOLS_URL", "not set; required"))
	default:
		if err := cli.RequireSecureURL(url, "DELINEA_TOOLS_URL"); err != nil {
			out = append(out, fail("DELINEA_TOOLS_URL", err.Error()))
		} else {
			out = append(out, ok("DELINEA_TOOLS_URL", url))
		}
	}

	// Validity is decided by the same parseTarget run uses, so check cannot
	// accept a value run refuses; the per-value explanations stay here. An
	// unset target with a client-id present is the inferred-Platform case,
	// reported as such rather than as the ss default.
	t, terr := parseTarget(cc.Target)
	platform, perr := resolvePlatform(cc, t)
	switch {
	case terr != nil:
		out = append(out, fail("DELINEA_TOOLS_TARGET", fmt.Sprintf("%q is not a target (want ss or platform)", cc.Target)))
	case perr != nil:
		// Both a username and a client-id with no Target: run/print reject this
		// as ambiguous, so check must fail it too rather than pass silently.
		out = append(out, fail("DELINEA_TOOLS_TARGET", perr.Error()))
	case cc.Target == "" && platform:
		out = append(out, info("DELINEA_TOOLS_TARGET", "not set, but a client-id is present, so platform is inferred: secret fetches are routed to the tenant's vault, discovered through the vault broker (the credential section reports how the credential is used)"))
	case cc.Target == "" && cc.Username == "" && cc.ClientID == "":
		out = append(out, info("DELINEA_TOOLS_TARGET", "not set; raw API requests need no grant target, a bearer token is validated against the service found by the health probe, and secret fetches default to Secret Server unless platform is selected"))
	case cc.Target == "":
		out = append(out, info("DELINEA_TOOLS_TARGET", "not set, so ss: secret fetches go to Secret Server (the credential section reports how the credential is used)"))
	case cc.Target == "ss":
		out = append(out, info("DELINEA_TOOLS_TARGET", "ss: secret fetches go to Secret Server (the credential section reports how the credential is used)"))
	default:
		out = append(out, info("DELINEA_TOOLS_TARGET", "platform: secret fetches are routed to the tenant's vault, discovered through the vault broker (the credential section reports how the credential is used)"))
	}

	if user := cc.Username; user != "" {
		if err := cli.RequirePlainUsername(user); err != nil {
			out = append(out, fail("DELINEA_TOOLS_USERNAME", err.Error()))
		}
	}

	// Parsed with the same helpers run uses, so check cannot accept a value run
	// refuses or default differently.
	switch d, err := parseTimeout(cc.Timeout); {
	case err != nil:
		out = append(out, fail("DELINEA_TOOLS_TIMEOUT", err.Error()))
	case cc.Timeout == "":
		out = append(out, ok("DELINEA_TOOLS_TIMEOUT", d.String()+" (default)"))
	default:
		out = append(out, ok("DELINEA_TOOLS_TIMEOUT", d.String()))
	}

	if _, err := parseRetries(cc.Retries); err != nil {
		out = append(out, fail("DELINEA_TOOLS_RETRIES", err.Error()))
	}

	if path := cc.CACert; path != "" {
		bundle, cerr := caCertBytes(path)
		var loaded, skipped int
		if cerr == nil {
			loaded, skipped = countCerts(bundle)
		}
		switch {
		case cerr != nil:
			out = append(out, fail("DELINEA_TOOLS_CA_CERT", cerr.Error()))
		case loaded == 0:
			out = append(out, fail("DELINEA_TOOLS_CA_CERT", path+": no certificates found in PEM"))
		case skipped > 0:
			out = append(out, fail("DELINEA_TOOLS_CA_CERT",
				fmt.Sprintf("%s: %d %s loaded, but %d CERTIFICATE %s did not parse and will not be in the trust pool; a chain relying on one will fail verification",
					path, loaded, plural(loaded, "certificate"), skipped, plural(skipped, "block"))))
		default:
			out = append(out, ok("DELINEA_TOOLS_CA_CERT",
				fmt.Sprintf("%s: %d %s, added to the system trust store", path, loaded, plural(loaded, "certificate"))))
		}
	}

	if paths := cc.GatewayHeaderPaths(); len(paths) > 0 {
		headers, herr := cli.ReadHeaderFiles(paths)
		if herr == nil {
			herr = api.ValidateHeaders(headers)
		}
		if herr != nil {
			out = append(out, fail("DELINEA_TOOLS_GATEWAY_HEADER_FILE", herr.Error()))
		} else {
			out = append(out, ok("DELINEA_TOOLS_GATEWAY_HEADER_FILE",
				fmt.Sprintf("%d %s loaded from %d %s; values are hidden", len(headers), plural(len(headers), "header"), len(paths), plural(len(paths), "file"))))
		}
	}

	out = append(out, checkUnknownEnv()...)

	if cc.TLSSkipVerify {
		out = append(out, warn("DELINEA_TOOLS_TLS_SKIP_VERIFY", "set: the vault's TLS certificate is not verified, so the connection can be intercepted"))
	}
	return out
}

// countCerts reports how many certificates in a bundle actually parse (the
// ones AppendCertsFromPEM loads into the pool) and how many CERTIFICATE
// blocks it skips over — a truncated intermediate keeps PEM framing, is
// silently dropped by the pool, and would otherwise be reported as trusted.
func countCerts(bundle []byte) (loaded, skipped int) {
	for rest := bundle; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			skipped++
		} else {
			loaded++
		}
	}
	return loaded, skipped
}

// targetMismatch reports a configured target that contradicts the service that
// answered the probe: the wrong target sends the credential to the wrong token
// endpoint, which fails as an opaque denial.
func targetMismatch(target api.Target, b api.Backend) string {
	switch {
	case target == api.TargetPlatform && b == api.BackendSecretServer:
		return "platform is configured, but Secret Server answered at DELINEA_TOOLS_URL; unset DELINEA_TOOLS_TARGET (or set ss) so the credential is sent to Secret Server's token endpoint"
	case target == api.TargetSecretServer && b == api.BackendPlatform:
		return "ss is configured (the default), but the Delinea Platform answered at DELINEA_TOOLS_URL; set DELINEA_TOOLS_TARGET=platform and use an OAuth client_id/client_secret"
	}
	return ""
}

// credMode is how the resolved credential authenticates: a pre-obtained bearer
// token, a Platform client_id/client_secret, or a Secret Server
// username/password. The domain finding depends on it.
type credMode int

const (
	modeToken credMode = iota
	modePlatform
	modeSS
)

// credentialModeFrom reads the effective mode from a resolved, valid config —
// what the engine actually uses — so the domain finding cannot contradict the
// credential finding. A token wins over any identity: the engine sends it and
// performs no grant.
func credentialModeFrom(cfg ds.Config) credMode {
	switch {
	case cfg.Token != "":
		return modeToken
	case cfg.Target == api.TargetPlatform:
		return modePlatform
	default:
		return modeSS
	}
}

// credentialModeCC infers the mode from the raw flags/env when the config did
// not resolve or validate, so the domain finding still reflects the target the
// operator was aiming at rather than going silent.
func credentialModeCC(cc cliConfig) credMode {
	switch {
	case cc.Token != "":
		return modeToken
	case cc.ClientID != "" || cc.ClientSecret != "" || cc.Target == "platform":
		return modePlatform
	case cc.Username != "" || cc.Password != "":
		return modeSS
	default:
		return modeToken
	}
}

// describeCredential reports how a VALID resolved credential is used. It is
// called only when the config resolved and validated, so it never has to flag a
// bad combination — ds.New already rejected those. For the Platform, secrets.New
// folds the client_id/client_secret into Username/Password, so cfg.Username here
// is the client_id.
func describeCredential(cfg ds.Config, cc cliConfig) []finding {
	switch {
	case cfg.Token != "":
		detail := "a pre-obtained bearer token was accepted by the target; no grant was performed"
		if cc.Username != "" || cc.ClientID != "" {
			detail += "; the username/client-id is ignored"
		}
		return []finding{info("DELINEA_TOOLS_TOKEN", detail)}
	case cfg.Target == api.TargetPlatform:
		out := []finding{info("DELINEA_TOOLS_CLIENT_ID", fmt.Sprintf("%q was accepted as a Platform OAuth client_id; the credential is its client_secret", cfg.Username))}
		if strings.Contains(cfg.Username, "@") {
			out = append(out, warn("DELINEA_TOOLS_CLIENT_ID", "looks like a Platform user, not a service-user client_id; a Platform user's password is not valid for vault access"))
		}
		return out
	default:
		return []finding{info("DELINEA_TOOLS_USERNAME", fmt.Sprintf("%q was accepted as a Secret Server username; the credential is its password", cfg.Username))}
	}
}

// domainFinding always reports DELINEA_TOOLS_DOMAIN, so a reader always sees the
// variable and how it applies, and it reflects the effective mode: neither a
// bearer token nor the Platform uses a domain (only a Secret Server username
// does), and a bearer token must never be told it uses client credentials.
func domainFinding(mode credMode, domain string) finding {
	switch mode {
	case modeToken:
		if domain != "" {
			return warn("DELINEA_TOOLS_DOMAIN", "ignored: a bearer token carries its own identity, so no domain applies")
		}
		return info("DELINEA_TOOLS_DOMAIN", "not used: a bearer token carries its own identity, so no domain applies")
	case modePlatform:
		if domain != "" {
			return warn("DELINEA_TOOLS_DOMAIN", "ignored: the Platform authenticates client credentials, which have no domain")
		}
		return info("DELINEA_TOOLS_DOMAIN", "not used: the Platform authenticates client credentials, which have no domain")
	default:
		if domain != "" {
			return info("DELINEA_TOOLS_DOMAIN", fmt.Sprintf("%q; Secret Server requires it for an Active Directory user, and it must be omitted for a local account", domain))
		}
		return info("DELINEA_TOOLS_DOMAIN", "not set, which is correct for a local Secret Server account; an Active Directory user requires its domain here")
	}
}

// credentialFindings builds the credential section from the same resolution and
// authentication run used to prepare the optional mapping client. resolvedCfg
// and cfgErr come from buildConfig, credValidErr from api.Client.Authenticate,
// and credErr from the stdin read. The domain finding is always appended.
func credentialFindings(cc cliConfig, resolvedCfg ds.Config, cfgErr, credValidErr, credErr error, attempted bool, authSkip string) []finding {
	var out []finding
	switch {
	case credErr != nil:
		// A mis-encoded or unreadable stdin credential: a delivery failure.
		out = append(out, fail("stdin", cli.SanitizeText(credErr.Error())))
	case authSkip != "":
		// A credential is present but was deliberately not sent (--no-auth, or
		// an unreachable host); the reason is reported, never a silent pass.
		out = append(out, skip("credential", authSkip))
	case !attempted:
		// No identity or secret was supplied and none was forced on stdin:
		// check's documented reachability-only mode. Configuration and the vault
		// probe still run; nothing is authenticated. run/print require a
		// credential, but verifying reachability without one is a deliberate
		// check mode, so this is a skip, not a failure.
		out = append(out, skip("credential", "no credential supplied; configuration and reachability were checked, but nothing was authenticated. Set DELINEA_TOOLS_TOKEN, DELINEA_TOOLS_PASSWORD, or DELINEA_TOOLS_CLIENT_SECRET, or pipe one on stdin with --secret-stdin, to verify authentication too"))
	case cc.URL == "" || cfgErr != nil:
		// A URL/target/timeout/retries problem the configuration section already
		// reports; do not double-report it as a credential fault. An empty URL
		// slips past buildConfig (RequireSecureURL allows it) but leaves nothing
		// to authenticate against, so it belongs to configuration too.
		out = append(out, skip("credential", "not evaluated: fix the configuration above"))
	case credValidErr != nil:
		// Structural credential errors and authoritative authentication failures
		// share one finding; both prevent run/print from authenticating.
		out = append(out, fail("credential", cli.SanitizeText(credValidErr.Error())))
	default:
		out = append(out, describeCredential(resolvedCfg, cc)...)
	}
	// Classify from the resolved config whenever it built successfully: it
	// reflects where the credential actually landed (including a stdin-piped
	// secret) even when that credential then fails validation, so the domain
	// finding never contradicts the credential finding. credentialModeCC(cc) is
	// only the fallback for a config that failed to build.
	mode := credentialModeCC(cc)
	if attempted && cc.URL != "" && cfgErr == nil {
		mode = credentialModeFrom(resolvedCfg)
	}
	return append(out, domainFinding(mode, cc.Domain))
}

// checkChildEnv reports exactly what a run child would receive, which is
// otherwise invisible: the baseline is compiled in and the withheld variables
// leave no trace.
func checkChildEnv(passEnv []string) []finding {
	env, err := childEnv(passEnv)
	if err != nil {
		return []finding{fail("--pass-env", err.Error())}
	}
	var passed []string
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		passed = append(passed, name)
	}
	sort.Strings(passed)

	// Names are compared under envNameKey, exactly as childEnv delivers them:
	// on Windows --pass-env HTTPS_PROXY matches an environment spelling of
	// https_proxy, and check must not report withheld what run passes.
	named := make(map[string]bool, len(passEnv))
	for _, n := range passEnv {
		named[envNameKey(n)] = true
	}
	withheld := 0
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if !inBaseline(name) && !named[envNameKey(name)] {
			withheld++
		}
	}
	out := []finding{
		ok("passed to child", strings.Join(passed, " ")),
		ok("withheld", fmt.Sprintf("%d %s in the calling environment withheld", withheld, plural(withheld, "variable"))),
	}
	warned := map[string]bool{}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		key := envNameKey(name)
		if os.Getenv(name) != "" && !named[key] && !warned[key] {
			warned[key] = true
			out = append(out, warn(name, fmt.Sprintf("set in the calling environment but withheld; add --pass-env %s if the child needs a proxy, or it will hang rather than fail when it cannot reach the network", name)))
		}
	}
	return out
}

func checkSecrets(client *ds.Client, mappings []ds.Mapping) []finding {
	results, err := client.Verify(context.Background(), mappings)
	if err != nil {
		return []finding{fail("secrets", err.Error()+"; raise DELINEA_TOOLS_TIMEOUT if the vault is simply slow")}
	}
	var out []finding
	for _, r := range results {
		label := r.Mapping.EnvName
		if r.Mapping.Expand {
			label = r.Mapping.Prefix + "*"
		}
		ref := r.Mapping.Ref()
		if r.Err != nil {
			out = append(out, fail(label, r.Err.Error()))
			continue
		}
		var parts []string
		for _, f := range r.Fields {
			parts = append(parts, fmt.Sprintf("%s (%d %s)", f.Name, f.Bytes, plural(f.Bytes, "byte")))
		}
		f := ok(label, fmt.Sprintf("%s -> %s", ref, strings.Join(parts, ", ")))
		for _, fld := range r.Fields {
			if fld.Bytes == 0 {
				f = warn(label, fmt.Sprintf("%s -> %s; %s resolves to an empty value, which is delivered as a defined but empty variable", ref, strings.Join(parts, ", "), fld.Name))
				break
			}
		}
		out = append(out, f)
	}
	return append(out, collisionFindings(results)...)
}

// collisionFindings reports every sink-neutral name more than one mapping
// defines, which run, print and template always refuse to deliver. Sink-specific
// checks handle any narrower identity rules when a delivery mode is selected.
func collisionFindings(results []ds.Result) []finding {
	counts := map[string]int{}
	var order []string
	for _, r := range results {
		for _, f := range r.Fields {
			if counts[f.Name] == 0 {
				order = append(order, f.Name)
			}
			counts[f.Name]++
		}
	}
	var out []finding
	for _, name := range order {
		if counts[name] > 1 {
			out = append(out, fail(name, fmt.Sprintf("defined %d times across the mappings; run, print and template refuse the collision, so drop or rename one", counts[name])))
		}
	}
	return out
}

// cmdCheck runs the check diagnostic. Help is handled by the exported Check
// wrapper (check is the top-level "delinea-util check" verb), so cmdCheck never
// sees a help request.
func cmdCheck(args []string) error {
	cc := configFromEnv()
	rest0, err := extractConnFlags(args, &cc)
	if err != nil {
		return err
	}
	quiet, asJSON, noAuth := false, false, false
	var rest []string
	for _, a := range rest0 {
		switch a {
		case "--quiet":
			quiet = true
		case "--json":
			asJSON = true
		case "--no-auth":
			noAuth = true
		default:
			rest = append(rest, a)
		}
	}
	p, err := parseArgs("check", rest, "env", false)
	if err != nil {
		return err
	}
	if p.viaSet {
		return fmt.Errorf("--via applies only to run and print; check delivers nothing")
	}

	// The secret comes from the environment, or from stdin only when
	// --secret-stdin selects it. --no-auth deliberately does not
	// touch stdin: its monitoring contract is configuration and reachability only,
	// and an inherited open pipe must not block that probe indefinitely.
	var stdinCred string
	var credErr error
	var stdinFindings []finding
	if !noAuth && cc.SecretStdin && cli.IsTerminal(os.Stdin) {
		// Nothing can be read, so do not let an empty stdin secret clear the
		// environment credential and misreport as "no credentials": name the
		// actual problem and check the rest as if the flag were absent.
		cc.SecretStdin = false
		stdinFindings = append(stdinFindings,
			fail("--secret-stdin", "stdin is a terminal, so no credential can be piped; run without --secret-stdin or pipe the secret"))
	} else if !noAuth && cc.SecretStdin {
		stdinCred, _, credErr = cli.ReadCredential(os.Stdin)
		if credErr == nil && stdinCred == "" {
			// An empty forced pipe is a credential-delivery failure, reported
			// as one (a FAIL in the credential section) rather than swallowed
			// into a config-referencing skip via buildConfig's empty refusal.
			credErr = fmt.Errorf("--secret-stdin: stdin was empty; the pipe delivered no credential")
		}
	}

	sections := []section{{title: "configuration", findings: append(checkConfig(cc), stdinFindings...)}}

	// Resolve the credential exactly as run/print do. Authentication happens after
	// the Delinea-credential-free health probe below, and the resulting token is
	// reused by the optional mapping client so check never performs a duplicate
	// grant.
	resolvedCfg, cfgErr := buildConfig(cc, strings.NewReader(stdinCred))
	var client *ds.Client
	var credValidErr error

	// A credential was attempted if any identity or secret was configured, or
	// stdin was forced: then an empty/mismatched result is a failure, matching
	// run/print. With nothing attempted, check runs its reachability-only mode
	// (skip, not fail) — a username or client-id counts, so a half-configured
	// identity still fails rather than passing as reachability-only.
	credentialAttempted := cc.Username != "" || cc.ClientID != "" ||
		cc.Token != "" || cc.Password != "" || cc.ClientSecret != "" ||
		cc.SecretStdin || stdinCred != ""
	if !noAuth && cfgErr == nil && credentialAttempted {
		// Validate the resolved credential structure without network I/O before
		// deciding whether an outage or --no-auth should suppress authentication.
		// This keeps a missing password/client secret visible as an independent
		// local problem instead of hiding it behind reachability.
		validationClient, validationErr := api.New(resolvedCfg.EngineConfig())
		credValidErr = validationErr
		if validationClient != nil {
			validationClient.CloseIdleConnections()
		}
	}

	target := effectiveTarget(cc)
	url := cc.URL
	var backend api.Backend
	var mismatch string
	probeFailed := false
	var vault []finding
	probeCfg, probeCfgErr := probeConfig(cc)
	switch {
	case url == "":
		vault = append(vault, skip("reachability", "not probed: DELINEA_TOOLS_URL is not set"))
	case cli.RequireSecureURL(url, "DELINEA_TOOLS_URL") != nil:
		vault = append(vault, skip("reachability", "not probed: DELINEA_TOOLS_URL was rejected, see configuration above"))
	case probeCfgErr != nil:
		vault = append(vault, skip("reachability", "not probed: the gateway header file was rejected, see configuration above"))
	default:
		b, perr := api.ProbeBackend(context.Background(), probeCfg)
		backend = b
		switch {
		case b != api.BackendUnknown:
			vault = append(vault, ok("backend", fmt.Sprintf("%s answered the health probe (no Delinea credential sent)", b)))
			if mismatch = targetMismatch(target, b); mismatch != "" {
				vault = append(vault, fail("DELINEA_TOOLS_TARGET", mismatch))
			}
		case perr != nil:
			// The host never answered; authentication is skipped rather than
			// re-reporting the same outage as a credential failure.
			probeFailed = true
			vault = append(vault, fail("reachability", perr.Error()))
		default:
			// The host answered but no health endpoint identified it. The API
			// paths may still work (a proxy can block health endpoints alone),
			// so authentication proceeds against the effective target.
			vault = append(vault, fail("backend", "reachable, but neither the Secret Server nor the Platform health endpoint reported healthy; check the URL path"))
		}
	}
	sections = append(sections, section{title: "vault", findings: vault})
	// Decide whether to actually send the credential. It is withheld — with
	// the reason reported as a skip, never a silent pass — when nothing was
	// supplied, when --no-auth asked for the request-free mode, when the
	// target contradicts the backend the probe identified (the credential
	// must not be sent to the wrong token endpoint), and when the host is
	// unreachable (the grant would only burn its retry budget against a dead
	// host and re-report the outage as a credential failure).
	authSkip := ""
	switch {
	case noAuth:
		authSkip = "not attempted: --no-auth requested configuration and reachability checks only, so no authentication request was made"
	case cfgErr != nil || credErr != nil || !credentialAttempted || credValidErr != nil:
		// credentialFindings reports these cases from its own arguments.
	case mismatch != "":
		credValidErr = fmt.Errorf("credential was not sent because DELINEA_TOOLS_TARGET contradicts the service at DELINEA_TOOLS_URL")
	case probeFailed:
		authSkip = "not attempted: the vault is unreachable, see the vault section above"
	default:
		client, credValidErr = authenticateCredential(context.Background(), resolvedCfg, backend)
	}
	if client != nil {
		defer client.CloseIdleConnections()
	}

	sections = append(sections, section{title: "credential", findings: credentialFindings(cc, resolvedCfg, cfgErr, credValidErr, credErr, credentialAttempted, authSkip)})

	var secrets []finding
	switch {
	case len(p.mappings) == 0:
		secrets = append(secrets, skip("secrets", "none given; pass mappings to check that each resolves"))
	case noAuth:
		secrets = append(secrets, skip("secrets", "not checked: --no-auth requested configuration and reachability checks only"))
	case credErr != nil:
		secrets = append(secrets, skip("secrets", "not checked: the credential on stdin was rejected or unreadable, see credential above"))
	case cfgErr != nil || credValidErr != nil:
		secrets = append(secrets, skip("secrets", "not checked: see the configuration and credential sections above"))
	case client == nil:
		secrets = append(secrets, skip("secrets", "not checked: no authentication was performed, see the credential section above"))
	default:
		secrets = checkSecrets(client, p.mappings)
	}
	sections = append(sections, section{title: "secrets", findings: secrets})
	sections = append(sections, section{title: "child environment (run)", findings: checkChildEnv(p.passEnv)})

	n := countFailures(sections)
	shown := sections
	if quiet {
		shown = keepProblems(shown)
	}
	if err := writeCheckOutput(os.Stdout, sections, shown, asJSON, quiet); err != nil {
		return fmt.Errorf("writing check output: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("check found %d %s", n, plural(n, "problem"))
	}
	return nil
}

func writeCheckOutput(w io.Writer, sections, shown []section, asJSON, quiet bool) error {
	switch {
	case asJSON:
		doc, err := renderJSON(sections, shown)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, doc)
		return err
	case quiet:
		// A healthy run says nothing at all, so check can gate a pipeline
		// without filling its log.
		if out := render(shown, outputWidth()); strings.TrimSpace(out) != "" {
			_, err := fmt.Fprintln(w, out)
			return err
		}
		return nil
	default:
		_, err := fmt.Fprintln(w, render(sections, outputWidth()))
		return err
	}
}

// authenticateCredential verifies the credential, then gives the resolver the
// resulting token so optional mapping checks reuse it instead of granting a
// second time. A targetless bearer temporarily uses the backend found by the
// health probe only to choose its read-only validation endpoint; cfg itself is
// left unchanged, so mapping routing retains the resolver's documented default.
func authenticateCredential(ctx context.Context, cfg ds.Config, backend api.Backend) (*ds.Client, error) {
	apiCfg := cfg.EngineConfig()
	if cfg.Token != "" && apiCfg.Target == api.TargetAuto {
		switch backend {
		case api.BackendSecretServer:
			apiCfg.Target = api.TargetSecretServer
		case api.BackendPlatform:
			apiCfg.Target = api.TargetPlatform
		default:
			return nil, fmt.Errorf("%w: cannot validate the bearer token because the health probe could not identify the service at DELINEA_TOOLS_URL; fix reachability or set DELINEA_TOOLS_TARGET=ss or platform to choose the validation endpoint", api.ErrConfig)
		}
	}

	ac, err := api.New(apiCfg)
	if err != nil {
		return nil, err
	}
	defer ac.CloseIdleConnections()
	token, err := ac.Authenticate(ctx)
	if err != nil {
		return nil, err
	}

	resolved := cfg
	resolved.Token = token
	resolved.Username, resolved.Password = "", ""
	return ds.New(resolved)
}

// probeConfig builds just enough configuration for a Delinea-credential-free
// probe from the parsed flags-over-env in cc. Invalid gateway headers stop the
// probe after checkConfig reports them as configuration failures. Configured
// valid gateway headers are retained so the probe can reach the same-origin
// service.
func probeConfig(cc cliConfig) (api.Config, error) {
	cfg := api.Config{URL: cc.URL, SkipTLSVerify: cc.TLSSkipVerify}
	header, err := cli.ReadHeaderFiles(cc.GatewayHeaderPaths())
	if err != nil {
		return cfg, err
	}
	if err := api.ValidateHeaders(header); err != nil {
		return cfg, err
	}
	cfg.Header = header
	if pem, err := caCertBytes(cc.CACert); err == nil {
		cfg.CACert = pem
	}
	if d, err := parseTimeout(cc.Timeout); err == nil {
		cfg.Timeout = d
	}
	return cfg, nil
}

// knownEnv is every DELINEA_TOOLS_ variable this tool reads — the same set the
// raw delinea-util side reads, since the secrets group now authenticates the
// same way. TestKnownEnvCoversEveryVariableRead cross-checks it against the
// source, so a new setting cannot be introduced without appearing here.
var knownEnv = []string{
	"DELINEA_TOOLS_URL",
	"DELINEA_TOOLS_TARGET",
	"DELINEA_TOOLS_USERNAME",
	"DELINEA_TOOLS_PASSWORD",
	"DELINEA_TOOLS_DOMAIN",
	"DELINEA_TOOLS_CLIENT_ID",
	"DELINEA_TOOLS_CLIENT_SECRET",
	"DELINEA_TOOLS_TOKEN",
	"DELINEA_TOOLS_CA_CERT",
	"DELINEA_TOOLS_TIMEOUT",
	"DELINEA_TOOLS_RETRIES",
	"DELINEA_TOOLS_TLS_SKIP_VERIFY",
	"DELINEA_TOOLS_VAULT_ALLOW",
	"DELINEA_TOOLS_GATEWAY_HEADER_FILE",
}

// checkUnknownEnv reports DELINEA_TOOLS_ variables the tool does not read. A
// misspelled setting is otherwise silent: it is never read and the run proceeds
// as though it were unset. Values are never printed -- an unrecognised variable
// may hold the password its author believed was being used.
func checkUnknownEnv() []finding {
	var names []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		// DELINEA_TOOLS_TEST_* are the e2e test suite's fixtures, not runtime
		// config; they are deliberately outside the runtime namespace (a typo
		// there cannot silently point the tool at a real backend), so do not
		// flag them as unrecognized settings.
		if strings.HasPrefix(name, "DELINEA_TOOLS_") && !strings.HasPrefix(name, "DELINEA_TOOLS_TEST_") && !slices.Contains(knownEnv, name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var out []finding
	for _, name := range names {
		if near := nearestKnown(name); near != "" {
			out = append(out, warn(name, "not read by delinea-util; did you mean "+near+"?"))
		} else {
			out = append(out, warn(name, "not read by delinea-util"))
		}
	}
	return out
}

// nearestKnown returns the recognised name a typo most likely meant, or "" when
// nothing is close enough for the guess to help.
func nearestKnown(name string) string {
	best, bestDist := "", 0
	for _, k := range knownEnv {
		if d := editDistance(name, k); best == "" || d < bestDist {
			best, bestDist = k, d
		}
	}
	if bestDist == 0 || bestDist > 3 {
		return ""
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(curr[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}
