package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/DelineaXPM/delinea-tools/cmd/delinea-util/secretscmd"
	"github.com/DelineaXPM/delinea-tools/internal/cli"

	da "github.com/DelineaXPM/delinea-common/api"
	ds "github.com/DelineaXPM/delinea-common/secrets"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	err := dispatch(args)
	if err == nil {
		return 0
	}
	if ue, ok := errors.AsType[*cli.UsageError](err); ok {
		// A usage error gets the help for the invocation that produced it — the
		// specific command, not the top-level page — so the remedy shown matches
		// what was typed.
		name, u := usageFor(args)
		fmt.Fprintf(os.Stderr, "\n%s: %s\n\n%s\n\n", name, cli.SanitizeText(ue.Msg), u)
		return 1
	}
	fmt.Fprintln(os.Stderr, "delinea-util:", cli.SanitizeText(err.Error()))
	return exitCode(err)
}
func exitCode(err error) int {
	// The secrets resolver returns its own sentinels (ds.Err*), distinct from
	// the engine's (da.Err*) even where the meaning matches, so both are mapped
	// to the same documented code — otherwise a secrets transport failure would
	// fall through to 1 instead of 3, and a denial to 1 instead of 2.
	switch {
	case isHTTPErr(err):
		return 4
	case errors.Is(err, da.ErrAccessDenied), errors.Is(err, da.ErrAuth), errors.Is(err, da.ErrVault),
		errors.Is(err, ds.ErrAccessDenied):
		return 2
	case errors.Is(err, da.ErrTimeout), errors.Is(err, da.ErrTransport),
		errors.Is(err, ds.ErrTimeout), errors.Is(err, ds.ErrTransport):
		return 3
	}
	return 1
}

// httpErr reports a completed API call with a non-2xx status.
type httpErr struct{ status string }

func (e *httpErr) Error() string { return "HTTP " + e.status }

func isHTTPErr(err error) bool {
	_, ok := errors.AsType[*httpErr](err)
	return ok
}

var httpMethods = map[string]bool{
	http.MethodGet: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodHead: true,
	http.MethodOptions: true,
}

func dispatch(args []string) error {
	if len(args) == 0 {
		cli.PrintDoc(os.Stdout, topLevelHelp())
		return nil
	}
	switch args[0] {
	case "help":
		return helpTopic(args[1:])
	case "-h", "--help":
		cli.PrintDoc(os.Stdout, topLevelHelp())
		return nil
	case "--readme":
		cli.PrintDoc(os.Stdout, readmeText)
		return nil
	case "--tree":
		cli.PrintDoc(os.Stdout, commandTree())
		return nil
	case "--version":
		fmt.Fprintln(os.Stdout, cli.Version("delinea-util"))
		return nil
	}
	// Connection flags may precede the command, as every documented synopsis
	// permits. Find the first positional without mistaking a flag value for the
	// command, then preserve those leading flags for the delegated parser.
	cmdIndex, cmd, err := topLevelCommand(args)
	if err != nil {
		return err
	}
	// check and the secrets group own their help (Cobra-formatted in secretscmd).
	if cmd == "check" {
		return secretscmd.Check(withoutArg(args, cmdIndex), readmeText)
	}
	if cmd == "secrets" {
		return dispatchSecrets(args[:cmdIndex], args[cmdIndex+1:])
	}
	cc := configFromEnv()
	o, err := parseArgs(args, &cc)
	if err != nil {
		return err
	}
	// -h/--help anywhere on a token or METHOD invocation prints that command's
	// help (or the top-level page when no command was named).
	if o.help {
		if len(o.positionals) == 0 {
			cli.PrintDoc(os.Stdout, topLevelHelp())
			return nil
		}
		return printCommandHelp(o.positionals[0])
	}
	if len(o.positionals) == 0 {
		cli.PrintDoc(os.Stdout, topLevelHelp())
		return nil
	}
	cmd, rest := o.positionals[0], o.positionals[1:]
	if o.interactive && cmd != "token" {
		return &cli.UsageError{Msg: "--interactive is only valid with token"}
	}
	if o.interactive {
		if cc.Target == "ss" {
			return &cli.UsageError{Msg: "token --interactive is only supported for the platform target; omit --target or use --target platform"}
		}
		if cc.Target == "" {
			cc.Target = "platform"
		}
	}
	method := strings.ToUpper(cmd)
	if err := validateInvocation(cc, o, cmd, method, rest); err != nil {
		return err
	}
	if o.secretStdin {
		if o.interactive {
			return &cli.UsageError{Msg: "token --interactive prompts on stdin; --secret-stdin is not supported"}
		}
		if o.dataSet && o.data == "@-" {
			return &cli.UsageError{Msg: "--secret-stdin conflicts with -d @- (both read stdin)"}
		}
		if cli.IsTerminal(os.Stdin) {
			return &cli.UsageError{Msg: "--secret-stdin requires piped credential input; stdin is a terminal"}
		}
		secret, err := readSecretStdin(os.Stdin)
		if err != nil {
			return err
		}
		if err := applyStdinSecret(&cc, secret); err != nil {
			return err
		}
	}
	if cmd == "token" {
		return cmdToken(cc, o)
	}
	return cmdCall(cc, o, method, rest[0])
}

// validateInvocation rejects flags that parse globally but have no meaning for
// the selected operation. Keep this before reading credential stdin so an
// invalid invocation fails immediately instead of consuming a secret first.
func validateInvocation(cc cliConfig, o *options, cmd, method string, rest []string) error {
	if o.secretStdin && cc.Target == "" && cc.Username != "" && cc.ClientID != "" {
		return &cli.UsageError{Msg: "--secret-stdin: both a username and a client-id are set; pass --target ss or --target platform to name the credential the secret belongs to"}
	}
	switch {
	case cmd == "token":
		if len(rest) != 0 {
			return &cli.UsageError{Msg: "token takes no arguments"}
		}
		if o.dataSet {
			return &cli.UsageError{Msg: "token takes no request body"}
		}
		if len(o.headers) != 0 {
			return &cli.UsageError{Msg: "token does not take -H/--header; use --gateway-header-file for headers required by the token grant"}
		}
		if o.include {
			return &cli.UsageError{Msg: "-i/--include applies only to raw METHOD PATH requests"}
		}
		if o.verbose {
			return &cli.UsageError{Msg: "-v/--verbose applies only to raw METHOD PATH requests"}
		}
		if o.useVault || o.vaultIDSet {
			return &cli.UsageError{Msg: "token does not take --vault or --vault-id"}
		}
		if len(cc.VaultAllow) != 0 {
			return &cli.UsageError{Msg: "token does not take --vault-allow; it performs no vault request"}
		}
		return nil
	case httpMethods[method]:
		if len(rest) != 1 {
			return &cli.UsageError{Msg: fmt.Sprintf("%s requires exactly one PATH", method)}
		}
		if o.allowTerminal {
			return &cli.UsageError{Msg: "--allow-terminal is only valid with token"}
		}
		if o.useVault && requestTargetsSecretServer(cc, o.secretStdin) {
			return &cli.UsageError{Msg: "--vault is only supported for the platform target; omit --target or use --target platform"}
		}
		if o.vaultIDSet {
			if o.vaultID == "" {
				return &cli.UsageError{Msg: "--vault-id requires a non-empty ID"}
			}
			if !o.useVault {
				return &cli.UsageError{Msg: "--vault-id has no effect without --vault"}
			}
		}
		if len(cc.VaultAllow) != 0 && !o.useVault {
			return &cli.UsageError{Msg: "--vault-allow requires --vault; it only controls trust for a discovered Platform vault"}
		}
		return nil
	default:
		return &cli.UsageError{Msg: fmt.Sprintf("unknown method or subcommand %q", cmd)}
	}
}

// requestTargetsSecretServer predicts the target after --secret-stdin has
// selected its credential slot, without consuming the credential. It mirrors
// the engine's bearer-token precedence and automatic credential-pair routing.
func requestTargetsSecretServer(cc cliConfig, secretStdin bool) bool {
	if cc.Target == "ss" {
		return true
	}
	if cc.Target == "platform" {
		return false
	}
	if secretStdin {
		switch {
		case cc.Username != "" && cc.ClientID == "":
			cc.Password, cc.Token = "stdin", ""
		case cc.ClientID != "" && cc.Username == "":
			cc.ClientSecret, cc.Token = "stdin", ""
		default:
			cc.Token = "stdin"
		}
	}
	if cc.Token != "" {
		return false
	}
	ss := cc.Username != "" || cc.Password != ""
	platform := cc.ClientID != "" || cc.ClientSecret != ""
	return ss && !platform
}

type rootBoolSpec struct {
	apply func(cc *cliConfig, o *options)
}

// rootBoolFlags is shared by top-level routing and parseArgs, so accepting a
// new valueless root flag in one place cannot make the other misroute it.
var rootBoolFlags = map[string]rootBoolSpec{
	"--tls-skip-verify": {func(cc *cliConfig, _ *options) { cc.TLSSkipVerify = true }},
	"--vault":           {func(_ *cliConfig, o *options) { o.useVault = true }},
	"--allow-terminal":  {func(_ *cliConfig, o *options) { o.allowTerminal = true }},
	"--secret-stdin":    {func(_ *cliConfig, o *options) { o.secretStdin = true }},
	"--interactive":     {func(_ *cliConfig, o *options) { o.interactive = true }},
	"-i":                {func(_ *cliConfig, o *options) { o.include = true }},
	"--include":         {func(_ *cliConfig, o *options) { o.include = true }},
	"-v":                {func(_ *cliConfig, o *options) { o.verbose = true }},
	"--verbose":         {func(_ *cliConfig, o *options) { o.verbose = true }},
	"-h":                {func(_ *cliConfig, o *options) { o.help = true }},
	"--help":            {func(_ *cliConfig, o *options) { o.help = true }},
}

// topLevelCommand returns the first positional argument and its index. It knows
// the arity of the root flags so a value such as "check" in --url check is not
// mistaken for a verb. A flag it does not know is a hard error rather than a
// guess: its arity is unknowable here, so skipping it either consumes the
// command as the flag's value or promotes the flag's value to the command —
// both produce a misrouted invocation with a contradictory message.
func topLevelCommand(args []string) (int, string, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, _, inline := cli.SplitInlineFlag(a)
		if cli.IsCredentialFlag(name) {
			return 0, "", cli.CredentialFlagError(name)
		}
		if _, ok := rootValueFlags[name]; ok {
			if !inline {
				i++
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if _, ok := rootBoolFlags[a]; ok {
				continue
			}
			return 0, "", &cli.UsageError{Msg: fmt.Sprintf("unknown flag %q before the command; connection flags may precede the command, and a command's own flags follow it", cli.UnknownFlagName(a))}
		}
		return i, a, nil
	}
	return -1, "", nil
}

func withoutArg(args []string, index int) []string {
	out := make([]string, 0, len(args)-1)
	out = append(out, args[:index]...)
	return append(out, args[index+1:]...)
}

// dispatchSecrets keeps the leaf subcommand first, as secretscmd.Dispatch's
// contract requires, while placing root connection flags immediately after it.
// Flags written after "secrets" remain later and therefore keep last-one-wins
// behavior when the same setting appears on both sides.
func dispatchSecrets(leading, rest []string) error {
	if len(rest) == 0 {
		return secretscmd.Dispatch(nil, readmeText)
	}
	args := make([]string, 0, len(leading)+len(rest))
	args = append(args, rest[0])
	args = append(args, leading...)
	args = append(args, rest[1:]...)

	switch rest[0] {
	case "--readme":
		cli.PrintDoc(os.Stdout, readmeText)
		return nil
	case "--tree":
		cli.PrintDoc(os.Stdout, commandTree())
		return nil
	}
	return secretscmd.Dispatch(args, readmeText)
}

// cliConfig holds the raw configuration strings; env values are loaded first
// and flags overwrite them during parsing.
type cliConfig = cli.ConnConfig

type options struct {
	data          string
	dataSet       bool
	headers       []string
	useVault      bool
	vaultID       string
	vaultIDSet    bool
	include       bool
	verbose       bool
	allowTerminal bool
	secretStdin   bool
	interactive   bool
	help          bool
	positionals   []string
}

type rootValueSpec struct {
	apply  func(value string, cc *cliConfig, o *options)
	inline bool // long flag accepts the --flag=value form
}

// rootValueFlags is the single arity table shared by top-level command routing
// and parseArgs. Adding a value-taking root flag here makes the router skip its
// value and makes the parser accept and apply it.
var rootValueFlags = map[string]rootValueSpec{
	"--url":       {func(v string, cc *cliConfig, o *options) { cc.URL = v }, true},
	"--target":    {func(v string, cc *cliConfig, o *options) { cc.Target = v }, true},
	"--username":  {func(v string, cc *cliConfig, o *options) { cc.Username = v }, true},
	"--domain":    {func(v string, cc *cliConfig, o *options) { cc.Domain = v }, true},
	"--client-id": {func(v string, cc *cliConfig, o *options) { cc.ClientID = v }, true},
	"--ca-cert":   {func(v string, cc *cliConfig, o *options) { cc.CACert = v }, true},
	"--timeout":   {func(v string, cc *cliConfig, o *options) { cc.Timeout = v }, true},
	"--retries":   {func(v string, cc *cliConfig, o *options) { cc.Retries = v }, true},
	"--vault-id": {func(v string, cc *cliConfig, o *options) {
		o.vaultID, o.vaultIDSet = v, true
	}, true},
	"--vault-allow": {func(v string, cc *cliConfig, o *options) { cc.VaultAllow = append(cc.VaultAllow, v) }, true},
	"--gateway-header-file": {func(v string, cc *cliConfig, o *options) {
		cc.GatewayHeaderFiles = append(cc.GatewayHeaderFiles, v)
	}, true},
	"-d":       {func(v string, cc *cliConfig, o *options) { o.data, o.dataSet = v, true }, false},
	"--data":   {func(v string, cc *cliConfig, o *options) { o.data, o.dataSet = v, true }, true},
	"-H":       {func(v string, cc *cliConfig, o *options) { o.headers = append(o.headers, v) }, false},
	"--header": {func(v string, cc *cliConfig, o *options) { o.headers = append(o.headers, v) }, true},
}

func configFromEnv() cliConfig { return cli.ConnConfigFromEnv() }
func parseArgs(args []string, cc *cliConfig) (*options, error) {
	o := &options{}
	// Authentication secret material (password, client_secret, bearer token) is
	// deliberately absent: it never comes from a command-line argument, because
	// argv is world-readable (ps, /proc/<pid>/cmdline) and leaks into shell
	// history and CI logs. It arrives from the environment or stdin only. A
	// sensitive request-header value similarly belongs in -H @FILE, not inline.
	need := func(flag string, i int) (string, error) {
		if i+1 >= len(args) {
			return "", &cli.UsageError{Msg: fmt.Sprintf("%s needs a value", flag)}
		}
		return args[i+1], nil
	}
	for i := 0; i < len(args); {
		a := args[i]
		name, inline, hasInline := cli.SplitInlineFlag(a)
		spec, valueFlag := rootValueFlags[name]
		boolSpec, boolFlag := rootBoolFlags[a]
		switch {
		case cli.IsCredentialFlag(name):
			return nil, cli.CredentialFlagError(name)
		case hasInline && valueFlag && spec.inline:
			spec.apply(inline, cc, o)
			i++
		case !hasInline && valueFlag:
			v, err := need(a, i)
			if err != nil {
				return nil, err
			}
			spec.apply(v, cc, o)
			i += 2
		case boolFlag:
			boolSpec.apply(cc, o)
			i++
		case strings.HasPrefix(a, "-") && len(a) > 1:
			return nil, &cli.UsageError{Msg: fmt.Sprintf("unknown flag %q", cli.UnknownFlagName(a))}
		default:
			o.positionals = append(o.positionals, a)
			i++
		}
	}
	return o, nil
}

func buildConfig(cc cliConfig) (da.Config, error) {
	gatewayHeader, err := cli.ReadHeaderFiles(cc.GatewayHeaderPaths())
	if err != nil {
		return da.Config{}, err
	}
	// Timeout and Retries are left zero when unset: the engine owns the 30s
	// and 3-attempt defaults, and pinning them here once duplicated them.
	cfg := da.Config{
		URL:           cc.URL,
		Username:      cc.Username,
		Password:      cc.Password,
		Domain:        cc.Domain,
		ClientID:      cc.ClientID,
		ClientSecret:  cc.ClientSecret,
		Token:         cc.Token,
		Header:        gatewayHeader,
		SkipTLSVerify: cc.TLSSkipVerify,
		// A one-shot CLI process grants at most once and reuses that within
		// its single client's own memoized token; it never reads the shared
		// cross-client cache, and nothing persists past exit. Opt out so a
		// live bearer token is not also stored in the process-wide cache for
		// the run's duration. (Paged listing commands are unaffected: they
		// reuse the client's own token across pages, not the shared cache.)
		DisableCache: true,
	}
	switch cc.Target {
	case "":
	case "ss", "platform":
		cfg.Target = da.Target(cc.Target)
	default:
		return da.Config{}, &cli.UsageError{Msg: fmt.Sprintf("unknown target %q (want ss or platform)", cc.Target)}
	}
	if cfg.URL == "" {
		return da.Config{}, &cli.UsageError{Msg: "DELINEA_TOOLS_URL / --url is required"}
	}
	if err := cli.RequireSecureURL(cfg.URL, "DELINEA_TOOLS_URL / --url"); err != nil {
		return da.Config{}, &cli.UsageError{Msg: err.Error()}
	}
	if err := cli.RequirePlainUsername(cfg.Username); err != nil {
		return da.Config{}, &cli.UsageError{Msg: err.Error()}
	}
	if cc.CACert != "" {
		pem, err := os.ReadFile(cc.CACert)
		if err != nil {
			return da.Config{}, fmt.Errorf("reading CA certificate: %w", err)
		}
		cfg.CACert = pem
	}
	if cc.Timeout != "" {
		d, err := time.ParseDuration(cc.Timeout)
		if err != nil {
			return da.Config{}, &cli.UsageError{Msg: fmt.Sprintf("invalid timeout %q: %v", cc.Timeout, err)}
		}
		// A non-positive value would silently fall back to the engine's 30s
		// default rather than mean what it says, so refuse it.
		if d <= 0 {
			return da.Config{}, &cli.UsageError{Msg: fmt.Sprintf("invalid timeout %q: must be positive", cc.Timeout)}
		}
		cfg.Timeout = d
	}
	if cc.Retries != "" {
		n, err := strconv.Atoi(cc.Retries)
		if err != nil || n < 1 {
			return da.Config{}, &cli.UsageError{Msg: fmt.Sprintf("invalid retries %q (want an integer >= 1)", cc.Retries)}
		}
		cfg.Retries = n
	}
	// The flag wins, like every other setting: any --vault-allow replaces the
	// env list entirely, so a flag can narrow or revoke what CI exported
	// rather than only ever widening it.
	hosts := cc.VaultAllow
	if len(hosts) == 0 && cc.VaultAllowEnv != "" {
		hosts = []string{cc.VaultAllowEnv}
	}
	for _, h := range hosts {
		cfg.AllowedVaultHosts = append(cfg.AllowedVaultHosts, cli.SplitHosts(h)...)
	}
	return cfg, nil
}

func newClient(cc cliConfig) (*da.Client, error) {
	cfg, err := buildConfig(cc)
	if err != nil {
		return nil, err
	}
	if cfg.SkipTLSVerify {
		fmt.Fprintln(os.Stderr, "delinea-util: WARNING: TLS certificate verification disabled (DELINEA_TOOLS_TLS_SKIP_VERIFY)")
	}
	return da.New(cfg)
}
func readSecretStdin(r io.Reader) (string, error) {
	secret, _, err := cli.ReadCredential(r)
	if err != nil {
		return "", err
	}
	if secret == "" {
		return "", &cli.UsageError{Msg: "--secret-stdin: stdin was empty"}
	}
	return secret, nil
}

// applyStdinSecret fills the credential slot the declared target names:
// password for ss, client secret for platform. Without a target it falls back
// to the target-inference rule — a username makes it the password, a client-id
// the client secret, neither a bearer token — and refuses the ambiguous case
// where both are set (a stale USERNAME export must not swallow the client
// secret into the password slot). Filling a grant slot clears the token slot:
// the piped secret is the declared credential, and the engine would otherwise
// prefer a lingering DELINEA_TOOLS_TOKEN and never perform the grant.
func applyStdinSecret(cc *cliConfig, secret string) error {
	switch cc.Target {
	case "ss":
		cc.Password, cc.Token = secret, ""
		return nil
	case "platform":
		cc.ClientSecret, cc.Token = secret, ""
		return nil
	}
	switch {
	case cc.Username != "" && cc.ClientID != "":
		return &cli.UsageError{Msg: "--secret-stdin: both a username and a client-id are set; pass --target ss or --target platform to name the credential the secret belongs to"}
	case cc.Username != "":
		cc.Password, cc.Token = secret, ""
	case cc.ClientID != "":
		cc.ClientSecret, cc.Token = secret, ""
	default:
		cc.Token = secret
	}
	return nil
}

func cmdToken(cc cliConfig, o *options) error {
	if err := checkOutputSink(cli.IsTerminal(os.Stdout), o.allowTerminal); err != nil {
		return err
	}
	client, err := newClient(cc)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx := context.Background()
	var tok string
	if o.interactive {
		// The interactive Platform Identity API flow (password + MFA challenges)
		// for MFA-gated accounts the automatic grant cannot serve. The prompts
		// run on stderr/stdin; the token still lands on stdout like a plain grant.
		tok, err = client.InteractiveLogin(ctx, &stdioPrompter{in: bufio.NewReader(os.Stdin)})
	} else {
		tok, err = client.Token(ctx)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, tok)
	return err
}

// stdioPrompter drives MFA challenges on stderr/stdin, leaving stdout free
// for the token so $(delinea-util token) works.
type stdioPrompter struct {
	in *bufio.Reader
}

func (p *stdioPrompter) ChooseMechanism(mechs []da.Mechanism) (int, error) {
	fmt.Fprintln(os.Stderr, "Choose an authentication mechanism:")
	for i, m := range mechs {
		label := m.PromptSelectMech
		if label == "" {
			label = m.Name
		}
		// label is server-supplied (Identity API challenge text); sanitize it.
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, cli.SanitizeText(label))
	}
	for {
		fmt.Fprint(os.Stderr, "> ")
		line, err := p.in.ReadString('\n')
		if err != nil {
			return 0, fmt.Errorf("reading mechanism choice: %w", err)
		}
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err == nil && n >= 1 && n <= len(mechs) {
			return n - 1, nil
		}
		fmt.Fprintf(os.Stderr, "enter a number between 1 and %d\n", len(mechs))
	}
}

func (p *stdioPrompter) ReadAnswer(prompt string) (string, error) {
	// prompt derives from server-supplied challenge text; sanitize it.
	fmt.Fprintf(os.Stderr, "%s: ", cli.SanitizeText(prompt))
	line, err := p.in.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading answer: %w", err)
	}
	return strings.TrimSpace(line), nil
}
func checkOutputSink(isTTY, allow bool) error {
	if isTTY && !allow {
		return fmt.Errorf("refusing to print the bearer token to a terminal (it would land in your scrollback); capture it with $(...), redirect, or pass --allow-terminal")
	}
	return nil
}

func cmdCall(cc cliConfig, o *options, method, path string) error {
	client, err := newClient(cc)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	return cmdCallWithClient(client, o, method, path)
}

func cmdCallWithClient(client *da.Client, o *options, method, path string) error {
	body, err := requestBody(o)
	if err != nil {
		return err
	}
	hdr, err := requestHeaders(o.headers)
	if err != nil {
		return err
	}
	if o.verbose {
		fmt.Fprintf(os.Stderr, "> %s %s\n", clientDiagnosticText(client, method), requestDiagnosticPath(client, path))
	}
	resp, err := client.Do(context.Background(), da.Request{
		Method:   method,
		Path:     path,
		Header:   hdr,
		Body:     body,
		UseVault: o.useVault,
		VaultID:  o.vaultID,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if o.verbose {
		fprintResponseSummary(os.Stderr, resp)
	}
	if o.include {
		// The status line and headers are server-controlled; sanitize them so a
		// hostile endpoint cannot write terminal escapes into stdout. The body
		// below is copied raw, curl-style — that is the point of -i.
		if err := writeResponseHead(os.Stdout, resp.Proto, resp.Status, resp.Header); err != nil {
			return fmt.Errorf("writing response headers: %w", err)
		}
	}
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		return fmt.Errorf("copying response body to stdout: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &httpErr{status: responseDiagnosticText(resp, resp.Status)}
	}
	return nil
}

func clientDiagnosticText(client *da.Client, text string) string {
	if text == "" {
		return ""
	}
	return client.DiagnosticSnippet([]byte(text))
}

func requestDiagnosticPath(client *da.Client, path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	return clientDiagnosticText(client, path)
}

func responseDiagnosticText(resp *da.Response, text string) string {
	if text == "" {
		return ""
	}
	return resp.DiagnosticSnippet([]byte(text))
}

func writeResponseHead(w io.Writer, proto, status string, h http.Header) error {
	if _, err := fmt.Fprintf(w, "%s %s\r\n", cli.SanitizeText(proto), cli.SanitizeText(status)); err != nil {
		return err
	}
	for k, v := range sanitizedHeaders(h) {
		if _, err := fmt.Fprintf(w, "%s: %s\r\n", k, v); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, "\r\n")
	return err
}

// sanitizedHeaders yields every header key/value in sorted order, both
// sanitized against terminal-escape injection for the explicit -i output.
func sanitizedHeaders(h http.Header) iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for _, k := range slices.Sorted(maps.Keys(h)) {
			sk := cli.SanitizeText(k)
			for _, v := range h[k] {
				if !yield(sk, cli.SanitizeText(v)) {
					return
				}
			}
		}
	}
}

// fprintResponseSummary prints the verbose (-v) response summary. Every field
// is server-controlled and reaches a terminal, so it is bounded, sanitized,
// and redacted with the exact credentials bound to this response.
func fprintResponseSummary(w io.Writer, resp *da.Response) {
	fmt.Fprintf(w, "< %s %s\n", responseDiagnosticText(resp, resp.Proto), responseDiagnosticText(resp, resp.Status))
	for _, k := range slices.Sorted(maps.Keys(resp.Header)) {
		for _, v := range resp.Header[k] {
			value := responseDiagnosticText(resp, v)
			if sensitiveResponseHeader(k) {
				value = "[REDACTED]"
			}
			fmt.Fprintf(w, "< %s: %s\n", responseDiagnosticText(resp, k), value)
		}
	}
}

func sensitiveResponseHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "Set-Cookie2", "Authentication-Info", "Proxy-Authentication-Info":
		return true
	default:
		return false
	}
}

func requestBody(o *options) (io.Reader, error) {
	if !o.dataSet {
		return nil, nil
	}
	switch {
	case o.data == "@-":
		return os.Stdin, nil
	case strings.HasPrefix(o.data, "@"):
		b, err := os.ReadFile(o.data[1:])
		if err != nil {
			return nil, fmt.Errorf("reading -d %s: %w", o.data, err)
		}
		return bytes.NewReader(b), nil
	default:
		return strings.NewReader(o.data), nil
	}
}

func parseHeaders(raw []string) (http.Header, error) { return cli.ParseHeaders(raw) }

// requestHeaders expands @FILE arguments without placing their contents in
// argv. A file contains one Name: value header per non-empty line. Errors from
// parsing a file deliberately identify only the file and line ordinal, never
// the line itself, because every header value is treated as potentially secret.
func requestHeaders(raw []string) (http.Header, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	h := http.Header{}
	for i, arg := range raw {
		if strings.HasPrefix(arg, "@") {
			file := strings.TrimPrefix(arg, "@")
			if file == "" {
				return nil, &cli.UsageError{Msg: fmt.Sprintf("header argument %d has an empty @FILE path", i+1)}
			}
			part, err := cli.ReadHeaderFile(file)
			if err != nil {
				return nil, err
			}
			for name, values := range part {
				h[name] = append(h[name], values...)
			}
			continue
		}
		part, err := parseHeaders([]string{arg})
		if err != nil {
			return nil, err
		}
		for name, values := range part {
			h[name] = append(h[name], values...)
		}
	}
	if len(h) == 0 {
		return nil, nil
	}
	return h, nil
}

func commandTree() string {
	return cli.Tree("delinea-util  — make one authenticated REST call against Delinea Secret Server or the Delinea Platform", []cli.TreeItem{
		{Name: "METHOD PATH", Desc: "perform the request (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)"},
		{Name: "token", Desc: "authenticate and print the bearer token (--interactive: Platform MFA login)"},
		{Name: "check", Desc: "report what is configured, reachable, and resolvable"},
		{Name: "secrets run", Desc: "fetch secrets and exec a command with them injected"},
		{Name: "secrets print", Desc: "fetch secrets and write them to stdout"},
		{Name: "secrets template", Desc: "render a template file with secret values"},
	})
}
