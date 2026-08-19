package secretscmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/DelineaXPM/delinea-common/api"
	ds "github.com/DelineaXPM/delinea-common/secrets"
	"github.com/DelineaXPM/delinea-common/secrets/ciout"
	"github.com/DelineaXPM/delinea-tools/internal/cli"
)

// UsageText returns the secrets-group usage with the command synopsis,
// connection settings, and mapping forms single-sourced from the ONE unified
// README that package main embeds and passes in, so they cannot drift and there
// is a single authoritative document for the whole tool. The parent
// (delinea-util) renders it beneath a usage error whose args begin with
// "secrets".
func UsageText(readme string) string {
	return groupHelp(readme)
}

// writeSecretFile writes secret output to path. New and replaced regular files
// use mode 0600. Callers invoke it only after a successful fetch/render, and the
// write itself installs the new contents by renaming a completed temp file over
// the target, so no failure at any point truncates or destroys what was there.
// An existing regular file is replaced rather than rewritten in place, so the
// secret cannot inherit the old file's wider permissions; a symlink is refused
// rather than followed, since it may point somewhere the author of the path did
// not intend. Anything else (a FIFO, /dev/null) is written as-is: replacing it
// would destroy something the caller set up deliberately.
func writeSecretFile(path string, data []byte) error {
	fi, err := os.Lstat(path)
	switch {
	case err != nil && !os.IsNotExist(err):
		return err
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("refusing to write secrets to %q, which is a symlink; name its target directly", path)
	case err == nil && !fi.Mode().IsRegular():
		return writeExisting(path, data, fi)
	}
	return writeReplacing(path, data)
}

// appendSecretFile appends one payload to a GitHub command file. Those files
// are an append protocol shared by every step command, so replacing one would
// silently discard earlier environment variables or outputs. The descriptor
// checks mirror writeExisting: no symlink is followed and a path swap is
// rejected before any secret is written.
func appendSecretFile(path string, data []byte) error {
	want, err := os.Lstat(path)
	if os.IsNotExist(err) {
		f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
		if openErr != nil {
			return openErr
		}
		return writeAndClose(f, data)
	}
	if err != nil {
		return err
	}
	if want.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to append secrets to %q, which is a symlink; name its target directly", path)
	}
	if !want.Mode().IsRegular() {
		return fmt.Errorf("refusing to append secrets to %q, which is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	got, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if !got.Mode().IsRegular() || !os.SameFile(want, got) {
		f.Close()
		return fmt.Errorf("refusing to append secrets to %q: it changed between the check and the open", path)
	}
	// The pre-existing file's mode is left alone: a GitHub runner creates
	// $GITHUB_ENV and owns it — chmod by the appending step fails with EPERM
	// when the step runs as a different user, and this process is a guest in
	// the runner's file, not its owner.
	return writeAndClose(f, data)
}

// writeReplacing writes data to a fresh 0600 temp file in the target's own
// directory and renames it over path. The rename is the only step that touches
// the target, so an existing file survives every earlier failure; a symlink
// planted at the path after the Lstat is replaced as a directory entry rather
// than followed.
func writeReplacing(path string, data []byte) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := writeAndClose(f, data); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// writeExisting writes to a pre-existing non-regular target (a FIFO or device
// the caller set up deliberately) without following a symlink or being
// redirected by a race. O_NOFOLLOW refuses a symlink swapped in after the
// Lstat; the SameFile check then confirms the opened descriptor is still the
// very object Lstat saw, so a swap to any other file — a different FIFO, a
// regular file — is refused before a single byte of secret is written.
func writeExisting(path string, data []byte, want os.FileInfo) error {
	f, err := os.OpenFile(path, os.O_WRONLY|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	got, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if !os.SameFile(want, got) {
		f.Close()
		return fmt.Errorf("refusing to write secrets to %q: it changed between the check and the open", path)
	}
	return writeAndClose(f, data)
}

func writeAndClose(f *os.File, data []byte) error {
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// checkSink refuses to write secrets to a terminal, whether that is stdout
// (no --out) or an --out path that resolves to a character device, unless
// --allow-terminal is given. print and template share it.
func checkSink(out string, allowTerminal bool) error {
	if out == "" {
		return checkOutputSink(cli.IsTerminal(os.Stdout), allowTerminal)
	}
	return checkOutFileSink(out, allowTerminal)
}

// checkOutFileSink refuses an --out target that is a terminal (character
// device) unless --allow-terminal is given, mirroring the stdout guard: a
// secret written to /dev/tty lands in scrollback exactly as one printed to
// stdout would. A path that does not exist yet, or is a regular file, is fine.
func checkOutFileSink(path string, allow bool) error {
	fi, err := os.Stat(path)
	if err != nil {
		return nil // absent or unstattable; writeSecretFile handles those
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		return checkOutputSink(true, allow)
	}
	return nil
}

// Dispatch runs one secrets subcommand (run/print/template). It is the exported
// entry point the parent (delinea-util) calls as "delinea-util secrets ...",
// handed everything after the "secrets" word plus the unified README (for help
// text). It returns errors rather than rendering them: the parent owns error
// rendering, exit-code mapping, --version, and the --readme/--tree
// docs. The child-process exit-code propagation in launch_stream.go still calls
// os.Exit directly, unchanged.
//
// check is NOT here: it is the top-level "delinea-util check" verb (see Check),
// because configuration, reachability, and credential validity are not
// secrets-specific.
func Dispatch(args []string, readme string) error {
	if len(args) == 0 {
		return &cli.UsageError{Msg: "no subcommand"}
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:], readme)
	case "print":
		return cmdPrint(args[1:], readme)
	case "template":
		return cmdTemplate(args[1:], readme)
	case "help", "-h", "--help":
		cli.PrintDoc(os.Stdout, UsageText(readme))
		return nil
	default:
		if strings.HasPrefix(args[0], "-") {
			// A flag where the subcommand belongs. Echo only its name: the
			// inline value of a credential flag placed here ("secrets
			// --token=SECRET run") would otherwise be written into terminal
			// scrollback and CI logs by this very error.
			if name, _, _ := cli.SplitInlineFlag(args[0]); cli.IsCredentialFlag(name) {
				return cli.CredentialFlagError(name)
			}
			return &cli.UsageError{Msg: fmt.Sprintf("unknown flag %q; the subcommand comes first (run, print, or template)", cli.FlagName(args[0]))}
		}
		return &cli.UsageError{Msg: fmt.Sprintf("unknown subcommand %q", args[0])}
	}
}

// Check runs the top-level "delinea-util check" diagnostic. It shares the check
// machinery (buildConfig, ds.New, checkConfig, probeConfig, checkChildEnv, ...)
// with the secrets group but is a whole-tool verb: configuration, reachability,
// and credential validity are diagnosed for the whole tool, and verifying
// secret mappings is the optional extra it does when mappings are passed. The
// parent renders any usage error (via CheckUsage); Check handles only help.
func Check(args []string, readme string) error {
	if wantsHelp(args) {
		cli.PrintDoc(os.Stdout, CheckUsage(readme))
		return nil
	}
	return cmdCheck(args)
}

// CheckUsage returns the usage for the top-level check verb, its synopsis and
// mapping forms scraped from the unified README so they cannot drift.
func CheckUsage(readme string) string {
	return checkHelp(readme)
}

func cmdRun(args []string, readme string) error {
	if wantsHelp(args) {
		printCommandHelp("run", readme)
		return nil
	}
	cc := configFromEnv()
	rest, err := extractConnFlags(args, &cc)
	if err != nil {
		return err
	}
	p, err := parseArgs("run", rest, "env", true)
	if err != nil {
		return err
	}
	if !validRunMode(p.mode) {
		return fmt.Errorf("unknown --via %q (want env|stdin|sh)", p.mode)
	}
	if !p.hasCommand || len(p.command) == 0 {
		return fmt.Errorf("run requires a command after --")
	}
	if err := requireMappings("run", p.mappings); err != nil {
		return err
	}
	// Built before resolving so a misspelled --pass-env fails without spending an
	// authentication attempt against the vault.
	env, err := childEnv(p.passEnv)
	if err != nil {
		return err
	}
	vars, err := resolve(cc, p.mappings)
	if err != nil {
		return err
	}
	if err := checkCollisions(vars); err != nil {
		return err
	}
	if err := checkDeliverable("run", p.mode, vars); err != nil {
		return err
	}
	if p.mode == "env" {
		if err := refuseUnsafeChildVars(vars); err != nil {
			return err
		}
		if err := checkPassEnvCollisions(vars, p.passEnv); err != nil {
			return err
		}
		for _, v := range vars {
			env = append(env, v.Name+"="+v.Value)
		}
	}
	// --via sh emits export lines a shell evals, so a code-loading name
	// (LD_PRELOAD, BASH_ENV) is as dangerous there as in env injection.
	if p.mode == "sh" {
		if err := refuseUnsafeExports(vars); err != nil {
			return err
		}
	}
	return launch(p.command, env, payloadFor(p.mode, vars))
}

func cmdPrint(args []string, readme string) error {
	if wantsHelp(args) {
		printCommandHelp("print", readme)
		return nil
	}
	cc := configFromEnv()
	rest0, err := extractConnFlags(args, &cc)
	if err != nil {
		return err
	}
	var out string
	allowTerminal := false
	rest, err := extractSinkFlags(rest0, map[string]*string{"--out": &out}, &allowTerminal)
	if err != nil {
		return err
	}
	p, err := parseArgs("print", rest, "stdin", false)
	if err != nil {
		return err
	}
	if !validPrintMode(p.mode) {
		return fmt.Errorf("print --via must be stdin, sh, json, raw, github-env, github-output, or ado (got %q)", p.mode)
	}
	if len(p.passEnv) > 0 {
		return fmt.Errorf("--pass-env applies only to run, which launches a child process")
	}
	if p.mode == "ado" && out != "" {
		return &cli.UsageError{Msg: "--via ado writes Azure Pipelines logging commands to stdout, where the agent reads them; it cannot be used with --out"}
	}
	if err := requireMappings("print", p.mappings); err != nil {
		return err
	}
	if isGitHubFileMode(p.mode) {
		// The mode's contract is masks-then-values, and the masks go to the
		// step's stdout — writing the payload to stdout instead would mix the
		// two streams or, worse, deliver unmasked values. Requiring --out is
		// what keeps the "already masked in job logs" promise true.
		if out == "" {
			commandFile := "$GITHUB_ENV"
			if p.mode == "github-output" {
				commandFile = "$GITHUB_OUTPUT"
			}
			return &cli.UsageError{Msg: fmt.Sprintf("--via %s requires --out FILE (usually --out \"%s\"); the ::add-mask:: lines go to stdout", p.mode, commandFile)}
		}
		// Stdout carries the masks — secret values — so the terminal guard
		// applies to it too, before any credential is spent or secret fetched.
		if err := checkOutputSink(cli.IsTerminal(os.Stdout), allowTerminal); err != nil {
			return err
		}
	}
	if err := checkSink(out, allowTerminal); err != nil {
		return err
	}
	vars, err := resolve(cc, p.mappings)
	if err != nil {
		return err
	}
	if err := checkCollisions(vars); err != nil {
		return err
	}
	if err := checkRawCount(p.mode, len(vars)); err != nil {
		return err
	}
	if err := checkDeliverable("print", p.mode, vars); err != nil {
		return err
	}
	// sh (export lines eval'd in the operator's shell) and github-env (values
	// become environment variables in every later job step) both inject into an
	// environment that loads code, so a code-loading name must be refused for
	// either — including one produced by PREFIX_* expansion, since vars is the
	// resolved set.
	if exportsToEnvironment(p.mode) {
		if err := refuseUnsafeExports(vars); err != nil {
			return err
		}
	}
	payload := payloadFor(p.mode, vars)
	if isGitHubFileMode(p.mode) {
		// Masks first, on stdout, so the runner registers them before the
		// values exist anywhere it might echo; then append — GitHub command
		// files are an append protocol shared by every step command.
		masks, err := ciout.GitHubMask(vars)
		if err != nil {
			return err
		}
		if _, err := os.Stdout.WriteString(masks); err != nil {
			return err
		}
		return appendSecretFile(out, payload)
	}
	if out != "" {
		return writeSecretFile(out, payload)
	}
	_, err = os.Stdout.Write(payload)
	return err
}

func resolve(cc cliConfig, mappings []ds.Mapping) ([]ds.Var, error) {
	// --secret-stdin is explicit, but reading a terminal would still block
	// silently forever with no prompt (check guards the same way).
	if cc.SecretStdin && cli.IsTerminal(os.Stdin) {
		return nil, fmt.Errorf("--secret-stdin requires credential input, but stdin is a terminal; pipe the credential in (e.g. from a keychain or secret manager)")
	}
	// stdin is read only with --secret-stdin, so a run/print with no secret in
	// the environment and no flag is a configuration mistake — name the remedy
	// rather than letting the engine's generic "no credentials" surface, since
	// pipelines that relied on the old implicit stdin fallback need to hear
	// that stdin is now explicit.
	if !cc.SecretStdin && cc.Token == "" && cc.Password == "" && cc.ClientSecret == "" {
		return nil, &cli.UsageError{Msg: "no credential: set DELINEA_TOOLS_PASSWORD, DELINEA_TOOLS_CLIENT_SECRET, or DELINEA_TOOLS_TOKEN, or pipe the secret with --secret-stdin (stdin is never read implicitly)"}
	}
	cfg, err := buildConfig(cc, os.Stdin)
	if err != nil {
		return nil, err
	}
	if cfg.SkipTLSVerify {
		fmt.Fprintln(os.Stderr, "delinea-util secrets: WARNING: TLS certificate verification disabled (DELINEA_TOOLS_TLS_SKIP_VERIFY)")
	}
	client, err := ds.New(cfg)
	if err != nil {
		return nil, err
	}
	return client.Resolve(context.Background(), mappings)
}

// cliConfig is the shared connection-settings type: one definition for the
// raw verbs and the secrets group, so the two cannot drift (internal/cli).
type cliConfig = cli.ConnConfig

func configFromEnv() cliConfig { return cli.ConnConfigFromEnv() }

// extractConnFlags pulls the connection flags out of args into cc (each flag
// overriding the env value already loaded), returning the remaining arguments
// for the per-command parser. It stops at "--", copying it and everything after
// verbatim so a run command line is never reinterpreted; the sink flags
// (--out/--in/--allow-terminal), delivery flags (--via/--pass-env), check flags
// (--quiet/--json) and the mappings all fall through untouched.
func extractConnFlags(args []string, cc *cliConfig) ([]string, error) {
	// Secret material (password, client_secret, bearer token) is deliberately
	// absent: it never comes from a command-line argument, because argv is
	// world-readable (ps, /proc/<pid>/cmdline) and leaks into shell history and
	// CI logs. It arrives from the environment or stdin only. The flags here
	// carry identities and settings, which argv may safely hold.
	stringFlag := map[string]*string{
		"--url": &cc.URL, "--target": &cc.Target,
		"--username": &cc.Username, "--domain": &cc.Domain,
		"--client-id": &cc.ClientID,
		"--ca-cert":   &cc.CACert, "--timeout": &cc.Timeout,
		"--retries": &cc.Retries,
	}
	var rest []string
	for i := 0; i < len(args); {
		a := args[i]
		name, inline, hasInline := cli.SplitInlineFlag(a)
		switch {
		case a == "--":
			return append(rest, args[i:]...), nil
		case cli.IsCredentialFlag(name):
			return nil, cli.CredentialFlagError(name)
		case a == "--tls-skip-verify":
			cc.TLSSkipVerify, i = true, i+1
		case a == "--secret-stdin":
			cc.SecretStdin, i = true, i+1
		case a == "--vault-allow":
			if i+1 >= len(args) {
				return nil, &cli.UsageError{Msg: "--vault-allow needs a value"}
			}
			cc.VaultAllow, i = append(cc.VaultAllow, args[i+1]), i+2
		case hasInline && name == "--vault-allow":
			cc.VaultAllow, i = append(cc.VaultAllow, inline), i+1
		case a == "--gateway-header-file":
			if i+1 >= len(args) {
				return nil, &cli.UsageError{Msg: "--gateway-header-file needs a value"}
			}
			cc.GatewayHeaderFiles, i = append(cc.GatewayHeaderFiles, args[i+1]), i+2
		case hasInline && name == "--gateway-header-file":
			cc.GatewayHeaderFiles, i = append(cc.GatewayHeaderFiles, inline), i+1
		case hasInline && stringFlag[name] != nil:
			*stringFlag[name], i = inline, i+1
		case stringFlag[a] != nil:
			if i+1 >= len(args) {
				return nil, &cli.UsageError{Msg: fmt.Sprintf("%s needs a value", a)}
			}
			*stringFlag[a], i = args[i+1], i+2
		default:
			rest, i = append(rest, a), i+1
		}
	}
	return rest, nil
}

// buildConfig turns the raw cliConfig into a ds.Config, filling the credential
// from stdin only when --secret-stdin is set, and routing it to the slot the
// target names (mirroring delinea-util's applyStdinSecret). It then
// folds the resolved principal into the ds.Config fields the engine expects:
// for the Platform the client_id/client_secret pair, otherwise username/password.
func buildConfig(cc cliConfig, stdin io.Reader) (ds.Config, error) {
	target, err := parseTarget(cc.Target)
	if err != nil {
		return ds.Config{}, err
	}
	if err := cli.RequireSecureURL(cc.URL, "DELINEA_TOOLS_URL"); err != nil {
		return ds.Config{}, err
	}
	if err := cli.RequirePlainUsername(cc.Username); err != nil {
		return ds.Config{}, err
	}
	// The secret is never a command-line argument. It comes from
	// DELINEA_TOOLS_TOKEN/_PASSWORD/_CLIENT_SECRET, or explicitly from stdin with
	// --secret-stdin, which overrides any environment secret. When it
	// comes from stdin, applyStdinSecret fills the target's slot and clears the
	// others, so a piped credential wins over a stale exported one.
	if cc.SecretStdin {
		secret, _, rerr := cli.ReadCredential(stdin)
		if rerr != nil {
			return ds.Config{}, rerr
		}
		if secret == "" {
			// Installing an empty secret would also clear the environment
			// credential and surface later as a misleading "no credentials";
			// the actual fault is the pipe.
			return ds.Config{}, &cli.UsageError{Msg: "--secret-stdin: stdin was empty; the pipe delivered no credential"}
		}
		if err := applyStdinSecret(&cc, target, secret); err != nil {
			return ds.Config{}, err
		}
	}
	platform, err := resolvePlatform(cc, target)
	if err != nil {
		return ds.Config{}, err
	}
	gatewayHeader, err := cli.ReadHeaderFiles(cc.GatewayHeaderPaths())
	if err != nil {
		return ds.Config{}, err
	}
	cfg := ds.Config{
		URL:               cc.URL,
		Domain:            cc.Domain,
		Token:             cc.Token,
		Header:            gatewayHeader,
		SkipTLSVerify:     cc.TLSSkipVerify,
		AllowedVaultHosts: vaultHosts(cc),
		// A one-shot CLI process never reads the shared cross-client cache —
		// a single client (even a paged listing command) reuses its own
		// memoized token, and nothing persists past exit. Opt out so a live
		// bearer token is not also held in the process-wide cache for the run.
		DisableCache: true,
	}
	if platform {
		cfg.Target = api.TargetPlatform
		cfg.Username, cfg.Password = cc.ClientID, cc.ClientSecret
	} else {
		cfg.Target = target
		cfg.Username, cfg.Password = cc.Username, cc.Password
	}
	if cfg.CACert, err = caCertBytes(cc.CACert); err != nil {
		return ds.Config{}, err
	}
	if cfg.Timeout, err = parseTimeout(cc.Timeout); err != nil {
		return ds.Config{}, err
	}
	if cfg.Retries, err = parseRetries(cc.Retries); err != nil {
		return ds.Config{}, err
	}
	return cfg, nil
}

// applyStdinSecret fills the credential slot the target names, mirroring
// delinea-util: password for ss, client_secret for platform. Without a target it
// falls back to the target-inference rule — a username makes it the password, a
// client-id the client_secret, neither a bearer token — and refuses the
// ambiguous case where both a username and a client-id are set.
func applyStdinSecret(cc *cliConfig, target api.Target, secret string) error {
	switch target {
	case api.TargetSecretServer:
		cc.Password, cc.Token = secret, ""
		return nil
	case api.TargetPlatform:
		cc.ClientSecret, cc.Token = secret, ""
		return nil
	}
	switch {
	case cc.Username != "" && cc.ClientID != "":
		return &cli.UsageError{Msg: "both a username and a client-id are set; set DELINEA_TOOLS_TARGET=ss or =platform to name the credential the stdin secret belongs to"}
	case cc.Username != "":
		cc.Password, cc.Token = secret, ""
	case cc.ClientID != "":
		cc.ClientSecret, cc.Token = secret, ""
	default:
		cc.Token = secret
	}
	return nil
}

// resolvePlatform decides whether the engine talks to the Platform (which
// authenticates a client_id/client_secret and routes fetches through the vault)
// or Secret Server. An explicit target wins; without one, a bearer token ignores
// stale identity fields and secret fetches retain their Secret Server default.
// Otherwise a client-id alone means platform, a username alone means ss, and
// both together is ambiguous.
func resolvePlatform(cc cliConfig, target api.Target) (bool, error) {
	switch target {
	case api.TargetPlatform:
		return true, nil
	case api.TargetSecretServer:
		return false, nil
	}
	if cc.Token != "" {
		return false, nil
	}
	switch {
	case cc.Username != "" && cc.ClientID != "":
		return false, &cli.UsageError{Msg: "both a username and a client-id are set; set DELINEA_TOOLS_TARGET=ss or =platform"}
	case cc.ClientID != "":
		return true, nil
	default:
		return false, nil
	}
}

// vaultHosts resolves the allowed-vault-host list: any --vault-allow replaces
// the env list entirely (the flag wins), so a flag can narrow or revoke what CI
// exported rather than only widen it.
func vaultHosts(cc cliConfig) []string {
	sources := cc.VaultAllow
	if len(sources) == 0 && cc.VaultAllowEnv != "" {
		sources = []string{cc.VaultAllowEnv}
	}
	var out []string
	for _, s := range sources {
		out = append(out, cli.SplitHosts(s)...)
	}
	return out
}

// parseTarget maps a target string to the engine Target: empty and "ss" both
// mean Secret Server, "platform" routes secret fetches through the tenant's
// vault. check mirrors this through the same function so the two cannot drift.
func parseTarget(target string) (api.Target, error) {
	switch target {
	case "":
		return api.TargetAuto, nil
	case "ss":
		return api.TargetSecretServer, nil
	case "platform":
		return api.TargetPlatform, nil
	default:
		return api.TargetAuto, fmt.Errorf("invalid DELINEA_TOOLS_TARGET %q (want ss or platform)", target)
	}
}

// caCertBytes loads a PEM bundle from path, when set.
func caCertBytes(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading DELINEA_TOOLS_CA_CERT: %w", err)
	}
	return pem, nil
}

// parseTimeout parses a timeout string, defaulting to 30s. A non-positive value
// is refused: it would silently disable the whole-resolve deadline.
func parseTimeout(d string) (time.Duration, error) {
	if d == "" {
		return 30 * time.Second, nil
	}
	to, err := time.ParseDuration(d)
	if err != nil {
		return 0, fmt.Errorf("invalid DELINEA_TOOLS_TIMEOUT %q: %w", d, err)
	}
	if to <= 0 {
		return 0, fmt.Errorf("invalid DELINEA_TOOLS_TIMEOUT %q: must be positive", d)
	}
	return to, nil
}

// parseRetries parses the retry count, defaulting to 3 (the CLI default; the
// library default is 1). A value below 1 is refused.
func parseRetries(s string) (int, error) {
	if s == "" {
		return 3, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("invalid DELINEA_TOOLS_RETRIES %q (want an integer >= 1)", s)
	}
	return n, nil
}

// checkCollisions rejects two mappings that define the same variable, including
// two expanded slugs that differ only in punctuation (api-key and api_key both
// become PREFIX_API_KEY). Only one value would survive delivery, and which one
// differs by mode, so the collision is refused rather than resolved. Names are
// compared with envNameKey: on Windows the child's environment folds case, so
// ApiKey and APIKEY are one variable there.
func checkCollisions(vars []ds.Var) error {
	seen := make(map[string]bool, len(vars))
	for _, v := range vars {
		key := envNameKey(v.Name)
		if seen[key] {
			return fmt.Errorf("%s is defined more than once; drop or rename one of its mappings", v.Name)
		}
		seen[key] = true
	}
	return nil
}

// checkPassEnvCollisions refuses a resolved variable that --pass-env also
// names: both would land in the child's environment as duplicate entries, and
// which value the child sees depends on its libc, so the stale parent value
// could silently win over the fetched secret.
func checkPassEnvCollisions(vars []ds.Var, passEnv []string) error {
	named := make(map[string]bool, len(passEnv))
	for _, name := range passEnv {
		named[envNameKey(name)] = true
	}
	for _, v := range vars {
		if named[envNameKey(v.Name)] {
			return fmt.Errorf("%s is both a --pass-env variable and a secret mapping; drop one, or the child would see two values for it", v.Name)
		}
	}
	return nil
}

// checkDeliverable rejects values a mode cannot carry intact, naming the
// variable and a remedy that the invoking subcommand actually offers. env is
// rejected here rather than left to execve; stdin frames pairs with NUL and
// sh cannot quote one; Windows environment blocks and JSON cannot preserve
// invalid UTF-8. Those constraints would silently corrupt a binary attachment
// on exactly the path recommended for arbitrary values. Only raw truly carries
// any bytes on every platform.
func checkDeliverable(cmd, mode string, vars []ds.Var) error {
	nulRemedy := "use --via raw or --via json"
	if cmd == "run" {
		// run offers no NUL-safe mode; pointing at modes it rejects would be
		// a dead end.
		nulRemedy = "run has no delivery mode for it; write it with print --via raw or a template --out file instead"
	}
	if isGitHubFileMode(mode) || mode == "ado" {
		// The formatter owns the format's constraints; run it once for the
		// verdict and keep its variable-naming errors verbatim.
		format := ciout.GitHubEnv
		if mode == "github-output" {
			format = ciout.GitHubOutput
		} else if mode == "ado" {
			format = ciout.AzurePipelines
		}
		if _, err := format(vars); err != nil {
			return fmt.Errorf("--via %s: %w", mode, err)
		}
		return nil
	}
	for _, v := range vars {
		switch mode {
		case "env":
			if strings.IndexByte(v.Value, 0) >= 0 {
				return fmt.Errorf("%s contains a NUL byte, which --via %s cannot carry; %s", v.Name, mode, nulRemedy)
			}
			if envRequiresUTF8 && !utf8.ValidString(v.Value) {
				return fmt.Errorf("%s is not valid UTF-8, which a Windows child environment cannot carry intact; use run --via stdin, or write it with print --via raw", v.Name)
			}
		case "stdin", "sh":
			if strings.IndexByte(v.Value, 0) >= 0 {
				return fmt.Errorf("%s contains a NUL byte, which --via %s cannot carry; %s", v.Name, mode, nulRemedy)
			}
		case "json":
			if !utf8.ValidString(v.Value) {
				return fmt.Errorf("%s is not valid UTF-8, which --via json would silently corrupt to replacement characters; use --via raw for binary values", v.Name)
			}
		}
	}
	return nil
}

// unsafeChildVars are well-known environment variable names that steer how a
// child loads or executes code — dynamic linker, shell startup, command hooks,
// pagers/editors, and language interpreters. A value for one of these controls
// the child, so defining it from a secret (whose value another party may
// control) is refused even though the operator chose the name. This is
// defense-in-depth rather than a sandbox: the operator still owns the mapping
// names and command. Keys must be upper case; envNameKey folds on Windows.
var unsafeChildVars = map[string]bool{
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true, "GCONV_PATH": true,
	"DYLD_INSERT_LIBRARIES": true, "DYLD_LIBRARY_PATH": true, "DYLD_FALLBACK_LIBRARY_PATH": true,
	"DYLD_FRAMEWORK_PATH": true, "DYLD_FALLBACK_FRAMEWORK_PATH": true,
	"BASH_ENV": true, "ENV": true, "SHELLOPTS": true, "PS4": true, "IFS": true,
	"PROMPT_COMMAND": true, "ZDOTDIR": true,
	"GIT_SSH_COMMAND": true, "GIT_EXTERNAL_DIFF": true, "GIT_PAGER": true, "GIT_EDITOR": true, "GIT_ASKPASS": true,
	"PAGER": true, "MANPAGER": true, "SYSTEMD_PAGER": true, "EDITOR": true, "VISUAL": true,
	"SSH_ASKPASS": true, "SUDO_ASKPASS": true, "LESSOPEN": true, "LESSCLOSE": true,
	"MAKEFLAGS": true, "BROWSER": true,
	"PYTHONPATH": true, "PYTHONHOME": true, "PYTHONSTARTUP": true,
	"PERL5LIB": true, "PERLLIB": true, "PERL5OPT": true,
	"NODE_OPTIONS": true, "NODE_PATH": true,
	"RUBYOPT": true, "RUBYLIB": true,
	"LUA_PATH": true, "LUA_CPATH": true,
	"GLIBC_TUNABLES":    true,
	"JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true,
	"CLASSPATH":                true,
	"DOTNET_STARTUP_HOOKS":     true,
	"CORECLR_ENABLE_PROFILING": true, "CORECLR_PROFILER": true,
	"CORECLR_PROFILER_PATH": true, "CORECLR_PROFILER_PATH_32": true, "CORECLR_PROFILER_PATH_64": true,
	"COR_ENABLE_PROFILING": true, "COR_PROFILER": true,
	"COR_PROFILER_PATH": true, "COR_PROFILER_PATH_32": true, "COR_PROFILER_PATH_64": true,
}

// refuseUnsafeChildVars rejects a resolved variable whose name would shadow a
// baseline variable (a secret naming itself PATH would shadow the child's own;
// --pass-env is the sanctioned way to carry a baseline variable) or whose name
// controls how the child loads code. Only reached for --via env, where the
// name becomes an actual environment variable of the launched child.
func refuseUnsafeChildVars(vars []ds.Var) error {
	for _, v := range vars {
		if inBaseline(v.Name) {
			return fmt.Errorf("%s is a baseline environment variable; refusing to define it from a secret, which would shadow the child's own (pass it through with --pass-env instead)", v.Name)
		}
	}
	return refuseUnsafeExports(vars)
}

// refuseUnsafeExports rejects a resolved variable that eval'ing the --via sh
// output would let a secret weaponize: a code-loading name (LD_PRELOAD,
// BASH_ENV, ...), or a baseline variable the shell and its children rely on —
// PATH above all, since export PATH=<secret> redirects command resolution to
// an attacker-chosen directory. The export lines are meant to be eval'd into
// the operator's own shell (eval "$(delinea-util secrets print --via sh ...)"), so
// both classes take effect there. stdin/json/raw carry inert data a consumer
// parses, so they are exempt.
func refuseUnsafeExports(vars []ds.Var) error {
	for _, v := range vars {
		if inBaseline(v.Name) {
			return fmt.Errorf("%s is an environment variable the shell and its children rely on; refusing to define it from a secret, which eval would use to override the ambient value", v.Name)
		}
		if unsafeChildVars[envNameKey(v.Name)] {
			return fmt.Errorf("%s controls how a shell or its children load or execute code; refusing to define it from a secret", v.Name)
		}
	}
	return nil
}

// payloadFor renders the secrets for a delivery mode. Mode "env" has no payload:
// its values go into the child's environment instead.
func payloadFor(mode string, vars []ds.Var) []byte {
	switch mode {
	case "json":
		m := make(map[string]string, len(vars))
		for _, v := range vars {
			m[v.Name] = v.Value
		}
		payload, _ := json.Marshal(m)
		return payload
	case "raw":
		if len(vars) > 0 {
			return []byte(vars[0].Value)
		}
		return nil
	}
	if mode == "sh" || isGitHubFileMode(mode) || mode == "ado" {
		// checkDeliverable already refused what these formats refuse, and
		// mapping parsing refused invalid or duplicate names, so this cannot
		// fail here; the fallback keeps a future drift loud instead of silent.
		format := ciout.Shell
		if mode == "github-env" {
			format = ciout.GitHubEnv
		} else if mode == "github-output" {
			format = ciout.GitHubOutput
		} else if mode == "ado" {
			format = ciout.AzurePipelines
		}
		out, err := format(vars)
		if err != nil {
			panic("payloadFor: " + err.Error())
		}
		return []byte(out)
	}
	var payload []byte
	for _, v := range vars {
		if mode == "stdin" {
			payload = append(payload, (v.Name + "=" + v.Value)...)
			payload = append(payload, 0)
		}
	}
	return payload
}

// extractSinkFlags pulls the file-sink flags (--in/--out, with = or separate
// values, and --allow-terminal) out of args, so print and template share one
// extraction; the remaining arguments go to parseArgs.
func extractSinkFlags(args []string, fileFlags map[string]*string, allowTerminal *bool) ([]string, error) {
	var rest []string
	for i := 0; i < len(args); {
		a := args[i]
		name, inline, hasInline := cli.SplitInlineFlag(a)
		switch {
		case a == "--allow-terminal":
			*allowTerminal, i = true, i+1
		case hasInline && fileFlags[name] != nil:
			// An empty inline value (--out=) must not silently fall through to
			// the stdout sink, writing the secret wherever stdout points.
			if inline == "" {
				return nil, fmt.Errorf("%s needs a non-empty file path", name)
			}
			*fileFlags[name], i = inline, i+1
		case fileFlags[a] != nil:
			if i+1 >= len(args) || args[i+1] == "" {
				return nil, fmt.Errorf("%s needs a file path", a)
			}
			*fileFlags[a], i = args[i+1], i+2
		default:
			rest, i = append(rest, a), i+1
		}
	}
	return rest, nil
}

// parsed holds the flags and mappings common to every subcommand. viaSet
// records that --via appeared at all, so a subcommand with no delivery mode can
// reject it instead of silently ignoring it.
type parsed struct {
	mode       string
	viaSet     bool
	mappings   []ds.Mapping
	command    []string
	hasCommand bool
	passEnv    []string
}

// checkPassEnv rejects a --pass-env value that carries an inline value. Putting
// a value on the command line exposes it in ps output, shell history and CI
// logs, which is the one thing this tool exists to avoid.
func checkPassEnv(name string) error {
	if name == "" {
		return fmt.Errorf("--pass-env needs a variable name")
	}
	if strings.Contains(name, "=") {
		return fmt.Errorf("--pass-env takes a name, not an assignment; set the variable in the calling environment instead")
	}
	return nil
}

func parseArgs(cmd string, args []string, defaultMode string, wantCommand bool) (parsed, error) {
	p := parsed{mode: defaultMode}
	for i := 0; i < len(args); {
		a := args[i]
		name, inline, hasInline := cli.SplitInlineFlag(a)
		switch {
		case a == "--":
			if !wantCommand {
				return parsed{}, fmt.Errorf("%s takes no command (unexpected '--')", cmd)
			}
			p.command, p.hasCommand = args[i+1:], true
			return p, nil
		case a == "--via":
			if i+1 >= len(args) {
				return parsed{}, fmt.Errorf("--via needs a value")
			}
			p.mode, p.viaSet, i = args[i+1], true, i+2
		case hasInline && name == "--via":
			p.mode, p.viaSet, i = inline, true, i+1
		case a == "--pass-env":
			if i+1 >= len(args) {
				return parsed{}, fmt.Errorf("--pass-env needs a variable name")
			}
			if err := checkPassEnv(args[i+1]); err != nil {
				return parsed{}, err
			}
			p.passEnv, i = append(p.passEnv, args[i+1]), i+2
		case hasInline && name == "--pass-env":
			if err := checkPassEnv(inline); err != nil {
				return parsed{}, err
			}
			p.passEnv, i = append(p.passEnv, inline), i+1
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				// A flag no parser claimed (a raw-verb flag like -v or -H that
				// the router let through) must say so, not surface as a
				// cryptic mapping-parse error.
				return parsed{}, &cli.UsageError{Msg: fmt.Sprintf("unknown flag %s for secrets %s", cli.FlagName(a), cmd)}
			}
			m, perr := ds.ParseMapping(a)
			if perr != nil {
				return parsed{}, perr
			}
			p.mappings, i = append(p.mappings, m), i+1
		}
	}
	return p, nil
}

func validRunMode(m string) bool { return m == "env" || m == "stdin" || m == "sh" }
func validPrintMode(m string) bool {
	return m == "stdin" || m == "sh" || m == "json" || m == "raw" || isGitHubFileMode(m) || m == "ado"
}

func requireMappings(cmd string, mappings []ds.Mapping) error {
	if len(mappings) == 0 {
		return &cli.UsageError{Msg: fmt.Sprintf("%s requires at least one MAPPING", cmd)}
	}
	return nil
}

func isGitHubFileMode(m string) bool { return m == "github-env" || m == "github-output" }

// exportsToEnvironment reports whether a print --via mode injects its output into
// an environment that later loads code — an operator shell (sh, via eval) or a
// GitHub Actions job whose $GITHUB_ENV entries become variables in every later
// step. Those need the refuseUnsafeExports guard; the inert sinks (stdin, json,
// raw) carry no such risk.
func exportsToEnvironment(m string) bool { return m == "sh" || m == "github-env" }

func checkRawCount(mode string, n int) error {
	if mode == "raw" && n != 1 {
		return fmt.Errorf("--via raw expects exactly one value, got %d", n)
	}
	return nil
}

func parseTemplate(src string) (*template.Template, error) {
	tmpl, err := template.New("t").Option("missingkey=error").Parse(src)
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}
	return tmpl, nil
}

func renderTemplate(tmpl *template.Template, vars []ds.Var) ([]byte, error) {
	data := make(map[string]string, len(vars))
	for _, v := range vars {
		data[v.Name] = v.Value
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("rendering template: %w", err)
	}
	return buf.Bytes(), nil
}

func cmdTemplate(args []string, readme string) error {
	if wantsHelp(args) {
		printCommandHelp("template", readme)
		return nil
	}
	cc := configFromEnv()
	rest0, err := extractConnFlags(args, &cc)
	if err != nil {
		return err
	}
	var in, out string
	allowTerminal := false
	rest, err := extractSinkFlags(rest0, map[string]*string{"--in": &in, "--out": &out}, &allowTerminal)
	if err != nil {
		return err
	}
	if in == "" {
		return fmt.Errorf("template requires --in FILE")
	}
	p, err := parseArgs("template", rest, "stdin", false)
	if err != nil {
		return err
	}
	if p.viaSet {
		return fmt.Errorf("--via applies only to run and print; template always renders --in")
	}
	if len(p.passEnv) > 0 {
		return fmt.Errorf("--pass-env applies only to run, which launches a child process")
	}
	if err := requireMappings("template", p.mappings); err != nil {
		return err
	}
	if err := checkSink(out, allowTerminal); err != nil {
		return err
	}
	// Read and parse the template before resolving: a bad --in path or a
	// syntax error must fail before a credential grant and secret downloads
	// are spent (cmdRun validates --pass-env up front for the same reason).
	src, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("reading template %q: %w", in, err)
	}
	tmpl, err := parseTemplate(string(src))
	if err != nil {
		return err
	}
	vars, err := resolve(cc, p.mappings)
	if err != nil {
		return err
	}
	if err := checkCollisions(vars); err != nil {
		return err
	}
	rendered, err := renderTemplate(tmpl, vars)
	if err != nil {
		return err
	}
	if out == "" {
		_, err = os.Stdout.Write(rendered)
		return err
	}
	return writeSecretFile(out, rendered)
}

// childEnv builds the child's environment from the baseline plus the variables
// named by --pass-env. Nothing else is inherited. The parent's environment is
// not a safe thing to forward: it routinely holds unrelated credentials, and a
// dependency can add its own at any time (older Delinea SDK releases cached the
// vault access token there), so what the child receives is declared rather than
// filtered.
func childEnv(passEnv []string) ([]string, error) {
	// Baseline suppression folds names with envNameKey: on Windows a
	// --pass-env PATH must suppress the baseline's "Path" entry, or the
	// child receives duplicate spellings of one case-insensitive variable.
	named := make(map[string]bool, len(passEnv))
	for _, name := range passEnv {
		named[envNameKey(name)] = true
	}
	var out []string
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if ok && inBaseline(name) && !named[envNameKey(name)] {
			out = append(out, kv)
		}
	}
	var missing []string
	for _, name := range passEnv {
		value, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			continue
		}
		out = append(out, name+"="+value)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("--pass-env: not set in the environment: %s (a shell variable must be exported before it is one)", strings.Join(missing, ", "))
	}
	return out, nil
}

func checkOutputSink(isTTY, allow bool) error {
	if isTTY && !allow {
		return fmt.Errorf("refusing to write secrets to a terminal; redirect to a file or pipe, or pass --allow-terminal")
	}
	return nil
}
