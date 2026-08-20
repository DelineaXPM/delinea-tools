delinea-util
============

One authenticated tool for Delinea Secret Server (on-prem or cloud) and the
Delinea Platform. It has two faces that share one credential model, one token
engine, and one set of connection settings:

  - the raw REST verbs (METHOD PATH, token) make a
    single authenticated call, curl-style: delinea-util performs the OAuth2 token
    grant itself, attaches the bearer token, sends your request, and prints the
    response body to stdout;
  - the "secrets" subcommand group (run, print, template) fetches secret values
    from the vault and hands them to a process, a config file, or stdout without
    ever putting them on a command line;
  - and "check" diagnoses the whole tool — configuration, reachability, and the
    credential — with read-only diagnostic requests and without exposing a
    secret value.

Nothing is written to disk unless you ask for it. The reusable api and secrets
packages live in github.com/DelineaXPM/delinea-common; this repository ships the
CLI that wraps them.

AT A GLANCE
-----------

  - One credential model reaches Secret Server (on-prem or cloud) and the
    Delinea Platform — no separate tools or code paths.
  - A single self-contained binary with no runtime service dependency. Its sole
    Go module dependency is the standard-library-only delinea-common module.
  - The vault credential comes from the environment or stdin, never argv; tokens
    are cached in memory, and nothing is written to disk unless you ask.
  - The raw REST surface stays stable as services change — no per-service
    wrappers or generated types to maintain.

  Two commands cover most uses:

    # Any endpoint, curl-style:
    delinea-util GET /api/v1/users/current

    # Run a program with a secret injected into a declared environment:
    delinea-util secrets run PGPASSWORD=password#128 -- \
        psql -h db.internal -U appuser -d orders -c 'select count(*) from users'

INSTALL
-------

  go install github.com/DelineaXPM/delinea-tools/cmd/delinea-util@v1.0.0

USAGE
-----

  delinea-util [flags] METHOD PATH [-d BODY] [-H 'Name: value' | -H @FILE]
  delinea-util [flags] token [--interactive]
  delinea-util [flags] check [--json] [--quiet] [--no-auth] [--pass-env NAME]... [MAPPING...]
  delinea-util [flags] secrets run|print|template ...
  delinea-util help | --readme | --tree | --version

METHOD is GET, POST, PUT, PATCH, DELETE, HEAD, or OPTIONS (any case). PATH is
an absolute path on the target and may carry a query string:

  delinea-util GET /api/v1/secrets/4
  delinea-util GET '/api/v1/secrets?filter.searchText=web'
  delinea-util POST /api/v1/folders -d @folder.json

Subcommands:

  token    authenticate and print the bearer token, for reuse via
           DELINEA_TOOLS_TOKEN=$(delinea-util token); refuses to print to a
           terminal unless --allow-terminal is passed. With --interactive, get
           the token by interactive Platform Identity API login (password + MFA
           challenges) for MFA-gated accounts instead of the automatic grant
  check    diagnose configuration, reachability, and the credential with
           read-only requests that never expose a secret value; see CHECK
  secrets  fetch secret values and deliver them to a process, file, or stdout;
           see SECRETS SUBCOMMANDS

CONFIGURATION
-------------

Connection settings come from the environment. Most non-secret settings have a
flag override (the flag wins). --tls-skip-verify is enable-only: when
DELINEA_TOOLS_TLS_SKIP_VERIFY is true, unset it or set it false before the
invocation to restore certificate verification. The authentication secret itself
— password, client_secret, or bearer token — is never a flag: it comes from the
environment or --secret-stdin only, because argv is world-readable (ps,
/proc/<pid>/cmdline) and leaks into shell history and CI logs:

  DELINEA_TOOLS_URL              --url URL          Secret Server or Platform base URL
                                                  (must be https; http is allowed only
                                                  for a loopback host, for local testing)
  DELINEA_TOOLS_TARGET           --target KIND      ss | platform (explicit target kind)
  DELINEA_TOOLS_USERNAME         --username U       Secret Server username
  DELINEA_TOOLS_PASSWORD                            Secret Server password (env or --secret-stdin)
  DELINEA_TOOLS_DOMAIN           --domain D         Active Directory domain for an on-prem Secret
                                                  Server user. Give it here, not as DOMAIN\user
                                                  in DELINEA_TOOLS_USERNAME, which is rejected;
                                                  omit for a local account, the Platform, and a
                                                  bearer token
  DELINEA_TOOLS_CLIENT_ID        --client-id ID     Platform OAuth client_id
  DELINEA_TOOLS_CLIENT_SECRET                       Platform OAuth client_secret (env or --secret-stdin)
  DELINEA_TOOLS_TOKEN                               pre-obtained bearer token, at least four bytes
                                                  (env or --secret-stdin; skips the grant)
  DELINEA_TOOLS_CA_CERT          --ca-cert FILE     PEM file of extra trusted CA roots
  DELINEA_TOOLS_TLS_SKIP_VERIFY  --tls-skip-verify  truthy to skip TLS verification (unsafe)
  DELINEA_TOOLS_TIMEOUT          --timeout DUR      header deadline and body idle limit,
                                                  e.g. 45s (default 30s)
  DELINEA_TOOLS_RETRIES          --retries N        attempts for GET/HEAD on transport errors
                                                  and retriable statuses (default 3; 1 disables)
  DELINEA_TOOLS_VAULT_ALLOW      --vault-allow H    extra trusted vault hosts (comma-separated;
                                                  the flag is repeatable, and giving it at
                                                  all replaces the env list — the flag wins)
  DELINEA_TOOLS_GATEWAY_HEADER_FILE
                                  --gateway-header-file FILE
                                                  same-origin gateway headers, one
                                                  Name: value per non-empty line; the
                                                  flag is repeatable and replaces the
                                                  environment file when present

Request options:

  -d BODY | -d @FILE | -d @-   request body (@- reads stdin); Content-Type
                               defaults to application/json unless -H overrides
  -H 'Name: value' | -H @FILE extra request header (repeatable; not Authorization).
                               FILE contains one header per non-empty line; use
                               this form whenever a header value is secret
  --vault                      platform only: discover the default vault via the
                               vault broker and send PATH there, same bearer
  --vault-id ID                with --vault, target this specific vault (its
                               vaultId from GET /vaultbroker/api/vaults)
                               instead of the default
  -i, --include                include the status line and headers on stdout
  -v, --verbose                request line, response status, and response
                               headers on stderr
  --interactive                token only: obtain the token by interactive
                               Platform Identity API login (password + MFA
                               challenges) instead of the automatic grant, for
                               MFA-gated accounts; prompts on stderr/stdin
  --allow-terminal             token only: allow printing a bearer token
                               to a terminal (refused by default; $(...) and
                               pipes are always fine)
  --secret-stdin               read the credential secret from stdin instead of
                               the environment: --target names its slot (ss:
                               password, platform: client secret); without a
                               target it becomes the password when a username
                               is set, the client secret when a client-id is
                               set, or the bearer token otherwise (with both a
                               username and a client-id, --target is required);
                               incompatible with -d @- and token --interactive

--gateway-header-file supplies headers needed to reach the configured service
through a same-origin gateway. They are sent on health probes, token grants,
Identity requests, and API calls to the primary origin, but never forwarded to a
platform vault on another origin. The file path, not its values, appears in argv.
By contrast, -H/--header belongs only to the one raw API request, so an
endpoint-specific header is not exposed to a probe or token endpoint.

The connection settings and the credential model are shared by every face of
the tool: the raw verbs, check, and the secrets group all read the same
DELINEA_TOOLS_* variables and honor --secret-stdin the same way.

--secret-stdin is the secret-manager integration path — it keeps the secret
off argv and out of the process environment entirely. When the secret fills a
password or client-secret slot, a lingering DELINEA_TOOLS_TOKEN is ignored so
the piped credential, not a stale token, is what authenticates:

  op read op://infra/delinea-svc/password | delinea-util --secret-stdin GET /api/v1/users/current

The usual pattern pipes the secret once into token and lets the short-lived
bearer carry the rest of the session:

  export DELINEA_TOOLS_TOKEN=$(op read op://infra/delinea-svc/password |
                             delinea-util --secret-stdin token)

TARGET SELECTION
----------------

The target kind decides which token grant is performed:

  ss        POST {URL}/oauth2/token with grant_type=password (and the AD
            domain when set). Covers on-prem Secret Server and Secret Server
            Cloud.
  platform  POST {URL}/identity/api/oauth2/token/xpmplatform with
            grant_type=client_credentials and scope=xpmheadless.

Without --target the kind is inferred: client-id/client-secret set means
platform, username/password set means ss. If both pairs are set, --target is
required. A pre-obtained token takes precedence over those identity settings
and performs no grant. Raw requests need no target; check uses the configured
target or the service found by its health probe to choose a read-only validation
endpoint, while --vault requires a platform target and is refused against ss.

VAULT ROUTING AND TRUST
-----------------------

A Platform tenant and its Secret Server vault are different hosts. By default
every PATH is sent to the configured URL. With --vault, delinea-util asks the
platform's vault broker (GET /vaultbroker/api/vaults) for the default active
vault and sends PATH to that vault's URL with the same bearer token:

  delinea-util --vault GET /api/v1/secrets/4

To reach a vault other than the default, pass its vaultId (list them with
GET /vaultbroker/api/vaults) with
--vault-id; the chosen vault is held to the same trust policy as the default:

  delinea-util --vault --vault-id 2 GET /api/v1/secrets/4

The discovered vault URL is treated as untrusted input. It must be HTTPS
without userinfo, query, or fragment, and its host must be same-origin with
the platform, on a fixed allowlist of Delinea cloud vault domains
(secretservercloud.com and its regional variants, devsecretservercloud.com),
or explicitly allow-listed with --vault-allow / DELINEA_TOOLS_VAULT_ALLOW. On-prem
vault hosts must be allow-listed. A hostname entry trusts only HTTPS port 443;
an alternate port must be listed as the exact host:port. Automatic trust for
Delinea cloud vault domains is likewise limited to port 443. The secrets group
applies the same trust policy when it routes Platform fetches through the vault.
The route is held for five minutes; the next request then refreshes it
synchronously through the broker and reapplies the trust policy. If refresh
fails, the request fails rather than using expired routing data.

TOKEN REUSE
-----------

Each CLI invocation using grant credentials performs its own token grant;
nothing is persisted. To make several calls on one grant, capture the token
explicitly:

  export DELINEA_TOOLS_TOKEN=$(delinea-util token)
  ...
  unset DELINEA_TOOLS_TOKEN

The token lives only in your shell's environment and expires on the server's
schedule — commonly 20 minutes for Secret Server (its "Session Timeout for
Webservices" setting) and an hour for the Platform, both admin-configurable.
Every process the shell launches meanwhile
inherits the exported value, so unset it after the last call — that stops the
inheritance; it does not scrub memory or revoke the token, which only expiry
does.

A configured token wins credential precedence everywhere, including in the
token verb itself: token passes DELINEA_TOOLS_TOKEN through unchanged rather
than granting a fresh one, so re-running the capture line above refreshes
nothing while the old export is still set. To force a fresh grant, unset
DELINEA_TOOLS_TOKEN first so the grant credentials win; check is the verb that
validates a token against the server.

A read loop that outlives the token can refresh preemptively. Pick a margin
under the configured lifetime, e.g. 900 seconds against Secret Server's
20-minute default. Restrict the helper to GET and HEAD: a generic wrapper must
not replay a POST, PUT, PATCH, or DELETE after an ambiguous failure. Also do not
treat every non-zero exit as expired authentication — exit 4 covers every
non-2xx response, including an expected 404 or an authorization denial.

  token_born=0
  refresh_token() {
    unset DELINEA_TOOLS_TOKEN        # token passes a configured token through
    export DELINEA_TOOLS_TOKEN=$(delinea-util token)
    token_born=$(date +%s)
  }
  read_call() {
    case "$1" in GET|HEAD) ;; *) echo "read_call accepts only GET or HEAD" >&2; return 64;; esac
    if [ $(( $(date +%s) - token_born )) -ge 900 ]; then refresh_token; fi
    delinea-util "$@"
  }

  refresh_token || exit
  while IFS= read -r path; do
    read_call GET "$path" >/dev/null || exit
  done < read-paths.txt

If a call fails before the refresh deadline, stop and diagnose it rather than
blindly replaying it. The common Go client has the response context needed to
recover rejected cached tokens safely: it retries GET/HEAD only and never
replays mutations. The grant credentials stay exported for the whole shell
loop — something must be able to re-grant — so the spend-then-unset hygiene
applies at script exit. The PowerShell equivalent is at the end of EXAMPLES.

Go programs embedding the package (github.com/DelineaXPM/delinea-common/api)
share tokens automatically: clients built without Config.Cache use one
process-wide in-memory cache, reusing a successful grant across clients until
the token approaches expiry, with nothing on disk. Clients with equivalent
grant settings sharing a pointer-valued cache also coalesce concurrent grants
per credential, so one overlapping burst costs one grant attempt, not one
attempt per caller. A failed grant is not cached, and a later call tries again.
Value-valued custom caches share completed entries but not in-flight grants,
and custom transports isolate cached grants per client because their
authentication behavior is opaque.
Construct one client per credential at startup regardless (the transport and
its connection pool are per-client). Supply your own api.NewMemoryCache()
via Config.Cache to scope the sharing, or set Config.DisableCache to opt
out. A cached token is reused while it is inside 90%
of its lifetime and clear of expiry by a minute (or a tenth of the lifetime,
for tokens living under ten minutes); if the API rejects one with 401 it is
evicted and a GET or HEAD request is retried once with a fresh grant. Secret
Server's exact expired-token 403 response receives the same treatment; all
other 403 responses are authorization answers and remain untouched. Mutating
requests are returned as-is rather than replayed, though an authoritative
stale-token response evicts their token for the next call. The cache keys on a
digest of the credential, so changing a password or client secret invalidates
its entry immediately. Custom TokenCache implementations are
possible, but they must be concurrent-safe and process-local: cache keys and
live bearer tokens must never be persisted.

TIMEOUTS AND RETRIES
--------------------

--timeout (default 30s) bounds three things independently: how long to wait
for the response headers, how long until the body starts being read, and how
long any single body read may then wait on the connection. A large download
that keeps flowing is never cut off, and once reading has begun a slow
consumer of the output is never penalized; a hung connection — or a response
abandoned without ever being read — is cut off. Token grants and identity
requests are bounded by the same duration end to end.

GET and HEAD requests are retried (three attempts total by default;
--retries adjusts, --retries 1 disables) on transport errors, with
exponential backoff, and on 408/429/500/502/503/504 responses, honoring the
server's Retry-After header up to 30 seconds — a longer Retry-After returns
the response to you immediately. Backoff waits are bounded by the same 30
seconds. POST, PUT, PATCH, and DELETE are never retried, so a write is never
replayed. A token grant retries only failures that carry no authentication
answer — transport errors and the transient statuses above, honoring
Retry-After; a completed authentication answer is never retried, so repeated
credential failures cannot be amplified toward an account lockout.

OUTPUT AND EXIT CODES
---------------------

The response body is streamed verbatim to stdout; nothing else is written to
stdout unless -i is passed. Non-2xx responses still print the body, with one
summary line on stderr. The secrets group uses the same codes for its own work:
an authentication or vault-discovery failure is 2, and a transport error is 3.
After a successful launch, secrets run instead returns the child's exit code.
check never inherits codes 2-4 — every failed probe is a reported finding, so
check itself exits 0 or, when any check failed, 1.

  0  success (HTTP 2xx, or a clean check)
  1  usage or configuration error
  2  authentication or vault discovery failed
  3  transport error (DNS, TLS, timeout)
  4  the HTTP call completed with a non-2xx status

INTERACTIVE LOGIN (MFA-GATED ACCOUNTS)
--------------------------------------

Accounts like cloudadmin@tenant are often MFA-gated and cannot use the OAuth2
password grant ("Login failed."). Redirect-based federated (external IdP / SSO)
logins are not supported: a redirect from the Identity API is refused.
token --interactive walks
the platform Identity API instead (StartAuthentication /
AdvanceAuthentication): the password mechanism is answered from
DELINEA_TOOLS_PASSWORD, and whatever second factor the account offers — an
out-of-band challenge (an emailed link or code, SMS, or push) or an
authenticator/OTP code — is prompted on stderr and read from stdin, so the
token still lands cleanly on stdout:

  export DELINEA_TOOLS_URL=https://acme.secureplatform.io
  export DELINEA_TOOLS_USERNAME=cloudadmin@acme
  export DELINEA_TOOLS_PASSWORD=$(secret-tool lookup service delinea account cloudadmin)
  export DELINEA_TOOLS_TOKEN=$(delinea-util token --interactive)
  unset DELINEA_TOOLS_PASSWORD    # the token wins from here; stop exporting
                                # the password to every later child process

secret-tool is the Linux keychain CLI; on macOS substitute
$(security find-generic-password -s delinea -a cloudadmin -w). The same flow
is written out for PowerShell, with the password from SecretManagement, at
the end of EXAMPLES. token --interactive is the one invocation whose secret must
come from the environment — --secret-stdin is rejected because stdin carries the MFA
answers.

For an out-of-band challenge, enter the code you received, or press Enter
alone to poll after completing it out of band (e.g. clicking the emailed
link). The resulting token carries the xpminteractive scope and works
against the platform and, with --vault routing, its Secret Server vault.

CHECK
-----

  delinea-util check [--json] [--quiet] [--no-auth] [--pass-env NAME]... [MAPPING...]

check diagnoses the whole tool with read-only health and authentication requests.
It writes no files and never prints a secret value. It reports every problem it
finds rather than stopping at the first, and exits non-zero if any check failed.

  delinea-util check                              # configuration and reachability
  printf '%s' "$PW" | delinea-util --secret-stdin check          # ... and the credential
  printf '%s' "$PW" | delinea-util --secret-stdin check DB=password#128 API_KEY=token#45   # ... and each mapping

Both the credential and the mappings are optional:

  - Reachability-only mode (no Delinea credential): check still verifies the
    connection settings, that DELINEA_TOOLS_CA_CERT and
    DELINEA_TOOLS_GATEWAY_HEADER_FILE are readable and parse, and that
    DELINEA_TOOLS_TIMEOUT and DELINEA_TOOLS_RETRIES are valid, and — with up to two
    requests that send no Delinea credential (the Secret Server health
    endpoint, then the Platform one) — reports which service answers at
    DELINEA_TOOLS_URL. That answer is compared against DELINEA_TOOLS_TARGET, which
    decides whether a Secret Server username/password or a Platform OAuth
    client_id/client_secret is expected; a target that contradicts the service
    that answered is a common cause of an otherwise opaque "access denied". This
    mode is fine and exits 0 when nothing is misconfigured.
  - With a credential (env, or piped with --secret-stdin), check authenticates it
    for the target exactly the way the raw verbs and the secrets group do. A
    username/password or client_id/client_secret is verified by its token grant;
    a pre-obtained bearer token is verified with a read-only current-user (Secret
    Server) or vault-inventory (Platform) request. When no target is set, the
    Delinea-credential-free health probe selects that validation endpoint; this does not
    change the Secret Server default for secret mappings. A wrong or
    partial credential fails even when no mappings were supplied. The credential
    is deliberately not sent when the target contradicts the service the probe
    found, or when the host is unreachable; both are reported instead.
    A backend is selected only by 2xx JSON with healthy:true or the exact trimmed
    legacy text Healthy (case-insensitive), never by an HTML/error page that
    merely contains that word.
  - --no-auth keeps the Delinea credential out of every request: configuration
    and reachability are still checked, and the credential section reports the
    skip. Configured gateway headers are still sent so the probe can reach a
    protected same-origin health endpoint. It does not read credential stdin,
    even with --secret-stdin. A
    monitoring loop uses this so a stale credential in its environment cannot
    burn failed-login attempts toward a lockout.
  - With mappings, check additionally resolves each one and reports the variable
    it would define and the length of its value — never the value. A zero
    length is called out, since an empty field reaches a child as NAME= and
    otherwise looks like success.

check reports any DELINEA_TOOLS_ variable it does not read, suggesting the
nearest recognised name when a typo is close. A misspelled setting is otherwise
silent — it is simply never read — and a near miss of a real credential
variable (DELINEA_TOOLS_PASSWORD, DELINEA_TOOLS_TOKEN, DELINEA_TOOLS_CLIENT_SECRET) is
the likeliest instance. Only names are reported, never values.

check also prints exactly what a "secrets run" child would receive from the
environment, which is otherwise invisible: the baseline is compiled in and a
withheld variable leaves no trace. If HTTPS_PROXY is set here but not passed,
check says so, because a child that cannot reach the network usually hangs
rather than fails.

The credential comes from DELINEA_TOOLS_TOKEN/_PASSWORD/_CLIENT_SECRET, or from a
pipe on stdin when --secret-stdin is set. Without an environment credential or
--secret-stdin, credential checks are skipped rather than reading stdin or
blocking. --quiet reports only warnings and failures, so a
healthy run prints nothing; --json emits the findings structurally with a
summary count per status, nothing wrapped:

  printf '%s' "$PW" | delinea-util --secret-stdin check --json --quiet DB=password#128 \
    | jq -r '.sections[].findings[] | "\(.status)\t\(.label)"'

SECRETS SUBCOMMANDS
-------------------

The raw GET verb can fetch a secret's JSON, but consuming the value by hand
— jq to a shell variable, export, redirect to a file — leaks at every step:
scrollback, the shell's environment (inherited by every later child), a
umask-permissioned file, set -x and CI logs. The secrets group exists to own
that last step: you declare which fields you need and where they should go,
and delivery happens without the value ever crossing a command line, a
terminal, or an unrequested file.

The secrets group fetches secret values from the vault and hands them to a
process (as environment variables or on stdin), renders them into a config
file, or prints them to stdout. Secrets are held only in memory for a single
command; nothing is written to disk unless you ask for it (template --out,
print --out, or redirecting print). Secret values are never passed as
arguments — only references (ids, paths, field names) are — and a run child
receives a declared environment rather than an inherited one, so the credential
cannot leak downstream. On Unix, run exec-replaces the CLI with your program,
so the CLI's copies leave memory when the child takes over. Delivered values
still live in the child's environment or stdin pipe as described under SECRETS
SAFETY (a --via stdin payload larger than a pipe holds, about 60KB, cannot be
prebuffered ahead of exec, so run then spawns the child and streams, exactly as
on Windows).

  delinea-util secrets run      [--via env|stdin|sh] [--pass-env NAME]... MAPPING... -- command [args...]
  delinea-util secrets print    [--via stdin|sh|json|raw|github-env|github-output|ado] [--out FILE] [--allow-terminal] MAPPING...
  delinea-util secrets template --in FILE [--out FILE] [--allow-terminal] MAPPING...
  delinea-util secrets --readme | --tree | help

  run       fetch, then exec command with the secrets injected. On Unix it
            replaces itself with the child (nothing lingers); on Windows it
            supervises the child (see PLATFORM NOTES).
  print     fetch and write to stdout in the chosen format.
  template  render --in (Go text/template, {{.NAME}} per mapping) to --out or
            stdout; new/replaced regular output files use mode 0600 on Unix and
            inherit directory ACLs on Windows; a missing key is an error.

To diagnose configuration, reachability, and the credential without fetching a
secret, use the top-level "delinea-util check".

Mappings:

  NAME=field#id      output NAME <- given field of the secret with that id
  NAME=field@path    output NAME <- given field of the secret at that folder path
  PREFIX_*=#id       one variable per field, named PREFIX_<SLUG>
  PREFIX_*=@path     same, resolving the secret by folder path

The field comes first, and the separator says what follows it: '#' an id, '@' a
folder path. The field is required. Neither separator can appear in a field:
Secret Server rewrites '#' and '@', with 27 other characters, to '-' when it
generates a slug. So the first occurrence of either is always the separator,
and a path may contain both freely. Both kinds of reference stay reachable with
no guessing — 'password#128' is the secret with id 128, and 'password@128' is a
folderless secret named 128.

Mapping names start with a letter or underscore and may contain letters, digits,
underscores, dots, or hyphens. Delivery narrows that safe grammar to what the
selected sink supports: env, stdin, sh, and both GitHub modes require environment
identifiers (letters, digits, and underscores); Azure Pipelines also accepts dots
and hyphens.

Secret paths are folder paths, as the folders API reports them in folderPath:
\folder\subfolder\Secret Name. Quote the mapping so the shell does not eat the
backslashes — single quotes in a POSIX shell.

  'DB_PASS=password@\ci\database\prod'
  'DB_USER=username@\ci\database\prod'
  DB_PASS=password#128

Nothing in a path is treated as a separator, because nothing in one can be.
Secret Server splits a path on both '\' and '/', only a folder name forbids a
backslash, and a secret name may contain either — so /ci/database/prod and
\ci\a/b are both valid paths and both work here. A path containing '@' works
too, since the separator is always the first one.

Delivery (--via):

  env     inject as environment variables (run only)
  stdin   NUL-delimited NAME=value pairs on the child's stdin (or stdout for print)
  sh      shell 'export NAME=value' lines for eval "$(...)"
  json    JSON object {"NAME":"value", ...} (print only; values must be
          valid UTF-8 — use raw for binary values, which JSON would corrupt)
  raw     the one secret value, verbatim, no name (print only; exactly one mapping)
  github-env
          $GITHUB_ENV heredocs (print only). GitHub-reserved GITHUB_* and
          RUNNER_* names and NODE_OPTIONS are refused rather than written to a
          sink that cannot override them. Names differing only by case are
          refused so the payload has the same meaning on Windows runners
  github-output
          $GITHUB_OUTPUT heredocs (print only). Output names do not inherit the
          environment sink's reserved-name rules, but they compare
          case-insensitively, so TOKEN and token are refused as duplicates.
          Both GitHub modes carry LF-delimited multiline values intact and
          require valid UTF-8 without NUL or carriage returns. Both require --out (usually --out
          "$GITHUB_ENV" or --out "$GITHUB_OUTPUT") and append, preserving
          entries from earlier step commands. An ::add-mask:: line per secret
          line goes to stdout first, so the runner masks values in job logs
          before anything can echo them
  ado     Azure Pipelines task.setsecret and secret task.setvariable commands
          (print only; stdout only). Values become secret pipeline variables
          for subsequent steps in the same job and must be valid UTF-8 without
          NUL, CR, or LF. Names may not begin, case-insensitively, with endpoint,
          input, secret, path, or securefile. Script steps must explicitly map
          them under env


FINDING A SECRET'S REFERENCE
---------------------------

A mapping needs a secret id or folder path, and a field slug.

Which reference to use:

  - An id is exact. It survives a rename and a move between folders, and it
    cannot match more than one secret. It is also specific to one instance, so
    a mapping written against staging will not resolve against production.
  - A path is portable between instances whose folder structure matches, which
    an id is not. It breaks when a secret is renamed or a folder reorganised.
  - A path may match several secrets. Secret Server resolves that itself by
    taking the first, and the only ordering observed is that an active
    secret precedes an inactive one; among several active secrets sharing a
    name in one folder the choice is undefined.

The secrets resolver never searches automatically: a search listing that
silently truncates is worse than none. Find a reference once with a raw request
or another Secret Server client, then pin it in your configuration.

Secret id: open the secret in Secret Server and read it out of the address bar;
it is the number after "secrets" in the URL of the secret's page.

Folder path: the secret search reports it, in the canonical spelling, backslashes
and all. The last column below is the mapping path. The query string is passed
verbatim; percent-encode a search text that is not a plain word:

  delinea-util GET '/api/v1/secrets?filter.searchText=<secret name>' \
    | jq -r '.records[] | "\(.id)\t\(.folderPath)\\\(.name)"'
  # 128   \ci\database\prod        ->  'DB_PASS=password@\ci\database\prod'

Field slugs: the same secret response lists them, without exposing any value:

  delinea-util GET '/api/v1/secrets/<id>' | jq '[.items[] | {slug, isFile}]'

Or use check, which needs no jq and prints no values. A PREFIX_* mapping
expands to one variable per field, and check reports the variables it would
define with the length of each:

  printf '%s' "$PW" | delinea-util --secret-stdin check 'ALL_*=@\ci\database\prod'

PREFIX_* skips file attachments, so a private-key field will not appear;
reference those by slug explicitly.

CHILD ENVIRONMENT (run)
-----------------------

A child launched by run does not inherit this process's environment. It gets a
fixed baseline, the resolved secrets, and whatever --pass-env names. Nothing
else: the calling environment routinely holds unrelated credentials, and a
dependency can add more at any time, so what the child sees is declared rather
than filtered.

The baseline is every variable that inertly describes the session — where things
live, who and where you are, what encoding:

  Unix     PATH HOME PWD TMPDIR USER LOGNAME SHELL TZ TERM LANG LC_ALL LC_CTYPE
  Windows  PATH PATHEXT COMSPEC SystemRoot windir SystemDrive TEMP TMP
           USERPROFILE HOMEDRIVE HOMEPATH APPDATA LOCALAPPDATA PROGRAMDATA
           ProgramFiles ProgramFiles(x86) USERNAME USERDOMAIN COMPUTERNAME
           NUMBER_OF_PROCESSORS OS PROCESSOR_ARCHITECTURE TZ LANG LC_ALL
           LC_CTYPE

Nothing that redirects traffic, changes trust, or confers a capability is in the
baseline, so HTTP_PROXY, HTTPS_PROXY, NO_PROXY, SSL_CERT_FILE, SSL_CERT_DIR,
SSH_AUTH_SOCK and KRB5CCNAME are all absent by design. So is anything
toolchain-specific (JAVA_HOME, KUBECONFIG, GOPROXY, PYTHONPATH, ...). Pass what
the child needs, per invocation:

  delinea-util secrets run --pass-env HTTPS_PROXY --pass-env JAVA_HOME DB=password#128 -- ./app

--pass-env takes a name, never NAME=VALUE: a value on the command line is
visible in ps output, shell history and CI logs. Naming a variable that is unset
is an error, listing every missing name at once. Note that a shell variable is
not an environment variable until it is exported ("export FOO" in a POSIX shell,
"$env:FOO" rather than "$FOO" in PowerShell); an unexported variable is invisible
here however plainly you set it.

Resolved secrets are refused for a conservative set of well-known variables
that cause a child to load or execute code, including dynamic-loader,
shell-startup, Git command, pager/editor, askpass, language-runtime, and JVM
controls such as LD_PRELOAD, BASH_ENV, PROMPT_COMMAND, GIT_SSH_COMMAND,
PYTHONPATH, NODE_OPTIONS, JAVA_TOOL_OPTIONS, CLASSPATH, GCONV_PATH, language
module paths, and .NET startup/profiling hooks. This guard is defense-in-depth,
not a sandbox: the operator still controls mapping names and the command. Use
--pass-env for an operator-controlled runtime setting instead of sourcing its
value from a secret.

Run "delinea-util check" to see exactly what a run child would receive.

SECRETS SAFETY
--------------

  - Nothing on disk by default. Secrets and the credential live only in process
    memory; on Unix the CLI exec-replaces itself for run (except a --via stdin
    payload over ~60KB, which is streamed from a parent that exits with the
    child). Files appear only when you ask (template --out, print --out, or
    redirecting print), and then the operator owns their lifetime.
  - print and template refuse to write secrets to a terminal unless
    --allow-terminal is given, since the values would land in your scrollback.
    To feed a program, prefer run, which never writes secrets to a visible sink.
  - --via env exposure: injected values live in the child's environment (on Linux
    readable via /proc/<pid>/environ and inherited by descendants; Windows
    differs, see PLATFORM NOTES). Prefer --via stdin where the consumer supports it.
  - Two mappings that would define the same variable are refused before delivery
    — including two expanded slugs that differ only in punctuation (api-key and
    api_key both become PREFIX_API_KEY). check reports the collision the same way.
  - CI systems do not mask values fetched at runtime; avoid echoing them, and
    don't eval --via sh output under set -x.

EXAMPLES
--------

The examples below use POSIX shell syntax (Linux and macOS); the key flows
are written out for PowerShell at the end of this section.

Secret Server (on-prem or cloud), password grant. Source the password from
the system keychain so nothing plaintext lands on the command line or in
shell history — secret-tool on Linux (libsecret / GNOME Keyring); on macOS
substitute the login keychain:
$(security find-generic-password -s delinea -a svc-api -w)

  export DELINEA_TOOLS_URL=https://vault.example.com/SecretServer
  export DELINEA_TOOLS_USERNAME=svc-api
  export DELINEA_TOOLS_PASSWORD=$(secret-tool lookup service delinea account svc-api)
  delinea-util GET /api/v1/users/current
  delinea-util GET /api/v1/secrets/126
  delinea-util POST /api/v1/secrets/126/restore

Delinea Platform, client credentials, calling through to the vault (the
client secret from the keychain, same substitution on macOS):

  export DELINEA_TOOLS_URL=https://acme.secureplatform.io
  export DELINEA_TOOLS_CLIENT_ID=svc-ci
  export DELINEA_TOOLS_CLIENT_SECRET=$(secret-tool lookup service delinea account svc-ci)
  delinea-util GET /vaultbroker/api/vaults
  delinea-util --vault GET /api/v1/secrets/4
  delinea-util --vault GET /api/v1/users/current

Reuse one token across several calls:

  export DELINEA_TOOLS_TOKEN=$(delinea-util token)
  delinea-util GET /api/v1/folders
  delinea-util GET '/api/v1/secrets?filter.folderId=15'
  unset DELINEA_TOOLS_TOKEN

A loop that outlives the token's lifetime — preemptive refresh plus one
retry on denial — is written out in TOKEN REUSE, and for PowerShell at the
end of this section.

Create a folder from a JSON body:

  delinea-util POST /api/v1/folders -d '{"folderName":"ci","folderTypeId":1,"parentFolderId":-1}'

Diagnose before trusting a pipeline (read-only diagnostic requests):

  delinea-util check                                    # config + reachability
  printf '%s' "$PW" | delinea-util --secret-stdin check DB=password#128

Fetch secrets and hand them to a process (credential piped from a keychain, so
nothing plaintext lands on disk, on the command line, or in shell history):

  # Linux (libsecret / GNOME Keyring)
  secret-tool lookup service delinea account ss-pw \
    | delinea-util --secret-stdin secrets run DB_PASS=password#128 API_KEY=token#45 -- ./app

  # macOS (login keychain)
  security find-generic-password -s delinea -a ss-pw -w \
    | delinea-util --secret-stdin secrets run DB_PASS=password#128 -- ./app

  # a single secret to a new/replaced regular file (mode 0600 on Unix;
  # inherited directory ACLs on Windows)
  secret-tool lookup service delinea account ss-pw \
    | delinea-util --secret-stdin secrets print --via raw --out tls.key 'TLS_KEY=private-key@\certs\prod'

  # render a config file
  secret-tool lookup service delinea account ss-pw \
    | delinea-util --secret-stdin secrets template --in app.conf.tmpl --out app.conf DB_PASSWORD=password#128

  # every usable field of one secret, as DB_USERNAME, DB_PASSWORD, DB_NOTES, ...
  secret-tool lookup service delinea account ss-pw \
    | delinea-util --secret-stdin secrets run 'DB_*=#128' -- ./app

  # Delinea Platform (client_id + client_secret; stdin carries the client_secret)
  export DELINEA_TOOLS_URL="$PLATFORM_URL"
  export DELINEA_TOOLS_TARGET=platform
  export DELINEA_TOOLS_CLIENT_ID="$CLIENT_ID"
  printf '%s' "$CLIENT_SECRET" \
    | delinea-util --secret-stdin secrets run 'DB_PASS=password@\ci\database\prod' -- ./deploy.sh

  # Windows (PowerShell 7 + SecretManagement); set the console output encoding to
  # UTF-8 with no BOM first, so the piped credential is not re-encoded
  [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
  Get-Secret -Name ss-pw -AsPlainText | delinea-util.exe --secret-stdin secrets run DB_PASS=password#128 -- .\app.exe

PowerShell (Windows). Environment variables are set with $env:NAME and
removed with Remove-Item Env:NAME; a native command's stdout is captured by
assignment, so no $(...) is needed. Single-quoted arguments work as in POSIX
shells. The same flows as above:

  # Secret Server, password grant (password from SecretManagement, so nothing
  # plaintext lands on the command line or in history)
  $env:DELINEA_TOOLS_URL = "https://vault.example.com/SecretServer"
  $env:DELINEA_TOOLS_USERNAME = "svc-api"
  $env:DELINEA_TOOLS_PASSWORD = Get-Secret -Name ss-pw -AsPlainText
  delinea-util.exe GET /api/v1/users/current
  delinea-util.exe GET /api/v1/secrets/126

  # Delinea Platform, client credentials, calling through to the vault
  $env:DELINEA_TOOLS_URL = "https://acme.secureplatform.io"
  $env:DELINEA_TOOLS_CLIENT_ID = "svc-ci"
  $env:DELINEA_TOOLS_CLIENT_SECRET = Get-Secret -Name svc-ci -AsPlainText
  delinea-util.exe GET /vaultbroker/api/vaults
  delinea-util.exe --vault GET /api/v1/secrets/4

  # reuse one token across several calls, then stop exporting it
  $env:DELINEA_TOOLS_TOKEN = (delinea-util.exe token)
  delinea-util.exe GET /api/v1/folders
  delinea-util.exe GET '/api/v1/secrets?filter.folderId=15'
  Remove-Item Env:DELINEA_TOOLS_TOKEN

  # interactive login for an MFA-gated account; challenge prompts appear on
  # the console, and the password stops being exported once the token wins
  $env:DELINEA_TOOLS_URL = "https://acme.secureplatform.io"
  $env:DELINEA_TOOLS_USERNAME = "cloudadmin@acme"
  $env:DELINEA_TOOLS_PASSWORD = Get-Secret -Name cloudadmin -AsPlainText
  $env:DELINEA_TOOLS_TOKEN = (delinea-util.exe token --interactive)
  Remove-Item Env:DELINEA_TOOLS_PASSWORD

  # a read loop that outlives the token: refresh preemptively (900s suits
  # Secret Server's 20-minute default), and stop on a failed call
  $script:tokenBorn = [DateTime]::MinValue
  function Refresh-Token {
    Remove-Item Env:DELINEA_TOOLS_TOKEN -ErrorAction Ignore   # token passes it through
    $env:DELINEA_TOOLS_TOKEN = (delinea-util.exe token)
    $script:tokenBorn = [DateTime]::UtcNow
  }
  function Invoke-DelineaRead {
    param([ValidateSet('GET', 'HEAD')] [string] $Method, [string] $Path)
    if (([DateTime]::UtcNow - $script:tokenBorn).TotalSeconds -ge 900) { Refresh-Token }
    delinea-util.exe $Method $Path
  }
  Refresh-Token
  foreach ($path in Get-Content .\read-paths.txt) {
    Invoke-DelineaRead GET $path | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Delinea API read failed with exit $LASTEXITCODE" }
  }

CI PIPELINES
------------

GitHub Actions, Azure Pipelines, and GitLab get their secrets with this binary
alone — no wrapper code. The credential comes from the CI system's own secret
store as DELINEA_TOOLS_* variables; the mappings say what to fetch.

GitHub Actions: one step writes the variables for every later step, and the
::add-mask:: lines the mode prints first mean the values are already masked
in the job log before anything can echo them.

  - name: Fetch secrets
    env:
      DELINEA_TOOLS_URL: ${{ vars.DELINEA_URL }}
      DELINEA_TOOLS_CLIENT_ID: ${{ secrets.DELINEA_CLIENT_ID }}
      DELINEA_TOOLS_CLIENT_SECRET: ${{ secrets.DELINEA_CLIENT_SECRET }}
    run: delinea-util secrets print --via github-env --out "$GITHUB_ENV" DB_PASS=password#128

Use --via github-output --out "$GITHUB_OUTPUT" when the value must be a named
step output instead. Environment delivery rejects GitHub's GITHUB_* and RUNNER_*
names plus NODE_OPTIONS; output names have a separate namespace and do not.
Both modes reject names that differ only by case.

Azure Pipelines: prefer "secrets run" in a bash step when it can wrap the
consumer. For a marketplace task that needs a pipeline variable, --via ado
registers each non-empty value with the masker before publishing it as a secret
variable:

  - bash: delinea-util secrets print --via ado DSS_private-key=password#128
    env:
      DELINEA_TOOLS_URL: $(DELINEA_URL)
      DELINEA_TOOLS_CLIENT_ID: $(DELINEA_CLIENT_ID)
      DELINEA_TOOLS_CLIENT_SECRET: $(DELINEA_CLIENT_SECRET)
  - task: ExampleDeploy@1
    inputs:
      token: $(DSS_private-key)

The variable is available to subsequent steps in the same job only. Secret
variables are not mapped into script environments automatically; use
"env: { API_TOKEN: $(API_TOKEN) }" on a script consumer. The mode is stdout-only
because the agent reads logging commands there. It rejects multiline values:
Azure rejects multiline secret variables under its safe default configuration.
Use "secrets run" or same-step file delivery for keys and certificates. Masking
is best-effort; never echo a secret.

Resolution and formatting are all-or-nothing: every mapping must fetch,
resolve, and validate before the first ##vso command is written. A failure
therefore exits non-zero with no partial variable publication. An operating
system write failure after emission begins can still leave a partial stdout
stream; no stdout protocol can make a failed pipe atomic.

GitLab CI: fetch in the job that consumes the values. There is deliberately
no artifact-based delivery — a dotenv report would upload the values to the
GitLab server, where pipeline users can read them until the artifact
expires; GitLab's own docs say not to put credentials in one. Set the
DELINEA_TOOLS_* variables as masked CI/CD variables, then either hand the
secrets straight to the process:

  deploy:
    script:
      - delinea-util secrets run DB_PASS=password#128 -- ./deploy.sh

or export them for the rest of the script block:

  deploy:
    script:
      - eval "$(delinea-util secrets print --via sh DB_PASS=password#128)"
      - ./deploy.sh

GitLab has no runtime masking (its masking covers only pre-declared CI
variables), so values fetched at runtime appear verbatim if a script echoes
them — do not echo them, and never eval --via sh output under set -x.

DISCOVERING THE API
-------------------

The endpoints this tool can call are Delinea's own REST APIs, and this README
does not catalogue them. Both products publish machine-readable OpenAPI
specifications, and tenants commonly serve them on the same base URL the tool
is already configured for, so a plain GET retrieves them:

  delinea-util GET /Documents/restapi/TokenAuth/swagger.json     # ss
  delinea-util GET /identity/swagger/v1/swagger.json             # platform

A Secret Server vault serves one Swagger 2.0 document for the whole API,
version-matched to the running server and several megabytes long. The
Platform publishes OpenAPI 3 documents per service at
/{service}/swagger/v1/swagger.json (identity and vaultbroker are the services
this tool itself touches); on a platform target, the vault's document is
reached with --vault:

  delinea-util --vault GET /Documents/restapi/TokenAuth/swagger.json

Two cautions. Exposure of these paths varies with tenant hardening, so treat
them as a probe, not a contract. And a Platform tenant answers unknown paths
with 200 and the web application's HTML shell — /documents/restapi/ on the
platform host is one such trap — so confirm a response is JSON before
trusting it.

The vault document is too large to read whole. Enumerate the paths first,
then extract the one operation you need:

  delinea-util GET /Documents/restapi/TokenAuth/swagger.json \
    | jq '.paths | keys'
  delinea-util GET /Documents/restapi/TokenAuth/swagger.json \
    | jq '.paths["/v1/secrets/{id}"].get'

Human-readable guides live at https://docs.delinea.com — "APIs and
Scripting" under Secret Server, "API Reference" under the Delinea Platform —
and each Secret Server instance links its own version-matched interactive
guide from the help (question-mark) menu.

COMMON DIAGNOSTIC CALLS
-----------------------

Read-only calls that answer the usual questions when inspecting a server or
diagnosing access, verified against live tenants. Against a Secret Server
target they run as written; on a platform target, prefix the vault-scoped
ones (version, folders, secrets) with --vault:

  delinea-util GET /api/v1/users/current     # which identity am I?
  delinea-util GET /api/v1/healthcheck       # is the vault up? (check's probe
                                            # endpoint — on the platform host:
                                            # GET /health. The endpoint needs no
                                            # credential, but the raw verb still
                                            # authenticates first; with no
                                            # credential configured, use check)
  delinea-util GET /api/v1/version           # which version is it running?
  delinea-util GET '/api/v1/secrets?take=1'  # can this identity list anything?
  delinea-util GET '/api/v1/folders?take=25'                    # visible folders
  delinea-util GET '/api/v1/secrets?filter.folderId=15&take=25' # secrets in folder 15
  delinea-util GET '/api/v1/folders/0?folderPath=%5Cci%5Cdatabase'  # folder by path
  delinea-util GET '/api/v1/secrets/0?secretPath=%5Cci%5Cdatabase%5Cprod'  # secret by path
  delinea-util GET '/api/v1/secrets?filter.searchText=prod&take=25' # search secrets
  delinea-util GET '/api/v1/folders?filter.searchText=ci&take=25'   # search folders
  delinea-util GET /vaultbroker/api/vaults   # platform: which vaults exist?

filter.searchText behavior depends on the tenant's Secret Server version and
Search Indexer configuration. Standard mode searches whole words; Extended
mode can match partial words. Template fields participate only when configured
as searchable, so a hit is not necessarily a name match and a miss does not
prove that a value is absent. filter.searchFieldSlug can restrict matching to
one searchable template field. Treat password-field indexing as server policy,
not a client guarantee, and never use search as an authorization check or a
secret-value oracle.

The /0?...Path= calls resolve a backslash path to the object and its id; the
path rides in a query string, so escape each backslash as %5C. Secret by
path is the same request a secrets @\folder\name mapping makes. The 0 is a
server-side sentinel ("no id — resolve the path first"), and it is not
read-only sugar: Secret Server honors it on the whole family of id-shaped
routes, PUT and DELETE included, so a path in a destructive call resolves
and acts on whatever it names.

Three things to keep in mind reading the answers. Results are
permission-scoped: an empty folders or secrets list usually means nothing is
shared with this identity, not that nothing exists. List endpoints are paged
(take, skip) and cap what one call returns. And on a Secret Server target,
GET /api/v1/users/current is the same request check and token validation use
to prove a pre-obtained token (a platform token is proven against
/vaultbroker/api/vaults, and a password or client secret by its own grant), so
if that call works, a credential finding from check is about something else.

When the answer is larger than one page, walk skip until hasNext goes false.
Every visible secret name (for folders, swap in /api/v1/folders and
.records[].folderPath):

  take=1000; skip=0
  while :; do
    page=$(delinea-util GET "/api/v1/secrets?take=$take&skip=$skip") || exit $?
    printf '%s\n' "$page" | jq -r '.records[].name'
    [ "$(printf '%s' "$page" | jq '.hasNext')" = true ] || break
    skip=$((skip + take))
  done

The list filters compose with the pager: append &filter.searchText=prod or
&filter.folderId=15 to the loop's query to walk a filtered listing — the
take=25 search one-liners above stop at one page, so a match set that can
outgrow a page belongs in this loop. Secret Server matches text, not
patterns; for a real pattern, page everything and select client-side by
swapping the jq line:

  printf '%s\n' "$page" \
    | jq -r '.records[] | select(.name | test("^db-.*-prod$")) | .name'

SECURITY NOTES
--------------

  - The secret (password, client_secret, or bearer token) is never taken as a
    command-line argument — there is no --password/--client-secret/--token flag,
    and passing one is a usage error. argv is world-readable (ps,
    /proc/<pid>/cmdline) and leaks into shell history and CI logs, so it is the
    leakiest place to put a secret. Supply it in the environment, or with
    --secret-stdin (which avoids both argv and the environment). This holds for
    every face of the tool: the raw verbs, check, and the secrets group.
  - Fetched secret values never appear on the command line; only references do.
    A literal -d/--data request body does appear in argv, so use -d @- or
    -d @FILE for a sensitive body. An inline -H value also appears in argv; use
    -H @FILE for a request-specific secret or --gateway-header-file for a secret
    same-origin gateway header.
  - The CLI requires an https URL and refuses to connect over plaintext http
    (except to a loopback host for local testing), since the credential is sent
    on the first request.
  - TLS settings apply to this process's own HTTP client only; the tool never
    modifies Go's global default transport.
  - Token grants never follow redirects and retry only failures that carry
    no authentication answer; API calls
    refuse cross-origin redirects so the bearer token cannot be replayed to
    another host.
  - Token and Identity API responses are capped at 1 MiB. Endpoint-controlled
    error text is sanitized, and submitted passwords, client secrets, and MFA
    answers are redacted before an authentication error can reach stderr.
  - The token subcommand (with or without --interactive) prints a live bearer
    token to stdout by design; treat its output like a password. It refuses to
    write to a terminal (the token would land in your scrollback) unless
    --allow-terminal is passed; command substitution and pipes are not terminals
    and always work. Response bodies are deliberately not guarded: this is a
    curl-style tool and printing responses is its purpose.

PLATFORM NOTES
--------------

secrets run execution model:
  - Unix (Linux/macOS): the CLI replaces itself with the child via execve, so the
    parent and every secret in its memory are gone the moment the child starts.
    One exception: a --via stdin payload over a pipe's ~60KB capacity cannot be
    prebuffered ahead of exec, so run supervises the child instead, exactly as
    on Windows — forwarding termination signals to the child (SIGTERM from
    systemd or Kubernetes reaches the application) and propagating its exit
    status, including 128+signal when a signal kills it.
  - Windows: there is no execve, so the CLI stays as a supervising parent that
    starts the child, waits, and propagates its exit code. The --via stdin
    payload is wiped as soon as it is handed to the child; --via env values live
    in the parent's memory (immutable Go strings) for the child's lifetime.
    Windows environment blocks are Unicode, so --via env rejects a binary value
    that is not valid UTF-8; use --via stdin or print --via raw for that value.

Credential on stdin:
  - Credential stdin is read only when --secret-stdin is set; an unrelated pipe
    is never treated as a password, client_secret, or bearer token.
  - Under PowerShell, piping a credential into a native command re-encodes it
    using the console output encoding, which can deliver UTF-16 or a byte-order
    mark. delinea-util rejects a credential carrying a BOM or a NUL byte and names
    the cause rather than sending it to the vault, where it would come back as an
    unexplained access denial. It does not transcode: a legacy console codepage
    replaces non-ASCII characters with "?" before the bytes ever arrive. Set
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false), use PowerShell 7,
    or pipe from a byte-clean source. cmd.exe and POSIX shells pass bytes through
    unchanged.
  - secrets print --out / template --out create or replace regular files at mode
    0600 (on Unix) and only after a successful fetch or render. Explicit existing
    special sinks such as FIFOs retain their mode. github-env and github-output
    append to their shared command files without changing an existing
    runner-owned file's mode; ado is stdout-only; other modes atomically replace
    regular files.
    Prefer --out over a '>' redirect, which uses the shell umask and is
    re-encoded by PowerShell.
  - Mapping resolution and format validation complete before print emits any
    payload. If either fails, stdout and regular --out destinations receive no
    secret output. A later sink I/O failure can be partial for append files,
    special files, or stdout; regular files retain atomic replacement.

LIBRARY USAGE
-------------

The command's implementation packages are provided by the dependency-free
github.com/DelineaXPM/delinea-common module:

  - github.com/DelineaXPM/delinea-common/api — the authentication and transport
    engine (api.New, api.Config, the token cache); build an *api.Client and call
    Do, Token, or the vault-broker helpers directly.
  - github.com/DelineaXPM/delinea-common/secrets — the resolve engine over the
    api client.

  import (
      "github.com/DelineaXPM/delinea-common/api"
      ds "github.com/DelineaXPM/delinea-common/secrets"
  )

  client, err := ds.New(ds.Config{
      URL:      os.Getenv("DELINEA_TOOLS_URL"),
      Target:   api.TargetPlatform, // omit for Secret Server / SSC
      Username: clientID,           // empty Username => the caller authenticates with a Token
      Password: clientSecret,       // or set Token directly for a pre-obtained bearer token
      Timeout:  30 * time.Second,
      Retries:  3,
  })

  m, err := ds.ParseMapping(`DB_PASS=password@\ci\database\prod`)
  vars, err := client.Resolve(ctx, []ds.Mapping{m}) // []ds.Var{Name, Value}, ordered; one fetch per secret
  //   errors.Is(err, ds.ErrNotFound)     a requested field is absent on a fetched secret
  //   errors.Is(err, ds.ErrAccessDenied) secret missing or not permitted (SS conflates these)
  //   errors.Is(err, ds.ErrTransport)    network/transport (retried automatically)
  //   errors.Is(err, ds.ErrTimeout)      exceeded Config.Timeout

Resolve stops at the first failure. Verify instead reports what happened to every
mapping, reporting variable names and value lengths, never values:

  results, err := client.Verify(ctx, mappings) // err is non-nil only on timeout or cancellation
  for _, r := range results {
      // r.Mapping     the mapping this result is for
      // r.Err         why it failed, nil if it resolved
      // r.Fields      []ds.Field{Name, Bytes} the variables it would define
  }

To share one authenticated client — and its token cache — between raw api calls
and secret resolution, build an api.Client and wrap it: sc := ds.NewWithClient(c).
Config.Header carries same-origin gateway headers through probes, grants and API
calls; its values are redacted from formatted Config output. Config.CACert /
Config.SkipTLSVerify configure TLS, and apply to this client's transport only.
See "go doc github.com/DelineaXPM/delinea-common/secrets".

Long-running services set Config.Logger (a *log/slog.Logger; nil is silent)
to see token grant outcomes, request retries, vault selection, and discarded
cache entries. A failed token grant may include a bounded, sanitized,
credential-redacted error-body snippet; logs never include a request body, a
successful response body, a credential, or a query string. Construct one client
per credential at startup; clients are safe for concurrent use, and clients
built without Config.Cache share a process-wide token cache
(Config.DisableCache opts out).

COMMAND TREE
------------

delinea-util  — make one authenticated REST call against Delinea Secret Server or the Delinea Platform
├── METHOD PATH  — perform the request (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
├── token  — authenticate and print the bearer token (--interactive: Platform MFA login)
├── check  — report what is configured, reachable, and resolvable
├── secrets run  — fetch secrets and exec a command with them injected
├── secrets print  — fetch secrets and write them to stdout
└── secrets template  — render a template file with secret values

TESTING
-------

The default test suite is fully offline. The live end-to-end tests, and the
fixtures they require, are documented in docs/E2E.txt in the repository.

LICENSE
-------

MIT. See the LICENSE file.
