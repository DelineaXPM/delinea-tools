# delinea-tools

Go tooling for Delinea Secret Server (on-prem or cloud) and the Delinea
Platform, with no dependencies outside the standard library. One shared
engine and one command-line tool:

| Path | What it is |
|---|---|
| [`api/`](api/) | The engine: OAuth2 grants (Secret Server password, Platform client-credentials, interactive MFA login), vault-broker discovery with a trust policy, an in-memory token cache, and a raw `Do(request)` for any REST endpoint. Importable by other Go programs. |
| [`secrets/`](secrets/) | The resolve layer: maps `NAME=field#id` / `NAME=field@path` references onto fetched secrets, with file-attachment download, per-secret caching, and a `Verify` that reports every mapping outcome without disclosing a value. Importable by Go CI integrations. |
| [`cmd/delinea-util`](cmd/delinea-util/) | The CLI. Raw curl-style REST (`delinea-util GET /path`, `token`, `token --interactive` for MFA login), a top-level `delinea-util check` diagnostic, and the `secrets` subcommand group — `delinea-util secrets run\|print\|template` — which fetches secret fields and hands them to a process, a template, or stdout. Secret output refuses a terminal by default, and files are written only when explicitly requested. A `secrets run` child gets a declared environment, not an inherited one. |

At a glance:

- One credential model reaches Secret Server (on-prem or cloud) and the Delinea
  Platform — no separate tools or code paths.
- A single self-contained binary (standard library only, no runtime service
  dependency), also importable as the `api` and `secrets` Go libraries.
- The vault credential comes from the environment or stdin, never argv; tokens
  are cached in memory, and nothing is written to disk unless you ask.
- The raw-REST surface stays stable as services change — no per-service
  wrappers or generated types to maintain.

Two commands cover most uses:

```
# First set the target and one credential (see `delinea-util --readme`):
#   export DELINEA_TOOLS_URL=https://tenant.secretservercloud.com
#   export DELINEA_TOOLS_PASSWORD=...   # or DELINEA_TOOLS_TOKEN / _CLIENT_SECRET

# Any endpoint, curl-style:
delinea-util GET /api/v1/users/current

# Run a program with a secret injected into a declared environment:
delinea-util secrets run PGPASSWORD=password#128 -- \
    psql -h db.internal -U appuser -d orders -c 'select count(*) from users'
```

Install:

```
go install github.com/DelineaXPM/delinea-tools/cmd/delinea-util@latest
```

The binary carries its own full documentation: `delinea-util --readme` and
`delinea-util secrets --readme` (the live test guide is `docs/E2E.txt`).

Design commitments shared by everything here: credentials never appear on
argv; nothing is written to disk unless explicitly requested; TLS settings
apply per-client, never process-wide; token grants and mutating API requests
never follow redirects; writes are never retried. `make test` is fully offline; `make e2e` runs the
live suites and skips cleanly when fixtures are absent, while `make e2e-strict`
requires the baseline fixture set. CI enforces an 88% offline coverage floor;
the scheduled quality workflow repeats the shuffled suite and fuzzes every
declared target.

## As a library

Both packages are importable. The `secrets` resolver covers "read a field";
the `api` engine reaches any endpoint for everything else. Library clients
require HTTPS outside loopback; normalize operator input with
`api.NormalizeURL`, and set `AllowInsecureHTTP` only when an operator has
explicitly accepted plaintext transport on a trusted network.

```go
// Resolve secret fields (Secret Server or, with Target: api.TargetPlatform, the vault).
c, err := secrets.New(secrets.Config{URL: url, Username: user, Password: pw})
if err != nil {
    log.Fatal(err)
}
vars, err := c.Resolve(ctx, []secrets.Mapping{{EnvName: "DB_PASS", SecretID: 126, Field: "password"}})
if err != nil {
    log.Fatal(err)
}

// Or reach any endpoint directly (search, create, update, delete, folders).
ac, err := api.New(api.Config{URL: url, Username: user, Password: pw})
if err != nil {
    log.Fatal(err)
}
resp, err := ac.Do(ctx, api.Request{Method: "GET", Path: "/api/v1/secrets/126"})
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()
```

Embedders can share one authenticated client and its token cache across both
layers with `secrets.NewWithClient(ac)`. Escape hatches on
`api.Config` cover the awkward environments: `Transport` (mTLS / custom dialer /
proxy), `Header` (gateway headers), `CACert` / `AllowedVaultHosts`, and
`Backoff`. Full reference: `go doc github.com/DelineaXPM/delinea-tools/api` and
`.../secrets`.

While `http.DefaultTransport` retains its startup identity, clients without an
explicit `Transport` clone an immutable snapshot captured when the package
initializes. Later in-place mutations must be passed as `Config.Transport`;
replacing `http.DefaultTransport` is detected and used automatically as an
opaque transport. Opaque transports deliberately disable token caching.

Long-running programs should reuse clients. A program that intentionally
discards a client can call `CloseIdleConnections` first to release its private
connection pool promptly. Platform vault routes are cached per vault ID for five
minutes, then refreshed synchronously and revalidated against the same host trust
policy before another request is routed through them.

The engine replays only safe reads: a reused bearer token rejected with 401 is
evicted and a GET/HEAD is attempted once with a fresh grant. It does the same
for Secret Server's exact, documented expired-token 403 response; unrelated 403
authorization responses remain untouched. Writes are never replayed, although
an authoritative stale-token response evicts their rejected token for the next
call. `Config.Retries` counts total attempts; the exact retry, `Retry-After`, and
progress-timeout contract is recorded in
[`docs/api-contracts.md`](docs/api-contracts.md).

Docs:

- [Features](docs/FEATURES.txt) — the full inventory of what the CLI and both
  libraries do.
- [External API contracts](docs/api-contracts.md) — the small set of Delinea
  behaviors the engine pins, and how upstream changes are detected.

MIT licensed. See [LICENSE](LICENSE).
