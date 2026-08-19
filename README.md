# delinea-tools

`delinea-util` is a dependency-light command-line client for Delinea Secret
Server, Secret Server Cloud, and the Delinea Platform. It provides:

- authenticated curl-style REST requests to any endpoint;
- Secret Server password and Platform client-credentials grants;
- interactive Platform login for supported native-account MFA flows;
- Platform vault discovery and explicit vault routing;
- configuration, reachability, authentication, and mapping diagnostics; and
- secret delivery to a child process, CI command file, template, file, or
  standard output.

The command is built on the standard-library-only packages in
[`DelineaXPM/delinea-common`](https://github.com/DelineaXPM/delinea-common).
This repository has exactly that one Go module dependency.

## Install

```sh
go install github.com/DelineaXPM/delinea-tools/cmd/delinea-util@v1.0.0
```

The binary contains its complete reference documentation:

```sh
delinea-util --help
delinea-util --readme
delinea-util --tree
delinea-util secrets --readme
```

## Examples

Set the target URL and one credential pair. Authentication secrets can also be
read from stdin with `--secret-stdin`; they are never accepted on argv.

```sh
export DELINEA_TOOLS_URL=https://tenant.secretservercloud.com
export DELINEA_TOOLS_USERNAME=automation
export DELINEA_TOOLS_PASSWORD='...'

delinea-util GET /api/v1/users/current
delinea-util GET '/api/v1/secrets?filter.searchText=database'
```

For the Delinea Platform, set `DELINEA_TOOLS_CLIENT_ID` and
`DELINEA_TOOLS_CLIENT_SECRET`. Use `--vault` when the path belongs to the
Platform-managed Secret Server vault:

```sh
delinea-util --vault GET /api/v1/secrets/126
```

Resolve a secret and expose it only to one child process:

```sh
delinea-util secrets run PGPASSWORD=password#126 -- \
  psql -h db.internal -U app -d orders -c 'select 1'
```

Run a read-only diagnostic without printing secret values:

```sh
delinea-util check DB_PASSWORD=password#126
```

## Security

Authentication credentials are accepted through environment variables or
stdin, never command-line values. Sensitive request bodies and headers have
file/stdin forms. Diagnostics and operational logs redact configured
credentials and sensitive headers. Secret output refuses a terminal unless
explicitly armed, and regular output files are replaced atomically at mode
`0600` on Unix.

Token grants and mutating requests do not follow redirects. Cross-origin API
redirects are refused. TLS configuration is client-local, and discovered vault
URLs must satisfy the common library's host and port trust policy. A `secrets
run` child receives a deliberately constructed environment rather than the
caller's ambient environment.

Use scoped `secrets run` delivery where possible. CI-specific GitHub and Azure
formats validate names, escape their wire protocols, and register masks before
publishing values, but platform masking remains best effort.

## Documentation

- [CI integration](docs/CI.txt)
- [Command feature inventory](docs/FEATURES.txt)
- [Live E2E fixtures](docs/E2E.txt)
- [Library packages and API contracts](https://github.com/DelineaXPM/delinea-common)
- [Security policy](SECURITY.md)

`make test` is fully offline. `make e2e` runs the live CLI suites and skips
cleanly when fixtures are absent; `make e2e-strict` requires the complete
fixture set.

MIT licensed. See [LICENSE](LICENSE).
