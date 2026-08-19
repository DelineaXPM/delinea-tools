# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately — please do not open a public GitHub
issue. Use this repository's private vulnerability reporting (the **Security**
tab → **Report a vulnerability**), or contact Delinea product security through
your usual Delinea support channel.

## Supply chain

delinea-tools is a single, self-contained Go module with **zero third-party
dependencies** — it imports only the Go standard library. This is enforced, not
merely asserted:

- An offline test (`internal/supplychain`) fails the build if `go.mod` ever
  gains a `require` directive. It runs in the ordinary test suite, so it fires
  in `make test`, in the cross-platform CI `test` job, and under the `e2e`
  build tag.
- CI additionally verifies that `go.mod` is tidy and that no `go.sum` exists.

Because there are no module dependencies, the Go toolchain and standard library
are the module's entire third-party build and runtime dependency surface. CI
runs a version-pinned
[`govulncheck`](https://go.dev/doc/security/vuln/) on every pull request and
push to `main` (`.github/workflows/ci.yml`), scanning with the minimum Go
version in `go.mod`. A reachable standard-library vulnerability therefore
keeps CI red until that minimum is advanced to a fixed release.

## Supported toolchain and the version floor

The `go` directive in `go.mod` (currently `go 1.26.6`) is the minimum toolchain
consumers build against — a patch-level floor chosen deliberately so the
standard-library security baseline is explicit and auditable.

When an upstream Go security release fixes a standard-library vulnerability
that affects this module, the `go` directive is advanced to that patch release
(or newer) and shipped as a normal pull request through CI. Until a broader
team policy supersedes it, the repository maintainer owns this bump and targets
it within one week of a high- or critical-severity standard-library advisory.

## Release artifacts

The supply-chain evidence shipped with a tagged release (checksums, SBOM, build
provenance, signature) is being decided as part of public-release preparation
and is not yet finalized.
