# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately — please do not open a public GitHub
issue. Use the **Report issue** link in Delinea's
[Responsible Disclosure](https://trust.delinea.com/) portal, or contact Delinea
product security through your usual Delinea support channel. After this
repository is public, its **Security** tab may also offer private vulnerability
reporting.

## Supply chain

delinea-tools has exactly one direct Go module dependency:
[`github.com/DelineaXPM/delinea-common`](https://github.com/DelineaXPM/delinea-common).
That module imports only the Go standard library. This boundary is enforced,
not merely asserted:

- An offline test (`internal/supplychain`) requires exactly the reviewed
  `delinea-common v1.0.0` dependency and rejects additional, indirect,
  replacement, exclusion, or retraction directives.
- CI verifies that `go.mod` and `go.sum` are tidy and that the resolved module
  graph contains only delinea-tools and delinea-common.

The Go toolchain, standard library, and the pinned common module are the entire
build and runtime dependency surface. CI runs a version-pinned
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

The tag-triggered release workflow builds archives for the supported Linux,
macOS, and Windows targets from the tagged module and publishes a `SHA256SUMS`
manifest with them. It verifies that the tag points at `main` and that each
binary's embedded Go module version is the release tag. Release archives are
not currently signed and do not include an SBOM or separate provenance
attestation; consumers should verify the checksum and the GitHub tag/release.
