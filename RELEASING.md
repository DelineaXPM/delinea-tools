# Releasing

Releases are tagged Go module source. The project does not attach binaries or
other build artifacts to GitHub releases.

1. Merge all intended changes to `main` and wait for its CI and CodeQL runs to
   pass.
2. In GitHub Actions, run the `release` workflow from `main` with a new stable
   semantic version such as `v1.1.0`.
3. Confirm that the workflow passes its cross-platform CI and serialized live
   E2E gates. It then verifies that `main` has not moved, creates an annotated
   tag for the tested commit, and publishes generated release notes without
   attached assets.
4. Verify the tag from a clean module cache before announcing the release.

The workflow rejects prerelease syntax, an existing version, and any version
that is lower than the latest release. Matching `v*` tags can be created only
with a deploy key held by the `release` environment, which accepts `main` only.
A separate rule blocks every actor, including that deploy key, from updating or
deleting a release tag after creation.

Do not add another write-enabled deploy key without revisiting the tag-creation
rule: GitHub rulesets grant their deploy-key bypass by actor type, not by an
individual key.

When a change spans both public modules, release `delinea-common` first. Update
`delinea-tools` to require that immutable common version, merge and test the
update, and then release `delinea-tools`. A change confined to one module needs
only that module's release.
