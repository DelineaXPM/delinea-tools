// Package supplychain holds build-time invariants that protect delinea-tools'
// zero-third-party-dependency guarantee. It carries no runtime code; the
// guarantee is enforced by its tests, which fail the build if go.mod ever
// declares a dependency.
package supplychain
