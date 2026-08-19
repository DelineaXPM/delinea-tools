// Package supplychain holds build-time invariants that protect delinea-tools'
// one-dependency boundary. It carries no runtime code; its tests require the
// module to depend directly on delinea-common and nothing else.
package supplychain
