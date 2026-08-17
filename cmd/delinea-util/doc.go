package main

import _ "embed"

// readmeText is the plain-text documentation shipped inside the binary,
// printed by --readme; the usage synopsis is scraped from it so the two
// cannot drift.
//
//go:embed README.txt
var readmeText string
