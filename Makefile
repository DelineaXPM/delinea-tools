CLIS := ./cmd/delinea-util

.PHONY: all test stress e2e e2e-strict vet cover coverage-check install fmt clean help

all: vet test

## test: offline unit tests (no credentials, no network)
test:
	go test ./...

## stress: run the offline suite ten times in shuffled order
stress:
	go test -shuffle=on -count=10 ./...

## e2e: end-to-end tests against real Delinea instances; requires the
## DELINEA_TOOLS_TEST_* fixtures (see docs/E2E.txt) and skips cleanly when absent
e2e:
	go test -count=1 -tags e2e ./...

## e2e-strict: run live tests and fail instead of skip when a required fixture is absent
e2e-strict:
	DELINEA_TOOLS_TEST_REQUIRE_E2E=1 go test -count=1 -tags e2e ./...

## vet: vet the default and e2e builds
vet:
	go vet ./...
	go vet -tags e2e ./...

## cover: coverage summary for the offline suite
cover:
	go test -covermode=count -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

## coverage-check: enforce the same 85% command-only coverage floor as CI
coverage-check:
	go test -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | awk '/^total:/ { seen=1; gsub(/%/, "", $$3); print "total coverage: " $$3 "%"; if ($$3 + 0 < 85.0) exit 1 } END { if (!seen) { print "coverage gate: no total: line from go tool cover"; exit 1 } }'

## install: install the CLI to $GOBIN (or $GOPATH/bin)
install:
	go install $(CLIS)

## fmt: format all Go sources
fmt:
	gofmt -w .

## clean: remove generated artifacts
clean:
	rm -f coverage.out

## help: list targets
help:
	@echo
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'
	@echo
