# omniban — one ban manager for every Linux firewall & IDS.
# Coded by Adrian Jon Kriel :: admin@extremeshok.com

SHELL := /bin/bash

BINARY  := omniban
PKG     := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
COVERAGE_PACKAGES := ./internal/... ./cmd/...

.PHONY: all tidy build install run fmt vet lint test test-coverage coverage-check \
        security-scan security-scan-gosec security-scan-govulncheck clean

all: fmt vet lint test

tidy:
	go mod tidy

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/omniban

install: build
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

run:
	go run ./cmd/omniban

fmt:
	gofmt -w ./cmd ./internal
	@command -v goimports >/dev/null 2>&1 && goimports -w ./cmd ./internal || true

vet:
	go vet $(PKG)

lint:
	golangci-lint run $(PKG)

test:
	go test -race $(PKG)

test-coverage:
	go test -race -covermode=atomic -coverprofile=coverage.out $(COVERAGE_PACKAGES)

coverage-check: test-coverage
	./scripts/check_coverage.sh

security-scan: security-scan-gosec security-scan-govulncheck

# Block only on HIGH-severity AND HIGH-confidence findings to avoid false-positive churn.
security-scan-gosec:
	gosec -severity high -confidence high ./cmd/... ./internal/...

security-scan-govulncheck:
	govulncheck ./...

clean:
	rm -rf bin coverage.out
