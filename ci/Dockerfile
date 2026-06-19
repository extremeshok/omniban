# syntax=docker/dockerfile:1
#
# Toolchain image for the omniban poll-ci gate. Build and publish where the CI
# VPS can reach it, then reference it from .poll-ci.yml:
#
#   docker build -t ghcr.io/extremeshok/omniban-ci:latest -f ci/Dockerfile .
#
# Provides on PATH: go, git, make, golangci-lint, gosec, govulncheck,
# shellcheck, hadolint, gitleaks. Arch-aware (amd64 + arm64).
FROM golang:1.26-bookworm

ARG GOLANGCI_VERSION=v2.12.2
ARG HADOLINT_VERSION=v2.12.0
ARG GITLEAKS_VERSION=8.21.2

# Fail a piped RUN (curl | tar) if any stage in the pipe errors.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
 && apt-get install -y --no-install-recommends shellcheck ca-certificates curl git make \
 && rm -rf /var/lib/apt/lists/*

RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION} \
 && go install github.com/securego/gosec/v2/cmd/gosec@latest \
 && go install golang.org/x/vuln/cmd/govulncheck@latest

# hadolint + gitleaks (release binaries; arch-aware for amd64 and arm64).
RUN set -eux; \
    dpkgArch="$(dpkg --print-architecture)"; \
    case "$dpkgArch" in \
      amd64) glArch=x64;   hadoArch=x86_64 ;; \
      arm64) glArch=arm64; hadoArch=arm64  ;; \
      *) echo "unsupported arch: $dpkgArch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${glArch}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-${hadoArch}" \
      -o /usr/local/bin/hadolint; \
    chmod +x /usr/local/bin/hadolint /usr/local/bin/gitleaks

ENV PATH="/root/go/bin:${PATH}"

# Fail the build early if any tool the gate calls is missing from PATH.
RUN set -eux; \
    for t in go git make golangci-lint gosec govulncheck shellcheck hadolint gitleaks; do \
      command -v "$t"; \
    done; \
    go version; golangci-lint version
