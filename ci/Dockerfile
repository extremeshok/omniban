# syntax=docker/dockerfile:1
#
# Toolchain image for the omniban poll-ci gate. Build and publish where the CI
# VPS can reach it, then reference it from .poll-ci.yml:
#
#   docker build -t ghcr.io/extremeshok/omniban-ci:latest -f ci/Dockerfile .
#
# Provides on PATH: go, git, make, golangci-lint, gosec, govulncheck,
# shellcheck, hadolint, gitleaks.
FROM golang:1.26-bookworm

ARG GOLANGCI_VERSION=v2.12.2
ARG HADOLINT_VERSION=v2.12.0
ARG GITLEAKS_VERSION=8.21.2

RUN apt-get update \
 && apt-get install -y --no-install-recommends shellcheck ca-certificates curl git make \
 && rm -rf /var/lib/apt/lists/*

RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION} \
 && go install github.com/securego/gosec/v2/cmd/gosec@latest \
 && go install golang.org/x/vuln/cmd/govulncheck@latest

RUN curl -fsSL -o /usr/local/bin/hadolint \
      "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
 && chmod +x /usr/local/bin/hadolint

RUN curl -fsSL \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

ENV PATH="/root/go/bin:${PATH}"
