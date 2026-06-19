#!/usr/bin/env bash
#
# omniban — run the live e2e suites against real tools in a privileged Linux
# container. Cross-builds a Linux binary, then runs each scenario. Requires
# Docker. Override the base image with E2E_IMAGE.
#
#   ./test/e2e/run.sh
set -euo pipefail

cd "$(dirname "$0")/../.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bin="$tmp/omniban-linux"

echo "### cross-building linux/amd64 binary"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version=e2e" -o "$bin" ./cmd/omniban

img="${E2E_IMAGE:-debian:bookworm-slim}"
rc=0
for script in netfilter_e2e.sh fail2ban_e2e.sh; do
  echo "### running ${script} in ${img}"
  if ! docker run --rm --privileged \
      -v "$bin":/usr/local/bin/omniban:ro \
      -v "$PWD/test/e2e/${script}":/e2e.sh:ro \
      "$img" sh /e2e.sh; then
    rc=1
  fi
done
exit "$rc"
