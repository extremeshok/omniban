#!/usr/bin/env bash
#
# omniban — run the live e2e suites against real tools in privileged Linux
# containers. Cross-builds a Linux binary, then runs each scenario. Requires
# Docker. Override the base image with E2E_IMAGE. Pass scenario filenames as
# arguments to run a subset; with no args, every *_e2e.sh runs.
#
#   ./test/e2e/run.sh                       # all scenarios
#   ./test/e2e/run.sh ufw_e2e.sh            # just one
#   E2E_IMAGE=almalinux:9 ./test/e2e/run.sh netfilter_e2e.sh
set -uo pipefail

cd "$(dirname "$0")/../.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bin="$tmp/omniban-linux"

echo "### cross-building linux/amd64 binary"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version=e2e" -o "$bin" ./cmd/omniban

img="${E2E_IMAGE:-debian:bookworm-slim}"

if [ "$#" -gt 0 ]; then
  scenarios="$*"
else
  scenarios="$(cd test/e2e && ls ./*_e2e.sh | sed 's#^\./##')"
fi

rc=0
for script in $scenarios; do
  echo
  echo "### ${script} (${img})"
  if ! docker run --rm --privileged \
      -v "$bin":/usr/local/bin/omniban:ro \
      -v "$PWD/test/e2e/${script}":/e2e.sh:ro \
      "$img" sh /e2e.sh; then
    rc=1
  fi
done
exit "$rc"
