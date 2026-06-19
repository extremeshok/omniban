#!/usr/bin/env bash
#
# omniban — one ban manager for every Linux firewall & IDS.
# Coded by Adrian Jon Kriel :: admin@extremeshok.com
#
# Fails if total test coverage (from coverage.out) is below COVERAGE_MIN.
# The minimum starts modest and rises as backends gain test suites per milestone.
set -euo pipefail

MIN="${COVERAGE_MIN:-30}"

if [[ ! -f coverage.out ]]; then
  echo "coverage.out not found; run 'make test-coverage' first" >&2
  exit 1
fi

total="$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%","",$3); print $3}')"
if [[ -z "${total}" ]]; then
  echo "could not determine total coverage" >&2
  exit 1
fi

printf 'total coverage: %s%% (minimum %s%%)\n' "${total}" "${MIN}"
if awk -v t="${total}" -v m="${MIN}" 'BEGIN { exit !(t + 0 >= m + 0) }'; then
  echo "coverage OK"
else
  echo "coverage ${total}% is below the minimum ${MIN}%" >&2
  exit 1
fi
