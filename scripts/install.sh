#!/usr/bin/env bash
#
# omniban installer — downloads the latest release binary to PREFIX (default
# /usr/local/bin). Override the version with VERSION=vX.Y.Z.
#
#   curl -fsSL https://raw.githubusercontent.com/extremeshok/omniban/master/scripts/install.sh | sudo bash
#
set -euo pipefail

REPO="extremeshok/omniban"
BIN="omniban"
PREFIX="${PREFIX:-/usr/local/bin}"

latest_version() {
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' \
    | head -n1 \
    | sed 's/.*"\(v[^"]*\)".*/\1/'
}

main() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "omniban installer must run as root (use sudo)" >&2
    exit 1
  fi

  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  if [[ "$os" != "linux" ]]; then
    echo "omniban supports Linux only (detected: ${os})" >&2
    exit 1
  fi

  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64) arch="amd64" ;;
    aarch64 | arm64) arch="arm64" ;;
    *)
      echo "unsupported architecture: ${arch}" >&2
      exit 1
      ;;
  esac

  local version
  version="${VERSION:-$(latest_version)}"
  if [[ -z "$version" ]]; then
    echo "could not determine the latest release version" >&2
    exit 1
  fi

  local tarball url tmp
  tarball="${BIN}_${version#v}_linux_${arch}.tar.gz"
  url="https://github.com/${REPO}/releases/download/${version}/${tarball}"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  echo "downloading ${url}"
  curl -fsSL -o "${tmp}/${tarball}" "$url"
  tar -xzf "${tmp}/${tarball}" -C "$tmp" "$BIN"
  install -m 0755 "${tmp}/${BIN}" "${PREFIX}/${BIN}"

  echo "installed ${BIN} to ${PREFIX}/${BIN}"
  "${PREFIX}/${BIN}" version

  echo
  echo "self-update is enabled for this standalone install:"
  echo "  sudo ${BIN} update                # update to the latest release"
  echo "  sudo ${BIN} update --enable-timer # opt in to automatic daily updates"
}

main "$@"
