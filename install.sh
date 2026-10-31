#!/usr/bin/env bash
# XHTTP-CDN installer: run a local checkout, or supply --source RAW_GITHUB_URL.
set -Eeuo pipefail
umask 077
if [[ ${EUID} -ne 0 ]]; then echo 'Please run with sudo bash install.sh'; exit 1; fi
if [[ ! -t 0 ]]; then echo 'An interactive terminal is required. Download first; do not pipe to bash.'; exit 1; fi
source_url=''
if [[ ${1:-} == --source ]]; then source_url=${2:?Missing source URL}; shift 2; fi
if [[ -n "$source_url" && ! "$source_url" =~ ^https://raw\.githubusercontent\.com/[^/]+/[^/]+/.+ ]]; then
  echo '--source must be an HTTPS raw.githubusercontent.com repository path'; exit 1
fi
command -v apt-get >/dev/null || { echo 'Only Debian/Ubuntu with apt are supported'; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
dpkg-query -W -f='${binary:Package}\t${db:Status-Status}\n' > "$tmp/packages-before"
export XHTTP_CDN_BOOTSTRAP_BASELINE="$tmp/packages-before"
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
  apt-get update
  apt-get install -y python3 curl ca-certificates
fi
if [[ -n "$source_url" ]]; then
  for name in deploy.py SHA256SUMS; do
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
      "${source_url%/}/$name" -o "$tmp/$name"
  done
  (cd "$tmp"; grep -E '^[0-9a-f]{64}  deploy\.py$' SHA256SUMS | sha256sum --check --strict -)
  python3 "$tmp/deploy.py" "$@"
else
  here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
  python3 "$here/deploy.py" "$@"
fi
