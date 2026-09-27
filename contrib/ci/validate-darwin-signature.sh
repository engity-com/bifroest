#!/usr/bin/env bash

set -euo pipefail

dist_dir="${1:?usage: validate-darwin-signature.sh <dist-directory> [--gatekeeper]}"
gatekeeper="${2:-}"
archive="${dist_dir}/bifroest-darwin-arm64-extended.tgz"
extract_dir="$(mktemp -d)"
trap 'rm -rf "${extract_dir}"' EXIT

tar -xzf "${archive}" -C "${extract_dir}" bifroest
binary="${extract_dir}/bifroest"
codesign --verify --strict --verbose=2 "${binary}"
signature="$(codesign --display --verbose=4 "${binary}" 2>&1)"
grep -Eq '^Authority=Developer ID Application: Engity GmbH \([A-Z0-9]+\)$' <<<"${signature}"
grep -Eq '^TeamIdentifier=[A-Z0-9]+$' <<<"${signature}"
grep -Eq '^CodeDirectory .*flags=.*\(.*runtime.*\)' <<<"${signature}"
grep -Eq '^Timestamp=.+' <<<"${signature}"

if test "${gatekeeper}" = "--gatekeeper"; then
  spctl --status | grep -Fq 'assessments enabled'
  assessment="$(spctl --assess --type execute --verbose=4 "${binary}" 2>&1)" || {
    printf '%s\n' "${assessment}" >&2
    exit 1
  }
  printf '%s\n' "${assessment}"
  grep -Fq 'source=Notarized Developer ID' <<<"${assessment}"
elif test -n "${gatekeeper}"; then
  echo "Unknown option: ${gatekeeper}" >&2
  exit 2
fi
