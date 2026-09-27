#!/usr/bin/env bash

set -euo pipefail

dist_dir="${1:?usage: validate-darwin-release.sh <dist-directory>}"
deployment_target="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
prefix="bifroest-darwin-arm64-extended"
archive="${dist_dir}/${prefix}.tgz"
manifest="${dist_dir}/bifroest-release-manifest.json"
checksums="${dist_dir}/bifroest-checksums.txt"

for required in \
  "${archive}" \
  "${dist_dir}/${prefix}.third-party-notices.txt" \
  "${archive}.spdx.json" \
  "${archive}.cdx.json" \
  "${manifest}" \
  "${checksums}"; do
  test -f "${required}"
done

(cd "${dist_dir}" && shasum -a 256 --check bifroest-checksums.txt)

while IFS= read -r entry; do
  case "${entry}" in
    *.a|*.h|*MacOSX*.sdk*|*/usr/include/security/pam*)
      echo "Forbidden SDK header or static library in archive: ${entry}" >&2
      exit 1
      ;;
  esac
done < <(tar -tzf "${archive}")

extract_dir="$(mktemp -d)"
trap 'rm -rf "${extract_dir}"' EXIT
tar -xzf "${archive}" -C "${extract_dir}" bifroest
binary="${extract_dir}/bifroest"
test -x "${binary}"

"${binary}" version --no-long
test "$(lipo -archs "${binary}")" = "arm64"
file -b "${binary}" | grep -Eq '^Mach-O 64-bit executable arm64$'
vtool -show-build "${binary}" | grep -Eq "minos[[:space:]]+${deployment_target//./\\.}([[:space:]]|$)"

dependencies="$(otool -L "${binary}")"
grep -Fq '/usr/lib/libpam.2.dylib' <<<"${dependencies}"
while IFS= read -r dependency; do
  case "${dependency}" in
    /usr/lib/*|/System/Library/*) ;;
    *) echo "Non-system dynamic dependency: ${dependency}" >&2; exit 1 ;;
  esac
done < <(awk 'NR > 1 { print $1 }' <<<"${dependencies}")

symbols="$(nm -m "${binary}")"
for symbol in _pam_start _pam_authenticate _pam_acct_mgmt; do
  grep -Eq "\(undefined\) external ${symbol} \(from libpam\)$" <<<"${symbols}"
done

strings_file="${extract_dir}/strings.txt"
strings "${binary}" > "${strings_file}"
if grep -Eq '/Applications/Xcode|/Library/Developer|MacOSX[^/]*\.sdk' "${strings_file}"; then
  echo "Binary embeds an Apple SDK or Xcode path" >&2
  exit 1
fi

python3 - "${manifest}" "${prefix}" <<'PY'
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
prefix = sys.argv[2]
manifest = json.loads(manifest_path.read_text())
assert manifest["manifestAsset"] == "bifroest-release-manifest.json"
assert manifest["checksumAsset"] == "bifroest-checksums.txt"
assert len(manifest["variants"]) == 1
variant = manifest["variants"][0]
assert (variant["os"], variant["architecture"], variant["edition"]) == ("darwin", "arm64", "extended")
assert variant["archive"] == f"{prefix}.tgz"
assert variant["notice"] == f"{prefix}.third-party-notices.txt"
assert variant["sboms"]["archive"] == {
    "spdx": f"{prefix}.tgz.spdx.json",
    "cycloneDx": f"{prefix}.tgz.cdx.json",
}
assert "image" not in variant
assert "image" not in variant["sboms"]
assert {asset["name"] for asset in manifest["assets"]} == {
    f"{prefix}.tgz",
    f"{prefix}.third-party-notices.txt",
    f"{prefix}.tgz.spdx.json",
    f"{prefix}.tgz.cdx.json",
}
PY
