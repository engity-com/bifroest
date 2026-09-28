#!/usr/bin/env bash

set -euo pipefail

dist_dir="$(cd "${1:?usage: test-darwin-launchdaemon.sh <dist-directory> <architecture>}" && pwd)"
architecture="${2:?usage: test-darwin-launchdaemon.sh <dist-directory> <architecture>}"
case "${architecture}" in
  amd64|arm64) ;;
  *) echo "Unsupported Darwin architecture: ${architecture}" >&2; exit 2 ;;
esac
if test "$(id -u)" -ne 0; then
  exec sudo -n env \
    "PATH=${PATH}" \
    "BIFROEST_LAUNCHD_TEST_USER=$(id -un)" \
    bash "$0" "${dist_dir}" "${architecture}"
fi
archive="${dist_dir}/bifroest-darwin-${architecture}-extended.tgz"
label="com.engity.bifroest"
plist="/Library/LaunchDaemons/${label}.plist"
binary="/usr/local/bin/bifroest"
state_directory="/Library/Application Support/Engity/Bifroest"
configuration="${state_directory}/configuration.yaml"
log_directory="/Library/Logs/Engity/Bifroest"
management_directory="/usr/local/libexec/bifroest"

for path in "${plist}" "${binary}" "${state_directory}" "${log_directory}" "${management_directory}"; do
  if test -e "${path}"; then
    echo "Clean-host launchd test refuses to replace existing path: ${path}" >&2
    exit 1
  fi
done
if nc -z 127.0.0.1 22 >/dev/null 2>&1; then
  echo "Clean-host launchd test requires port 22 to be unused" >&2
  exit 1
fi

extract_directory="$(mktemp -d)"
cleanup() {
  bash "${extract_directory}/contrib/launchd/bifroest-service.sh" uninstall >/dev/null 2>&1 || true
  rm -rf "${state_directory}" "${log_directory}"
  rm -rf "${extract_directory}"
}
trap cleanup EXIT
tar -xzf "${archive}" -C "${extract_directory}"

service_script="${extract_directory}/contrib/launchd/bifroest-service.sh"
source_plist="${extract_directory}/contrib/launchd/${label}.plist"
plutil -lint "${source_plist}"
test "$(/usr/libexec/PlistBuddy -c 'Print :Label' "${source_plist}")" = "${label}"
test "$(/usr/libexec/PlistBuddy -c 'Print :UserName' "${source_plist}")" = root
test "$(/usr/libexec/PlistBuddy -c 'Print :GroupName' "${source_plist}")" = wheel
test "$(/usr/libexec/PlistBuddy -c 'Print :WorkingDirectory' "${source_plist}")" = "${state_directory}"
test "$(/usr/libexec/PlistBuddy -c 'Print :KeepAlive:SuccessfulExit' "${source_plist}")" = false

runner_user="${BIFROEST_LAUNCHD_TEST_USER:?missing invoking user}"
configuration_source="${extract_directory}/contrib/configurations/native-macos.yaml"
sed "s/- alice/- ${runner_user}/" "${configuration_source}" > "${extract_directory}/configuration.yaml"
install -d -o root -g wheel -m 0750 "${state_directory}"
install -d -o root -g wheel -m 0710 "${log_directory}"
install -o root -g wheel -m 0640 "${extract_directory}/configuration.yaml" "${configuration}"
touch "${state_directory}/preserve-on-upgrade" "${log_directory}/preserve-on-upgrade"
state_mode_before="$(stat -f '%Su:%Sg:%Lp' "${state_directory}")"
log_mode_before="$(stat -f '%Su:%Sg:%Lp' "${log_directory}")"
bash "${service_script}" install "${extract_directory}/bifroest"

wait_for_service() {
  local attempts=60
  while (( attempts > 0 )); do
    if launchctl print "system/${label}" >/dev/null 2>&1 && nc -z 127.0.0.1 22 >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts - 1))
    sleep 1
  done
  launchctl print "system/${label}" >&2 || true
  return 1
}

service_pid() {
  launchctl kickstart -p "system/${label}"
}

wait_for_service
first_pid="$(service_pid)"
test -n "${first_pid}"
test "$(ps -o user= -p "${first_pid}" | tr -d ' ')" = root
lsof -a -p "${first_pid}" -d cwd -Fn | grep -Fxq "n${state_directory}"
test "$(stat -f '%Su:%Sg:%Lp' "${plist}")" = "root:wheel:644"
test "$(stat -f '%Su:%Sg:%Lp' "${binary}")" = "root:wheel:755"
test "$(stat -f '%Su:%Sg:%Lp' "${configuration}")" = "root:wheel:640"
test -f "${log_directory}/stdout.log"
test -f "${log_directory}/stderr.log"

kill -KILL "${first_pid}"
wait_for_service
second_pid="$(service_pid)"
test -n "${second_pid}"
test "${second_pid}" != "${first_pid}"

source_binary_digest="$(shasum -a 256 "${extract_directory}/bifroest" | awk '{ print $1 }')"
source_plist_digest="$(shasum -a 256 "${source_plist}" | awk '{ print $1 }')"
broken_binary="${extract_directory}/broken-binary"
printf broken > "${broken_binary}"
chmod 0700 "${broken_binary}"
mv -f "${broken_binary}" "${binary}"
printf '<!-- broken -->\n' >> "${plist}"
chmod 0600 "${plist}"
bash "${service_script}" upgrade "${extract_directory}/bifroest"
wait_for_service
test "$(shasum -a 256 "${binary}" | awk '{ print $1 }')" = "${source_binary_digest}"
test "$(shasum -a 256 "${plist}" | awk '{ print $1 }')" = "${source_plist_digest}"
test "$(stat -f '%Su:%Sg:%Lp' "${state_directory}")" = "${state_mode_before}"
test "$(stat -f '%Su:%Sg:%Lp' "${log_directory}")" = "${log_mode_before}"
test -f "${state_directory}/preserve-on-upgrade"
test -f "${log_directory}/preserve-on-upgrade"
touch "${state_directory}/preserve-on-uninstall" "${log_directory}/preserve-on-uninstall"

bash "/usr/local/libexec/bifroest/bifroest-service" stop
! launchctl print "system/${label}" >/dev/null 2>&1
sleep 11
! launchctl print "system/${label}" >/dev/null 2>&1

bash "/usr/local/libexec/bifroest/bifroest-service" start
wait_for_service
bash "/usr/local/libexec/bifroest/bifroest-service" uninstall
! test -e "${plist}"
! test -e "${binary}"
! test -e "${management_directory}"
test -f "${configuration}"
test -f "${state_directory}/preserve-on-uninstall"
test -f "${log_directory}/preserve-on-uninstall"
