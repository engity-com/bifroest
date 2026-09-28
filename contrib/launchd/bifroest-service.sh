#!/usr/bin/env bash

set -euo pipefail

label="com.engity.bifroest"
plist="/Library/LaunchDaemons/${label}.plist"
binary="/usr/local/bin/bifroest"
state_directory="/Library/Application Support/Engity/Bifroest"
configuration="${state_directory}/configuration.yaml"
log_directory="/Library/Logs/Engity/Bifroest"
management_directory="/usr/local/libexec/bifroest"
installed_script="${management_directory}/bifroest-service"
installed_plist="${management_directory}/${label}.plist"
script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_plist="${script_directory}/${label}.plist"
archive_root="$(cd "${script_directory}/../.." && pwd)"
default_source_binary="${archive_root}/bifroest"
if ! test -f "${default_source_binary}" && test -f "${binary}"; then
  default_source_binary="${binary}"
fi
temporary_files=()
transaction_active=false
transaction_deployment_started=false
transaction_was_loaded=false
transaction_targets=()
transaction_backups=()
transaction_had_original=()

if test "$(id -u)" -ne 0; then
  echo "Bifröst service management must run as root" >&2
  exit 1
fi

is_loaded() {
  launchctl print "system/${label}" >/dev/null 2>&1
}

stop_service() {
  if is_loaded; then
    launchctl bootout "system/${label}"
  fi
}

stage_file() {
  local source="$1"
  local target="$2"
  local mode="$3"
  install -o root -g wheel -m "${mode}" "${source}" "${target}"
}

rollback_transaction() {
  if test "${transaction_active}" = false; then
    return
  fi
  if test "${transaction_deployment_started}" = false; then
    if (( ${#transaction_backups[@]} > 0 )); then
      rm -f "${transaction_backups[@]}"
    fi
    transaction_active=false
    return
  fi
  stop_service || true
  local index target backup
  for ((index = 0; index < ${#transaction_targets[@]}; index++)); do
    target="${transaction_targets[index]}"
    backup="${transaction_backups[index]}"
    if test "${transaction_had_original[index]}" = true; then
      if test -e "${backup}"; then
        mv -f "${backup}" "${target}" || true
      fi
    else
      rm -f "${target}"
    fi
  done
  if test "${transaction_was_loaded}" = true && test -e "${plist}"; then
    launchctl bootstrap system "${plist}" || true
  fi
  transaction_active=false
  transaction_deployment_started=false
  echo "Service upgrade failed; previous installation was restored" >&2
}

cleanup() {
  local status="$?"
  rollback_transaction
  if (( ${#temporary_files[@]} > 0 )); then
    rm -f "${temporary_files[@]}"
  fi
  return "${status}"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

ensure_secure_directory() {
  local directory="$1"
  local mode="$2"
  if ! test -e "${directory}"; then
    install -d -o root -g wheel -m "${mode}" "${directory}"
    return
  fi
  if ! test -d "${directory}"; then
    echo "Expected directory: ${directory}" >&2
    exit 1
  fi
  local owner group current_mode permissions
  owner="$(stat -f '%u' "${directory}")"
  group="$(stat -f '%g' "${directory}")"
  current_mode="$(stat -f '%Lp' "${directory}")"
  permissions=$((8#${current_mode}))
  if test "${owner}" -ne 0 || test "${group}" -ne 0 || (( permissions & 022 )); then
    echo "Directory must be owned by root:wheel and not group/world-writable: ${directory}" >&2
    exit 1
  fi
}

validate_configuration() {
  if ! test -f "${configuration}"; then
    echo "Configuration does not exist: ${configuration}" >&2
    exit 1
  fi
  local owner group mode permissions
  owner="$(stat -f '%u' "${configuration}")"
  group="$(stat -f '%g' "${configuration}")"
  mode="$(stat -f '%Lp' "${configuration}")"
  permissions=$((8#${mode}))
  if test "${owner}" -ne 0 || test "${group}" -ne 0 || (( permissions & 022 )); then
    echo "Configuration must be owned by root:wheel and not group/world-writable: ${configuration}" >&2
    exit 1
  fi
}

install_service() {
  local source_binary="${1:-${default_source_binary}}"
  local start="${2:-true}"
  if ! test -f "${source_binary}" || ! test -x "${source_binary}"; then
    echo "Executable Bifröst binary does not exist: ${source_binary}" >&2
    exit 1
  fi
  plutil -lint "${source_plist}" >/dev/null
  validate_configuration

  ensure_secure_directory "$(dirname "${binary}")" 0755
  ensure_secure_directory "${state_directory}" 0750
  ensure_secure_directory "${log_directory}" 0750
  ensure_secure_directory "${management_directory}" 0755

  local staged_binary staged_plist staged_script staged_template
  staged_binary="$(mktemp "${binary}.new.XXXXXX")"
  staged_plist="$(mktemp "${plist}.new.XXXXXX")"
  staged_script="$(mktemp "${installed_script}.new.XXXXXX")"
  staged_template="$(mktemp "${installed_plist}.new.XXXXXX")"
  temporary_files+=("${staged_binary}" "${staged_plist}" "${staged_script}" "${staged_template}")
  stage_file "${source_binary}" "${staged_binary}" 0755
  stage_file "${source_plist}" "${staged_plist}" 0644
  stage_file "${BASH_SOURCE[0]}" "${staged_script}" 0755
  stage_file "${source_plist}" "${staged_template}" 0644
  plutil -lint "${staged_plist}" >/dev/null

  transaction_was_loaded=false
  if is_loaded; then
    transaction_was_loaded=true
  fi
  transaction_targets=("${binary}" "${plist}" "${installed_script}" "${installed_plist}")
  transaction_backups=()
  transaction_had_original=()
  transaction_active=true
  transaction_deployment_started=false
  local target backup
  for target in "${transaction_targets[@]}"; do
    backup="${target}.previous.$$"
    transaction_backups+=("${backup}")
    if test -e "${target}"; then
      transaction_had_original+=(true)
      cp -p "${target}" "${backup}"
    else
      transaction_had_original+=(false)
    fi
  done

  transaction_deployment_started=true
  stop_service
  mv -f "${staged_binary}" "${binary}"
  mv -f "${staged_plist}" "${plist}"
  mv -f "${staged_script}" "${installed_script}"
  mv -f "${staged_template}" "${installed_plist}"
  if test "${start}" = true; then
    launchctl bootstrap system "${plist}"
  fi
  rm -f "${transaction_backups[@]}"
  transaction_active=false
  transaction_deployment_started=false
  temporary_files=()
}

case "${1:-}" in
  install|upgrade)
    start=true
    source_binary="${2:-${default_source_binary}}"
    if test "${3:-}" = "--no-start"; then
      start=false
    elif test -n "${3:-}"; then
      echo "Unknown option: ${3}" >&2
      exit 2
    fi
    if test -n "${4:-}"; then
      echo "Too many arguments" >&2
      exit 2
    fi
    install_service "${source_binary}" "${start}"
    ;;
  start)
    validate_configuration
    if is_loaded; then
      launchctl kickstart "system/${label}"
    else
      launchctl bootstrap system "${plist}"
    fi
    ;;
  stop)
    stop_service
    ;;
  uninstall)
    stop_service
    rm -f "${plist}" "${binary}"
    rm -rf "${management_directory}"
    echo "Preserved configuration and state in ${state_directory}"
    echo "Preserved logs in ${log_directory}"
    ;;
  *)
    echo "usage: bifroest-service.sh {install|upgrade} [binary] [--no-start] | start | stop | uninstall" >&2
    exit 2
    ;;
esac
