#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  set -- /usr/bin/zsh
fi

CLEAN_ENV=(
  env
  -u CLAUDE_USER
  -u CLAUDE_UID
  -u CLAUDE_GID
  -u PROXY_IP
  -u DIRECT_PROXY_PORT
  -u LOCKED_SUBNET
  -u BLOCK_PRIVATE_CIDRS
  -u PRIVATE_TCP_ALLOWLIST
  -u DEBIAN_FRONTEND
)

if [[ "$(id -u)" != "0" ]]; then
  exec "${CLEAN_ENV[@]}" -- "$@"
fi

if [[ -z "${CLAUDE_UID:-}" || -z "${CLAUDE_GID:-}" ]] && [[ -r /run/claude-guard.env ]]; then
  # shellcheck disable=SC1091
  source /run/claude-guard.env
fi

uid="${CLAUDE_UID:?CLAUDE_UID is required}"
gid="${CLAUDE_GID:?CLAUDE_GID is required}"

exec "${CLEAN_ENV[@]}" setpriv \
  --reuid="$uid" \
  --regid="$gid" \
  --init-groups \
  --bounding-set=-net_admin,-net_raw \
  --inh-caps=-net_admin,-net_raw \
  -- "$@"
