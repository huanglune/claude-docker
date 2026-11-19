#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${TZ:-}" && -f "/usr/share/zoneinfo/$TZ" ]]; then
  ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime
  printf '%s\n' "$TZ" > /etc/timezone
fi

uid="${CLAUDE_UID:?CLAUDE_UID is required}"
gid="${CLAUDE_GID:?CLAUDE_GID is required}"

prev_umask="$(umask)"
umask 0077
cat > /run/claude-guard.env <<EOF
CLAUDE_UID=$(printf '%q' "$uid")
CLAUDE_GID=$(printf '%q' "$gid")
PROXY_IP=$(printf '%q' "${PROXY_IP:?PROXY_IP is required}")
DIRECT_PROXY_PORT=$(printf '%q' "${DIRECT_PROXY_PORT:?DIRECT_PROXY_PORT is required}")
LOCKED_SUBNET=$(printf '%q' "${LOCKED_SUBNET:?LOCKED_SUBNET is required}")
BLOCK_PRIVATE_CIDRS=$(printf '%q' "${BLOCK_PRIVATE_CIDRS:?BLOCK_PRIVATE_CIDRS is required}")
PRIVATE_TCP_ALLOWLIST=$(printf '%q' "${PRIVATE_TCP_ALLOWLIST:-}")
EOF
chown 0:0 /run/claude-guard.env
chmod 0600 /run/claude-guard.env
umask "$prev_umask"

/usr/local/bin/claude-network-guard.sh apply

for dir_var in TMPDIR XDG_CACHE_HOME NPM_CONFIG_CACHE PIP_CACHE_DIR UV_CACHE_DIR UV_PYTHON_INSTALL_DIR; do
  dir="${!dir_var:-}"
  if [[ -n "$dir" ]]; then
    mkdir -p "$dir"
    chown "$uid:$gid" "$dir"
  fi
done

if [[ "$#" -eq 0 ]]; then
  set -- sleep infinity
fi

exec env \
  -u CLAUDE_USER \
  -u CLAUDE_UID \
  -u CLAUDE_GID \
  -u PROXY_IP \
  -u DIRECT_PROXY_PORT \
  -u LOCKED_SUBNET \
  -u BLOCK_PRIVATE_CIDRS \
  -u PRIVATE_TCP_ALLOWLIST \
  -u DEBIAN_FRONTEND \
  setpriv \
  --reuid="$uid" \
  --regid="$gid" \
  --init-groups \
  --bounding-set=-net_admin,-net_raw \
  --inh-caps=-net_admin,-net_raw \
  -- /usr/bin/tini -- "$@"
