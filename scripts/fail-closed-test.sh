#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "${CONFIRM_FAIL_CLOSED_TEST:-}" != "yes" ]]; then
  cat >&2 <<'EOF'
This test briefly blocks every configured upstream proxy endpoint.
Re-run with CONFIRM_FAIL_CLOSED_TEST=yes after confirming that a short network interruption is safe.
EOF
  exit 2
fi

PROBE_URL="${FAIL_CLOSED_PROBE_URL:-https://api.ipify.org}"
CHAIN="CLAUDE_FAIL_CLOSED_TEST"
CHAIN_INSTALLED=0

compose_exec() {
  docker compose exec -T "$@"
}

cleanup() {
  if [[ "$CHAIN_INSTALLED" == "1" ]]; then
    compose_exec proxy sh -s -- "$CHAIN" <<'SH' >/dev/null 2>&1 || true
chain="$1"
while iptables -w -C OUTPUT -j "$chain" 2>/dev/null; do
  iptables -w -D OUTPUT -j "$chain"
done
iptables -w -F "$chain" 2>/dev/null || true
iptables -w -X "$chain" 2>/dev/null || true
SH
    CHAIN_INSTALLED=0
  fi
}
trap cleanup EXIT INT TERM

container_state="$(docker compose ps --format '{{.Service}} {{.State}}' | awk '$1 == "proxy" { print $2 }')"
[[ "$container_state" == "running" ]] || {
  echo "proxy is not running" >&2
  exit 1
}

echo "Checking normal tunnel connectivity..."
compose_exec claude bash -lc 'curl -fsS --connect-timeout 5 --max-time 20 "$1" >/dev/null' bash "$PROBE_URL"

echo "Blocking configured upstream endpoints..."
CHAIN_INSTALLED=1
compose_exec proxy sh -s -- "$CHAIN" <<'SH'
set -eu
chain="$1"
iptables -w -N "$chain" 2>/dev/null || true
iptables -w -F "$chain"

python3 - <<'PY' | while read -r server port; do
import json

with open("/etc/sing-box/config.json", encoding="utf-8") as fh:
    config = json.load(fh)
seen = set()
for outbound in config["outbounds"]:
    server = outbound.get("server")
    port = outbound.get("server_port")
    if server and port and (server, port) not in seen:
        seen.add((server, port))
        print(f"{server}\t{port}")
PY
  if printf '%s' "$server" | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
    ips="$server"
  else
    ips="$(getent ahostsv4 "$server" | awk '{ print $1 }' | sort -u)"
  fi
  [ -n "$ips" ] || { echo "failed to resolve an upstream" >&2; exit 1; }
  for ip in $ips; do
    iface="$(ip route get "$ip" | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
    [ -n "$iface" ] || { echo "failed to find upstream route" >&2; exit 1; }
    iptables -w -A "$chain" -o "$iface" -p tcp -d "$ip" --dport "$port" -j REJECT
    iptables -w -A "$chain" -o "$iface" -p udp -d "$ip" --dport "$port" -j REJECT
  done
done

iptables -w -S "$chain" | grep -q -- '-j REJECT'
iptables -w -I OUTPUT 1 -j "$chain"
SH

sleep 2
echo "Verifying that client traffic fails instead of falling back to direct egress..."
if compose_exec claude bash -lc 'curl -fsS --connect-timeout 4 --max-time 10 "$1" >/dev/null' bash "$PROBE_URL"; then
  echo "SECURITY FAILURE: traffic succeeded while every upstream endpoint was blocked" >&2
  exit 1
fi

blocked_packets="$(compose_exec proxy sh -s -- "$CHAIN" <<'SH'
chain="$1"
iptables -w -L "$chain" -n -v -x \
  | awk '/REJECT/ { packets += $1 } END { print packets + 0 }'
SH
)"
[[ "$blocked_packets" -gt 0 ]] || {
  echo "test did not observe any blocked upstream packets" >&2
  exit 1
}
echo "Observed $blocked_packets blocked upstream packets; no direct fallback succeeded."

cleanup
trap - EXIT INT TERM

echo "Restoring and checking tunnel connectivity..."
recovered=0
for _ in $(seq 1 15); do
  if compose_exec claude bash -lc 'curl -fsS --connect-timeout 3 --max-time 8 "$1" >/dev/null' bash "$PROBE_URL"; then
    recovered=1
    break
  fi
  sleep 2
done
[[ "$recovered" == "1" ]] || {
  echo "upstream did not recover after removing the test block" >&2
  exit 1
}

echo "✓ Fail-closed outage test passed"
