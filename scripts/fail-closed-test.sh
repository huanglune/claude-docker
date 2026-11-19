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

PROBE_URL="${FAIL_CLOSED_PROBE_URL:-${EXIT_CHECK_URL:-https://www.cloudflare.com/cdn-cgi/trace}}"
EXPECTED_IP="${EXPECTED_EXIT_IP:-}"
CHAIN="CLAUDE_FAIL_CLOSED_TEST"
CHAIN_INSTALLED=0

compose_exec() {
  docker compose exec -T "$@"
}

claude_exec() {
  docker compose exec -T claude /usr/local/bin/claude-exec "$@"
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
claude_exec bash -lc 'curl -fsS --connect-timeout 5 --max-time 20 "$1" >/dev/null' bash "$PROBE_URL"

echo "Blocking configured upstream endpoints..."
CHAIN_INSTALLED=1
compose_exec proxy sh -s -- "$CHAIN" <<'SH'
set -eu
chain="$1"
iptables -w -N "$chain" 2>/dev/null || true
iptables -w -F "$chain"

python3 - <<'PY' | while read -r server port; do
import json

with open("/etc/xray/config.json", encoding="utf-8") as fh:
    config = json.load(fh)

seen = set()
for out in config.get("outbounds", []):
    proto = out.get("protocol", "")
    settings = out.get("settings") or {}
    if proto == "vless":
        for item in settings.get("vnext") or []:
            addr, port = item.get("address"), item.get("port")
            if addr and port and (addr, port) not in seen:
                seen.add((addr, port))
                print(f"{addr}\t{port}")
    elif proto in ("trojan", "shadowsocks"):
        for item in settings.get("servers") or []:
            addr, port = item.get("address"), item.get("port")
            if addr and port and (addr, port) not in seen:
                seen.add((addr, port))
                print(f"{addr}\t{port}")
PY
  [ -n "$server" ] || continue
  iface="$(ip -4 route get "$server" mark 0xff | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
  [ -n "$iface" ] || { echo "failed to find upstream route for $server" >&2; exit 1; }
  iptables -w -A "$chain" -o "$iface" -p tcp -d "$server" --dport "$port" -j REJECT
  iptables -w -A "$chain" -o "$iface" -p udp -d "$server" --dport "$port" -j REJECT
done

iptables -w -S "$chain" | grep -q -- '-j REJECT'
iptables -w -I OUTPUT 1 -j "$chain"
SH

sleep 2
echo "Verifying that client traffic fails instead of falling back to direct egress..."
if claude_exec bash -lc 'curl -fsS --connect-timeout 4 --max-time 10 "$1" >/dev/null' bash "$PROBE_URL"; then
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
recovered_ip=""
for _ in $(seq 1 15); do
  if trace="$(claude_exec bash -lc 'curl -fsS --connect-timeout 3 --max-time 8 "$1"' bash "$PROBE_URL" 2>/dev/null)"; then
    recovered_ip="$(awk -F= '$1 == "ip" { gsub(/[[:space:]]/, "", $2); print $2; exit }' <<<"$trace")"
    if [[ -z "$EXPECTED_IP" || "$recovered_ip" == "$EXPECTED_IP" ]]; then
      recovered=1
      break
    fi
  fi
  sleep 2
done
[[ "$recovered" == "1" ]] || {
  echo "upstream did not recover with expected exit IP ($EXPECTED_IP) after removing block" >&2
  exit 1
}

echo "✓ Fail-closed outage test passed (exit IP: ${recovered_ip:-verified})"
