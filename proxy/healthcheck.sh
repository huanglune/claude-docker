#!/usr/bin/env bash
set -euo pipefail

pgrep -x xray >/dev/null
pgrep -x dnsmasq >/dev/null
ip link show tun0 >/dev/null 2>&1

if iptables -w -C INPUT -j CLAUDE_CLIENT_GUARD 2>/dev/null \
  || iptables -w -C FORWARD -j CLAUDE_CLIENT_GUARD 2>/dev/null; then
  echo "client guard is still blocking traffic" >&2
  exit 1
fi

expected_ip="${EXPECTED_EXIT_IP:-}"
[[ -n "$expected_ip" ]] || {
  echo "EXPECTED_EXIT_IP is required" >&2
  exit 1
}

url="${EXIT_CHECK_URL:-https://www.cloudflare.com/cdn-cgi/trace}"
trace="$(curl -fsS --connect-timeout 5 --max-time 8 "$url")"

actual_ip="$(awk -F= '$1 == "ip" { gsub(/[[:space:]]/, "", $2); print $2; exit }' <<<"$trace")"
country="$(awk -F= '$1 == "loc" { gsub(/[^A-Za-z]/, "", $2); print toupper($2); exit }' <<<"$trace")"

lock_down_on_drift() {
  local locked_if
  locked_if="$(ip -o -4 addr show | awk -v listen="${PROXY_IP:-}" '{ split($4, a, "/"); if (a[1] == listen) { print $2; exit } }')"
  if [[ -n "$locked_if" && -n "${LOCKED_SUBNET:-}" ]]; then
    iptables -w -N CLAUDE_CLIENT_GUARD 2>/dev/null || true
    iptables -w -F CLAUDE_CLIENT_GUARD
    iptables -w -A CLAUDE_CLIENT_GUARD -i "$locked_if" -s "$LOCKED_SUBNET" -j REJECT
    iptables -w -C INPUT -j CLAUDE_CLIENT_GUARD 2>/dev/null || iptables -w -I INPUT 1 -j CLAUDE_CLIENT_GUARD
    iptables -w -C FORWARD -j CLAUDE_CLIENT_GUARD 2>/dev/null || iptables -w -I FORWARD 1 -j CLAUDE_CLIENT_GUARD
  fi
}

if [[ "$actual_ip" != "$expected_ip" ]]; then
  echo "exit IP mismatch: expected=$expected_ip actual=${actual_ip:-<empty>}" >&2
  lock_down_on_drift
  exit 1
fi

denylist="${EXIT_COUNTRY_DENYLIST:-}"
if [[ -n "${denylist//[[:space:],]/}" ]]; then
  if ! [[ "$country" =~ ^[A-Z]{2}$ ]]; then
    echo "missing exit country in trace" >&2
    exit 1
  fi
  for blocked in ${denylist//,/ }; do
    blocked="$(printf '%s' "$blocked" | tr '[:lower:]' '[:upper:]')"
    if [[ "$country" == "$blocked" ]]; then
      echo "exit country is denied: $country" >&2
      lock_down_on_drift
      exit 1
    fi
  done
fi
