#!/usr/bin/env bash
set -euo pipefail

XRAY_CONFIG_PATH="${XRAY_CONFIG_PATH:-/etc/xray/config.json}"
DNSMASQ_PID=""
XRAY_PID=""
WATCHDOG_PID=""
ENTRYPOINT_PID="$$"
ORIGINAL_RESOLV_CONF=""

log() {
  printf '%s\n' "$*" >&2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "$1 is required"
    exit 1
  fi
}

require_env() {
  if [[ -z "${!1:-}" ]]; then
    log "$1 is required"
    exit 1
  fi
}

is_ipv4_literal() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    addr = ipaddress.ip_address(sys.argv[1])
    raise SystemExit(0 if addr.version == 4 and not addr.is_unspecified else 1)
except ValueError:
    raise SystemExit(1)
PY
}

validate_security_policy() {
  if ! is_ipv4_literal "$EXPECTED_EXIT_IP"; then
    log "EXPECTED_EXIT_IP must be a valid IPv4 literal"
    exit 1
  fi

  local endpoints_output tag server port
  endpoints_output="$(upstream_endpoints)" || {
    log "failed to parse upstream proxy endpoints"
    exit 1
  }
  while IFS=$'\t' read -r tag server port; do
    [[ -n "$server" ]] || continue
    if ! is_ipv4_literal "$server"; then
      log "upstream $tag must use an IPv4 literal server; keep TLS SNI as a domain"
      exit 1
    fi
  done <<<"$endpoints_output"

  local interval="${EXIT_CHECK_INTERVAL:-60}"
  if ! [[ "$interval" =~ ^[0-9]+$ ]] || (( interval < 10 || interval > 3600 )); then
    log "EXIT_CHECK_INTERVAL must be an integer between 10 and 3600"
    exit 1
  fi
  local check_url="${EXIT_CHECK_URL:-https://www.cloudflare.com/cdn-cgi/trace}"
  if [[ "$check_url" != https://* ]]; then
    log "EXIT_CHECK_URL must use https://"
    exit 1
  fi
}

sync_timezone() {
  local timezone="${TZ:-}"
  [[ -n "$timezone" ]] || return 0
  if [[ -f "/usr/share/zoneinfo/$timezone" ]]; then
    ln -snf "/usr/share/zoneinfo/$timezone" /etc/localtime
    printf '%s\n' "$timezone" > /etc/timezone
  else
    log "warning: timezone not found: $timezone"
  fi
}

render_xray_config() {
  mkdir -p "$(dirname "$XRAY_CONFIG_PATH")"
  python3 /usr/local/bin/generate-xray.py > "$XRAY_CONFIG_PATH"
  chmod 0600 "$XRAY_CONFIG_PATH"
  xray run -test -config "$XRAY_CONFIG_PATH" >/dev/null
}

upstream_endpoints() {
  python3 - <<'PY'
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location("generate_xray", "/usr/local/bin/generate-xray.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

uris = [
    ("proxy", os.environ["PROXY_URI"]),
    ("download", os.environ.get("DOWNLOAD_PROXY_URI", "")),
]
seen = set()
for tag, uri in uris:
    if not uri.strip():
        continue
    proxy = module.parse_proxy(uri, tag)
    key = (proxy.server, proxy.port)
    if key in seen:
        continue
    seen.add(key)
    print(f"{tag}\t{proxy.server}\t{proxy.port}")
PY
}

private_tcp_allowlist() {
  python3 - <<'PY'
import importlib.util
import ipaddress
import os
import sys

spec = importlib.util.spec_from_file_location("generate_xray", "/usr/local/bin/generate-xray.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

for item in module.parse_private_tcp_allowlist(os.environ.get("PRIVATE_TCP_ALLOWLIST", "")):
    network = ipaddress.ip_network(item.cidr, strict=False)
    print(f"{item.cidr}\t{item.port}\t{network.network_address}")
PY
}

route_iface_for_ip() {
  ip -4 route get "$1" mark 0xff | awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i == "dev") {
          print $(i + 1)
          exit
        }
      }
    }
  '
}

locked_iface() {
  ip -o -4 addr show | awk -v listen="$PROXY_IP" '
    {
      split($4, addr, "/")
      if (addr[1] == listen) {
        print $2
        exit
      }
    }
  '
}

install_ipv6_block() {
  require_command ip6tables

  local key
  for key in all default lo; do
    if [[ "$(sysctl -n "net.ipv6.conf.$key.disable_ipv6")" != "1" ]]; then
      sysctl -qw "net.ipv6.conf.$key.disable_ipv6=1"
    fi
  done
  ip -6 route flush table main 2>/dev/null || true
  ip6tables -w -P INPUT DROP
  ip6tables -w -P OUTPUT DROP
  ip6tables -w -P FORWARD DROP
  ip6tables -w -F
  ip6tables -w -X
}

activate_client_guard() {
  require_command iptables

  local locked_if chain
  locked_if="$(locked_iface)"
  [[ -n "$locked_if" ]] || {
    log "failed to detect locked interface for client guard"
    return 1
  }
  chain="CLAUDE_CLIENT_GUARD"

  iptables -w -P FORWARD DROP
  iptables -w -P OUTPUT DROP
  iptables -w -N "$chain" 2>/dev/null || true
  iptables -w -F "$chain"
  iptables -w -A "$chain" -i "$locked_if" -s "$LOCKED_SUBNET" -j REJECT
  iptables -w -C INPUT -j "$chain" 2>/dev/null || iptables -w -I INPUT 1 -j "$chain"
  iptables -w -C FORWARD -j "$chain" 2>/dev/null || iptables -w -I FORWARD 1 -j "$chain"
}

release_client_guard() {
  local chain="CLAUDE_CLIENT_GUARD"
  while iptables -w -C INPUT -j "$chain" 2>/dev/null; do
    iptables -w -D INPUT -j "$chain"
  done
  while iptables -w -C FORWARD -j "$chain" 2>/dev/null; do
    iptables -w -D FORWARD -j "$chain"
  done
  iptables -w -F "$chain" 2>/dev/null || true
  iptables -w -X "$chain" 2>/dev/null || true
}

install_input_firewall() {
  require_command iptables

  local locked_if
  locked_if="$(locked_iface)"
  [[ -n "$locked_if" ]] || {
    log "failed to detect locked interface"
    exit 1
  }

  iptables -w -P INPUT DROP
  iptables -w -F INPUT
  if iptables -w -L CLAUDE_CLIENT_GUARD >/dev/null 2>&1; then
    iptables -w -I INPUT 1 -j CLAUDE_CLIENT_GUARD
  fi
  iptables -w -A INPUT -i lo -j ACCEPT
  iptables -w -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -w -A INPUT -i "$locked_if" -s "$LOCKED_SUBNET" -d "$PROXY_IP/32" -p udp --dport 53 -j ACCEPT
  iptables -w -A INPUT -i "$locked_if" -s "$LOCKED_SUBNET" -d "$PROXY_IP/32" -p tcp --dport 53 -j ACCEPT
  iptables -w -A INPUT -i "$locked_if" -s "$LOCKED_SUBNET" -d "$PROXY_IP/32" -p tcp --dport "$DIRECT_PROXY_PORT" -j ACCEPT
  iptables -w -A INPUT -i "$locked_if" -j REJECT
  iptables -w -A INPUT -j DROP
}

install_forward_firewall() {
  require_command iptables

  local locked_if
  locked_if="$(locked_iface)"
  [[ -n "$locked_if" ]] || {
    log "failed to detect locked interface"
    exit 1
  }

  iptables -w -P FORWARD DROP
  iptables -w -F FORWARD
  if iptables -w -L CLAUDE_CLIENT_GUARD >/dev/null 2>&1; then
    iptables -w -I FORWARD 1 -j CLAUDE_CLIENT_GUARD
  fi
  # Client TCP packets from locked network may ONLY traverse into/out of Xray tun0,
  # never directly to the host egress interface and never as raw UDP/QUIC/ICMP.
  iptables -w -A FORWARD -i "$locked_if" -s "$LOCKED_SUBNET" -o tun0 -p tcp -j ACCEPT
  iptables -w -A FORWARD -i tun0 -o "$locked_if" -d "$LOCKED_SUBNET" -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -w -A FORWARD -j REJECT
}

install_output_kill_switch() {
  require_command iptables

  local locked_if chain
  locked_if="$(locked_iface)"
  [[ -n "$locked_if" ]] || {
    log "failed to detect locked interface"
    exit 1
  }
  chain="PROXY_KILLSWITCH"

  local endpoints_output endpoint tag server port egress_iface rule protocol
  local -a endpoints allowed_rules=()
  endpoints_output="$(upstream_endpoints)" || {
    log "failed to parse upstream proxy endpoints"
    exit 1
  }
  mapfile -t endpoints <<<"$endpoints_output"
  [[ "${#endpoints[@]}" -gt 0 ]] || {
    log "no upstream proxy endpoints found"
    exit 1
  }

  for endpoint in "${endpoints[@]}"; do
    IFS=$'\t' read -r tag server port <<<"$endpoint"
    [[ -n "$server" && -n "$port" ]] || continue
    egress_iface="$(route_iface_for_ip "$server")"
    [[ -n "$egress_iface" ]] || {
      log "failed to detect egress interface for upstream: $tag"
      exit 1
    }
    allowed_rules+=("$egress_iface"$'\t'"tcp"$'\t'"$server/32"$'\t'"$port")
    allowed_rules+=("$egress_iface"$'\t'"udp"$'\t'"$server/32"$'\t'"$port")
  done

  local allowlist_output target cidr route_ip
  local -a allowlist=()
  allowlist_output="$(private_tcp_allowlist)" || {
    log "failed to parse PRIVATE_TCP_ALLOWLIST"
    exit 1
  }
  if [[ -n "$allowlist_output" ]]; then
    mapfile -t allowlist <<<"$allowlist_output"
    for target in "${allowlist[@]}"; do
      IFS=$'\t' read -r cidr port route_ip <<<"$target"
      [[ -n "$cidr" && -n "$port" && -n "$route_ip" ]] || continue
      egress_iface="$(route_iface_for_ip "$route_ip")"
      [[ -n "$egress_iface" ]] || {
        log "failed to detect egress interface for private TCP allowlist: $cidr:$port"
        exit 1
      }
      allowed_rules+=("$egress_iface"$'\t'"tcp"$'\t'"$cidr"$'\t'"$port")
    done
  fi

  iptables -w -N "$chain" 2>/dev/null || true
  iptables -w -F "$chain"
  iptables -w -A "$chain" -d 127.0.0.11/32 -j REJECT
  iptables -w -A "$chain" -o lo -j ACCEPT
  iptables -w -A "$chain" -o "$locked_if" -d "$LOCKED_SUBNET" -j ACCEPT
  iptables -w -A "$chain" -o tun0 -j ACCEPT
  for rule in "${allowed_rules[@]}"; do
    IFS=$'\t' read -r egress_iface protocol cidr port <<<"$rule"
    iptables -w -A "$chain" -o "$egress_iface" -m mark --mark 0xff -p "$protocol" -d "$cidr" --dport "$port" -j ACCEPT
  done
  iptables -w -A "$chain" -j REJECT

  while iptables -w -C OUTPUT -j "$chain" 2>/dev/null; do
    iptables -w -D OUTPUT -j "$chain"
  done
  iptables -w -I OUTPUT 1 -j "$chain"
}

remove_policy_routing() {
  local pref
  for pref in 100 110 111 120; do
    while ip -4 rule del pref "$pref" 2>/dev/null; do :; done
  done
  ip -4 route flush table 100 2>/dev/null || true
}

start_xray_and_tun() {
  remove_policy_routing
  xray run -c "$XRAY_CONFIG_PATH" &
  XRAY_PID="$!"

  local attempt
  for attempt in $(seq 1 50); do
    if ! kill -0 "$XRAY_PID" 2>/dev/null; then
      log "xray exited prematurely during startup"
      exit 1
    fi
    if ip link show tun0 >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  if ! ip link show tun0 >/dev/null 2>&1; then
    log "tun0 did not appear within 5s"
    exit 1
  fi

  ip -4 addr replace "$TUN_ADDRESS" dev tun0
  ip link set dev tun0 up mtu "$TUN_MTU"

  ip -4 route replace default dev tun0 table 100
  ip -4 rule add pref 100 to "$LOCKED_SUBNET" lookup main
  ip -4 rule add pref 110 fwmark 0xff lookup main
  ip -4 rule add pref 111 fwmark 0xff unreachable
  ip -4 rule add pref 120 lookup 100
}

start_dns_forwarder() {
  dnsmasq \
    --keep-in-foreground \
    --pid-file= \
    --no-resolv \
    --server="$DNS_SERVER" \
    --listen-address="$PROXY_IP" \
    --bind-interfaces \
    --filter-AAAA \
    --cache-size=1000 \
    --log-facility=- &
  DNSMASQ_PID="$!"
  sleep 0.2
  if ! kill -0 "$DNSMASQ_PID" 2>/dev/null; then
    log "dnsmasq failed to start"
    exit 1
  fi
}

use_tunnel_dns_only() {
  printf 'nameserver %s\noptions edns0 trust-ad ndots:0\n' "$PROXY_IP" > /etc/resolv.conf
}

restore_bootstrap_resolver() {
  if [[ -n "$ORIGINAL_RESOLV_CONF" ]]; then
    printf '%s\n' "$ORIGINAL_RESOLV_CONF" > /etc/resolv.conf 2>/dev/null || true
  fi
}

verify_exit_identity() {
  local quiet="${1:-}"
  local url="${EXIT_CHECK_URL:-https://www.cloudflare.com/cdn-cgi/trace}"
  local denylist="${EXIT_COUNTRY_DENYLIST:-}"
  local attempt trace actual_ip country blocked

  for attempt in 1 2 3 4 5; do
    if trace="$(curl -fsS --connect-timeout 5 --max-time 12 "$url" 2>/dev/null)"; then
      actual_ip="$(awk -F= '$1 == "ip" { gsub(/[[:space:]]/, "", $2); print $2; exit }' <<<"$trace")"
      country="$(awk -F= '$1 == "loc" { gsub(/[^A-Za-z]/, "", $2); print toupper($2); exit }' <<<"$trace")"
      if [[ -n "$actual_ip" ]]; then
        break
      fi
    fi
    sleep 1
  done

  if [[ -z "${actual_ip:-}" ]]; then
    log "failed to query exit trace from $url; keeping client egress blocked"
    return 1
  fi
  if [[ "$actual_ip" != "$EXPECTED_EXIT_IP" ]]; then
    log "exit IP mismatch (expected=$EXPECTED_EXIT_IP actual=$actual_ip); keeping client egress blocked"
    return 1
  fi

  if [[ -n "${denylist//[[:space:],]/}" ]]; then
    if ! [[ "${country:-}" =~ ^[A-Z]{2}$ ]]; then
      log "failed to verify exit country; keeping client egress blocked"
      return 1
    fi
    for blocked in ${denylist//,/ }; do
      blocked="$(printf '%s' "$blocked" | tr '[:lower:]' '[:upper:]')"
      if [[ "$country" == "$blocked" ]]; then
        log "proxy exit country is denied ($country); keeping client egress blocked"
        return 1
      fi
    done
  fi

  if [[ "$quiet" != "--quiet" ]]; then
    log "proxy exit verified: ip=$actual_ip country=${country:-unknown}"
  fi
}

start_exit_watchdog() {
  local interval="${EXIT_CHECK_INTERVAL:-60}"
  (
    while sleep "$interval"; do
      if ! verify_exit_identity --quiet; then
        activate_client_guard || true
        log "exit watchdog locked client egress due to anomaly"
        kill -TERM "$ENTRYPOINT_PID"
        exit 1
      fi
    done
  ) &
  WATCHDOG_PID="$!"
}

cleanup() {
  local code=$?
  trap - EXIT TERM INT

  if [[ -n "${PROXY_IP:-}" && -n "${LOCKED_SUBNET:-}" ]]; then
    activate_client_guard 2>/dev/null || true
  elif command -v iptables >/dev/null 2>&1; then
    iptables -w -P FORWARD DROP 2>/dev/null || true
    iptables -w -P OUTPUT DROP 2>/dev/null || true
  fi
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -w -P INPUT DROP 2>/dev/null || true
    ip6tables -w -P OUTPUT DROP 2>/dev/null || true
    ip6tables -w -P FORWARD DROP 2>/dev/null || true
  fi
  if [[ -n "$WATCHDOG_PID" ]]; then
    kill "$WATCHDOG_PID" 2>/dev/null || true
    wait "$WATCHDOG_PID" 2>/dev/null || true
  fi
  if [[ -n "$XRAY_PID" ]]; then
    kill "$XRAY_PID" 2>/dev/null || true
    wait "$XRAY_PID" 2>/dev/null || true
  fi
  if [[ -n "$DNSMASQ_PID" ]]; then
    kill "$DNSMASQ_PID" 2>/dev/null || true
    wait "$DNSMASQ_PID" 2>/dev/null || true
  fi
  remove_policy_routing
  restore_bootstrap_resolver

  exit "$code"
}

main() {
  require_env CONFIG_SOURCE
  require_env PROXY_IP
  require_env LOCKED_SUBNET
  if [[ "$PROXY_IP" == "0.0.0.0" ]]; then
    log "refusing to listen on 0.0.0.0"
    exit 1
  fi

  trap cleanup EXIT TERM INT
  require_command iptables
  iptables -w -P FORWARD DROP
  iptables -w -P OUTPUT DROP
  install_ipv6_block
  activate_client_guard

  require_env PROXY_URI
  require_env DIRECT_PROXY_PORT
  require_env DNS_SERVER
  require_env TUN_ADDRESS
  require_env TUN_MTU
  require_env BLOCK_PRIVATE_CIDRS
  require_env EXPECTED_EXIT_IP
  require_command python3
  require_command xray
  require_command dnsmasq

  ORIGINAL_RESOLV_CONF="$(cat /etc/resolv.conf)"
  validate_security_policy
  sync_timezone
  render_xray_config
  install_input_firewall
  install_forward_firewall
  install_output_kill_switch
  start_xray_and_tun
  start_dns_forwarder
  use_tunnel_dns_only
  verify_exit_identity
  start_exit_watchdog
  release_client_guard

  local -a supervised_pids=("$XRAY_PID" "$DNSMASQ_PID")
  if [[ -n "$WATCHDOG_PID" ]]; then
    supervised_pids+=("$WATCHDOG_PID")
  fi
  local status=0
  wait -n "${supervised_pids[@]}" || status=$?
  log "a supervised proxy process exited (exit=$status); shutting down fail-closed"
  return "$status"
}

main "$@"
