#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${SINGBOX_CONFIG_PATH:-/etc/sing-box/config.json}"
DNSMASQ_PID=""
SINGBOX_PID=""
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

env_bool() {
  case "${!1:-}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    0|false|FALSE|no|NO|off|OFF|"") return 1 ;;
    *) log "$1 must be a boolean"; exit 1 ;;
  esac
}

proxy_only_enabled() {
  if [[ -v PROXY_ONLY ]]; then
    env_bool PROXY_ONLY
  else
    env_bool STRICT_EGRESS
  fi
}

validate_security_policy() {
  if proxy_only_enabled; then
    if ! python3 - <<'PY'
import ipaddress
import os

locked = ipaddress.ip_network(os.environ["LOCKED_SUBNET"], strict=False)
excludes = {
    ipaddress.ip_network(item, strict=False)
    for item in os.environ["ROUTE_EXCLUDE_CIDRS"].replace(",", " ").split()
}
raise SystemExit(0 if excludes == {locked} else 1)
PY
    then
      log "PROXY_ONLY=true requires ROUTE_EXCLUDE_CIDRS to equal LOCKED_SUBNET"
      exit 1
    fi
    local endpoints_output tag server port
    endpoints_output="$(upstream_endpoints)" || {
      log "failed to parse upstream proxy endpoints"
      exit 1
    }
    while IFS=$'\t' read -r tag server port; do
      if ! is_ipv4_literal "$server"; then
        log "PROXY_ONLY=true requires an IPv4 literal upstream for $tag; keep the TLS SNI as a domain"
        exit 1
      fi
    done <<<"$endpoints_output"
  fi

  local interval="${EXIT_COUNTRY_CHECK_INTERVAL:-60}"
  if ! [[ "$interval" =~ ^[0-9]+$ ]] || (( interval < 10 || interval > 3600 )); then
    log "EXIT_COUNTRY_CHECK_INTERVAL must be an integer between 10 and 3600"
    exit 1
  fi
  if [[ -n "${EXIT_COUNTRY_DENYLIST:-}" && "${EXIT_COUNTRY_CHECK_URL:-}" != https://* ]]; then
    log "EXIT_COUNTRY_CHECK_URL must use https when country checks are enabled"
    exit 1
  fi
}

is_ipv4_literal() {
  python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    raise SystemExit(0 if ipaddress.ip_address(sys.argv[1]).version == 4 else 1)
except ValueError:
    raise SystemExit(1)
PY
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

render_singbox_config() {
  mkdir -p "$(dirname "$CONFIG_PATH")"
  python3 /usr/local/bin/generate-singbox.py > "$CONFIG_PATH"
  sing-box check -c "$CONFIG_PATH" >/dev/null
}

iptables_append_once() {
  local chain="$1"
  shift

  iptables -w -C "$chain" "$@" 2>/dev/null \
    || iptables -w -A "$chain" "$@"
}

iptables_insert_once() {
  local chain="$1"
  local position="$2"
  shift 2

  iptables -w -C "$chain" "$@" 2>/dev/null \
    || iptables -w -I "$chain" "$position" "$@"
}

first_tun_peer() {
  python3 - <<'PY'
import ipaddress
import os

iface = ipaddress.ip_interface(os.environ["TUN_ADDRESS"])
for host in iface.network.hosts():
    if host != iface.ip:
        print(host)
        break
PY
}

upstream_endpoints() {
  python3 - <<'PY'
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location("generate_singbox", "/usr/local/bin/generate-singbox.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

uris = [
    ("proxy", os.environ["PROXY_URI"]),
    ("download", os.environ.get("DOWNLOAD_PROXY_URI") or os.environ.get("DIRECT_PROXY_URI", "")),
]
seen = set()
for tag, uri in uris:
    if not uri.strip():
        continue
    proxy = module.parse_proxy(uri)
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

spec = importlib.util.spec_from_file_location("generate_singbox", "/usr/local/bin/generate-singbox.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

for item in module.parse_private_tcp_allowlist(os.environ.get("PRIVATE_TCP_ALLOWLIST", "")):
    network = ipaddress.ip_network(item.cidr, strict=False)
    route_ip = network.network_address
    for host in network.hosts():
        route_ip = host
        break
    print(f"{item.cidr}\t{item.port}\t{route_ip}")
PY
}

resolve_upstream_ipv4s() {
  local server="$1"

  if is_ipv4_literal "$server"; then
    printf '%s\n' "$server"
    return
  fi

  getent ahostsv4 "$server" | awk '{ print $1 }' | sort -u
}

default_iface() {
  ip route show default | awk 'NR == 1 { print $5 }'
}

route_iface_for_ip() {
  ip route get "$1" | awk '
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
  local listen="$PROXY_IP"
  ip -o -4 addr show | awk -v listen="$listen" '
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
}

activate_client_guard() {
  require_command iptables

  local locked_if chain
  locked_if="$(locked_iface)"
  [[ -n "$locked_if" ]] || {
    log "failed to detect locked interface for bootstrap guard"
    return 1
  }
  chain="CLAUDE_CLIENT_GUARD"

  iptables -w -P FORWARD DROP
  iptables -w -P OUTPUT DROP
  iptables -w -N "$chain" 2>/dev/null || true
  iptables -w -F "$chain"
  iptables -w -A "$chain" -i "$locked_if" -s "$LOCKED_SUBNET" -j REJECT
  iptables -w -C INPUT -j "$chain" 2>/dev/null \
    || iptables -w -I INPUT 1 -j "$chain"
}

release_client_guard() {
  local chain="CLAUDE_CLIENT_GUARD"
  while iptables -w -C INPUT -j "$chain" 2>/dev/null; do
    iptables -w -D INPUT -j "$chain"
  done
  iptables -w -F "$chain" 2>/dev/null || true
  iptables -w -X "$chain" 2>/dev/null || true
}

install_output_kill_switch() {
  require_command iptables

  local locked_if chain
  locked_if="$(locked_iface)"
  chain="PROXY_KILLSWITCH"

  # Legacy mode can refresh domain-based upstreams through Docker's resolver.
  # Proxy-only mode requires IP literals and never opens this bootstrap DNS path.
  local bootstrap_dns_allowed=0
  if ! proxy_only_enabled; then
    iptables -w -I OUTPUT 1 -d 127.0.0.11/32 -p udp --dport 53 -j ACCEPT
    iptables -w -I OUTPUT 1 -d 127.0.0.11/32 -p tcp --dport 53 -j ACCEPT
    bootstrap_dns_allowed=1
  fi
  python3 - <<'PY'
path = "/etc/hosts"
with open(path, encoding="utf-8") as fh:
    lines = [line for line in fh if not line.rstrip().endswith("# claude-docker-upstream")]
with open(path, "w", encoding="utf-8") as fh:
    fh.writelines(lines)
PY

  local endpoints_output endpoint tag server port ips ip first_ip egress_iface rule protocol
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
    mapfile -t ips < <(resolve_upstream_ipv4s "$server")
    [[ "${#ips[@]}" -gt 0 ]] || {
      log "failed to resolve upstream: $tag"
      exit 1
    }
    first_ip="${ips[0]}"
    if ! is_ipv4_literal "$server"; then
      printf '%s %s # claude-docker-upstream\n' "$first_ip" "$server" >> /etc/hosts
    fi
    for ip in "${ips[@]}"; do
      egress_iface="$(route_iface_for_ip "$ip")"
      [[ -n "$egress_iface" ]] || {
        log "failed to detect egress interface for upstream: $tag"
        exit 1
      }
      allowed_rules+=("$egress_iface"$'\t'"tcp"$'\t'"$ip"$'\t'"$port")
      allowed_rules+=("$egress_iface"$'\t'"udp"$'\t'"$ip"$'\t'"$port")
    done
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

  if [[ "$bootstrap_dns_allowed" == "1" ]]; then
    iptables -w -D OUTPUT -d 127.0.0.11/32 -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -w -D OUTPUT -d 127.0.0.11/32 -p udp --dport 53 -j ACCEPT 2>/dev/null || true
  fi

  iptables -w -N "$chain" 2>/dev/null || true
  iptables -w -F "$chain"
  iptables -w -A "$chain" -d 127.0.0.11/32 -p udp --dport 53 -j REJECT
  iptables -w -A "$chain" -d 127.0.0.11/32 -p tcp --dport 53 -j REJECT
  iptables -w -A "$chain" -o lo -j ACCEPT
  if [[ -n "$locked_if" ]]; then
    iptables -w -A "$chain" -o "$locked_if" -j ACCEPT
  fi
  iptables -w -A "$chain" -o tun0 -j ACCEPT
  for rule in "${allowed_rules[@]}"; do
    IFS=$'\t' read -r egress_iface protocol ip port <<<"$rule"
    iptables -w -A "$chain" -o "$egress_iface" -p "$protocol" -d "$ip" --dport "$port" -j ACCEPT
  done
  iptables -w -A "$chain" -j REJECT

  while iptables -w -C OUTPUT -j "$chain" 2>/dev/null; do
    iptables -w -D OUTPUT -j "$chain"
  done
  iptables -w -I OUTPUT 1 -j "$chain"
}

install_forward_firewall() {
  require_command iptables

  iptables -w -P FORWARD DROP
  if proxy_only_enabled; then
    while iptables -w -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do
      iptables -w -D FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    done
  else
    iptables_append_once FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi

  local tun_dns_target
  tun_dns_target="$(first_tun_peer)"
  if [[ -n "$tun_dns_target" ]]; then
    iptables_insert_once FORWARD 1 -p udp -d "$tun_dns_target" --dport 53 -j ACCEPT
    iptables_insert_once FORWARD 1 -p tcp -d "$tun_dns_target" --dport 53 -j ACCEPT
  fi

  local allowlist_output target allowed_cidr allowed_port route_ip
  local -a allowlist=()
  allowlist_output="$(private_tcp_allowlist)" || {
    log "failed to parse PRIVATE_TCP_ALLOWLIST"
    exit 1
  }
  if [[ -n "$allowlist_output" ]]; then
    mapfile -t allowlist <<<"$allowlist_output"
    for target in "${allowlist[@]}"; do
      IFS=$'\t' read -r allowed_cidr allowed_port route_ip <<<"$target"
      [[ -n "$allowed_cidr" && -n "$allowed_port" ]] || continue
      iptables_insert_once FORWARD 1 -p tcp -d "$allowed_cidr" --dport "$allowed_port" -j ACCEPT
    done
  fi

  local cidr
  local cidrs="$BLOCK_PRIVATE_CIDRS"
  for cidr in ${cidrs//,/ }; do
    [[ -z "$cidr" || "$cidr" == *:* ]] && continue
    iptables_append_once FORWARD -d "$cidr" -j DROP
  done
}

start_dns_forwarder() {
  local listen="$PROXY_IP"
  local upstream="$DNS_SERVER"

  dnsmasq \
    --keep-in-foreground \
    --no-resolv \
    --server="$upstream" \
    --listen-address="$listen" \
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

start_singbox() {
  sing-box run -c "$CONFIG_PATH" &
  SINGBOX_PID="$!"
}

exit_country() {
  local url="${EXIT_COUNTRY_CHECK_URL:-https://www.cloudflare.com/cdn-cgi/trace}"
  curl -fsS --connect-timeout 5 --max-time 15 "$url" \
    | awk -F= '$1 == "loc" { gsub(/[^A-Za-z]/, "", $2); print toupper($2); exit }'
}

verify_exit_country() {
  local denylist="${EXIT_COUNTRY_DENYLIST:-}"
  [[ -n "${denylist//[[:space:],]/}" ]] || return 0

  local attempt country blocked
  country=""
  for attempt in 1 2 3; do
    country="$(exit_country 2>/dev/null || true)"
    [[ "$country" =~ ^[A-Z]{2}$ ]] && break
    sleep 1
  done
  if ! [[ "$country" =~ ^[A-Z]{2}$ ]]; then
    log "failed to verify proxy exit country; keeping client egress blocked"
    return 1
  fi

  for blocked in ${denylist//,/ }; do
    blocked="$(printf '%s' "$blocked" | tr '[:lower:]' '[:upper:]')"
    if [[ "$country" == "$blocked" ]]; then
      log "proxy exit country is denied: $country; keeping client egress blocked"
      return 1
    fi
  done
  log "proxy exit country verified: $country"
}

start_exit_country_watchdog() {
  local denylist="${EXIT_COUNTRY_DENYLIST:-}"
  [[ -n "${denylist//[[:space:],]/}" ]] || return 0

  local interval="${EXIT_COUNTRY_CHECK_INTERVAL:-60}"
  (
    while sleep "$interval"; do
      if ! verify_exit_country; then
        activate_client_guard || true
        log "exit-country watchdog closed client egress"
        kill -TERM "$ENTRYPOINT_PID"
        exit 1
      fi
    done
  ) &
  WATCHDOG_PID="$!"
}

install_local_redirect_bypass() {
  local listen="$PROXY_IP"
  local chain
  local attempt
  local direct_port="$DIRECT_PROXY_PORT"

  for attempt in $(seq 1 50); do
    if chain="$(nft list chain inet sing-box prerouting 2>/dev/null)"; then
      if ! grep -Fq "ip daddr $listen udp dport 53 return" <<<"$chain"; then
        nft insert rule inet sing-box prerouting ip daddr "$listen" udp dport 53 return
      fi
      if ! grep -Fq "ip daddr $listen tcp dport 53 return" <<<"$chain"; then
        nft insert rule inet sing-box prerouting ip daddr "$listen" tcp dport 53 return
      fi
      if [[ "$direct_port" =~ ^[0-9]+$ && "$direct_port" -gt 0 ]]; then
        if ! grep -Fq "ip daddr $listen tcp dport $direct_port return" <<<"$chain"; then
          nft insert rule inet sing-box prerouting ip daddr "$listen" tcp dport "$direct_port" return
        fi
      fi
      return
    fi
    sleep 0.1
  done

  log "warning: sing-box prerouting chain was not ready; local bypass rules were not installed"
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
  if [[ -n "$SINGBOX_PID" ]]; then
    kill "$SINGBOX_PID" 2>/dev/null || true
    wait "$SINGBOX_PID" 2>/dev/null || true
  fi
  if [[ -n "$DNSMASQ_PID" ]]; then
    kill "$DNSMASQ_PID" 2>/dev/null || true
    wait "$DNSMASQ_PID" 2>/dev/null || true
  fi
  restore_bootstrap_resolver

  exit "$code"
}

main() {
  require_command iptables
  iptables -w -P FORWARD DROP
  iptables -w -P OUTPUT DROP
  install_ipv6_block

  require_env PROXY_IP
  require_env DIRECT_PROXY_LISTEN
  require_env LOCKED_SUBNET
  if [[ "$PROXY_IP" == "0.0.0.0" || "$DIRECT_PROXY_LISTEN" == "0.0.0.0" ]]; then
    log "refusing to listen on 0.0.0.0"
    exit 1
  fi
  activate_client_guard

  require_env PROXY_URI
  require_env DIRECT_PROXY_PORT
  require_env DNS_SERVER
  require_env TUN_ADDRESS
  require_env BLOCK_PRIVATE_CIDRS
  require_env ROUTE_EXCLUDE_CIDRS
  require_command python3
  require_command sing-box
  require_command dnsmasq
  require_command nft

  ORIGINAL_RESOLV_CONF="$(cat /etc/resolv.conf)"
  validate_security_policy
  sync_timezone
  render_singbox_config
  install_forward_firewall
  install_output_kill_switch
  start_dns_forwarder
  start_singbox
  install_local_redirect_bypass
  use_tunnel_dns_only
  verify_exit_country
  start_exit_country_watchdog
  release_client_guard

  local -a supervised_pids=("$SINGBOX_PID" "$DNSMASQ_PID")
  if [[ -n "$WATCHDOG_PID" ]]; then
    supervised_pids+=("$WATCHDOG_PID")
  fi
  local status=0
  wait -n "${supervised_pids[@]}" || status=$?
  log "a supervised proxy process exited (exit=$status); shutting down for a clean restart"
  return "$status"
}

trap cleanup EXIT TERM INT
main "$@"
