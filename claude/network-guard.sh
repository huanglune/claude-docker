#!/usr/bin/env bash
set -Eeuo pipefail

CHAIN="CLAUDE_EGRESS_GUARD"
LOCK_FILE="/run/claude-network-guard.lock"
GUARD_ENV_FILE="/run/claude-guard.env"

log() {
  printf '%s\n' "$*" >&2
}

on_error() {
  local status=$?
  log "claude network guard failed at line $1: $2 (exit=$status)"
  exit "$status"
}

trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

require_env() {
  [[ -n "${!1:-}" ]] || { log "$1 is required"; exit 1; }
}

locked_iface() {
  ip -o -4 route show "$LOCKED_SUBNET" | awk 'NR == 1 { print $3 }'
}

install_ipv6_block() {
  local key

  ip6tables -w -P INPUT DROP
  ip6tables -w -P OUTPUT DROP
  ip6tables -w -P FORWARD DROP
  ip6tables -w -F
  ip6tables -w -X

  for key in all default lo; do
    if [[ "$(sysctl -n "net.ipv6.conf.$key.disable_ipv6")" != "1" ]]; then
      sysctl -qw "net.ipv6.conf.$key.disable_ipv6=1"
    fi
  done
  ip -6 route flush table main 2>/dev/null || true
}

install_ipv4_guard() {
  local iface cidr target allowed_cidr allowed_port

  iptables -w -P OUTPUT DROP
  iptables -w -P FORWARD DROP
  iptables -w -F OUTPUT
  iptables -w -F FORWARD

  iface="$(locked_iface)"
  [[ -n "$iface" ]] || { log "failed to detect locked interface"; return 1; }

  iptables -w -N "$CHAIN" 2>/dev/null || true
  iptables -w -F "$CHAIN"
  # Block all ports/protocols to Docker embedded DNS (127.0.0.11) because
  # nat DOCKER_OUTPUT rewrites dport 53 before filter OUTPUT runs.
  iptables -w -A "$CHAIN" -d 127.0.0.11/32 -j REJECT
  iptables -w -A "$CHAIN" -o lo -j ACCEPT
  iptables -w -A "$CHAIN" -o "$iface" -d "$PROXY_IP/32" -p udp --dport 53 -j ACCEPT
  iptables -w -A "$CHAIN" -o "$iface" -d "$PROXY_IP/32" -p tcp --dport 53 -j ACCEPT
  iptables -w -A "$CHAIN" -o "$iface" -d "$PROXY_IP/32" -p tcp --dport "$DIRECT_PROXY_PORT" -j ACCEPT
  iptables -w -A "$CHAIN" -d "$LOCKED_SUBNET" -j REJECT
  # Force all DNS through PROXY_IP:53 (--filter-AAAA) and reject client UDP/QUIC
  # so HTTP/3 falls back immediately to IPv4-pinned TCP 443 and WebRTC STUN fails closed.
  iptables -w -A "$CHAIN" -p udp --dport 53 -j REJECT
  iptables -w -A "$CHAIN" -p tcp --dport 53 -j REJECT
  iptables -w -A "$CHAIN" -p tcp --dport 853 -j REJECT
  iptables -w -A "$CHAIN" -p udp -j REJECT

  for target in ${PRIVATE_TCP_ALLOWLIST//,/ }; do
    allowed_cidr="${target%:*}"
    allowed_port="${target##*:}"
    if [[ -z "$allowed_cidr" || "$allowed_cidr" == "$target" || "$allowed_cidr" == *:* \
      || ! "$allowed_port" =~ ^[0-9]+$ || "$allowed_port" -lt 1 || "$allowed_port" -gt 65535 ]]; then
      log "invalid PRIVATE_TCP_ALLOWLIST item: $target"
      return 1
    fi
    [[ "$allowed_cidr" == */* ]] || allowed_cidr="$allowed_cidr/32"
    iptables -w -A "$CHAIN" -o "$iface" -d "$allowed_cidr" -p tcp --dport "$allowed_port" -j ACCEPT
  done

  for cidr in ${BLOCK_PRIVATE_CIDRS//,/ }; do
    [[ -n "$cidr" && "$cidr" != *:* ]] || continue
    iptables -w -A "$CHAIN" -d "$cidr" -j REJECT
  done
  for cidr in 0.0.0.0/8 127.0.0.0/8 224.0.0.0/4 240.0.0.0/4; do
    iptables -w -A "$CHAIN" -d "$cidr" -j REJECT
  done

  iptables -w -A "$CHAIN" -o "$iface" -p tcp -j ACCEPT
  iptables -w -A "$CHAIN" -j REJECT
  iptables -w -A OUTPUT -j "$CHAIN"

  while ip -4 route del default 2>/dev/null; do :; done
  ip -4 route add default via "$PROXY_IP" dev "$iface"
}

verify() {
  local iface cidr target allowed_cidr allowed_port expected_rules actual_rules default_routes

  iface="$(locked_iface)"
  [[ -n "$iface" ]] || return 1

  default_routes="$(ip -4 route show default)"
  [[ "$(wc -l <<<"$default_routes")" -eq 1 ]] || return 1
  awk -v gateway="$PROXY_IP" -v iface="$iface" '
    $1 == "default" && $2 == "via" && $3 == gateway && $4 == "dev" && $5 == iface { found = 1 }
    END { exit !found }
  ' <<<"$default_routes" || return 1

  [[ "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" == "1" ]] || return 1
  [[ "$(sysctl -n net.ipv6.conf.default.disable_ipv6)" == "1" ]] || return 1
  [[ "$(sysctl -n net.ipv6.conf.lo.disable_ipv6)" == "1" ]] || return 1
  if ip -6 address show | grep -q 'inet6 '; then
    return 1
  fi
  if ip -6 route show | grep -q .; then
    return 1
  fi
  ip6tables -w -S INPUT | grep -qx -- '-P INPUT DROP' || return 1
  ip6tables -w -S OUTPUT | grep -qx -- '-P OUTPUT DROP' || return 1
  ip6tables -w -S FORWARD | grep -qx -- '-P FORWARD DROP' || return 1
  if ip6tables -w -S | grep -q '^-A '; then
    return 1
  fi

  iptables -w -S OUTPUT | grep -qx -- '-P OUTPUT DROP' || return 1
  [[ "$(iptables -w -S OUTPUT | grep -c "^-A OUTPUT ")" -eq 1 ]] || return 1
  iptables -w -S OUTPUT | grep -qx -- "-A OUTPUT -j $CHAIN" || return 1
  iptables -w -S FORWARD | grep -qx -- '-P FORWARD DROP' || return 1
  if iptables -w -S FORWARD | grep -q '^-A FORWARD '; then
    return 1
  fi

  iptables -w -C "$CHAIN" -d 127.0.0.11/32 -j REJECT || return 1
  iptables -w -C "$CHAIN" -o lo -j ACCEPT || return 1
  iptables -w -C "$CHAIN" -o "$iface" -d "$PROXY_IP/32" -p udp --dport 53 -j ACCEPT || return 1
  iptables -w -C "$CHAIN" -o "$iface" -d "$PROXY_IP/32" -p tcp --dport 53 -j ACCEPT || return 1
  iptables -w -C "$CHAIN" -o "$iface" -d "$PROXY_IP/32" -p tcp --dport "$DIRECT_PROXY_PORT" -j ACCEPT || return 1
  iptables -w -C "$CHAIN" -d "$LOCKED_SUBNET" -j REJECT || return 1
  iptables -w -C "$CHAIN" -p udp --dport 53 -j REJECT || return 1
  iptables -w -C "$CHAIN" -p tcp --dport 53 -j REJECT || return 1
  iptables -w -C "$CHAIN" -p tcp --dport 853 -j REJECT || return 1
  iptables -w -C "$CHAIN" -p udp -j REJECT || return 1

  expected_rules=12
  for target in ${PRIVATE_TCP_ALLOWLIST//,/ }; do
    allowed_cidr="${target%:*}"
    allowed_port="${target##*:}"
    [[ -n "$allowed_cidr" && "$allowed_cidr" != "$target" && "$allowed_cidr" != *:* ]] || return 1
    [[ "$allowed_port" =~ ^[0-9]+$ && "$allowed_port" -ge 1 && "$allowed_port" -le 65535 ]] || return 1
    [[ "$allowed_cidr" == */* ]] || allowed_cidr="$allowed_cidr/32"
    iptables -w -C "$CHAIN" -o "$iface" -d "$allowed_cidr" -p tcp --dport "$allowed_port" -j ACCEPT \
      || return 1
    expected_rules=$((expected_rules + 1))
  done
  for cidr in ${BLOCK_PRIVATE_CIDRS//,/ }; do
    [[ -n "$cidr" && "$cidr" != *:* ]] || continue
    iptables -w -C "$CHAIN" -d "$cidr" -j REJECT || return 1
    expected_rules=$((expected_rules + 1))
  done
  for cidr in 0.0.0.0/8 127.0.0.0/8 224.0.0.0/4 240.0.0.0/4; do
    iptables -w -C "$CHAIN" -d "$cidr" -j REJECT || return 1
    expected_rules=$((expected_rules + 1))
  done

  iptables -w -C "$CHAIN" -o "$iface" -p tcp -j ACCEPT || return 1
  iptables -w -C "$CHAIN" -j REJECT || return 1
  iptables -w -S "$CHAIN" | tail -1 | grep -q -- "^-A $CHAIN -j REJECT" || return 1
  actual_rules="$(iptables -w -S "$CHAIN" | grep -c "^-A $CHAIN ")"
  [[ "$actual_rules" -eq "$expected_rules" ]] || return 1
}

apply() {
  iptables -w -P OUTPUT DROP
  ip6tables -w -P OUTPUT DROP
  install_ipv6_block
  install_ipv4_guard
  if ! verify; then
    log "claude network guard verification failed; current fail-closed state follows"
    ip -4 route show >&2 || true
    ip -6 address show >&2 || true
    ip -6 route show >&2 || true
    iptables -w -S >&2 || true
    ip6tables -w -S >&2 || true
    return 1
  fi
}

main() {
  if [[ -z "${PROXY_IP:-}" || -z "${DIRECT_PROXY_PORT:-}" ]] && [[ -r "$GUARD_ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$GUARD_ENV_FILE"
  fi
  require_env PROXY_IP
  require_env DIRECT_PROXY_PORT
  require_env LOCKED_SUBNET
  require_env BLOCK_PRIVATE_CIDRS
  PRIVATE_TCP_ALLOWLIST="${PRIVATE_TCP_ALLOWLIST:-}"

  case "${1:-check}" in
    check)
      (
        flock -x 9
        verify
      ) 9>"$LOCK_FILE"
      ;;
    apply)
      (
        flock -x 9
        apply
      ) 9>"$LOCK_FILE"
      log "claude network guard active: default via $PROXY_IP, IPv6/UDP/127.0.0.11 blocked"
      ;;
    *)
      log "usage: claude-network-guard.sh [apply|check]"
      exit 2
      ;;
  esac
}

main "$@"
