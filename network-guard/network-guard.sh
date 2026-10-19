#!/usr/bin/env bash
set -Eeuo pipefail

CHAIN="CLAUDE_EGRESS_GUARD"
LOCK_FILE="/run/network-guard.lock"

log() {
  printf '%s\n' "$*" >&2
}

on_error() {
  local status=$?
  log "network guard failed at line $1: $2 (exit=$status)"
  exit "$status"
}

trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

require_env() {
  [[ -n "${!1:-}" ]] || { log "$1 is required"; exit 1; }
}

proxy_only_enabled() {
  case "${PROXY_ONLY:-${STRICT_EGRESS:-false}}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
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

  # Close egress before changing any route or rule. A failed re-apply therefore
  # degrades to no network instead of exposing Docker's original default route.
  iptables -w -P OUTPUT DROP
  iptables -w -P FORWARD DROP
  iptables -w -F OUTPUT
  iptables -w -F FORWARD

  iface="$(locked_iface)"
  [[ -n "$iface" ]] || { log "failed to detect locked interface"; return 1; }

  iptables -w -N "$CHAIN" 2>/dev/null || true
  iptables -w -F "$CHAIN"
  iptables -w -A "$CHAIN" -d 127.0.0.11/32 -p udp --dport 53 -j REJECT
  iptables -w -A "$CHAIN" -d 127.0.0.11/32 -p tcp --dport 53 -j REJECT
  iptables -w -A "$CHAIN" -o lo -j ACCEPT
  iptables -w -A "$CHAIN" -o "$iface" -d "$PROXY_IP/32" -j ACCEPT
  iptables -w -A "$CHAIN" -d "$LOCKED_SUBNET" -j REJECT

  for target in ${PRIVATE_TCP_ALLOWLIST//,/ }; do
    allowed_cidr="${target%:*}"
    allowed_port="${target##*:}"
    if [[ -z "$allowed_cidr" || "$allowed_cidr" == "$target" || "$allowed_cidr" == *:* \
      || ! "$allowed_port" =~ ^[0-9]+$ || "$allowed_port" -lt 1 || "$allowed_port" -gt 65535 ]]; then
      log "invalid PRIVATE_TCP_ALLOWLIST item: $target"
      return 1
    fi
    iptables -w -A "$CHAIN" -o "$iface" -d "$allowed_cidr" -p tcp --dport "$allowed_port" -j ACCEPT
  done

  if proxy_only_enabled; then
    for cidr in ${BLOCK_PRIVATE_CIDRS//,/ }; do
      [[ -n "$cidr" && "$cidr" != *:* ]] || continue
      iptables -w -A "$CHAIN" -d "$cidr" -j REJECT
    done
    for cidr in 0.0.0.0/8 127.0.0.0/8 224.0.0.0/4 240.0.0.0/4; do
      iptables -w -A "$CHAIN" -d "$cidr" -j REJECT
    done
  fi
  iptables -w -A "$CHAIN" -o "$iface" -j ACCEPT
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

  iptables -w -C "$CHAIN" -d 127.0.0.11/32 -p udp --dport 53 -j REJECT || return 1
  iptables -w -C "$CHAIN" -d 127.0.0.11/32 -p tcp --dport 53 -j REJECT || return 1
  iptables -w -C "$CHAIN" -o lo -j ACCEPT || return 1
  iptables -w -C "$CHAIN" -o "$iface" -d "$PROXY_IP/32" -j ACCEPT || return 1
  iptables -w -C "$CHAIN" -d "$LOCKED_SUBNET" -j REJECT || return 1

  expected_rules=7
  for target in ${PRIVATE_TCP_ALLOWLIST//,/ }; do
    allowed_cidr="${target%:*}"
    allowed_port="${target##*:}"
    [[ -n "$allowed_cidr" && "$allowed_cidr" != "$target" && "$allowed_cidr" != *:* ]] || return 1
    [[ "$allowed_port" =~ ^[0-9]+$ && "$allowed_port" -ge 1 && "$allowed_port" -le 65535 ]] || return 1
    iptables -w -C "$CHAIN" -o "$iface" -d "$allowed_cidr" -p tcp --dport "$allowed_port" -j ACCEPT \
      || return 1
    expected_rules=$((expected_rules + 1))
  done
  if proxy_only_enabled; then
    for cidr in ${BLOCK_PRIVATE_CIDRS//,/ }; do
      [[ -n "$cidr" && "$cidr" != *:* ]] || continue
      iptables -w -C "$CHAIN" -d "$cidr" -j REJECT || return 1
      expected_rules=$((expected_rules + 1))
    done
    for cidr in 0.0.0.0/8 127.0.0.0/8 224.0.0.0/4 240.0.0.0/4; do
      iptables -w -C "$CHAIN" -d "$cidr" -j REJECT || return 1
      expected_rules=$((expected_rules + 1))
    done
  fi
  iptables -w -C "$CHAIN" -o "$iface" -j ACCEPT || return 1
  iptables -w -C "$CHAIN" -j REJECT || return 1
  iptables -w -S "$CHAIN" | tail -1 | grep -q -- "^-A $CHAIN -j REJECT" || return 1
  actual_rules="$(iptables -w -S "$CHAIN" | grep -c "^-A $CHAIN ")"
  [[ "$actual_rules" -eq "$expected_rules" ]] || return 1
}

apply() {
  # Establish both drop policies before any operation that may fail.
  iptables -w -P OUTPUT DROP
  ip6tables -w -P OUTPUT DROP
  install_ipv6_block
  install_ipv4_guard
  if ! verify; then
    log "network guard verification failed; current fail-closed state follows"
    ip -4 route show >&2 || true
    ip -6 address show >&2 || true
    ip -6 route show >&2 || true
    iptables -w -S >&2 || true
    ip6tables -w -S >&2 || true
    return 1
  fi
}

locked_verify() {
  (
    flock -x 9
    verify
  ) 9>"$LOCK_FILE"
}

locked_apply() {
  (
    flock -x 9
    apply
  ) 9>"$LOCK_FILE"
}

main() {
  require_env PROXY_IP
  require_env LOCKED_SUBNET
  require_env BLOCK_PRIVATE_CIDRS
  PRIVATE_TCP_ALLOWLIST="${PRIVATE_TCP_ALLOWLIST:-}"

  case "${1:-run}" in
    check)
      locked_verify
      exit
      ;;
    apply)
      locked_apply
      log "network guard policy re-applied"
      exit
      ;;
    run) ;;
    *)
      log "usage: network-guard.sh [run|check|apply]"
      exit 2
      ;;
  esac

  locked_apply
  log "network guard active: default via $PROXY_IP, IPv6 disabled, proxy_only=${PROXY_ONLY:-${STRICT_EGRESS:-false}}"
  trap 'exit 0' TERM INT
  while sleep 2; do
    if ! locked_verify; then
      log "network guard drift detected; re-applying fail-closed policy"
      locked_apply
    fi
  done
}

main "$@"
