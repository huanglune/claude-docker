#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  green=$'\033[32m'
  red=$'\033[31m'
  yellow=$'\033[33m'
  blue=$'\033[34m'
  bold=$'\033[1m'
  dim=$'\033[2m'
  reset=$'\033[0m'
else
  green=""
  red=""
  yellow=""
  blue=""
  bold=""
  dim=""
  reset=""
fi

env_value() {
  local key="$1"
  [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 0
  printenv "$key" || true
}

compose_exec() {
  docker compose exec -T "$@"
}

title() {
  printf '%s%s%s\n' "$bold" "$*" "$reset"
}

section() {
  printf '\n%s%s%s\n' "$blue" "$*" "$reset"
}

ok() {
  local label="$1"
  local detail="${2:-}"
  printf '  %s✓%s %s' "$green" "$reset" "$label"
  [[ -n "$detail" ]] && printf ' %s%s%s' "$dim" "$detail" "$reset"
  printf '\n'
}

warn() {
  local label="$1"
  local detail="${2:-}"
  printf '  %s!%s %s' "$yellow" "$reset" "$label"
  [[ -n "$detail" ]] && printf ' %s%s%s' "$dim" "$detail" "$reset"
  printf '\n'
}

die() {
  local label="$1"
  local detail="${2:-}"
  printf '  %s✗%s %s' "$red" "$reset" "$label" >&2
  [[ -n "$detail" ]] && printf ' %s%s%s' "$dim" "$detail" "$reset" >&2
  printf '\n' >&2
  exit 1
}

required_env_value() {
  local key="$1"
  local value
  value="$(env_value "$key")"
  [[ -n "$value" ]] || die "TOML environment" "missing: $key; run through account-env.py"
  printf '%s' "$value"
}

run_check() {
  local label="$1"
  shift

  local output
  if output="$("$@" 2>&1)"; then
    ok "$label" "$output"
  else
    die "$label" "$output"
  fi
}

PROXY_IP="$(required_env_value PROXY_IP)"
DIRECT_PROXY_PORT="$(required_env_value DIRECT_PROXY_PORT)"
CLAUDE_UID="$(required_env_value CLAUDE_UID)"
CLAUDE_GID="$(required_env_value CLAUDE_GID)"
CLAUDE_HOME="$(required_env_value CLAUDE_HOME)"
CLAUDE_UV_CACHE_DIR="$(required_env_value CLAUDE_UV_CACHE_DIR)"
PROXY_ONLY_VALUE="$(env_value PROXY_ONLY)"
if [[ -z "$PROXY_ONLY_VALUE" ]]; then
  PROXY_ONLY_VALUE="$(env_value STRICT_EGRESS)"
fi
PROXY_ONLY_VALUE="${PROXY_ONLY_VALUE:-false}"
EXIT_COUNTRY_DENYLIST_VALUE="$(env_value EXIT_COUNTRY_DENYLIST)"
EXIT_COUNTRY_CHECK_URL_VALUE="$(env_value EXIT_COUNTRY_CHECK_URL)"
EXIT_COUNTRY_CHECK_URL_VALUE="${EXIT_COUNTRY_CHECK_URL_VALUE:-https://www.cloudflare.com/cdn-cgi/trace}"

title "Claude Docker Check"

section "Containers"
containers="$(docker compose ps -a --format 'table {{.Service}}\t{{.State}}\t{{.Status}}' 2>&1)" \
  || die "docker compose ps" "$containers"
ok "compose services visible"
printf '%s\n' "$containers" | sed 's/^/    /'

guard_container="$(docker compose ps -a -q network-guard)"
[[ -n "$guard_container" ]] || die "network guard healthy" "network-guard container not found"
guard_state="$(docker inspect -f '{{.State.Status}}' "$guard_container")"
guard_health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$guard_container")"
if [[ "$guard_state" == "running" && "$guard_health" == "healthy" ]]; then
  ok "network guard healthy" "$guard_state/$guard_health"
else
  die "network guard healthy" "$guard_state/$guard_health"
fi

run_check "network guard policy valid" \
  compose_exec network-guard /usr/local/bin/network-guard.sh check

claude_container="$(docker compose ps -q claude)"
[[ -n "$claude_container" ]] || die "shared network namespace" "claude container not found"
guard_netns="$(compose_exec network-guard readlink /proc/self/ns/net)"
claude_netns="$(compose_exec claude readlink /proc/self/ns/net)"
proxy_netns="$(compose_exec proxy readlink /proc/self/ns/net)"
if [[ -n "$guard_netns" && "$guard_netns" == "$claude_netns" ]]; then
  ok "claude shares only guard network namespace" "$guard_netns"
else
  die "claude shares only guard network namespace" "network-guard=$guard_netns claude=$claude_netns"
fi
if [[ -n "$proxy_netns" && "$proxy_netns" != "$claude_netns" ]]; then
  ok "proxy network namespace isolated" "proxy=$proxy_netns claude=$claude_netns"
else
  die "proxy network namespace isolated" "proxy=$proxy_netns claude=$claude_netns"
fi

guard_pidns="$(compose_exec network-guard readlink /proc/self/ns/pid)"
claude_pidns="$(compose_exec claude readlink /proc/self/ns/pid)"
guard_mntns="$(compose_exec network-guard readlink /proc/self/ns/mnt)"
claude_mntns="$(compose_exec claude readlink /proc/self/ns/mnt)"
if [[ -n "$guard_pidns" && "$guard_pidns" != "$claude_pidns" \
  && -n "$guard_mntns" && "$guard_mntns" != "$claude_mntns" ]]; then
  ok "guard process and filesystem isolated" "pid=$guard_pidns/$claude_pidns mnt=$guard_mntns/$claude_mntns"
else
  die "guard process and filesystem isolated" "pid=$guard_pidns/$claude_pidns mnt=$guard_mntns/$claude_mntns"
fi

claude_cap_drop="$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$claude_container")"
if grep -q 'NET_ADMIN' <<<"$claude_cap_drop" && grep -q 'NET_RAW' <<<"$claude_cap_drop"; then
  ok "network capabilities removed from claude" "$claude_cap_drop"
else
  die "network capabilities removed from claude" "$claude_cap_drop"
fi

guard_caps="$(docker inspect -f 'drop={{json .HostConfig.CapDrop}} add={{json .HostConfig.CapAdd}} readonly={{.HostConfig.ReadonlyRootfs}} security={{json .HostConfig.SecurityOpt}}' "$guard_container")"
if [[ "$guard_caps" == *'drop=["ALL"]'* && "$guard_caps" == *'add=["CAP_NET_ADMIN"]'* \
  && "$guard_caps" == *'readonly=true'* && "$guard_caps" == *'no-new-privileges:true'* ]]; then
  ok "network guard least privilege" "$guard_caps"
else
  die "network guard least privilege" "$guard_caps"
fi

resolver_mount="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/resolv.conf"}}type={{.Type}} rw={{.RW}} source={{.Source}}{{end}}{{end}}' "$claude_container")"
if [[ "$resolver_mount" == type=bind\ rw=false\ source=* ]]; then
  ok "resolver mounted read-only" "$resolver_mount"
else
  die "resolver mounted read-only" "${resolver_mount:-mount not found}"
fi

locked_networks=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -n "$line" ]] || continue
  locked_networks+=("$line")
done < <(
  docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{"\n"}}{{end}}' "$guard_container" \
    | awk 'NF'
)
[[ "${#locked_networks[@]}" -eq 1 ]] || die "isolated Docker network" "expected one network, found: ${locked_networks[*]:-none}"
network_policy="$(docker network inspect -f 'internal={{.Internal}} ipv6={{.EnableIPv6}}' "${locked_networks[0]}")"
if [[ "$network_policy" == "internal=true ipv6=false" ]]; then
  ok "isolated Docker network" "${locked_networks[0]} $network_policy"
else
  die "isolated Docker network" "${locked_networks[0]} $network_policy"
fi

published_ports=""
while IFS= read -r container_id || [[ -n "$container_id" ]]; do
  [[ -n "$container_id" ]] || continue
  bindings="$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$container_id")"
  if [[ "$bindings" != "null" && "$bindings" != "{}" && "$bindings" != "map[]" ]]; then
    published_ports+="$(docker inspect -f '{{.Name}}' "$container_id") ${bindings} "
  fi
done < <(docker compose ps -aq)
if [[ -z "$published_ports" ]]; then
  ok "no host port publish"
else
  die "no host port publish" "$published_ports"
fi

section "Proxy Gateway"
run_check "sing-box config is valid" \
  compose_exec proxy sing-box check -c /etc/sing-box/config.json

upstreams=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -n "$line" ]] || continue
  upstreams+=("$line")
done < <(compose_exec proxy python3 - <<'PY'
import json

with open("/etc/sing-box/config.json", encoding="utf-8") as fh:
    config = json.load(fh)
for outbound in config["outbounds"]:
    server = outbound.get("server")
    if server:
        print(f'{outbound.get("tag", outbound.get("type"))}\t{server}\t{outbound.get("server_port", "")}')
PY
)
[[ "${#upstreams[@]}" -gt 0 ]] || die "proxy upstreams configured" "none found"
for upstream in "${upstreams[@]}"; do
  IFS=$'\t' read -r tag server port <<<"$upstream"
  route_output="$(compose_exec proxy sh -lc '
    server="$1"
    if ip route get "$server" 2>/dev/null; then
      exit 0
    fi
    ip="$(getent ahostsv4 "$server" | awk "NR == 1 { print \$1 }")"
    [ -n "$ip" ] && ip route get "$ip"
  ' sh "$server" 2>&1)" \
    && ok "proxy route to $tag upstream" "$server:$port -> $(printf '%s' "$route_output" | head -1)" \
    || die "proxy route to $tag upstream" "$route_output"
done

split_route_output="$(compose_exec proxy python3 - <<'PY'
import ipaddress
import json
import os

with open("/etc/sing-box/config.json", encoding="utf-8") as fh:
    config = json.load(fh)

tags = {outbound.get("tag") for outbound in config["outbounds"]}
inbounds = {inbound.get("tag"): inbound for inbound in config["inbounds"]}
download_suffixes = []
manual_download_rule = False
infrastructure_rules = []
for rule in config["route"]["rules"]:
    if rule.get("outbound") == "download":
        download_suffixes.extend(rule.get("domain_suffix", []))
    if rule.get("outbound") == "download" and "download-proxy-in" in rule.get("inbound", []):
        manual_download_rule = True
    if rule.get("outbound") == "infrastructure-direct":
        infrastructure_rules.append(rule)
    if rule.get("action") == "reject" and any(
        key in rule for key in ("domain", "domain_suffix", "domain_keyword", "domain_regex")
    ):
        raise SystemExit("domain-based reject rule would prevent arbitrary public websites")

if "proxy" not in tags:
    raise SystemExit("missing proxy outbound")
if "download" not in tags:
    raise SystemExit("missing download outbound")
if not download_suffixes:
    raise SystemExit("missing download domain_suffix rule")
direct_in = inbounds.get("download-proxy-in")
if not direct_in:
    raise SystemExit("missing download-proxy-in inbound")
if direct_in.get("listen") in {None, "", "0.0.0.0", "::", "::0"}:
    raise SystemExit("download proxy listen must be a specific address")
if not manual_download_rule:
    raise SystemExit("missing download-proxy-in route")
if config["route"].get("final") != "proxy":
    raise SystemExit("route final must be proxy")

proxy_only = os.environ.get("PROXY_ONLY", os.environ.get("STRICT_EGRESS", "false")).lower() in {
    "1", "true", "yes", "on"
}
direct_outbounds = [outbound for outbound in config["outbounds"] if outbound.get("type") == "direct"]
if proxy_only:
    if [outbound.get("tag") for outbound in direct_outbounds] != ["infrastructure-direct"]:
        raise SystemExit("proxy-only mode permits only the infrastructure-direct outbound")
    expected_direct_cidrs = {str(ipaddress.ip_network(os.environ["LOCKED_SUBNET"], strict=False))}
    expected_private_targets = set()
    for item in os.environ.get("PRIVATE_TCP_ALLOWLIST", "").replace(",", " ").split():
        host, port = item.rsplit(":", 1)
        expected_private_targets.add((str(ipaddress.ip_network(host, strict=False)), int(port)))
    for outbound in config["outbounds"]:
        server = outbound.get("server")
        if not server:
            continue
        ip = ipaddress.ip_address(server)
        expected_direct_cidrs.add(f"{ip}/32")
    actual_direct_cidrs = set()
    actual_private_targets = set()
    for rule in infrastructure_rules:
        keys = set(rule)
        if keys == {"ip_cidr", "outbound"}:
            actual_direct_cidrs.update(
                str(ipaddress.ip_network(cidr, strict=False)) for cidr in rule.get("ip_cidr", [])
            )
        elif keys == {"ip_cidr", "port", "outbound"}:
            actual_private_targets.update(
                (str(ipaddress.ip_network(cidr, strict=False)), int(port))
                for cidr in rule.get("ip_cidr", [])
                for port in rule.get("port", [])
            )
        else:
            raise SystemExit(f"unexpected infrastructure-direct rule: {rule}")
    if actual_direct_cidrs != expected_direct_cidrs:
        raise SystemExit(
            f"infrastructure-direct scope mismatch: expected={sorted(expected_direct_cidrs)} "
            f"actual={sorted(actual_direct_cidrs)}"
        )
    if actual_private_targets != expected_private_targets:
        raise SystemExit(
            f"private direct scope mismatch: expected={sorted(expected_private_targets)} "
            f"actual={sorted(actual_private_targets)}"
        )
else:
    expected_private_targets = set()

print(
    f'download domains={len(download_suffixes)} '
    f'manual_download_proxy={direct_in.get("listen")}:{direct_in.get("listen_port")} '
    f'infrastructure_direct_cidrs={len(infrastructure_rules[0].get("ip_cidr", [])) if infrastructure_rules else 0} '
    f'private_direct_targets={len(expected_private_targets)} '
    f'final=proxy'
)
PY
)" \
  && ok "proxy-only routing enabled" "$split_route_output" \
  || die "proxy-only routing enabled" "$split_route_output"

fail_closed_output="$(compose_exec proxy sh -lc '
  set -eu
  iptables -S FORWARD | grep -qx -- "-P FORWARD DROP"
  iptables -S OUTPUT | grep -qx -- "-P OUTPUT DROP"
  iptables -S OUTPUT | grep -q -- "-A OUTPUT -j PROXY_KILLSWITCH"
  rules="$(iptables -S PROXY_KILLSWITCH)"
  printf "%s\n" "$rules" | grep -q -- "-d 127.0.0.11/32 -p udp .*--dport 53 -j REJECT"
  printf "%s\n" "$rules" | grep -q -- "-d 127.0.0.11/32 -p tcp .*--dport 53 -j REJECT"
  ! printf "%s\n" "$rules" | grep -q -- "--ctstate .*ESTABLISHED.* -j ACCEPT"
  ! printf "%s\n" "$rules" | grep -q -- "-j RETURN"
  printf "%s\n" "$rules" | tail -1 | grep -q -- "-A PROXY_KILLSWITCH -j REJECT"
  ! iptables -C INPUT -j CLAUDE_CLIENT_GUARD >/dev/null 2>&1
  test "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" = 1
  test "$(sysctl -n net.ipv6.conf.default.disable_ipv6)" = 1
  test "$(sysctl -n net.ipv6.conf.lo.disable_ipv6)" = 1
  ! ip -6 address show | grep -q "inet6 "
  ip6tables -S INPUT | grep -qx -- "-P INPUT DROP"
  ip6tables -S OUTPUT | grep -qx -- "-P OUTPUT DROP"
  ip6tables -S FORWARD | grep -qx -- "-P FORWARD DROP"
  case "${PROXY_ONLY:-${STRICT_EGRESS:-false}}" in
    1|true|TRUE|yes|YES|on|ON)
      ! iptables -S FORWARD | grep -q -- "--ctstate .*ESTABLISHED.* -j ACCEPT"
      ;;
  esac
  private_tcp_allowlist="$(printf "%s" "${PRIVATE_TCP_ALLOWLIST:-}" | tr "," " ")"
  for target in $private_tcp_allowlist; do
    cidr="${target%:*}"
    port="${target##*:}"
    case "$cidr" in
      */*) ;;
      *) cidr="$cidr/32" ;;
    esac
    matching_rules="$(printf "%s\n" "$rules" \
      | grep -F -- "-d $cidr " \
      | grep -F -- "-p tcp " \
      | grep -F -- "--dport $port " \
      | grep -F -- "-j ACCEPT")"
    test "$(printf "%s\n" "$matching_rules" | grep -c .)" = 1
    iptables -C FORWARD -p tcp -d "$cidr" --dport "$port" -j ACCEPT
  done
  printf "ipv4=DROP/REJECT ipv6=disabled/DROP docker_dns=blocked client_guard=released"
' 2>&1)" \
  && ok "fail-closed firewall policy" "$fail_closed_output" \
  || die "fail-closed firewall policy" "$fail_closed_output"

runtime_resolver="$(compose_exec proxy sh -lc 'cat /etc/resolv.conf' 2>&1)" \
  || die "proxy runtime DNS is tunnel-only" "$runtime_resolver"
if grep -qx "nameserver $PROXY_IP" <<<"$runtime_resolver" && ! grep -q '127\.0\.0\.11' <<<"$runtime_resolver"; then
  ok "proxy runtime DNS is tunnel-only" "nameserver=$PROXY_IP"
else
  die "proxy runtime DNS is tunnel-only" "$runtime_resolver"
fi

forced_direct_output="$(compose_exec proxy sh -lc '
  iface="$(ip route show default | awk "NR == 1 { print \$5 }")"
  if curl -fsS --interface "$iface" --connect-timeout 3 --max-time 6 https://api.ipify.org >/dev/null 2>&1; then
    echo "direct connection unexpectedly succeeded on $iface"
    exit 1
  fi
  printf "direct connection rejected on %s" "$iface"
' 2>&1)" \
  && ok "proxy direct fallback blocked" "$forced_direct_output" \
  || die "proxy direct fallback blocked" "$forced_direct_output"

proxy_only_runtime="$(compose_exec proxy sh -lc 'printf "%s" "${PROXY_ONLY:-${STRICT_EGRESS:-false}}"' 2>&1)" \
  || die "proxy-only mode" "$proxy_only_runtime"
if [[ "$proxy_only_runtime" == "$PROXY_ONLY_VALUE" ]]; then
  ok "proxy-only mode" "$proxy_only_runtime"
else
  die "proxy-only mode" "expected=$PROXY_ONLY_VALUE actual=$proxy_only_runtime"
fi

direct_proxy_ip="$(compose_exec claude bash -lc '
  curl -fsS --max-time 20 --proxy "http://$1:$2" https://api.ipify.org
' bash "$PROXY_IP" "$DIRECT_PROXY_PORT" 2>&1)" \
  && ok "manual download proxy port" "$PROXY_IP:$DIRECT_PROXY_PORT -> $direct_proxy_ip" \
  || die "manual download proxy port" "$direct_proxy_ip"

section "Claude Network"
if proxy_env="$(compose_exec claude bash -lc 'env | grep -Ei "^(HTTP|HTTPS|ALL|NO)_PROXY=|^(http|https|all|no)_proxy="' 2>&1)"; then
  die "no proxy environment variables" "$proxy_env"
else
  ok "no proxy environment variables"
fi

resolv_conf="$(compose_exec claude bash -lc 'cat /etc/resolv.conf' 2>&1)" \
  || die "DNS search domain hidden" "$resolv_conf"
resolver_nameservers=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -n "$line" ]] || continue
  resolver_nameservers+=("$line")
done < <(awk '$1 == "nameserver" { print $2 }' <<<"$resolv_conf")
if [[ "${#resolver_nameservers[@]}" -ne 1 || "${resolver_nameservers[0]:-}" != "$PROXY_IP" ]]; then
  die "DNS resolver pinned to proxy" "$resolv_conf"
fi
ok "DNS resolver pinned to proxy" "nameserver=$PROXY_IP"
if grep -Eq '^(search|domain)[[:space:]]+' <<<"$resolv_conf"; then
  die "DNS search domain hidden" "$(printf '%s\n' "$resolv_conf" | grep -E '^(search|domain)[[:space:]]+')"
fi
ok "DNS search domain hidden"

ipv6_state="$(compose_exec network-guard sh -lc '
  set -eu
  ! ip -6 address show | grep -q "inet6 "
  ! ip -6 route show | grep -q .
  test "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" = 1
  test "$(sysctl -n net.ipv6.conf.default.disable_ipv6)" = 1
  test "$(sysctl -n net.ipv6.conf.lo.disable_ipv6)" = 1
  printf "addresses=none routes=none sysctl=all/default/lo:1"
' 2>&1)" \
  && ok "IPv6 unavailable to claude" "$ipv6_state" \
  || die "IPv6 unavailable to claude" "$ipv6_state"

if compose_exec claude bash -lc 'curl -6 -fsS --connect-timeout 2 --max-time 4 https://api64.ipify.org >/dev/null 2>&1'; then
  die "IPv6 egress blocked" "IPv6 request unexpectedly succeeded"
else
  ok "IPv6 egress blocked"
fi

dns_route="$(compose_exec proxy sh -lc '
  set -e
  upstream="$(python3 - <<'"'"'PY'"'"'
import json
with open("/etc/sing-box/config.json", encoding="utf-8") as fh:
    config = json.load(fh)
print(config["dns"]["servers"][0]["address"])
PY
)"
  ip route get "$upstream" ipproto udp dport 53 sport 53000 | head -1
' 2>&1)" \
  || die "DNS upstream routed through tunnel" "$dns_route"
if [[ "$dns_route" == *" dev tun0 "* ]]; then
  ok "DNS upstream routed through tunnel" "$dns_route"
else
  die "DNS upstream routed through tunnel" "$dns_route"
fi

compose_exec proxy sh -lc '
  nft delete table inet leakcheck 2>/dev/null || true
  nft add table inet leakcheck
  nft "add chain inet leakcheck output { type filter hook output priority 0; policy accept; }"
  nft add rule inet leakcheck output oifname eth0 udp dport 53 counter comment direct_udp53
  nft add rule inet leakcheck output oifname eth0 tcp dport 53 counter comment direct_tcp53
  nft add rule inet leakcheck output oifname tun0 udp dport 53 counter comment tun_udp53
  nft add rule inet leakcheck output oifname tun0 tcp dport 53 counter comment tun_tcp53
' >/dev/null 2>&1 || die "DNS packet leak counter" "failed to install temporary nft counter"
compose_exec claude bash -lc '
  set +e
  for i in 1 2 3; do
    getent ahostsv4 "leakcheck-$i-$(date +%s%N).example.com" >/dev/null
  done
  true
' >/dev/null 2>&1 || true
dns_counter_output="$(compose_exec proxy sh -lc '
  nft list table inet leakcheck
  nft delete table inet leakcheck
' 2>&1)" || {
  compose_exec proxy sh -lc 'nft delete table inet leakcheck 2>/dev/null || true' >/dev/null 2>&1 || true
  die "DNS packet leak counter" "$dns_counter_output"
}
direct_dns_packets="$(printf '%s\n' "$dns_counter_output" | awk '/direct_(udp|tcp)53/ { for (i = 1; i <= NF; i++) if ($i == "packets") total += $(i + 1) } END { print total + 0 }')"
tun_dns_packets="$(printf '%s\n' "$dns_counter_output" | awk '/tun_(udp|tcp)53/ { for (i = 1; i <= NF; i++) if ($i == "packets") total += $(i + 1) } END { print total + 0 }')"
if [[ "$direct_dns_packets" == "0" && "$tun_dns_packets" -gt 0 ]]; then
  ok "DNS packet leak counter" "eth0_direct=$direct_dns_packets tun=$tun_dns_packets"
else
  die "DNS packet leak counter" "eth0_direct=$direct_dns_packets tun=$tun_dns_packets"
fi

dns_line="$(compose_exec claude bash -lc 'getent ahostsv4 google.com | awk "NR == 1 { print \$1, \$3 }"' 2>&1)" \
  && ok "DNS via proxy gateway" "$dns_line" \
  || die "DNS via proxy gateway" "$dns_line"

exit_ip="$(compose_exec claude bash -lc 'curl -fsS --max-time 20 https://api.ipify.org' 2>&1)" \
  && ok "transparent exit IP" "$exit_ip" \
  || die "transparent exit IP" "$exit_ip"

if [[ -n "${EXIT_COUNTRY_DENYLIST_VALUE//[[:space:],]/}" ]]; then
  exit_country="$(compose_exec claude bash -lc '
    curl -fsS --connect-timeout 5 --max-time 15 "$1" \
      | awk -F= '\''$1 == "loc" { gsub(/[^A-Za-z]/, "", $2); print toupper($2); exit }'\''
  ' bash "$EXIT_COUNTRY_CHECK_URL_VALUE" 2>&1)" \
    || die "exit country allowed" "$exit_country"
  [[ "$exit_country" =~ ^[A-Z]{2}$ ]] || die "exit country allowed" "invalid response: $exit_country"
  for blocked_country in ${EXIT_COUNTRY_DENYLIST_VALUE//,/ }; do
    blocked_country="${blocked_country^^}"
    [[ "$exit_country" != "$blocked_country" ]] \
      || die "exit country allowed" "denied country: $exit_country"
  done
  ok "exit country allowed" "$exit_country"
else
  warn "exit country observation" "disabled (not required for proxy-only)"
fi

if compose_exec claude bash -lc 'ip link show tun0 >/dev/null 2>&1'; then
  die "tun0 hidden from claude" "tun0 is visible"
else
  ok "tun0 hidden from claude"
fi

route_line="$(compose_exec claude bash -lc 'ip route get 1.1.1.1 | head -1' 2>&1)" \
  || die "default route via proxy gateway" "$route_line"
if compose_exec claude bash -lc 'ip route | grep -q "^default via $1"' bash "$PROXY_IP"; then
  ok "default route via proxy gateway" "$route_line"
else
  die "default route via proxy gateway" "$route_line"
fi

if compose_exec claude bash -lc 'curl -fsS --connect-timeout 3 --max-time 5 http://10.0.0.1 >/dev/null 2>&1'; then
  die "private network egress blocked" "10.0.0.1 was reachable"
else
  ok "private network egress blocked"
fi

section "Claude Runtime"
user_line="$(compose_exec claude bash -lc '
  set -euo pipefail
  printf "uid=%s gid=%s user=%s home=%s pwd=%s" "$(id -u)" "$(id -g)" "$(id -un)" "$HOME" "$PWD"
  [ "$(id -u)" = "$1" ]
  [ "$(id -g)" = "$2" ]
  [ "$HOME" = "$3" ]
  getent passwd "$(id -un)" | awk -F: "{ print \$7; exit }" | grep -q "/usr/bin/zsh"
  command -v sudo >/dev/null
  sudo -n true
  EXPECTED_UV_CACHE_DIR="$4" zsh -c "[[ \"\$UV_CACHE_DIR\" == \"\$EXPECTED_UV_CACHE_DIR\" ]]"
' bash "$CLAUDE_UID" "$CLAUDE_GID" "$CLAUDE_HOME" "$CLAUDE_UV_CACHE_DIR" 2>&1)" \
  && ok "user, HOME, shell, sudo" "$user_line" \
  || die "user, HOME, shell, sudo" "$user_line"

mounts_line="$(compose_exec claude bash -lc '
  set -euo pipefail
  fast_ssd="$1"
  dirs=("$HOME/workspace" "$TMPDIR" "$XDG_CACHE_HOME")
  if [ -n "$fast_ssd" ]; then
    dirs+=("$HOME/md1")
  fi
  for dir in "${dirs[@]}"; do
    [ -d "$dir" ] || { echo "missing: $dir"; exit 1; }
  done
  workspace_test="$(mktemp "$HOME/workspace/.claude-docker-check.XXXXXX")"
  cache_test="$(mktemp "$TMPDIR/.claude-docker-check.XXXXXX")"
  rm -f "$workspace_test" "$cache_test"
  if [ -n "$fast_ssd" ]; then
    printf "%s and %s writable" "$HOME/workspace" "$HOME/md1"
  else
    printf "%s writable" "$HOME/workspace"
  fi
' bash "${HOST_FAST_SSD:-}" 2>&1)" \
  && ok "data mounts writable" "$mounts_line" \
  || die "data mounts writable" "$mounts_line"

uv_output="$(compose_exec claude bash -lc '
  set -euo pipefail
  uv --version
  for var in UV_CACHE_DIR UV_PYTHON_INSTALL_DIR HF_HOME HF_ENDPOINT TOKENIZERS_PARALLELISM; do
    [ -n "${!var:-}" ] || { echo "missing env: $var"; exit 1; }
    printf "%s=%s\n" "$var" "${!var}"
  done
  for dir in "$UV_CACHE_DIR" "$UV_PYTHON_INSTALL_DIR" "$HF_HOME"; do
    mkdir -p "$dir"
    test_file="$(mktemp "$dir/.claude-docker-check.XXXXXX")"
    rm -f "$test_file"
  done
  if [ -n "${HF_TOKEN:-}" ]; then
    echo "HF_TOKEN should not be exposed as an environment variable"
    exit 1
  fi
  [ -s "$HF_HOME/token" ] && echo "HF_TOKEN_FILE=present" || echo "HF_TOKEN_FILE=missing"
' 2>&1)" \
  || die "uv and dataset environment" "$uv_output"
uv_version="$(printf '%s\n' "$uv_output" | head -1)"
hf_token_state="$(printf '%s\n' "$uv_output" | awk -F= '$1 == "HF_TOKEN_FILE" { print $2 }')"
ok "uv and dataset environment" "$uv_version"
if [[ "$hf_token_state" == "present" ]]; then
  ok "HF token file" "\$HF_HOME/token"
else
  warn "HF token file" "not found"
fi

printf '\n%s✓ All checks passed%s\n' "$green" "$reset"
