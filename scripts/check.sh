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

claude_exec() {
  docker compose exec -T claude /usr/local/bin/claude-exec "$@"
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
EXPECTED_EXIT_IP="$(required_env_value EXPECTED_EXIT_IP)"
CLAUDE_UID="$(required_env_value CLAUDE_UID)"
CLAUDE_GID="$(required_env_value CLAUDE_GID)"
CLAUDE_HOME="$(required_env_value CLAUDE_HOME)"
CLAUDE_UV_CACHE_DIR="$(required_env_value CLAUDE_UV_CACHE_DIR)"
EXIT_COUNTRY_DENYLIST_VALUE="$(env_value EXIT_COUNTRY_DENYLIST)"
EXIT_CHECK_URL_VALUE="$(env_value EXIT_CHECK_URL)"
EXIT_CHECK_URL_VALUE="${EXIT_CHECK_URL_VALUE:-https://www.cloudflare.com/cdn-cgi/trace}"

title "Claude Docker Check"

section "Repository & Configuration Hygiene"
leak_check_output="$(uv run scripts/account-env.py check-leaks 2>&1)" \
  && ok "repository secret & PII leak guard" "$leak_check_output" \
  || die "repository secret & PII leak guard" "$leak_check_output"

section "Containers & Namespace Isolation"
containers="$(docker compose ps -a --format 'table {{.Service}}\t{{.State}}\t{{.Status}}' 2>&1)" \
  || die "docker compose ps" "$containers"
ok "compose services visible (2-container stack)"
printf '%s\n' "$containers" | sed 's/^/    /'

proxy_container="$(docker compose ps -q proxy)"
[[ -n "$proxy_container" ]] || die "proxy healthy" "proxy container not found"
proxy_health="$(docker inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$proxy_container")"
[[ "$proxy_health" == "running/healthy" ]] \
  && ok "proxy healthy" "$proxy_health" \
  || die "proxy healthy" "$proxy_health"

claude_container="$(docker compose ps -q claude)"
[[ -n "$claude_container" ]] || die "claude healthy" "claude container not found"
claude_health="$(docker inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$claude_container")"
[[ "$claude_health" == "running/healthy" ]] \
  && ok "claude healthy" "$claude_health" \
  || die "claude healthy" "$claude_health"

run_check "claude network guard policy valid" \
  compose_exec -u 0 claude /usr/local/bin/claude-network-guard.sh check

proxy_netns="$(compose_exec proxy readlink /proc/self/ns/net)"
claude_netns="$(claude_exec readlink /proc/self/ns/net)"
proxy_pidns="$(compose_exec proxy readlink /proc/self/ns/pid)"
claude_pidns="$(claude_exec readlink /proc/self/ns/pid)"
proxy_mntns="$(compose_exec proxy readlink /proc/self/ns/mnt)"
claude_mntns="$(claude_exec readlink /proc/self/ns/mnt)"
if [[ -n "$proxy_netns" && -n "$claude_netns" && "$proxy_netns" != "$claude_netns" \
  && "$proxy_pidns" != "$claude_pidns" && "$proxy_mntns" != "$claude_mntns" ]]; then
  ok "proxy and claude namespaces isolated" "net=$proxy_netns/$claude_netns"
else
  die "proxy and claude namespaces isolated" "proxy=$proxy_netns claude=$claude_netns"
fi

proxy_caps="$(docker inspect -f 'drop={{json .HostConfig.CapDrop}} add={{json .HostConfig.CapAdd}} security={{json .HostConfig.SecurityOpt}}' "$proxy_container")"
if [[ "$proxy_caps" == *'drop=["ALL"]'* && "$proxy_caps" == *'no-new-privileges:true'* ]]; then
  ok "proxy least privilege" "$proxy_caps"
else
  die "proxy least privilege" "$proxy_caps"
fi

claude_cap_check="$(claude_exec bash -lc '
  set -euo pipefail
  cap_bnd_hex="$(awk "/^CapBnd:/ { print \$2 }" /proc/1/status)"
  exec_bnd_hex="$(sudo -n awk "/^CapBnd:/ { print \$2 }" /proc/self/status)"
  python3 - "$cap_bnd_hex" "$exec_bnd_hex" <<'"'"'PY'"'"'
import sys
for label, raw in (("pid1", sys.argv[1]), ("sudo", sys.argv[2])):
    val = int(raw, 16)
    # CAP_NET_ADMIN = 12, CAP_NET_RAW = 13
    if val & (1 << 12):
        raise SystemExit(f"{label} still has CAP_NET_ADMIN in CapBnd: {raw}")
    if val & (1 << 13):
        raise SystemExit(f"{label} still has CAP_NET_RAW in CapBnd: {raw}")
print(f"pid1_CapBnd={sys.argv[1]} sudo_CapBnd={sys.argv[2]}")
PY
  if sudo -n ip route del default >/dev/null 2>&1; then
    echo "sudo unexpectedly modified default route"
    exit 1
  fi
' 2>&1)" \
  && ok "NET_ADMIN/NET_RAW stripped from claude CapBnd (even under sudo)" "$claude_cap_check" \
  || die "NET_ADMIN/NET_RAW stripped from claude CapBnd (even under sudo)" "$claude_cap_check"

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
  docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{"\n"}}{{end}}' "$claude_container" \
    | awk 'NF'
)
[[ "${#locked_networks[@]}" -eq 1 ]] || die "isolated Docker network" "expected one network, found: ${locked_networks[*]:-none}"
network_policy="$(docker network inspect -f 'internal={{.Internal}} ipv6={{.EnableIPv6}} inhibit_ipv4={{index .Options "com.docker.network.bridge.inhibit_ipv4"}}' "${locked_networks[0]}")"
if [[ "$network_policy" == "internal=true ipv6=false inhibit_ipv4=true" ]]; then
  ok "isolated Docker network (host IP inhibited)" "${locked_networks[0]} $network_policy"
else
  die "isolated Docker network (host IP inhibited)" "${locked_networks[0]} $network_policy"
fi

egress_network_name="${locked_networks[0]%_locked}_egress"
egress_policy="$(docker network inspect -f 'ipv6={{.EnableIPv6}} containers={{len .Containers}}' "$egress_network_name")"
if [[ "$egress_policy" == "ipv6=false containers=1" ]]; then
  ok "dedicated per-account egress bridge (proxy only)" "$egress_network_name $egress_policy"
else
  die "dedicated per-account egress bridge (proxy only)" "$egress_network_name $egress_policy"
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

section "Proxy Gateway (Single Xray-core)"
run_check "xray config and process valid" \
  compose_exec proxy sh -lc 'xray run -test -config /etc/xray/config.json >/dev/null && pgrep -x xray >/dev/null && pgrep -x dnsmasq >/dev/null && ip link show tun0 >/dev/null'

upstreams=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -n "$line" ]] || continue
  upstreams+=("$line")
done < <(compose_exec proxy python3 - <<'PY'
import json

with open("/etc/xray/config.json", encoding="utf-8") as fh:
    config = json.load(fh)

seen = set()
for out in config.get("outbounds", []):
    tag = out.get("tag", "")
    proto = out.get("protocol", "")
    settings = out.get("settings") or {}
    if proto == "vless":
        vnext = settings.get("vnext") or []
        if vnext:
            server, port = vnext[0].get("address"), vnext[0].get("port")
            if server and (tag, server, port) not in seen:
                seen.add((tag, server, port))
                print(f"{tag}\t{server}\t{port}")
    elif proto in ("trojan", "shadowsocks"):
        servers = settings.get("servers") or []
        if servers:
            server, port = servers[0].get("address"), servers[0].get("port")
            if server and (tag, server, port) not in seen:
                seen.add((tag, server, port))
                print(f"{tag}\t{server}\t{port}")
PY
)
[[ "${#upstreams[@]}" -gt 0 ]] || die "proxy upstreams configured" "none found"
for upstream in "${upstreams[@]}"; do
  IFS=$'\t' read -r tag server port <<<"$upstream"
  route_output="$(compose_exec proxy sh -lc 'ip -4 route get "$1" mark 0xff | head -1' sh "$server" 2>&1)" \
    && ok "proxy marked route to $tag" "$server:$port -> $route_output" \
    || die "proxy marked route to $tag" "$route_output"
done

xray_route_summary="$(compose_exec proxy python3 - <<'PY'
import ipaddress
import json
import os

with open("/etc/xray/config.json", encoding="utf-8") as fh:
    config = json.load(fh)

inbounds = {item.get("tag"): item for item in config.get("inbounds", [])}
outbounds = {item.get("tag"): item for item in config.get("outbounds", [])}
for required_out in ("proxy", "proxy-upstream", "download", "download-upstream", "private-direct", "block"):
    if required_out not in outbounds:
        raise SystemExit(f"missing outbound: {required_out}")

for wrapper_tag, upstream_tag in (("proxy", "proxy-upstream"), ("download", "download-upstream")):
    wrapper = outbounds[wrapper_tag]
    sockopt = (wrapper.get("streamSettings") or {}).get("sockopt") or {}
    if sockopt.get("domainStrategy") != "UseIPv4":
        raise SystemExit(f"{wrapper_tag} must enforce sockopt.domainStrategy=UseIPv4")
    if sockopt.get("dialerProxy") != upstream_tag or sockopt.get("mark") != 255:
        raise SystemExit(f"{wrapper_tag} must chain via dialerProxy={upstream_tag} with mark=255")

if "tun-in" not in inbounds:
    raise SystemExit("missing tun-in inbound")
direct_in = inbounds.get("download-proxy-in")
if not direct_in or direct_in.get("listen") in {None, "", "0.0.0.0", "::", "::0"}:
    raise SystemExit("download-proxy-in must listen on a specific IPv4 address")
if (direct_in.get("settings") or {}).get("udp") is not False:
    raise SystemExit("download-proxy-in must disable UDP")

expected_private = set()
for item in os.environ.get("PRIVATE_TCP_ALLOWLIST", "").replace(",", " ").split():
    if not item:
        continue
    host, port = item.rsplit(":", 1)
    expected_private.add((str(ipaddress.ip_network(host, strict=False)), str(int(port))))

actual_private = set()
download_domains = 0
for rule in (config.get("routing") or {}).get("rules", []):
    out_tag = rule.get("outboundTag")
    if out_tag == "private-direct":
        ips = rule.get("ip") or []
        if len(ips) != 1 or rule.get("network") != "tcp":
            raise SystemExit(f"unexpected private-direct rule: {rule}")
        actual_private.add((ips[0], str(rule.get("port"))))
    elif out_tag == "download" and rule.get("domain"):
        download_domains += len(rule["domain"])
    elif out_tag == "block" and rule.get("domain"):
        raise SystemExit("domain-based block rule is prohibited")

if actual_private != expected_private:
    raise SystemExit(f"private allowlist mismatch: expected={sorted(expected_private)} actual={sorted(actual_private)}")
if download_domains == 0:
    raise SystemExit("missing download domain split rules")

print(
    f"download_domains={download_domains} "
    f"manual_proxy={direct_in.get('listen')}:{direct_in.get('port')} "
    f"private_allow={len(actual_private)} ipv4_pinned=UseIPv4+fragment"
)
PY
)" \
  && ok "xray split routing & IPv4 pinning" "$xray_route_summary" \
  || die "xray split routing & IPv4 pinning" "$xray_route_summary"

fail_closed_output="$(compose_exec proxy sh -lc '
  set -eu
  egress_if="$(ip -4 route show table main default | awk "NR == 1 { print \$5 }")"
  iptables -w -S INPUT | grep -qx -- "-P INPUT DROP"
  iptables -w -S FORWARD | grep -qx -- "-P FORWARD DROP"
  iptables -w -S OUTPUT | grep -qx -- "-P OUTPUT DROP"
  iptables -w -S OUTPUT | grep -q -- "-A OUTPUT -j PROXY_KILLSWITCH"
  ! iptables -w -S FORWARD | grep -q -- "-o $egress_if"
  iptables -w -S FORWARD | grep -q -- "-o tun0 -p tcp -j ACCEPT"
  rules="$(iptables -w -S PROXY_KILLSWITCH)"
  printf "%s\n" "$rules" | grep -qx -- "-A PROXY_KILLSWITCH -d 127.0.0.11/32 -j REJECT --reject-with icmp-port-unreachable"
  ! printf "%s\n" "$rules" | grep -q -- "--ctstate .*ESTABLISHED.* -j ACCEPT"
  printf "%s\n" "$rules" | tail -1 | grep -q -- "-A PROXY_KILLSWITCH -j REJECT"
  ! iptables -w -C INPUT -j CLAUDE_CLIENT_GUARD >/dev/null 2>&1
  ! iptables -w -C FORWARD -j CLAUDE_CLIENT_GUARD >/dev/null 2>&1
  python3 - <<PY
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
q = bytes.fromhex("abcd0100000100000000000006676f6f676c6503636f6d0000010001")
try:
    s.sendto(q, ("127.0.0.11", 53))
    s.recvfrom(512)
    raise SystemExit("127.0.0.11:53 unexpectedly reachable from proxy")
except (OSError, TimeoutError):
    pass
finally:
    s.close()
PY
  ip -4 rule show | grep -q "fwmark 0xff lookup main"
  ip -4 rule show | grep -q "fwmark 0xff unreachable"
  ip -4 rule show | grep -q "lookup 100"
  test "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" = 1
  test "$(sysctl -n net.ipv6.conf.default.disable_ipv6)" = 1
  test "$(sysctl -n net.ipv6.conf.lo.disable_ipv6)" = 1
  ! ip -6 address show | grep -q "inet6 "
  ip6tables -w -S INPUT | grep -qx -- "-P INPUT DROP"
  ip6tables -w -S OUTPUT | grep -qx -- "-P OUTPUT DROP"
  ip6tables -w -S FORWARD | grep -qx -- "-P FORWARD DROP"
  printf "ipv4=INPUT/FORWARD/OUTPUT-DROP mark=0xff ipv6=disabled/DROP docker_dns=blocked"
' 2>&1)" \
  && ok "fail-closed firewall & policy routing" "$fail_closed_output" \
  || die "fail-closed firewall & policy routing" "$fail_closed_output"

runtime_resolver="$(compose_exec proxy sh -lc 'cat /etc/resolv.conf' 2>&1)" \
  || die "proxy runtime DNS is tunnel-only" "$runtime_resolver"
if grep -qx "nameserver $PROXY_IP" <<<"$runtime_resolver" && ! grep -q '127\.0\.0\.11' <<<"$runtime_resolver"; then
  ok "proxy runtime DNS is tunnel-only" "nameserver=$PROXY_IP"
else
  die "proxy runtime DNS is tunnel-only" "$runtime_resolver"
fi

forced_direct_output="$(compose_exec proxy sh -lc '
  iface="$(ip -4 route show table main default | awk "NR == 1 { print \$5 }")"
  if curl -fsS --interface "$iface" --connect-timeout 3 --max-time 6 https://api.ipify.org >/dev/null 2>&1; then
    echo "direct connection unexpectedly succeeded on $iface"
    exit 1
  fi
  printf "direct connection rejected on %s" "$iface"
' 2>&1)" \
  && ok "proxy direct fallback blocked" "$forced_direct_output" \
  || die "proxy direct fallback blocked" "$forced_direct_output"

direct_proxy_trace="$(claude_exec bash -lc '
  curl -fsS --max-time 20 --proxy "http://$1:$2" "$3" \
    | awk -F= '\''$1 == "ip" { gsub(/[[:space:]]/, "", $2); print $2; exit }'\''
' bash "$PROXY_IP" "$DIRECT_PROXY_PORT" "$EXIT_CHECK_URL_VALUE" 2>&1)" \
  || die "manual download proxy port" "$direct_proxy_trace"
if [[ "$direct_proxy_trace" == "$EXPECTED_EXIT_IP" ]]; then
  ok "manual download proxy port (IPv4 pinned)" "$PROXY_IP:$DIRECT_PROXY_PORT -> $direct_proxy_trace"
else
  die "manual download proxy port (IPv4 pinned)" "expected=$EXPECTED_EXIT_IP actual=$direct_proxy_trace"
fi

section "Claude Network & Pinned Exit IP"
clean_env_check="$(claude_exec bash -lc '
  set -euo pipefail
  pattern="^(HTTP|HTTPS|ALL|NO)_PROXY=|^(http|https|all|no)_proxy=|^(PROXY_IP|DIRECT_PROXY_PORT|LOCKED_SUBNET|BLOCK_PRIVATE_CIDRS|PRIVATE_TCP_ALLOWLIST|CLAUDE_USER|CLAUDE_UID|CLAUDE_GID|DEBIAN_FRONTEND|PROXY_URI|DOWNLOAD_PROXY_URI|EXPECTED_EXIT_IP)="
  if env | grep -E "$pattern"; then
    exit 1
  fi
  if tr "\0" "\n" < /proc/1/environ | grep -E "$pattern"; then
    exit 1
  fi
  if [ -r /run/claude-guard.env ]; then
    echo "/run/claude-guard.env should not be readable by unprivileged user"
    exit 1
  fi
  printf "env & /proc/1/environ clean; /run/claude-guard.env root-only"
' 2>&1)" \
  && ok "no proxy or topology environment leaks" "$clean_env_check" \
  || die "no proxy or topology environment leaks" "$clean_env_check"

resolv_conf="$(claude_exec bash -lc 'cat /etc/resolv.conf' 2>&1)" \
  || die "DNS resolver pinned to proxy" "$resolv_conf"
resolver_nameservers="$(awk '$1 == "nameserver" { print $2 }' <<<"$resolv_conf")"
if [[ "$resolver_nameservers" != "$PROXY_IP" ]]; then
  die "DNS resolver pinned to proxy" "$resolv_conf"
fi
if grep -Eq '^(search|domain)[[:space:]]+' <<<"$resolv_conf"; then
  die "DNS search domain hidden" "$resolv_conf"
fi
ok "DNS resolver pinned to proxy (no search domain)" "nameserver=$PROXY_IP"

ipv6_state="$(claude_exec bash -lc '
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

if claude_exec bash -lc 'curl -6 -fsS --connect-timeout 2 --max-time 4 https://api64.ipify.org >/dev/null 2>&1'; then
  die "IPv6 egress blocked" "IPv6 request unexpectedly succeeded"
else
  ok "IPv6 egress blocked"
fi

dns_route="$(compose_exec proxy sh -lc '
  upstream="$(python3 -c '\''import json; print(json.load(open("/etc/xray/config.json"))["dns"]["servers"][0])'\'')"
  ip -4 route get "$upstream" ipproto udp dport 53 sport 53000 | head -1
' 2>&1)" || die "DNS upstream routed through tunnel" "$dns_route"
if [[ "$dns_route" == *" dev tun0 "* ]]; then
  ok "DNS upstream routed through tunnel" "$dns_route"
else
  die "DNS upstream routed through tunnel" "$dns_route"
fi

compose_exec proxy sh -lc '
  set -eu
  egress_if="$(ip -4 route show table main default | awk "NR == 1 { print \$5 }")"
  while iptables -w -C OUTPUT -j CLAUDE_DNS_LEAKCHECK 2>/dev/null; do
    iptables -w -D OUTPUT -j CLAUDE_DNS_LEAKCHECK
  done
  iptables -w -N CLAUDE_DNS_LEAKCHECK 2>/dev/null || true
  iptables -w -F CLAUDE_DNS_LEAKCHECK
  iptables -w -A CLAUDE_DNS_LEAKCHECK -o "$egress_if" -p udp --dport 53 -m comment --comment direct_dns
  iptables -w -A CLAUDE_DNS_LEAKCHECK -o "$egress_if" -p tcp --dport 53 -m comment --comment direct_dns
  iptables -w -A CLAUDE_DNS_LEAKCHECK -o tun0 -p udp --dport 53 -m comment --comment tun_dns
  iptables -w -A CLAUDE_DNS_LEAKCHECK -o tun0 -p tcp --dport 53 -m comment --comment tun_dns
  iptables -w -I OUTPUT 1 -j CLAUDE_DNS_LEAKCHECK
' >/dev/null 2>&1 || die "DNS packet leak counter" "failed to install temporary iptables counter"

claude_exec bash -lc '
  set +e
  for i in 1 2 3; do
    getent ahostsv4 "leakcheck-$i-$(date +%s%N).example.com" >/dev/null
  done
  true
' >/dev/null 2>&1 || true

dns_counter_output="$(compose_exec proxy sh -lc '
  set -eu
  out="$(iptables -w -L CLAUDE_DNS_LEAKCHECK -n -v -x)"
  while iptables -w -C OUTPUT -j CLAUDE_DNS_LEAKCHECK 2>/dev/null; do
    iptables -w -D OUTPUT -j CLAUDE_DNS_LEAKCHECK
  done
  iptables -w -F CLAUDE_DNS_LEAKCHECK 2>/dev/null || true
  iptables -w -X CLAUDE_DNS_LEAKCHECK 2>/dev/null || true
  printf "%s\n" "$out"
' 2>&1)" || {
  compose_exec proxy sh -lc '
    while iptables -w -C OUTPUT -j CLAUDE_DNS_LEAKCHECK 2>/dev/null; do iptables -w -D OUTPUT -j CLAUDE_DNS_LEAKCHECK; done
    iptables -w -F CLAUDE_DNS_LEAKCHECK 2>/dev/null || true
    iptables -w -X CLAUDE_DNS_LEAKCHECK 2>/dev/null || true
  ' >/dev/null 2>&1 || true
  die "DNS packet leak counter" "$dns_counter_output"
}
direct_dns_packets="$(awk '/direct_dns/ { total += $1 } END { print total + 0 }' <<<"$dns_counter_output")"
tun_dns_packets="$(awk '/tun_dns/ { total += $1 } END { print total + 0 }' <<<"$dns_counter_output")"
if [[ "$direct_dns_packets" == "0" && "$tun_dns_packets" -gt 0 ]]; then
  ok "DNS packet leak counter" "egress_direct=$direct_dns_packets tun0=$tun_dns_packets"
else
  die "DNS packet leak counter" "egress_direct=$direct_dns_packets tun0=$tun_dns_packets"
fi

dns_line="$(claude_exec bash -lc 'getent ahostsv4 google.com | awk "NR == 1 { print \$1, \$3 }"' 2>&1)" \
  && ok "DNS resolution via proxy gateway" "$dns_line" \
  || die "DNS resolution via proxy gateway" "$dns_line"

trace_output="$(claude_exec bash -lc 'curl -fsS --connect-timeout 5 --max-time 15 "$1"' bash "$EXIT_CHECK_URL_VALUE" 2>&1)" \
  || die "dual-stack trace exit IP" "$trace_output"
trace_ip="$(awk -F= '$1 == "ip" { gsub(/[[:space:]]/, "", $2); print $2; exit }' <<<"$trace_output")"
trace_country="$(awk -F= '$1 == "loc" { gsub(/[^A-Za-z]/, "", $2); print toupper($2); exit }' <<<"$trace_output")"
if [[ "$trace_ip" == "$EXPECTED_EXIT_IP" ]]; then
  ok "dual-stack exit IP pinned to EXPECTED_EXIT_IP" "$trace_ip (loc=${trace_country:-unknown})"
else
  die "dual-stack exit IP pinned to EXPECTED_EXIT_IP" "expected=$EXPECTED_EXIT_IP actual=${trace_ip:-<empty>}"
fi

ipify_ip="$(claude_exec bash -lc 'curl -fsS --max-time 20 https://api.ipify.org' 2>&1)" \
  || die "IPv4 exit IP (ipify)" "$ipify_ip"
if [[ "$ipify_ip" == "$EXPECTED_EXIT_IP" ]]; then
  ok "IPv4 exit IP matches EXPECTED_EXIT_IP" "$ipify_ip"
else
  die "IPv4 exit IP matches EXPECTED_EXIT_IP" "expected=$EXPECTED_EXIT_IP actual=$ipify_ip"
fi

if [[ -n "${EXIT_COUNTRY_DENYLIST_VALUE//[[:space:],]/}" ]]; then
  [[ "$trace_country" =~ ^[A-Z]{2}$ ]] || die "exit country allowed" "invalid response: $trace_country"
  for blocked_country in ${EXIT_COUNTRY_DENYLIST_VALUE//,/ }; do
    blocked_country="${blocked_country^^}"
    [[ "$trace_country" != "$blocked_country" ]] \
      || die "exit country allowed" "denied country: $trace_country"
  done
  ok "exit country allowed" "$trace_country"
fi

if claude_exec bash -lc 'ip link show tun0 >/dev/null 2>&1'; then
  die "tun0 hidden from claude" "tun0 is visible"
else
  ok "tun0 hidden from claude"
fi

route_line="$(claude_exec bash -lc 'ip route get 1.1.1.1 | head -1' 2>&1)" \
  || die "default route via proxy gateway" "$route_line"
if claude_exec bash -lc 'ip route | grep -q "^default via $1"' bash "$PROXY_IP"; then
  ok "default route via proxy gateway" "$route_line"
else
  die "default route via proxy gateway" "$route_line"
fi

if claude_exec bash -lc 'curl -fsS --connect-timeout 3 --max-time 5 http://10.0.0.1 >/dev/null 2>&1'; then
  die "private network egress blocked" "10.0.0.1 was reachable"
else
  ok "private network egress blocked"
fi

bypass_probes="$(claude_exec python3 - "$PROXY_IP" <<'PY' 2>&1
import socket
import sys

proxy_ip = sys.argv[1]
dns_q = bytes.fromhex("abcd0100000100000000000006676f6f676c6503636f6d0000010001")

for label, host, port in [
    ("docker_dns_127.0.0.11", "127.0.0.11", 53),
    ("direct_dns_8.8.8.8", "8.8.8.8", 53),
    ("quic_udp_443", "1.1.1.1", 443),
]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    try:
        s.connect((host, port))
        s.send(dns_q)
        s.recv(512)
        raise SystemExit(f"{label} ({host}:{port}/udp) unexpectedly succeeded")
    except (OSError, TimeoutError):
        pass
    finally:
        s.close()

t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.settimeout(1.0)
try:
    t.connect((proxy_ip, 22))
    raise SystemExit(f"proxy port {proxy_ip}:22/tcp unexpectedly reachable")
except (OSError, TimeoutError):
    pass
finally:
    t.close()

print("127.0.0.11=blocked direct_dns=blocked quic_udp=blocked proxy_ports=locked")
PY
)" \
  && ok "Docker DNS, direct DNS, QUIC/UDP & proxy port scan blocked" "$bypass_probes" \
  || die "Docker DNS, direct DNS, QUIC/UDP & proxy port scan blocked" "$bypass_probes"

section "Claude Runtime"
user_line="$(claude_exec bash -lc '
  set -euo pipefail
  printf "uid=%s gid=%s user=%s home=%s pwd=%s" "$(id -u)" "$(id -g)" "$(id -un)" "$HOME" "$PWD"
  [ "$(id -u)" = "$1" ]
  [ "$(id -g)" = "$2" ]
  [ "$HOME" = "$3" ]
  getent passwd "$(id -un)" | awk -F: "{ print \$7; exit }" | grep -q "/usr/bin/zsh"
  command -v claude >/dev/null
  command -v sudo >/dev/null
  sudo -n true
  EXPECTED_UV_CACHE_DIR="$4" zsh -c "[[ \"\$UV_CACHE_DIR\" == \"\$EXPECTED_UV_CACHE_DIR\" ]]"
' bash "$CLAUDE_UID" "$CLAUDE_GID" "$CLAUDE_HOME" "$CLAUDE_UV_CACHE_DIR" 2>&1)" \
  && ok "user, HOME, zsh, claude binary, sudo" "$user_line" \
  || die "user, HOME, zsh, claude binary, sudo" "$user_line"

runtime_dirs_output="$(claude_exec bash -lc '
  set -euo pipefail
  uv_ver="$(uv --version)"
  for dir in "$HOME/workspace" "$TMPDIR" "$XDG_CACHE_HOME" "$NPM_CONFIG_CACHE" "$PIP_CACHE_DIR" "$UV_CACHE_DIR" "$UV_PYTHON_INSTALL_DIR"; do
    [ -d "$dir" ] || { echo "missing: $dir"; exit 1; }
    probe="$(mktemp "$dir/.claude-docker-check.XXXXXX")"
    rm -f "$probe"
  done
  printf "%s; workspace & cache dirs writable" "$uv_ver"
' 2>&1)" \
  && ok "uv and cache mounts writable" "$runtime_dirs_output" \
  || die "uv and cache mounts writable" "$runtime_dirs_output"

printf '\n%s✓ All checks passed%s\n' "$green" "$reset"
