#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  green=$'\033[32m'
  red=$'\033[31m'
  blue=$'\033[34m'
  bold=$'\033[1m'
  dim=$'\033[2m'
  reset=$'\033[0m'
else
  green=""
  red=""
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

ok() {
  local label="$1"
  local detail="${2:-}"
  printf '  %s✓%s %s' "$green" "$reset" "$label"
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

title() {
  printf '%s%s%s\n' "$bold" "$*" "$reset"
}

section() {
  printf '\n%s%s%s\n' "$blue" "$*" "$reset"
}

service_state() {
  local service="$1"
  local container
  container="$(docker compose ps -q "$service")"
  [[ -n "$container" ]] || return 1
  docker inspect -f '{{.State.Status}}' "$container"
}

PROXY_IP="$(required_env_value PROXY_IP)"
EXPECTED_EXIT_IP="$(required_env_value EXPECTED_EXIT_IP)"
EXIT_CHECK_URL_VALUE="$(env_value EXIT_CHECK_URL)"
EXIT_CHECK_URL_VALUE="${EXIT_CHECK_URL_VALUE:-https://www.cloudflare.com/cdn-cgi/trace}"

title "Repair Claude Network Guard"

section "Services"
proxy_state="$(service_state proxy 2>/dev/null || true)"
[[ "$proxy_state" == "running" ]] || die "proxy running" "${proxy_state:-not found}"
proxy_health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$(docker compose ps -q proxy)")"
[[ "$proxy_health" == "healthy" ]] || die "proxy healthy" "$proxy_health"
ok "proxy healthy" "$proxy_health"

claude_state="$(service_state claude 2>/dev/null || true)"
[[ "$claude_state" == "running" ]] || die "claude running" "${claude_state:-not found}"
claude_container="$(docker compose ps -q claude)"
ok "claude running" "$claude_state"

section "Re-applying Claude Network Guard"
guard_output="$(docker compose exec -T -u 0 claude /usr/local/bin/claude-network-guard.sh apply 2>&1)" \
  && ok "network policy re-applied" "$guard_output" \
  || die "network policy re-applied" "$guard_output"

guard_check="$(docker compose exec -T -u 0 claude /usr/local/bin/claude-network-guard.sh check 2>&1)" \
  && ok "network policy valid" "$guard_check" \
  || die "network policy valid" "$guard_check"

for _ in $(seq 1 10); do
  claude_health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$claude_container")"
  [[ "$claude_health" == "healthy" ]] && break
  sleep 1
done
[[ "$claude_health" == "healthy" ]] || die "claude healthy after repair" "$claude_health"
ok "claude healthy after repair" "$claude_health"

section "Verification"
route_line="$(docker compose exec -T claude /usr/local/bin/claude-exec bash -lc 'ip route | awk "/^default / { print; exit }"' 2>&1)" \
  || die "default route present" "$route_line"
if [[ "$route_line" == default\ via\ "$PROXY_IP"\ * ]]; then
  ok "default route via proxy" "$route_line"
else
  die "default route via proxy" "$route_line"
fi

trace_ip="$(docker compose exec -T claude /usr/local/bin/claude-exec bash -lc '
  curl -fsS --connect-timeout 5 --max-time 15 "$1" \
    | awk -F= '\''$1 == "ip" { gsub(/[[:space:]]/, "", $2); print $2; exit }'\''
' bash "$EXIT_CHECK_URL_VALUE" 2>&1)" \
  || die "claude egress works" "$trace_ip"
if [[ "$trace_ip" == "$EXPECTED_EXIT_IP" ]]; then
  ok "claude egress pinned to EXPECTED_EXIT_IP" "$trace_ip"
else
  die "claude egress pinned to EXPECTED_EXIT_IP" "expected=$EXPECTED_EXIT_IP actual=$trace_ip"
fi

printf '\n%s✓ Network guard repair complete%s\n' "$green" "$reset"
