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
  if [[ -v "$key" ]]; then
    printf '%s\n' "${!key}"
  fi
  return 0
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

title "Repair Claude Network Guard"

section "Services"
proxy_state="$(service_state proxy 2>/dev/null || true)"
[[ "$proxy_state" == "running" ]] || die "proxy running" "${proxy_state:-not found}"
proxy_health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$(docker compose ps -q proxy)")"
[[ "$proxy_health" == "healthy" ]] || die "proxy healthy" "$proxy_health"
ok "proxy healthy" "$proxy_health"

claude_state="$(service_state claude 2>/dev/null || true)"
[[ "$claude_state" == "running" ]] || die "claude running" "${claude_state:-not found}"
ok "claude running" "$claude_state"

section "Network Guard"
guard_state="$(service_state network-guard 2>/dev/null || true)"
[[ "$guard_state" == "running" ]] || die "network guard running" "${guard_state:-not found}; recreate the stack"
guard_container="$(docker compose ps -q network-guard)"
guard_health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$guard_container")"
ok "network guard running" "$guard_state (health=$guard_health)"

guard_output="$(docker compose exec -T network-guard /usr/local/bin/network-guard.sh apply 2>&1)" \
  && ok "network policy re-applied" "$guard_output" \
  || die "network policy re-applied" "$guard_output"

guard_check="$(docker compose exec -T network-guard /usr/local/bin/network-guard.sh check 2>&1)" \
  && ok "network policy valid" "$guard_check" \
  || die "network policy valid" "$guard_check"

for _ in $(seq 1 10); do
  guard_health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$guard_container")"
  [[ "$guard_health" == "healthy" ]] && break
  sleep 1
done
[[ "$guard_health" == "healthy" ]] || die "network guard healthy after repair" "$guard_health"
ok "network guard healthy after repair" "$guard_health"

section "Verification"
route_line="$(docker compose exec -T claude bash -lc 'ip route | awk "/^default / { print; exit }"' 2>&1)" \
  || die "default route present" "$route_line"
if [[ "$route_line" == default\ via\ "$PROXY_IP"\ * ]]; then
  ok "default route via proxy" "$route_line"
else
  die "default route via proxy" "$route_line"
fi

probe_output="$(docker compose exec -T claude bash -lc 'curl -fsS --connect-timeout 5 --max-time 15 https://api.ipify.org' 2>&1)" \
  && ok "claude egress works" "$probe_output" \
  || die "claude egress works" "$probe_output"

printf '\n%s✓ Network guard repair complete%s\n' "$green" "$reset"
