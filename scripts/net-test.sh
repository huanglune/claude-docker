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

ROUNDS="${ROUNDS:-5}"
DOWNLOAD_ROUNDS="${DOWNLOAD_ROUNDS:-3}"
DOWNLOAD_BYTES="${DOWNLOAD_BYTES:-50000000}"
HTTP_URL="${HTTP_URL:-https://www.google.com/generate_204}"
DOWNLOAD_URL="${DOWNLOAD_URL:-https://speed.cloudflare.com/__down?bytes=${DOWNLOAD_BYTES}}"
DNS_HOST="${DNS_HOST:-google.com}"
CONNECT_URLS="${CONNECT_URLS:-https://www.google.com/generate_204 https://huggingface.co}"

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

ensure_running() {
  docker compose ps --format '{{.Service}} {{.State}}' | awk '$1 == "claude" && $2 == "running" { ok=1 } END { exit ok ? 0 : 1 }' \
    || die "claude container running" "run through: uv run scripts/account-env.py up <account>"
  ok "claude container running"
}

human_bps() {
  awk -v bps="$1" 'BEGIN {
    mbps = bps * 8 / 1000000
    mib = bps / 1048576
    printf "%.2f MiB/s  %.2f Mbps", mib, mbps
  }'
}

summarize_table() {
  local kind="$1"
  local file="$2"

  python3 - "$kind" "$file" <<'PY'
import csv
import statistics
import sys

kind = sys.argv[1]
path = sys.argv[2]

with open(path, encoding="utf-8") as fh:
    rows = list(csv.DictReader(fh, delimiter="\t"))

if not rows:
    print("no samples")
    sys.exit(1)

ok_rows = [row for row in rows if row.get("ok") == "1"]
fail_count = len(rows) - len(ok_rows)

def f(row, key):
    return float(row[key])

if kind == "latency":
    keys = ["dns_ms", "connect_ms", "ttfb_ms", "total_ms"]
    print(f"samples={len(rows)} ok={len(ok_rows)} failed={fail_count}")
    if ok_rows:
        for key in keys:
            values = [f(row, key) for row in ok_rows]
            print(
                f"{key}: avg={statistics.mean(values):.0f} "
                f"min={min(values):.0f} max={max(values):.0f}"
            )
elif kind == "download":
    speeds = [f(row, "speed_bps") for row in ok_rows]
    print(f"samples={len(rows)} ok={len(ok_rows)} failed={fail_count}")
    if speeds:
        mean = statistics.mean(speeds)
        print(
            f"speed: avg_Bps={mean:.0f} min_Bps={min(speeds):.0f} max_Bps={max(speeds):.0f} "
            f"avg_MiBps={mean / 1048576:.2f} avg_Mbps={mean * 8 / 1000000:.2f}"
        )
PY
}

title "Network Speed & Stability Test"
printf '%s\n' "Target container: claude"
printf '%s\n' "HTTP_URL=$HTTP_URL"
printf '%s\n' "DOWNLOAD_URL=$DOWNLOAD_URL"
printf '%s\n' "ROUNDS=$ROUNDS DOWNLOAD_ROUNDS=$DOWNLOAD_ROUNDS"

ensure_running

section "Exit IP"
exit_ip="$(compose_exec claude bash -lc 'curl -fsS --max-time 20 https://api.ipify.org' 2>&1)" \
  && ok "exit IP" "$exit_ip" \
  || die "exit IP" "$exit_ip"

section "DNS"
dns_output="$(compose_exec claude bash -lc '
  set -euo pipefail
  host="$1"
  start="$(date +%s%3N)"
  line="$(getent ahostsv4 "$host" | awk "NR == 1 { print \$1 }")"
  end="$(date +%s%3N)"
  [ -n "$line" ]
  printf "%s -> %s (%sms)" "$host" "$line" "$((end - start))"
' bash "$DNS_HOST" 2>&1)" \
  && ok "DNS resolution" "$dns_output" \
  || die "DNS resolution" "$dns_output"

section "Connectivity"
for url in $CONNECT_URLS; do
  output="$(compose_exec claude bash -lc '
    set -euo pipefail
    curl -LsS --connect-timeout 8 --max-time 20 -o /dev/null \
      -w "code=%{http_code} connect=%{time_connect}s ttfb=%{time_starttransfer}s total=%{time_total}s remote=%{remote_ip}" \
      "$1"
  ' bash "$url" 2>&1)" \
    && ok "$url" "$output" \
    || warn "$url" "$output"
done

section "Stability Samples"
latency_file="$(mktemp)"
download_file=""
trap 'rm -f "$latency_file" "$download_file"' EXIT
printf 'run\tok\tdns_ms\tconnect_ms\tttfb_ms\ttotal_ms\tcode\tremote_ip\n' > "$latency_file"

for run in $(seq 1 "$ROUNDS"); do
  line="$(compose_exec claude bash -lc '
    set -euo pipefail
    url="$1"
    run="$2"
    out="$(curl -LfsS --connect-timeout 8 --max-time 30 -o /dev/null \
      -w "%{time_namelookup}\t%{time_connect}\t%{time_starttransfer}\t%{time_total}\t%{http_code}\t%{remote_ip}" \
      "$url" 2>&1)" || {
        printf "%s\t0\t0\t0\t0\t0\t000\t%s\n" "$run" "$out"
        exit 0
      }
    IFS="$(printf "\t")" read -r dns connect ttfb total code remote_ip <<< "$out"
    awk -v run="$run" -v dns="$dns" -v connect="$connect" -v ttfb="$ttfb" -v total="$total" -v code="$code" -v remote="$remote_ip" \
      "BEGIN { printf \"%s\\t1\\t%.0f\\t%.0f\\t%.0f\\t%.0f\\t%s\\t%s\\n\", run, dns*1000, connect*1000, ttfb*1000, total*1000, code, remote }"
  ' bash "$HTTP_URL" "$run")"
  printf '%s\n' "$line" >> "$latency_file"

  if awk -F'\t' '$2 == "1" { exit 0 } { exit 1 }' <<<"$line"; then
    ok "sample $run/$ROUNDS" "$(awk -F'\t' '{ printf "dns=%sms connect=%sms ttfb=%sms total=%sms code=%s remote=%s", $3, $4, $5, $6, $7, $8 }' <<<"$line")"
  else
    warn "sample $run/$ROUNDS" "$(awk -F'\t' '{ print $8 }' <<<"$line")"
  fi
done

printf '\n'
summarize_table latency "$latency_file" | sed 's/^/  /'

section "Download Speed"
download_file="$(mktemp)"
printf 'run\tok\tbytes\ttotal_s\tspeed_bps\tremote_ip\n' > "$download_file"

for run in $(seq 1 "$DOWNLOAD_ROUNDS"); do
  line="$(compose_exec claude bash -lc '
    set -euo pipefail
    url="$1"
    run="$2"
    out="$(curl -LfsS --connect-timeout 10 --max-time 90 -o /dev/null \
      -w "%{size_download}\t%{time_total}\t%{speed_download}\t%{remote_ip}" \
      "$url" 2>&1)" || {
        printf "%s\t0\t0\t0\t0\t%s\n" "$run" "$out"
        exit 0
      }
    IFS="$(printf "\t")" read -r bytes total speed remote_ip <<< "$out"
    awk -v run="$run" -v bytes="$bytes" -v total="$total" -v speed="$speed" -v remote="$remote_ip" \
      "BEGIN { printf \"%s\\t1\\t%.0f\\t%.3f\\t%.0f\\t%s\\n\", run, bytes, total, speed, remote }"
  ' bash "$DOWNLOAD_URL" "$run")"
  printf '%s\n' "$line" >> "$download_file"

  if awk -F'\t' '$2 == "1" { exit 0 } { exit 1 }' <<<"$line"; then
    speed="$(awk -F'\t' '{ print $5 }' <<<"$line")"
    ok "download $run/$DOWNLOAD_ROUNDS" "$(human_bps "$speed") $(awk -F'\t' '{ printf "bytes=%s total=%ss remote=%s", $3, $4, $6 }' <<<"$line")"
  else
    warn "download $run/$DOWNLOAD_ROUNDS" "$(awk -F'\t' '{ print $6 }' <<<"$line")"
  fi
done

printf '\n'
summarize_table download "$download_file" | sed 's/^/  /'

failed_latency="$(awk -F'\t' 'NR > 1 && $2 != "1" { count++ } END { print count + 0 }' "$latency_file")"
failed_download="$(awk -F'\t' 'NR > 1 && $2 != "1" { count++ } END { print count + 0 }' "$download_file")"

if [[ "$failed_latency" == "0" && "$failed_download" == "0" ]]; then
  printf '\n%s✓ Network test completed%s\n' "$green" "$reset"
else
  printf '\n%s! Network test completed with failures%s latency_failed=%s download_failed=%s\n' "$yellow" "$reset" "$failed_latency" "$failed_download"
fi
