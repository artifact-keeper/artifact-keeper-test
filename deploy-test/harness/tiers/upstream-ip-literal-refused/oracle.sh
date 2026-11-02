#!/usr/bin/env bash
# =============================================================================
# tiers/upstream-ip-literal-refused/oracle.sh
#   artifact-keeper#5095 (PR #5100): an IP-literal destination read from upstream
#   content is checked against the outbound address policy in every routing mode.
# See the manifest for the topology and the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${RUN_ID:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

setup_workdir
W="$WORK_DIR"
SUF="${RUN_ID##*-}-$$"
UPSTREAM="http://172.16.${DTF_SLOT}.84/"
DECOY_IP="172.16.${DTF_SLOT}.85"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
REFUSED=(lit-dotted lit-integer lit-hex lit-octal lit-mapped lit-metadata lit-decoy)
SERVED=(ok-literal ok-hostname ok-relative)
INHERIT="dtf-lit-inherit-${SUF}"
DIRECT="dtf-lit-direct-${SUF}"

api() { # <method> <path> [json] -> HTTP code, body in $W/api.json
  local -a args=(-s -o "$W/api.json" -w '%{http_code}' --max-time 30 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" "${BASE_URL}$2" 2>/dev/null || echo 000
}
chart() { # <repo> <name> -> HTTP code, body in $W/chart.bin
  : > "$W/chart.bin"
  curl -s -o "$W/chart.bin" -w '%{http_code}' --max-time 60 -H "Authorization: Bearer ${TOK}" \
    "${BASE_URL}/helm/$1/charts/$2-1.0.0.tgz" 2>/dev/null || echo 000
}
log_of() { # <container suffix> <port> -> the listener's request log
  docker exec "ak-dtf${DTF_SLOT}-$1" python3 -c \
    "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:$2/__log',timeout=5).read().decode())" \
    2>/dev/null || true
}
listener_hits() { # -> everything mock-loopback and mock-decoy received
  log_of mock-loopback 18099; log_of mock-decoy 80
}
snip() { head -c 200 "$W/chart.bin" 2>/dev/null | tr -cd '[:print:]' || true; }

begin_suite "upstream-ip-literal-refused"

begin_test "setup: admin login, a Helm Remote under inherit and one under direct routing"
TOK="$(curl -s --max-time 30 -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jq -r '.access_token // empty' 2>/dev/null || true)"
if [ -z "$TOK" ]; then infra_fail "admin login failed at ${BASE_URL}"; end_suite; fi
cleanup_repos() { api DELETE "/api/v1/repositories/${INHERIT}" >/dev/null || true; api DELETE "/api/v1/repositories/${DIRECT}" >/dev/null || true; }
add_exit_handler "cleanup_repos"
ERR=""
for r in "$INHERIT" "$DIRECT"; do
  st="$(api POST /api/v1/repositories "$(jq -nc --arg k "$r" --arg u "$UPSTREAM" \
    '{key:$k,name:$k,format:"helm",repo_type:"remote",upstream_url:$u,is_public:false}')")"
  case "$st" in 2??) ;; *) ERR="${ERR} create ${r}: HTTP ${st} $(head -c 200 "$W/api.json");" ;; esac
done
st="$(api PUT "/api/v1/repositories/${DIRECT}/egress-proxy" '{"mode":"direct"}')"
[ "$st" = "200" ] || ERR="${ERR} direct routing: HTTP ${st} $(head -c 200 "$W/api.json");"
if [ -z "$ERR" ]; then pass; else infra_fail "$ERR"; end_suite; fi

begin_test "CONTROL: both listeners answer from the backend's network namespace"
a="$(docker exec "$BACKEND_CTR" curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:18099/__readyz 2>/dev/null || true)"
b="$(docker exec "$BACKEND_CTR" curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${DECOY_IP}/__readyz" 2>/dev/null || true)"
if [ "$a" = "200" ] && [ "$b" = "200" ]; then pass
else fail "loopback listener HTTP ${a}, decoy HTTP ${b}, want 200 both: the listeners must be reachable for 'received nothing' to mean anything"; fi

for repo in "$INHERIT" "$DIRECT"; do
  case "$repo" in "$INHERIT") mode=inherit ;; *) mode=direct ;; esac

  for name in "${SERVED[@]}"; do
    begin_test "CONTROL: ${name} is served under ${mode} routing"
    st="$(chart "$repo" "$name")"
    if [ "$st" = "200" ] && grep -aq 'dtf-helm-literal-chart-bytes-from-helm' "$W/chart.bin"; then pass
    else fail "HTTP ${st}, want 200 with mock-helm's bytes" "$(snip)"; fi
  done

  for name in "${REFUSED[@]}"; do
    begin_test "FIX #5095: ${name} is 502 UPSTREAM_DESTINATION_REFUSED under ${mode} routing"
    st="$(chart "$repo" "$name")"
    code="$(jq -r '.code // empty' "$W/chart.bin" 2>/dev/null || true)"
    if [ "$st" = "502" ] && [ "$code" = "UPSTREAM_DESTINATION_REFUSED" ] \
       && ! grep -aqE '127\.0\.0\.1|2130706433|0x7f|0177|ffff|169\.254|'"${DECOY_IP//./\\.}" "$W/chart.bin"; then pass
    else fail "HTTP ${st} code '${code}', want 502 UPSTREAM_DESTINATION_REFUSED with no address in the body" "$(snip)"; fi
  done
done

begin_test "FIX #5095: neither the loopback listener nor the private decoy received a request"
hits="$(listener_hits)"
if [ -z "$(printf '%s' "$hits" | tr -d '[:space:]')" ]; then pass
else fail "the listeners were dialled through an IP-literal chart URL" "${hits:0:600}"; fi

end_suite
