#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/stock-compose-caddy/oracle.sh
#   #4482  the stock Caddyfile routes /general, /pacman, /bazel and /lxc to
#          the backend, not to the web UI's HTML 404
#   #4564  it routes rattler's token-in-URL conda layout /t/<token>/conda/...
#          (#4555) to the backend
# Every probe is sent twice, straight to the backend and through the stock
# Caddy, and the two answers must be the same answer from the backend.
# See the manifest for the gates.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (Caddy's
# published :80), RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"
: "${RUN_ID:?}"; : "${TRIVY_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
CADDY="http://127.0.0.1:${TRIVY_PORT}"
SFX="${DTF_SLOT}-${RUN_ID##*-}-$$"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$@" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }
is_2xx(){ case "$1" in 2??) return 0;; *) return 1;; esac; }

req(){
  local -a ca=(-s -o "${W}/body" -w '%{http_code}' --max-time 60 -X "$1" -H "Authorization: Bearer ${TOK}")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$3")
  : >"${W}/body"
  CODE="$(curl "${ca[@]}" "${BASE}$2")"
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}
mk_repo(){ # <key> <format>
  req POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg f "$2" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')"
  is_2xx "$CODE" || { infra_fail "creating ${1} (${2}) answered ${CODE}: ${BODY:0:200}"; end_suite; }
}
# fetch <base> <path> <out prefix> [auth]: GET, saves body and headers; echoes the status.
fetch(){
  local -a ca=(-s -D "$3.h" -o "$3.b" -w '%{http_code}' --max-time 30)
  [ -n "${4:-}" ] && ca+=(-H "Authorization: Bearer $4")
  curl "${ca[@]}" "$1$2"
}
# same <label> <path> [auth]: the path answers identically straight from the
# backend and through Caddy, and Caddy's answer did not come from the web UI.
same(){
  local label="$1" path="$2" auth="${3:-}" d c wh shown
  d="$(fetch "$BASE" "$path" "${W}/d" "$auth")"
  c="$(fetch "$CADDY" "$path" "${W}/c" "$auth")"
  wh="$(grep -i '^x-dtf-upstream:' "${W}/c.h" | tr -d '\r' | awk '{print $2}')"
  shown="${path%%\?*}"; [ -n "${CTOK:-}" ] && shown="${shown//${CTOK}/<token>}"
  note "${label}: ${shown} -> backend ${d} ($(wc -c <"${W}/d.b" | tr -d ' ') B), via Caddy ${c} ($(wc -c <"${W}/c.b" | tr -d ' ') B)${wh:+, answered by the ${wh} stand-in}"
  if [ "$wh" = "web" ]; then
    fail_g "${label}: Caddy sent ${shown} to the web UI (HTML 404) instead of the backend"
  elif [ "$c" != "$d" ] || ! cmp -s "${W}/d.b" "${W}/c.b"; then
    fail_g "${label}: the answer through Caddy (${c}) differs from the backend's (${d})"
  fi
}

begin_suite "stock-compose-caddy"

begin_test "setup: admin session, stock Caddy and the web stand-in answering, one repository per probed format"
TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
hc="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${CADDY}/health")"
[ "$hc" = "200" ] || { infra_fail "stock Caddy is not answering /health on ${CADDY} (${hc})"; end_suite; }
CF="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/caddy/Caddyfile"}}{{.Source}}{{end}}{{end}}' "ak-dtf${DTF_SLOT}-stock-caddy" 2>/dev/null)"
echo "-- Caddyfile under test: ${CF:-unknown} (sha256 $(sha256sum "${CF:-/dev/null}" 2>/dev/null | cut -c1-12))"
R_GEN="sc-gen-${SFX}"; R_PAC="sc-pac-${SFX}"; R_BZL="sc-bzl-${SFX}"; R_CONDA="sc-conda-${SFX}"; R_NPM="sc-npm-${SFX}"
mk_repo "$R_GEN" generic; mk_repo "$R_PAC" pacman; mk_repo "$R_BZL" bazel; mk_repo "$R_CONDA" conda; mk_repo "$R_NPM" npm
printf 'stock caddy %s\n' "$SFX" > "${W}/p.txt"
curl -s -o /dev/null --max-time 30 -X PUT -H "Authorization: Bearer ${TOK}" --data-binary "@${W}/p.txt" \
  "${BASE}/api/v1/repositories/${R_GEN}/artifacts/a/p.txt"
pass

# =============================================================================
begin_test "CONTROL: /health, /api/v1 and /npm reach the backend through Caddy; an unrouted path reaches the web UI"
reset_case
same "health" "/health"
same "API" "/api/v1/repositories/${R_GEN}" "$TOK"
same "npm" "/npm/${R_NPM}/no-such-package" "$TOK"
c="$(fetch "$CADDY" "/dtf-unrouted-${SFX}" "${W}/u")"
wh="$(grep -i '^x-dtf-upstream:' "${W}/u.h" | tr -d '\r' | awk '{print $2}')"
note "unrouted /dtf-unrouted-...: via Caddy ${c}, upstream=${wh:-backend}"
[ "$wh" = "web" ] || fail_g "an unrouted path did not fall through to the web UI"
finish_case "the stock Caddy's established routes broke"

begin_test "#4482: /general/<repo>/<path> through Caddy serves the artifact from the backend"
reset_case
same "general" "/general/${R_GEN}/a/p.txt" "$TOK"
cmp -s "${W}/c.b" "${W}/p.txt" || fail_g "the bytes through Caddy are not the uploaded artifact"
finish_case "/general is not routed to the backend"

begin_test "#4482: /pacman, /bazel and /lxc through Caddy reach the backend"
reset_case
same "pacman" "/pacman/${R_PAC}/core/os/x86_64/core.db" "$TOK"
same "bazel" "/bazel/${R_BZL}/bazel_registry.json" "$TOK"
same "lxc" "/lxc/streams/v1/index.json" "$TOK"
finish_case "a native format prefix falls through to the web UI"

begin_test "#4564: the conda token-in-URL layout /t/<token>/conda/<repo>/... through Caddy reaches the backend"
reset_case
# rattler/pixi put an API token (not a session JWT) in the URL.
req POST /api/v1/auth/tokens '{"name":"stock-caddy-conda","scopes":["read:artifacts"],"expires_in_days":1}'
CTOK="$(jqr '.token // .api_key // empty' <<<"$BODY")"
[ -n "$CTOK" ] || fail_g "could not mint an API token for the /t/ layout (${CODE}: ${BODY:0:160})"
same "conda /t/" "/t/${CTOK}/conda/${R_CONDA}/noarch/repodata.json"
jq -e '.packages | type == "object"' "${W}/c.b" >/dev/null 2>&1 || fail_g "the answer through Caddy is not conda repodata JSON"
finish_case "/t/<token>/conda is not routed to the backend"

end_suite
