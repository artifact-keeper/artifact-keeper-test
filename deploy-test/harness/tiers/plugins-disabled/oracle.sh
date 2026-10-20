#!/usr/bin/env bash
# =============================================================================
# tiers/plugins-disabled/oracle.sh
#   #4650 / #4651  PLUGINS_ENABLED=false switches the WASM plugin runtime off:
#                  no registry / Wasmtime / startup plugin load, and the plugin
#                  management, format-handler and /ext routes unregistered
# See the manifest for the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# DTF_DIR, RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${DTF_DIR:?}"; : "${RUN_ID:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
PROJECT="ak-dtf${DTF_SLOT}"
FX="${HERE}/fixtures"
REPO="pd-gen-${DTF_SLOT}-${RUN_ID##*-}"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# recreate_backend <override>: recreate only the backend with
# fixtures/plugins.<override>.yml layered alone on compose.base.yml (postgres
# and the data volume stay), wait for health, log in again.
recreate_backend(){
  docker compose -p "$PROJECT" -f "${DTF_DIR}/compose.base.yml" -f "${FX}/plugins.$1.yml" \
    up -d --no-deps --force-recreate --wait backend >"${W}/recreate.log" 2>&1 || true
  TOK="$(curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // empty')"
  ENV_FLAG="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$BACKEND_CTR" 2>/dev/null | grep '^PLUGINS_ENABLED=' || true)"
  LOGS="$(docker logs "$BACKEND_CTR" 2>&1 || true)"
}
# req <METHOD> <PATH> [JSON] -> sets CODE / BODY
req(){
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 15 -X "$m" -H "Authorization: Bearer ${TOK}" \
      -H 'Content-Type: application/json' -d "$d" "${BASE}${p}")"
  else
    CODE="$(curl -s -o "${W}/body" -w '%{http_code}' --max-time 15 -X "$m" -H "Authorization: Bearer ${TOK}" "${BASE}${p}")"
  fi
  BODY="$(cat "${W}/body" 2>/dev/null || true)"
}

begin_suite "plugins-disabled"

# =============================================================================
# Leg 1: PLUGINS_ENABLED unset (the default). The runtime is on.
# =============================================================================
begin_test "CONTROL: with PLUGINS_ENABLED unset the plugin runtime starts and the plugin, format-handler and /ext routes answer"
reset_case
recreate_backend default
if [ -z "$TOK" ]; then
  infra_fail "no admin session after recreating the backend with PLUGINS_ENABLED unset: $(tail -3 "${W}/recreate.log")"; end_suite
fi
[ -z "$ENV_FLAG" ] || fail_g "PLUGINS_ENABLED is set in the container (${ENV_FLAG}); this leg needs it unset"
req POST /api/v1/repositories "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:true}')"
[ "$CODE" = "200" ] || [ "$CODE" = "201" ] || { infra_fail "could not create the generic repository ${REPO} (HTTP ${CODE}: ${BODY:0:200})"; end_suite; }
grep -q 'Initializing WASM plugin system' <<<"$LOGS" || fail_g "no 'Initializing WASM plugin system' startup line"
grep -q 'WASM plugin system initialized' <<<"$LOGS" || fail_g "no 'WASM plugin system initialized' startup line"
grep -q 'plugins_disabled_by_operator' <<<"$LOGS" && fail_g "the runtime logged plugins_disabled_by_operator although the flag is unset"
req GET /api/v1/plugins
note "GET /api/v1/plugins -> ${CODE} ${BODY:0:80}"
[ "$CODE" = "200" ] && [ "$(jqr '.items | type' <<<"$BODY")" = "array" ] || fail_g "GET /api/v1/plugins answered ${CODE}, expected 200 {items: [...]}"
req GET /api/v1/formats/maven
note "GET /api/v1/formats/maven -> ${CODE} handler_type=$(jqr '.handler_type // empty' <<<"$BODY")"
[ "$CODE" = "200" ] && [ "$(jqr '.format_key // empty' <<<"$BODY")" = "maven" ] || fail_g "GET /api/v1/formats/maven answered ${CODE}, expected 200 with format_key maven"
req POST /api/v1/plugins/install/local '{}'
note "POST /api/v1/plugins/install/local {} -> ${CODE} ${BODY:0:80}"
[ "$CODE" = "422" ] || [ "$CODE" = "400" ] || fail_g "the admin install route answered ${CODE} to an empty body, expected a 400/422 validation refusal (route registered)"
req GET "/ext/pdnope/${REPO}/x"
note "GET /ext/pdnope/${REPO}/x -> ${CODE} ${BODY:0:80}"
{ [ "$CODE" = "404" ] && grep -q "No protocol handler for format 'pdnope'" <<<"$BODY"; } || fail_g "/ext did not reach the WASM proxy (expected 404 \"No protocol handler for format 'pdnope'\", got ${CODE} ${BODY:0:120})"
finish_case "the default (PLUGINS_ENABLED unset) plugin runtime and routes are not present"

# =============================================================================
# Leg 2: PLUGINS_ENABLED=false.
# =============================================================================
begin_test "FIX #4650: with PLUGINS_ENABLED=false the plugin management, format-handler and /ext routes are not registered (404, no handler body)"
reset_case
recreate_backend off
if [ -z "$TOK" ]; then
  fail_g "no admin session after recreating the backend with PLUGINS_ENABLED=false: $(tail -3 "${W}/recreate.log")"
else
  [ "$ENV_FLAG" = "PLUGINS_ENABLED=false" ] || fail_g "the container does not carry PLUGINS_ENABLED=false (${ENV_FLAG:-unset})"
  req GET /api/v1/plugins
  note "GET /api/v1/plugins -> ${CODE} ${BODY:0:80}"
  [ "$CODE" = "404" ] || fail_g "GET /api/v1/plugins answered ${CODE}, expected 404"
  grep -q '"items"' <<<"$BODY" && fail_g "GET /api/v1/plugins still lists plugins"
  req GET /api/v1/formats
  note "GET /api/v1/formats -> ${CODE} ${BODY:0:80}"
  [ "$CODE" = "404" ] || fail_g "GET /api/v1/formats answered ${CODE}, expected 404"
  grep -q '"format_key"' <<<"$BODY" && fail_g "GET /api/v1/formats still lists format handlers"
  req POST /api/v1/formats/maven/disable
  note "POST /api/v1/formats/maven/disable -> ${CODE} ${BODY:0:80}"
  [ "$CODE" = "404" ] || fail_g "the format-handler admin route answered ${CODE}, expected 404"
  req POST /api/v1/plugins/install/local '{}'
  note "POST /api/v1/plugins/install/local {} -> ${CODE} ${BODY:0:80}"
  [ "$CODE" = "404" ] || fail_g "the plugin install route answered ${CODE}, expected 404 (unregistered)"
  req GET "/ext/pdnope/${REPO}/x"
  note "GET /ext/pdnope/${REPO}/x -> ${CODE} ${BODY:0:80}"
  [ "$CODE" = "404" ] || fail_g "/ext answered ${CODE}, expected 404"
  grep -q 'No protocol handler' <<<"$BODY" && fail_g "/ext still reaches the WASM proxy handler"
fi
finish_case "#4650: PLUGINS_ENABLED=false leaves the plugin routes registered"

begin_test "FIX #4650: with PLUGINS_ENABLED=false the backend logs plugins_disabled_by_operator and never initializes the WASM runtime or loads plugins"
reset_case
grep -q 'WASM plugin runtime disabled by operator.*plugins_disabled_by_operator' <<<"$LOGS" \
  || fail_g "no 'WASM plugin runtime disabled by operator' (event=plugins_disabled_by_operator) startup line"
for line in 'Initializing WASM plugin system' 'WASM plugin system initialized' 'Core format handlers synchronized' 'Loaded plugin:'; do
  grep -q "$line" <<<"$LOGS" && fail_g "the disabled backend still logged '${line}'"
done
note "plugin lines in the disabled backend's log: $(grep -ciE 'wasm|plugin' <<<"$LOGS") ($(grep -iE 'wasm plugin' <<<"$LOGS" | head -2 | sed 's/^.*Z  //' | tr '\n' '|' | head -c 200))"
finish_case "#4650: the disabled backend still initializes the plugin runtime"

begin_test "CONTROL: with PLUGINS_ENABLED=false the core (non-plugin) formats still work: a generic upload round-trips byte-exact and is listed"
reset_case
printf 'plugins-disabled %s\n' "$RUN_ID" > "${W}/a.txt"
c="$(curl -s -o "${W}/put" -w '%{http_code}' --max-time 15 -X PUT -H "Authorization: Bearer ${TOK}" --data-binary @"${W}/a.txt" "${BASE}/api/v1/repositories/${REPO}/artifacts/pd/a.txt")"
[ "$c" = "200" ] || [ "$c" = "201" ] || fail_g "generic upload answered ${c}: $(head -c 200 "${W}/put")"
c="$(curl -s -o "${W}/get" -w '%{http_code}' --max-time 15 -H "Authorization: Bearer ${TOK}" "${BASE}/api/v1/repositories/${REPO}/download/pd/a.txt")"
{ [ "$c" = "200" ] && cmp -s "${W}/a.txt" "${W}/get"; } || fail_g "generic download answered ${c} and is not byte-exact"
req GET "/api/v1/repositories/${REPO}"
[ "$CODE" = "200" ] && [ "$(jqr '.key // empty' <<<"$BODY")" = "$REPO" ] || fail_g "GET /api/v1/repositories/${REPO} answered ${CODE}"
req GET "/api/v1/repositories/${REPO}/artifacts"
note "GET /api/v1/repositories/${REPO}/artifacts -> ${CODE} ${BODY:0:120}"
{ [ "$CODE" = "200" ] && grep -q '"pd/a.txt"' <<<"$BODY"; } || fail_g "the artifact listing does not show pd/a.txt (HTTP ${CODE})"
finish_case "core formats break when the plugin runtime is disabled"

# =============================================================================
# Leg 3: back to unset. The switch is not sticky.
# =============================================================================
begin_test "CONTROL: unsetting PLUGINS_ENABLED again restores the plugin routes on the same database"
reset_case
recreate_backend default
[ -n "$TOK" ] || fail_g "no admin session after restoring the default"
req GET /api/v1/plugins
[ "$CODE" = "200" ] && [ "$(jqr '.items | type' <<<"$BODY")" = "array" ] || fail_g "GET /api/v1/plugins answered ${CODE} after re-enabling"
req GET /api/v1/formats/maven
[ "$CODE" = "200" ] || fail_g "GET /api/v1/formats/maven answered ${CODE} after re-enabling"
grep -q 'WASM plugin system initialized' <<<"$LOGS" || fail_g "the runtime did not initialize after re-enabling"
finish_case "re-enabling the plugin runtime does not restore its routes"

end_suite
