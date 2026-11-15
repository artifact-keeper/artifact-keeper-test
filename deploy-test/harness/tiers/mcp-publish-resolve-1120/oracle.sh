#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/mcp-publish-resolve-1120/oracle.sh
#   MCP publish and package-resolution fixes of 1.12.0: exact npm versions
#   at publish (#5549), a Virtual backing fills through the Remote its walk
#   serves from (#5537), and a publish right after a pull-through finds the
#   cache entry (#5702). See the manifest.
#
# run.sh exported BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
TEST_LIB="$(cd "$(dirname "$COMMON_SH")" && pwd)"
# shellcheck source=/dev/null
source "${TEST_LIB}/mcp-helpers.sh"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

BASE="$BASE_URL"
SFX="$(printf '%s' "${DTF_SLOT}-${RUN_ID##*-}-$$" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')"
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

# api METHOD PATH [JSON]: admin request; sets CODE, body in ${W}/api.json.
api(){
  local -a ca=(-s -o "${W}/api.json" -w '%{http_code}' --max-time 60 -X "$1" -H "$(auth_header)")
  [ -n "${3:-}" ] && ca+=(-H 'Content-Type: application/json' --data-binary "$3")
  CODE="$(curl "${ca[@]}" "${BASE}$2")"
}
# npm_repo KEY local|remote|virtual [UPSTREAM]
npm_repo(){
  local body
  case "$2" in
    remote) body="$(jq -nc --arg k "$1" --arg u "$3" '{key:$k,name:$k,format:"npm",repo_type:"remote",upstream_url:$u,is_public:true}')" ;;
    *) body="$(jq -nc --arg k "$1" --arg t "$2" '{key:$k,name:$k,format:"npm",repo_type:$t,is_public:true}')" ;;
  esac
  api POST /api/v1/repositories "$body"
  case "$CODE" in 2??) mcp_delete_repo_on_exit "$1"; return 0 ;; esac
  note "creating npm ${2} ${1} answered ${CODE}: $(head -c 200 "${W}/api.json")"
  return 1
}
# members VIRTUAL KEY:PRIORITY...
members(){
  local v="$1" m arr="[]"
  shift
  for m in "$@"; do arr="$(jq -c --arg k "${m%%:*}" --argjson p "${m##*:}" '. + [{member_key:$k,priority:$p}]' <<<"$arr")"; done
  api PUT "/api/v1/repositories/${v}/members" "$(jq -nc --argjson m "$arr" '{members:$m}')"
  case "$CODE" in 2??) return 0 ;; esac
  note "setting members of ${v} answered ${CODE}: $(head -c 200 "${W}/api.json")"
  return 1
}
# publish_npm_server MCP_REPO NAME VERSION PKG PKG_VERSION: POST /publish;
# MCP_STATUS / MCP_BODY.
publish_npm_server(){
  mcp_server_json "$2" "$3" "$(mcp_npm_package_json "$4" "$5")" > "${W}/server.json"
  mcp_publish "$1" "${W}/server.json"
}
# await_served MCP_REPO NAME VERSION SECS: poll the anonymous exact read until
# it answers 200 or a terminal hold (anything but mcp_resolving); sets
# SERVED_CODE / SERVED_ERR.
await_served(){
  local end=$(( $(date +%s) + $4 ))
  while :; do
    mcp_get "$1" "$(mcp_version_path "$2" "$3")"
    SERVED_CODE="$MCP_STATUS"; SERVED_ERR="$(mcp_json '.error // empty')"
    [ "$SERVED_CODE" = "200" ] && return 0
    [ "$SERVED_CODE" = "404" ] && [ "$SERVED_ERR" != "mcp_resolving" ] && return 1
    [ "$(date +%s)" -ge "$end" ] && return 1
    sleep 3
  done
}
# cached_count REPO: artifacts a Remote holds in its cache listing.
cached_count(){
  curl -s --max-time 30 -H "$(auth_header)" "${BASE}/api/v1/repositories/$1/artifacts?per_page=100" \
    | jq -r '[(.items // .artifacts // .data // .)[]? | select((.path // "") | test("\\.tgz$"))] | length' 2>/dev/null || echo "?"
}

begin_suite "mcp-publish-resolve-1120"

begin_test "setup: admin session, the backend's container address and the npm and mcp repositories"
auth_admin
mcp_require_registry
BACKEND_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "ak-dtf${DTF_SLOT}-backend" 2>/dev/null | awk '{print $1}')"
[ -n "$BACKEND_IP" ] || { infra_fail "could not read the backend container address"; end_suite; }
SELF="http://${BACKEND_IP}:8080"
P="l6-mpr-${SFX}"
NS="io.github.ak-dtf"
ok=1
npm_repo "${P}-npm" local || ok=0
mcp_create_repo "${P}-mcp" "$(jq -cn --arg n "${P}-npm" '{mcp_package_repos:{npm:$n}}')" true || { note "$MCP_CREATE_ERROR"; ok=0; }
[ "$ok" = "1" ] || { infra_fail "repository setup failed" "$DETAIL"; end_suite; }
echo "-- prefix ${P}, backend ${SELF}"
pass

# =============================================================================
# #5549 exact npm versions at publish
# =============================================================================
PKG="@l6/exact-${SFX}"
begin_test "CONTROL: an npm package version that is exact SemVer (1.2.0) publishes with 200"
reset_case
mcp_publish_echo_package "${P}-npm" "$PKG" 1.2.0 "${NS}/exact-${SFX}"
note "npm publish ${PKG}@1.2.0: ${MCP_STATUS}"
publish_npm_server "${P}-mcp" "${NS}/exact-${SFX}" 1.0.0 "$PKG" 1.2.0
note "MCP publish naming 1.2.0: ${MCP_STATUS} $(mcp_json '.error // empty')"
[ "$MCP_STATUS" = "200" ] || fail_g "an exact version answered ${MCP_STATUS}: $(mcp_snip)"
finish_case "MCP publish of an exact npm version is broken"

begin_test "FIX #5549: npm versions 1.2, v1.2.0, 1.2.0+build.5 and 01.2.3 answer 400 mcp_invalid_server_json at publish"
reset_case
i=0
for v in 1.2 v1.2.0 1.2.0+build.5 01.2.3; do
  i=$((i+1))
  # The npm repository holds the version, so only the version rule decides.
  mcp_publish_echo_package "${P}-npm" "$PKG" "$v" "${NS}/exact-${SFX}"
  n_code="$MCP_STATUS"
  name="${NS}/inexact${i}-${SFX}"
  publish_npm_server "${P}-mcp" "$name" 1.0.0 "$PKG" "$v"
  err="$(mcp_json '.error // empty')"; det="$(mcp_json '.detail // empty' | head -c 140)"
  note "${v} (npm publish ${n_code}): ${MCP_STATUS} ${err} ${det}"
  if [ "$MCP_STATUS" != "400" ] || [ "$err" != "mcp_invalid_server_json" ] || [[ "$det" != *"packages[0].version"* ]]; then
    fail_g "npm version '${v}' answered ${MCP_STATUS} ${err:-<no error code>}, expected 400 mcp_invalid_server_json naming packages[0].version"
  fi
  mcp_get "${P}-mcp" "$(mcp_version_path "$name" 1.0.0)" admin
  [ "$MCP_STATUS" = "404" ] || fail_g "the version naming '${v}' reads back with ${MCP_STATUS}; a refused publish must store nothing"
done
finish_case "MCP publish accepts npm versions the sandbox cannot run"

# =============================================================================
# #5537 a Virtual backing fills through the Remote its walk serves from
# =============================================================================
begin_test "CONTROL: a Virtual backing whose only member is a Remote fills a package nobody pulled yet (202, then served)"
reset_case
ok=1
npm_repo "${P}-ctl-h" local || ok=0
npm_repo "${P}-ctl-r" remote "${SELF}/npm/${P}-ctl-h/" || ok=0
npm_repo "${P}-ctl-v" virtual || ok=0
members "${P}-ctl-v" "${P}-ctl-r:1" || ok=0
mcp_create_repo "${P}-ctl-mcp" "$(jq -cn --arg n "${P}-ctl-v" '{mcp_package_repos:{npm:$n}}')" true || { note "$MCP_CREATE_ERROR"; ok=0; }
CPKG="@l6/ctl-${SFX}"
mcp_publish_echo_package "${P}-ctl-h" "$CPKG" 1.0.0 "${NS}/ctl-${SFX}" || ok=0
if [ "$ok" = "1" ]; then
  publish_npm_server "${P}-ctl-mcp" "${NS}/ctl-${SFX}" 1.0.0 "$CPKG" 1.0.0
  note "publish: ${MCP_STATUS} $(mcp_json '.status // .error // empty') pendingPackages=$(mcp_json '.pendingPackages // empty' | tr -d ' \n')"
  [ "$MCP_STATUS" = "202" ] || fail_g "the publish answered ${MCP_STATUS}, expected 202 resolving (nothing was pulled yet)"
  await_served "${P}-ctl-mcp" "${NS}/ctl-${SFX}" 1.0.0 120
  note "after the fill: ${SERVED_CODE} ${SERVED_ERR}"
  [ "$SERVED_CODE" = "200" ] || fail_g "the version was not served after the fill (${SERVED_CODE} ${SERVED_ERR})"
else
  fail_g "control repository setup failed"
fi
finish_case "the Virtual backing fill path is broken"

begin_test "FIX #5537: a Virtual backing fills through the Remote its walk serves from (nested Virtual ahead of a direct Remote), and the version is served"
reset_case
ok=1
for x in a b; do npm_repo "${P}-w${x}-h" local || ok=0; done
npm_repo "${P}-direct" remote "${SELF}/npm/${P}-wa-h/" || ok=0
npm_repo "${P}-nested-r" remote "${SELF}/npm/${P}-wb-h/" || ok=0
npm_repo "${P}-nested" virtual || ok=0
npm_repo "${P}-walk" virtual || ok=0
members "${P}-nested" "${P}-nested-r:1" || ok=0
members "${P}-walk" "${P}-nested:1" "${P}-direct:2" || ok=0
mcp_create_repo "${P}-walk-mcp" "$(jq -cn --arg n "${P}-walk" '{mcp_package_repos:{npm:$n}}')" true || { note "$MCP_CREATE_ERROR"; ok=0; }
WPKG="@l6/walk-${SFX}"
# The same version in both upstreams, with different bytes.
mcp_publish_echo_package "${P}-wa-h" "$WPKG" 1.0.0 "${NS}/walk-direct-${SFX}" || ok=0
mcp_publish_echo_package "${P}-wb-h" "$WPKG" 1.0.0 "${NS}/walk-nested-${SFX}" || ok=0
if [ "$ok" = "1" ]; then
  echo "-- walk: ${P}-walk = [${P}-nested (1) = [${P}-nested-r], ${P}-direct (2)]"
  publish_npm_server "${P}-walk-mcp" "${NS}/walk-${SFX}" 1.0.0 "$WPKG" 1.0.0
  note "publish: ${MCP_STATUS} $(mcp_json '.status // .error // empty')"
  case "$MCP_STATUS" in 200|202) ;; *) fail_g "the publish answered ${MCP_STATUS}: $(mcp_snip)" ;; esac
  await_served "${P}-walk-mcp" "${NS}/walk-${SFX}" 1.0.0 150
  note "after the fill: ${SERVED_CODE} ${SERVED_ERR}"
  [ "$SERVED_CODE" = "200" ] || fail_g "the version ended ${SERVED_CODE} ${SERVED_ERR}, expected 200: the fill did not go through the walk's Remote"
  nd="$(cached_count "${P}-direct")"; nn="$(cached_count "${P}-nested-r")"
  note "tarballs cached: nested Remote ${nn}, direct Remote ${nd}"
  [ "$nn" != "0" ] && [ "$nn" != "?" ] || fail_g "the nested Remote (the walk's winner) cached no tarball (${nn})"
else
  fail_g "walk repository setup failed"
fi
finish_case "the Virtual backing fill ignores the walk"

# =============================================================================
# #5702 a publish right after a pull-through
# =============================================================================
ITER="${MCP_PUBLISH_RACE_ITER:-20}"
RH="${P}-race-h"; RR="${P}-race-r"
begin_test "CONTROL: a publish naming a version nobody pulled through the Remote backing answers 202 resolving"
reset_case
ok=1
npm_repo "$RH" local || ok=0
npm_repo "$RR" remote "${SELF}/npm/${RH}/" || ok=0
mcp_create_repo "${P}-race-mcp" "$(jq -cn --arg n "$RR" '{mcp_package_repos:{npm:$n}}')" true || { note "$MCP_CREATE_ERROR"; ok=0; }
RPKG="@l6/race-${SFX}"
for i in $(seq 0 "$ITER"); do mcp_publish_echo_package "$RH" "$RPKG" "1.0.${i}" "${NS}/race-${SFX}" || ok=0; done
if [ "$ok" = "1" ]; then
  publish_npm_server "${P}-race-mcp" "${NS}/race-${SFX}" 1.0.0 "$RPKG" 1.0.0
  note "publish naming an unpulled version: ${MCP_STATUS} $(mcp_json '.status // .error // empty')"
  { [ "$MCP_STATUS" = "202" ] && [ "$(mcp_json '.status // empty')" = "resolving" ]; } \
    || fail_g "the publish answered ${MCP_STATUS} $(mcp_snip), expected 202 resolving"
else
  fail_g "race repository setup failed"
fi
finish_case "the Remote backing fill path is broken"

begin_test "FIX #5702: ${ITER} times, a publish right after pulling the tarball through the Remote backing answers 200, never 202 resolving"
reset_case
n200=0; n202=0; nother=0
ENC_PKG="$(printf '%s' "$RPKG" | sed 's#/#%2f#')"
for i in $(seq 1 "$ITER"); do
  tb="$(curl -s --max-time 60 "${BASE}/npm/${RR}/${ENC_PKG}" | jq -r --arg v "1.0.${i}" '.versions[$v].dist.tarball // empty' 2>/dev/null)"
  pulled="$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 "$tb")"
  publish_npm_server "${P}-race-mcp" "${NS}/race-${SFX}" "1.0.${i}" "$RPKG" "1.0.${i}"
  case "$MCP_STATUS" in
    200) n200=$((n200+1)) ;;
    202) n202=$((n202+1)); note "1.0.${i}: pull ${pulled}, publish 202 $(mcp_json '.status // empty') pendingPackages=$(mcp_json '.pendingPackages // empty' | tr -d ' \n')" ;;
    *) nother=$((nother+1)); note "1.0.${i}: pull ${pulled}, publish ${MCP_STATUS} $(mcp_snip)" ;;
  esac
done
note "publishes right after the pull: ${n200} x 200, ${n202} x 202, ${nother} other"
[ "$n202" = "0" ] || fail_g "${n202} of ${ITER} publishes right after the pull answered 202 resolving: the lookup missed the in-flight catalog commit"
[ "$nother" = "0" ] || fail_g "${nother} publishes answered neither 200 nor 202"
finish_case "MCP publish misses a pull-through that just finished"

end_suite
