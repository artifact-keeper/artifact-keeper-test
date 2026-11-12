#!/usr/bin/env bash
# shellcheck disable=SC2016  # jq programs use jq $variables, not shell ones
# =============================================================================
# tiers/mcpb-ingest-validation/oracle.sh
#   MCPB ingest validation of 1.12.0: the shared entry ceiling (#5467),
#   duplicate manifests and keys (#5468), unsafe entry names and symlinks
#   (#5469), malformed and conflicting names (#5470); and a listing cursor
#   that decodes to NUL (#5471). See the manifest.
#
# run.sh exported BASE_URL, ADMIN_PASS, RUN_ID, DTF_SLOT, RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe here records its outcome instead.
set +e

TIER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

login(){ curl -s --max-time 15 -X POST "${BASE}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg u "$1" --arg p "$2" '{username:$u,password:$p}')" | jqr '.access_token // empty'; }

begin_suite "mcpb-ingest-validation"

begin_test "setup: admin session, a public mcp repository and the bundle fixtures"
TOK="$(login admin "$ADMIN_PASS")"
[ -n "$TOK" ] || { infra_fail "no admin session"; end_suite; }
REPO="l6-mcpbiv-${SFX}"
SLUG="echo-${SFX}"
NAME="io.github.ak-dtf/${SLUG}"
ENC="io.github.ak-dtf%2F${SLUG}"
VER="1.0.0"
c="$(curl -s -o "${W}/create.json" -w '%{http_code}' --max-time 30 -X POST -H "Authorization: Bearer ${TOK}" \
  -H 'Content-Type: application/json' "${BASE}/api/v1/repositories" \
  -d "$(jq -nc --arg k "$REPO" '{key:$k,name:$k,format:"mcp",repo_type:"local",is_public:true}')")"
case "$c" in 2??) ;; *) infra_fail "creating the mcp repository answered ${c}" "$(head -c 300 "${W}/create.json")"; end_suite ;; esac
add_exit_handler "curl -s -o /dev/null --max-time 30 -X DELETE -H 'Authorization: Bearer ${TOK}' '${BASE}/api/v1/repositories/${REPO}' || true"
B="${W}/bundles"
if ! python3 -I "${TIER_DIR}/fixtures/build_bundles.py" "$B" "$SLUG" "$VER" 2>"${W}/build.err"; then
  infra_fail "fixtures/build_bundles.py failed" "$(head -c 400 "${W}/build.err")"; end_suite
fi
echo "-- repository ${REPO}, server ${NAME}@${VER}"
pass

# put_bundle CASE_FILE AS_FILE: PUT the bundle; sets CODE, ERR, DET.
put_bundle(){
  : >"${W}/put.json"
  CODE="$(curl -s -o "${W}/put.json" -w '%{http_code}' --max-time 120 -X PUT \
    -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/octet-stream' \
    --data-binary "@${B}/$1" "${BASE}/mcp/${REPO}/v0.1/servers/${ENC}/versions/${VER}/bundles/$2")"
  ERR="$(jqr '.error // empty' "${W}/put.json")"
  DET="$(jqr '.detail // empty' "${W}/put.json" | head -c 160)"
}

# refused CASE...: each defective bundle answers 400 mcp_bundle_invalid, and
# its file name then takes a plain bundle with 201 (nothing was stored there).
refused(){
  local cs
  for cs in "$@"; do
    put_bundle "${cs}.mcpb" "${cs}.mcpb"
    note "${cs}.mcpb: ${CODE} ${ERR} ${DET}"
    if [ "$CODE" != "400" ] || [ "$ERR" != "mcp_bundle_invalid" ]; then
      fail_g "${cs}.mcpb answered ${CODE} ${ERR:-<no error code>}, expected 400 mcp_bundle_invalid"
    fi
    put_bundle ok.mcpb "${cs}.mcpb"
    note "   then plain bytes as ${cs}.mcpb: ${CODE} ${ERR}"
    [ "$CODE" = "201" ] || fail_g "a plain bundle under ${cs}.mcpb answered ${CODE} ${ERR}, expected 201: the refused archive holds the name"
  done
}

# =============================================================================
# Controls
# =============================================================================
begin_test "CONTROL: a plain bundle and a bundle of exactly 10,000 entries upload with 201"
reset_case
put_bundle ok.mcpb ok.mcpb
note "ok.mcpb: ${CODE} $(jqr '"\(.file) entries manifest=\(.manifest.name)@\(.manifest.version)"' "${W}/put.json")"
[ "$CODE" = "201" ] || fail_g "a plain bundle answered ${CODE} ${ERR} ${DET}"
put_bundle entries-10000.mcpb entries-10000.mcpb
note "entries-10000.mcpb: ${CODE} ${ERR} ${DET}"
[ "$CODE" = "201" ] || fail_g "a bundle of exactly 10,000 entries answered ${CODE} ${ERR} ${DET}, expected 201"
finish_case "MCPB upload baseline is broken"

# =============================================================================
# #5467 the shared ingest entry ceiling
# =============================================================================
begin_test "FIX #5467: a bundle of 10,001 entries answers 400 mcp_bundle_invalid and is not stored"
reset_case
refused entries-10001
finish_case "MCPB ingest skips the shared 10,000-entry ceiling"

# =============================================================================
# #5468 duplicate manifest entries and duplicate JSON keys
# =============================================================================
begin_test "FIX #5468: a second manifest.json entry and a duplicate manifest key each answer 400 mcp_bundle_invalid"
reset_case
refused dup-manifest dup-json-key
finish_case "MCPB accepts duplicate manifest representations"

# =============================================================================
# #5469 traversal, absolute, drive, backslash and symlink entries
# =============================================================================
begin_test "FIX #5469: ../, absolute, drive-letter and backslash entry names and a symlink entry each answer 400 mcp_bundle_invalid"
reset_case
refused path-parent path-absolute path-drive path-backslash symlink
finish_case "MCPB stores unsafe archive entries"

# =============================================================================
# #5470 malformed names and central/local conflicts
# =============================================================================
begin_test "FIX #5470: a non-UTF-8 entry name and a central/local header name conflict each answer 400 mcp_bundle_invalid"
reset_case
refused name-not-utf8 name-central-local
finish_case "MCPB accepts malformed or conflicting entry names"

# =============================================================================
# #5471 a listing cursor that decodes to NUL
# =============================================================================
LIST="${BASE}/mcp/${REPO}/v0.1/servers"
begin_test "CONTROL: listings with no cursor, a malformed cursor and the backend's own cursor"
reset_case
for s in a b; do
  jq -nc --arg n "io.github.ak-dtf/list-${s}-${SFX}" \
    '{"$schema":"https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
      name:$n, description:"DTF listing fixture", version:"1.0.0",
      remotes:[{type:"streamable-http", url:"https://mcp.example.invalid/mcp"}]}' > "${W}/srv-${s}.json"
  c="$(curl -s -o "${W}/pub.json" -w '%{http_code}' --max-time 30 -X POST -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' --data-binary "@${W}/srv-${s}.json" "${BASE}/mcp/${REPO}/v0.1/publish")"
  note "publish list-${s}: ${c}"
  [ "$c" = "200" ] || fail_g "publishing list-${s} answered ${c}: $(head -c 200 "${W}/pub.json")"
done
c="$(curl -s -o "${W}/l1.json" -w '%{http_code}' --max-time 30 "${LIST}?limit=1")"
n1="$(jqr '.servers | length' "${W}/l1.json")"
NEXT="$(jqr '.metadata.nextCursor // empty' "${W}/l1.json")"
note "no cursor: ${c}, ${n1} server(s), nextCursor ${NEXT:+present}"
{ [ "$c" = "200" ] && [ "$n1" = "1" ] && [ -n "$NEXT" ]; } || fail_g "limit=1 answered ${c} with ${n1} server(s) and nextCursor '${NEXT}'"
c="$(curl -s -o "${W}/l2.json" -w '%{http_code}' --max-time 30 -G "${LIST}" --data-urlencode limit=1 --data-urlencode "cursor=${NEXT}")"
note "the backend's cursor: ${c}, $(jqr '.servers | length' "${W}/l2.json") server(s)"
[ "$c" = "200" ] || fail_g "the next page with the backend's own cursor answered ${c}: $(head -c 200 "${W}/l2.json")"
c="$(curl -s -o "${W}/lb.json" -w '%{http_code}' --max-time 30 "${LIST}?limit=1&cursor=!!!")"
note "cursor=!!!: ${c} $(jqr '.error // empty' "${W}/lb.json")"
{ [ "$c" = "400" ] && [ "$(jqr '.error // empty' "${W}/lb.json")" = "mcp_invalid_query" ]; } \
  || fail_g "cursor=!!! answered ${c} $(head -c 200 "${W}/lb.json"), expected 400 mcp_invalid_query"
finish_case "MCP listing cursor baseline is broken"

begin_test "FIX #5471: cursor=YToA (decodes to a coordinate holding NUL) answers 400 mcp_invalid_query, not 500"
reset_case
c="$(curl -s -o "${W}/ln.json" -w '%{http_code}' --max-time 30 "${LIST}?limit=1&cursor=YToA")"
note "cursor=YToA: ${c} $(head -c 200 "${W}/ln.json")"
{ [ "$c" = "400" ] && [ "$(jqr '.error // empty' "${W}/ln.json")" = "mcp_invalid_query" ]; } \
  || fail_g "cursor=YToA answered ${c} $(jqr '.error // empty' "${W}/ln.json"), expected 400 mcp_invalid_query"
h="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "${BASE}/health")"
note "health after: ${h}"
[ "$h" = "200" ] || fail_g "/health answered ${h} after the cursor request"
finish_case "a NUL listing cursor reaches SQL"

end_suite
