#!/usr/bin/env bash
# =============================================================================
# tiers/generic-route-scan-gate/oracle.sh
#   #4442 the generic download route (/api/v1/repositories/{key}/download/*,
#         /general/{key}/*) refuses a proxied file of a scan-on-proxy enforced
#         format with 403 scan_on_proxy_route_required (naming the format
#         handler) before any upstream request, on a Remote and on a Virtual
#         with a scanning Remote member (download and artifacts routes)
#   #4513 an ambiguous proxied path ('?' smuggled as %3F, ';') is refused 400
#         before any upstream request, on the generic route's Remote arm and
#         on the npm tarball route
#   #4420 chunked-session, generic PUT and multipart uploads refuse a Remote
#         (405) and a Virtual (400) before a session row or artifact exists
# See the manifest for the topology.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock's published control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
DBC="$DB_CONTAINER"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UPSTREAM="http://172.16.${DTF_SLOT}.70/f/"   # profiles/upstreams.mock-static.yml

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# GETs the mock saw for /f/<path> (the query is not part of the counted path).
mock_count(){ local c; c="$(curl -s --max-time 5 -G "${MOCK}/__requests" --data-urlencode "path=/f/$1" | jqr '.count // empty')"; echo "${c:-0}"; }
golden(){ curl -s --max-time 10 -o "$2" "${MOCK}/__golden/$1" || true; }
get(){ # <url-path> <outfile> -> http code
  curl -s --max-time 30 -o "$2" -w '%{http_code}' -H "Authorization: Bearer $TOK" "$BASE$1" || echo 000
}
# expect_route_required <url-path> <file> <handler> <upstream-path>
expect_route_required(){
  local code before after
  before="$(mock_count "$4")"
  code="$(get "$1" "$W/rr.json")"
  after="$(mock_count "$4")"
  note "GET $1: HTTP ${code} error=$(jqr '.error // empty' < "$W/rr.json") handler=$(jqr '.handler // empty' < "$W/rr.json") file=$(jqr '.file // empty' < "$W/rr.json"); upstream GETs ${before} -> ${after}"
  [ "$code" = "403" ] || fail_g "$1 answered ${code}, expected 403"
  [ "$(jqr '.error // empty' < "$W/rr.json")" = "scan_on_proxy_route_required" ] || fail_g "$1: error is not scan_on_proxy_route_required"
  [ "$(jqr '.handler // empty' < "$W/rr.json")" = "$3" ] || fail_g "$1: handler is not '$3'"
  [ "$(jqr '.file // empty' < "$W/rr.json")" = "$2" ] || fail_g "$1: file is not '$2'"
  [ "$before" = "$after" ] || fail_g "$1 reached the upstream ($before -> $after) before refusing"
}
# expect_ambiguous_400 <url-path> <upstream-path-stripped> <upstream-path-literal>
expect_ambiguous_400(){
  local code b1 b2 a1 a2
  b1="$(mock_count "$2")"; b2="$(mock_count "$3")"
  code="$(get "$1" "$W/amb.json")"
  a1="$(mock_count "$2")"; a2="$(mock_count "$3")"
  note "GET $1: HTTP ${code} $(head -c 120 "$W/amb.json" | tr -c '[:print:]' '.'); upstream GETs /f/$2 ${b1}->${a1}, /f/$3 ${b2}->${a2}"
  [ "$code" = "400" ] || fail_g "$1 answered ${code}, expected 400"
  [ "$(jqr '.code // empty' < "$W/amb.json")" = "VALIDATION_ERROR" ] || fail_g "$1: refusal is not VALIDATION_ERROR"
  [ "$b1" = "$a1" ] && [ "$b2" = "$a2" ] || fail_g "$1 reached the upstream before refusing"
}

# =============================================================================
begin_suite "generic-route-scan-gate"

begin_test "setup: Remote pypi/npm (scan on proxy), Remote pypi (scan off), Remote generic on the mock; local pypi + generic; Virtual pypi over local + scanning Remote"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-static.yml)"; end_suite
fi
SUF="${RUN_ID##*-}-$$"
R_PYS="grs-pys-${SUF}"; R_NPS="grs-nps-${SUF}"; R_PYO="grs-pyo-${SUF}"; R_GR="grs-gr-${SUF}"
R_LPY="grs-lpy-${SUF}"; R_LG="grs-lg-${SUF}"; R_V="grs-v-${SUF}"
mk(){ # <key> <format> <type> [upstream]
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
      '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + (if $u == "" then {} else {upstream_url:$u} end)')" \
    | jqr '.key // empty'
}
SETUP_ERR=""
[ "$(mk "$R_PYS" pypi remote "$UPSTREAM")" = "$R_PYS" ] || SETUP_ERR="${SETUP_ERR} pypi-remote-scan"
[ "$(mk "$R_NPS" npm remote "$UPSTREAM")" = "$R_NPS" ] || SETUP_ERR="${SETUP_ERR} npm-remote-scan"
[ "$(mk "$R_PYO" pypi remote "$UPSTREAM")" = "$R_PYO" ] || SETUP_ERR="${SETUP_ERR} pypi-remote-off"
[ "$(mk "$R_GR" generic remote "$UPSTREAM")" = "$R_GR" ] || SETUP_ERR="${SETUP_ERR} generic-remote"
[ "$(mk "$R_LPY" pypi local)" = "$R_LPY" ] || SETUP_ERR="${SETUP_ERR} pypi-local"
[ "$(mk "$R_LG" generic local)" = "$R_LG" ] || SETUP_ERR="${SETUP_ERR} generic-local"
[ "$(mk "$R_V" pypi virtual)" = "$R_V" ] || SETUP_ERR="${SETUP_ERR} pypi-virtual"
for m in "$R_LPY" "$R_PYS"; do
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories/${R_V}/members" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "{\"member_key\":\"$m\",\"priority\":1}")"
  case "$code" in 2*) ;; *) SETUP_ERR="${SETUP_ERR} member-${m}(${code})";; esac
done
for r in "$R_PYS" "$R_NPS"; do
  sop="$(curl -s -X PUT "$BASE/api/v1/repositories/${r}/security" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed"}' | jqr '.scan_on_proxy // empty')"
  [ "$sop" = "true" ] || SETUP_ERR="${SETUP_ERR} scan_on_proxy-${r}"
done
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
printf 'dtf-hosted-wheel-%s' "$SUF" > "$W/hosted.whl"
OWN="own${SUF//-/}-1.0-py3-none-any.whl"
code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" --data-binary @"$W/hosted.whl" \
  "$BASE/api/v1/repositories/${R_LPY}/artifacts/${OWN}")"
if [ "$code" != "201" ]; then infra_fail "hosted wheel upload answered ${code}"; end_suite; fi
echo "-- repos: ${R_PYS} ${R_NPS} (scan on), ${R_PYO} ${R_GR} (off) -> ${UPSTREAM}; ${R_V} = ${R_LPY} + ${R_PYS}"
pass

N="${SUF//-/}"
# =============================================================================
# #4442
# =============================================================================
begin_test "CONTROL: a Remote pypi that does NOT scan on proxy still serves a proxied wheel on the generic route (upstream bytes, one upstream GET)"
reset_case
F="ok${N}-1.0-py3-none-any.whl"
golden "$F" "$W/ok.golden"
before="$(mock_count "$F")"
code="$(get "/api/v1/repositories/${R_PYO}/download/${F}" "$W/ok.bin")"
after="$(mock_count "$F")"
note "GET .../${R_PYO}/download/${F}: HTTP ${code}, $(wc -c < "$W/ok.bin" | tr -d ' ') bytes; upstream GETs ${before} -> ${after}"
[ "$code" = "200" ] || fail_g "unscanned Remote answered ${code}"
cmp -s "$W/ok.bin" "$W/ok.golden" || fail_g "body differs from the upstream bytes"
[ "$after" -gt "$before" ] || fail_g "the upstream was not contacted"
finish_case "the generic route must keep serving Remotes that do not scan"

begin_test "#4442: a scanning Remote pypi refuses its proxied file on /api/v1/repositories/{key}/download and on /general/{key} with 403 scan_on_proxy_route_required (handler pypi), without an upstream GET"
reset_case
F="a${N}-1.0-py3-none-any.whl"
expect_route_required "/api/v1/repositories/${R_PYS}/download/${F}" "$F" pypi "$F"
F="b${N}-1.0-py3-none-any.whl"
expect_route_required "/general/${R_PYS}/${F}" "$F" pypi "$F"
finish_case "a scanning Remote's bytes must not stream around the scan gate on the generic route"

begin_test "#4442: a scanning Remote npm refuses a proxied tarball on the generic route with handler npm, without an upstream GET"
reset_case
F="c${N}-1.0.0.tgz"
expect_route_required "/api/v1/repositories/${R_NPS}/download/c${N}/-/${F}" "$F" npm "c${N}/-/${F}"
finish_case "the refusal must name the format route that gates the file"

begin_test "#4442: a Virtual with a scanning Remote member refuses a member-proxied file on its download and artifacts routes, without an upstream GET"
reset_case
F="d${N}-1.0-py3-none-any.whl"
expect_route_required "/api/v1/repositories/${R_V}/download/${F}" "$F" pypi "$F"
F="e${N}-1.0-py3-none-any.whl"
expect_route_required "/api/v1/repositories/${R_V}/artifacts/${F}" "$F" pypi "$F"
finish_case "the stricter-of-two rule must close the Virtual's generic routes too"

begin_test "CONTROL: the Virtual still serves a path its hosted member owns, on both routes, byte-identical"
reset_case
for route in download artifacts; do
  code="$(get "/api/v1/repositories/${R_V}/${route}/${OWN}" "$W/own.${route}")"
  note "GET .../${R_V}/${route}/${OWN}: HTTP ${code}"
  [ "$code" = "200" ] || fail_g "${route} of the hosted-owned path answered ${code}"
  cmp -s "$W/own.${route}" "$W/hosted.whl" || fail_g "${route} body differs from the hosted bytes"
done
finish_case "hosted content must keep serving through the Virtual"

# =============================================================================
# #4513
# =============================================================================
begin_test "CONTROL: a plain path on the Remote generic repository is fetched from the upstream and served"
reset_case
F="plain${N}.bin"
golden "$F" "$W/plain.golden"
before="$(mock_count "$F")"
code="$(get "/api/v1/repositories/${R_GR}/download/${F}" "$W/plain.bin")"
after="$(mock_count "$F")"
note "GET .../${R_GR}/download/${F}: HTTP ${code}; upstream GETs ${before} -> ${after}"
[ "$code" = "200" ] || fail_g "plain proxied path answered ${code}"
cmp -s "$W/plain.bin" "$W/plain.golden" || fail_g "body differs from the upstream bytes"
[ "$after" -gt "$before" ] || fail_g "the upstream was not contacted"
finish_case "well-formed proxied paths must keep working"

begin_test "#4513: '?' smuggled as %3F and ';' in a proxied path are refused 400 VALIDATION_ERROR with no upstream GET (generic route Remote arm and npm tarball route)"
reset_case
F="q${N}.bin"; expect_ambiguous_400 "/api/v1/repositories/${R_GR}/download/${F}%3FversionId=abc" "$F" "${F}?versionId=abc"
F="s${N}.bin"; expect_ambiguous_400 "/api/v1/repositories/${R_GR}/download/${F};x" "$F" "${F};x"
P="n${N}/-/n${N}-1.0.0.tgz"; expect_ambiguous_400 "/npm/${R_NPS}/${P}%3FversionId=abc" "$P" "${P}?versionId=abc"
P="m${N}/-/m${N}-1.0.0.tgz"; expect_ambiguous_400 "/npm/${R_NPS}/${P};x" "$P" "${P};x"
finish_case "a client path must not be able to smuggle a query or parameter to the upstream"

# =============================================================================
# #4420
# =============================================================================
SHA="$(sha256sum "$W/hosted.whl" | awk '{print $1}')"; SIZE="$(wc -c < "$W/hosted.whl" | tr -d ' ')"
session(){ # <repo> -> http code
  curl -s -o "$W/sess.json" -w '%{http_code}' -X POST -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg r "$1" --arg s "$SHA" --argjson n "$SIZE" '{repository_key:$r,artifact_path:"sess/x.bin",total_size:$n,checksum_sha256:$s}')" \
    "$BASE/api/v1/uploads" || echo 000
}
gput(){ curl -s -o "$W/gput.json" -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" --data-binary @"$W/hosted.whl" \
  "$BASE/api/v1/repositories/$1/artifacts/put/x.bin" || echo 000; }
mpart(){ curl -s -o "$W/mp.json" -w '%{http_code}' -X POST -H "Authorization: Bearer $TOK" -F "file=@$W/hosted.whl" -F 'path=mp/x.bin' \
  "$BASE/api/v1/repositories/$1/artifacts" || echo 000; }

begin_test "CONTROL: a chunked session, a generic PUT and a multipart POST into a local generic repository are 201"
reset_case
s="$(session "$R_LG")"; p="$(gput "$R_LG")"; m="$(mpart "$R_LG")"
note "local: session ${s}, PUT ${p}, multipart ${m}"
[ "$s" = "201" ] || fail_g "session open answered ${s}: $(head -c 150 "$W/sess.json")"
[ "$p" = "201" ] || fail_g "generic PUT answered ${p}"
[ "$m" = "201" ] || fail_g "multipart POST answered ${m}: $(head -c 150 "$W/mp.json")"
finish_case "hosted uploads must keep working"

begin_test "#4420: the same three uploads are 405 into a Remote and 400 into a Virtual, and no session row or artifact row is created"
reset_case
for pair in "${R_GR}:405" "${R_V}:400"; do
  r="${pair%%:*}"; want="${pair##*:}"
  s="$(session "$r")"; p="$(gput "$r")"; m="$(mpart "$r")"
  note "${r}: session ${s} ($(head -c 60 "$W/sess.json")), PUT ${p}, multipart ${m}"
  [ "$s" = "$want" ] || fail_g "${r}: session open answered ${s}, expected ${want}"
  [ "$p" = "$want" ] || fail_g "${r}: generic PUT answered ${p}, expected ${want}"
  [ "$m" = "$want" ] || fail_g "${r}: multipart POST answered ${m}, expected ${want}"
  rows="$(psql_q "SELECT COUNT(*) FROM upload_sessions WHERE repository_key = '${r}'")"
  arts="$(psql_q "SELECT COUNT(*) FROM artifacts a JOIN repositories x ON x.id = a.repository_id WHERE x.key = '${r}' AND a.path IN ('put/x.bin','mp/x.bin') AND NOT a.is_deleted")"
  note "${r}: upload_sessions rows ${rows}, artifact rows ${arts}"
  [ "$rows" = "0" ] || fail_g "${r}: ${rows} upload session(s) were opened"
  [ "$arts" = "0" ] || fail_g "${r}: ${arts} artifact(s) were planted"
done
finish_case "uploads must not plant artifacts in a proxy or a virtual repository"

end_suite
