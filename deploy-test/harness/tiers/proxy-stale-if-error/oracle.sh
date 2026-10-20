#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-stale-if-error/oracle.sh
#   #4581 (PR #4697) a body served under the RFC 5861 stale-if-error grace is
#         marked (Warning: 110 + X-AK-Stale-Since, a counter), the grace is
#         configurable per repository, and past it the upstream error is
#         returned instead of the stale body
#   #4640 (PR #4783) a kept copy after a definitive upstream 404/410 is served
#         WITHOUT the stale markers (the #4697 merge fix)
# See the manifest for THE FIX, the primitives and the gates.
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
MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the mock at (profiles/upstreams.mock-static.yml).
UPSTREAM="http://172.16.${DTF_SLOT}.70/"
TTL_SECS=2                             # per-repo cache TTL for the stale cases
DEFAULT_GRACE=3600                     # PROXY_STALE_IF_ERROR_GRACE_SECS default
SHORT_GRACE=6                          # per-repo grace for the past-grace case
GRACE_MAX=2592000                      # STALE_IF_ERROR_GRACE_MAX_SECS

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# --- mock upstream control ---------------------------------------------------
mock_count(){ curl -s --max-time 5 "${MOCK}/__requests?path=/f/$1" | jqr '.count // empty'; }
mock_mode(){ curl -s --max-time 5 -X POST "${MOCK}/__mode?path=/f/$1&mode=$2" | jqr '.mode // empty'; }
golden(){ curl -s --max-time 10 -o "$2" "${MOCK}/__golden/$1" || true; }

# --- API ---------------------------------------------------------------------
# api <METHOD> <path> [json] -> HTTP code; body in $W/api.body
api(){
  local code
  code="$(curl -s --max-time 30 -o "$W/api.body" -w '%{http_code}' -X "$1" "$BASE$2" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' ${3:+-d "$3"})" || true
  echo "${code:-000}"
}
abody(){ cat "$W/api.body" 2>/dev/null || true; }
mk_remote(){ # <key> -> 0 when created
  [ "$(api POST /api/v1/repositories "$(jq -nc --arg k "$1" --arg u "$UPSTREAM" \
    '{key:$k,name:$k,format:"generic",repo_type:"remote",is_public:false,upstream_url:$u}')")" = "200" ] \
    || [ "$(abody | jqr '.key // empty')" = "$1" ]
}
set_ttl(){ [ "$(api PUT "/api/v1/repositories/$1/cache-ttl" "{\"cache_ttl_seconds\":$2}")" = "200" ]; }
# mk_remote_ttl <key>: a Remote with the short TTL_SECS cache TTL.
mk_remote_ttl(){ if mk_remote "$1"; then set_ttl "$1" "$TTL_SECS"; else return 1; fi; }

# rget <repo> <name> <tag> -> "<http_code> <curl_rc>"; body $W/<tag>.body,
# lower-cased response headers $W/<tag>.hdr
rget(){
  local code rc
  rm -f "$W/$3.body" "$W/$3.hdr.raw"
  code="$(curl -s --max-time 100 -o "$W/$3.body" -D "$W/$3.hdr.raw" -w '%{http_code}' \
    -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/$1/download/f/$2")"; rc=$?
  [ -f "$W/$3.body" ] || : > "$W/$3.body"
  tr -d '\r' < "$W/$3.hdr.raw" 2>/dev/null | sed 's/^\([^:]*\):/\L\1:/' > "$W/$3.hdr" || : > "$W/$3.hdr"
  echo "${code:-000} ${rc}"
}
hdr(){ sed -n "s/^$2: //p" "$W/$1.hdr" 2>/dev/null | head -1 || true; }

# no_stale_markers <tag> <what>: gate that a response carries neither marker.
no_stale_markers(){
  local wv sv
  wv="$(hdr "$1" warning)"; sv="$(hdr "$1" x-ak-stale-since)"
  [ -z "$wv" ] || fail_g "$2 carries 'Warning: ${wv}'"
  [ -z "$sv" ] || fail_g "$2 carries 'X-AK-Stale-Since: ${sv}'"
}
# has_stale_markers <tag> <what> <earliest_epoch>: gate both markers, and that
# X-AK-Stale-Since is an RFC 3339 instant between <earliest_epoch> and now.
has_stale_markers(){
  local wv sv se now
  wv="$(hdr "$1" warning)"; sv="$(hdr "$1" x-ak-stale-since)"
  note "$2: Warning='${wv}' X-AK-Stale-Since='${sv}'"
  case "$wv" in 110*"Response is stale"*) ;; *) fail_g "$2 lacks 'Warning: 110 - \"Response is stale\"' (got '${wv}')";; esac
  if [ -z "$sv" ]; then
    fail_g "$2 lacks X-AK-Stale-Since"
  else
    se="$(date -d "$sv" +%s 2>/dev/null || true)"; now="$(date +%s)"
    if [ -z "$se" ]; then fail_g "$2 X-AK-Stale-Since '${sv}' is not a timestamp"
    elif [ "$se" -lt $(( $3 - 2 )) ] || [ "$se" -gt "$now" ]; then
      fail_g "$2 X-AK-Stale-Since ${sv} is not the entry's expiry (expected between $(date -u -d "@$3" +%FT%TZ) and now)"
    fi
  fi
}
metric(){ # <name> <label> <repo> -> value or empty
  curl -s --max-time 10 -H "Authorization: Bearer $TOK" "$BASE/api/v1/admin/metrics" 2>/dev/null \
    | awk -v m="$1{$2=\"$3\"}" '$1 == m {print $2}' | head -1 || true
}

# prime <repo> <name> <tag>: cold fetch through the Remote; echoes the epoch
# just before the fetch (the entry's expiry is that + TTL). Fails the setup on
# a non-200 or a wrong body.
prime(){
  local t code rc
  golden "$2" "$W/$3.golden"
  t="$(date +%s)"
  read -r code rc <<<"$(rget "$1" "$2" "$3.prime")"
  if [ "$code" != "200" ] || [ "$(sha_of "$W/$3.prime.body")" != "$(sha_of "$W/$3.golden")" ]; then
    echo ""; return 1
  fi
  echo "$t"
}

# =============================================================================
begin_suite "proxy-stale-if-error"

begin_test "setup: admin login, mock upstream, a non-admin user"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-static.yml)"; end_suite
fi
SUF="${RUN_ID##*-}-$$"
SUF="$(printf '%s' "$SUF" | tr -c 'a-zA-Z0-9-' '-')"
U_NAME="sieuser${SUF//-/}"; U_PASS="Sie-${SUF}-Passw0rd!"
api POST /api/v1/users "$(jq -nc --arg u "$U_NAME" --arg p "$U_PASS" '{username:$u,password:$p,email:($u+"@t.test")}')" >/dev/null
T_USER="$(login_as "$U_NAME" "$U_PASS")" || true
[ -n "$T_USER" ] || { infra_fail "could not create/log in ${U_NAME}"; end_suite; }
pass

# =============================================================================
# CONTROL (both images): cold fetch caches, the next fetch is a hit, and
# neither carries a stale marker.
# =============================================================================
begin_test "CONTROL: a cold proxied fetch and the cache hit after it return the upstream bytes with no Warning and no X-AK-Stale-Since"
reset_case
R_FRESH="sie-fresh-${SUF}"
mk_remote "$R_FRESH" || { infra_fail "could not create ${R_FRESH}: $(abody | head -c 200)"; end_suite; }
N="fresh-${SUF}.bin"
golden "$N" "$W/fresh.golden"
read -r code rc <<<"$(rget "$R_FRESH" "$N" fresh1)"
note "cold GET: HTTP ${code}, $(wc -c < "$W/fresh1.body" | tr -d ' ') bytes, upstream GETs $(mock_count "$N")"
[ "$code" = "200" ] && [ "$(sha_of "$W/fresh1.body")" = "$(sha_of "$W/fresh.golden")" ] || fail_g "cold fetch was HTTP ${code} or not the upstream bytes"
no_stale_markers fresh1 "the cold fetch"
c_ok=0
for _i in $(seq 1 40); do
  c0="$(mock_count "$N")"; read -r code rc <<<"$(rget "$R_FRESH" "$N" fresh2)"; c1="$(mock_count "$N")"
  if [ "$code" = "200" ] && [ -n "$c0" ] && [ "$c0" = "$c1" ]; then c_ok=1; break; fi
  sleep 0.25
done
note "cache hit: HTTP ${code}, upstream GETs ${c0} -> ${c1}"
[ "$c_ok" = "1" ] || fail_g "the entry never became a cache hit"
[ "$(sha_of "$W/fresh2.body")" = "$(sha_of "$W/fresh.golden")" ] || fail_g "the cache hit is not the upstream bytes"
no_stale_markers fresh2 "the cache hit"
finish_case "proxy cache control broken (cold fetch, hit, or a marker on a fresh response)"

# =============================================================================
# #4581 FIX: the grace API, default 3600 s, validated, Remote only.
# =============================================================================
begin_test "#4581: GET /api/v1/repositories/{key}/stale-if-error-grace reports the 3600 s default; PUT sets an override, validates the range and is Remote only"
reset_case
code="$(api GET "/api/v1/repositories/${R_FRESH}/stale-if-error-grace")"
note "GET default: HTTP ${code} $(abody | head -c 200)"
[ "$code" = "200" ] || fail_g "GET stale-if-error-grace answered HTTP ${code}, expected 200"
[ "$(abody | jqr '.stale_if_error_grace_seconds')" = "$DEFAULT_GRACE" ] || fail_g "default grace is not ${DEFAULT_GRACE}"
[ "$(abody | jqr '.override_seconds')" = "null" ] || fail_g "a repo with no override reports override_seconds $(abody | jqr '.override_seconds')"
code="$(api PUT "/api/v1/repositories/${R_FRESH}/stale-if-error-grace" '{"stale_if_error_grace_seconds":600}')"
note "PUT 600: HTTP ${code} $(abody | head -c 200)"
[ "$code" = "200" ] && [ "$(abody | jqr '.stale_if_error_grace_seconds')" = "600" ] && [ "$(abody | jqr '.override_seconds')" = "600" ] \
  || fail_g "PUT 600 did not answer 200 with the override and effective value 600"
code="$(api GET "/api/v1/repositories/${R_FRESH}/stale-if-error-grace")"
[ "$code" = "200" ] && [ "$(abody | jqr '.stale_if_error_grace_seconds')" = "600" ] || fail_g "GET after PUT does not read back 600 (HTTP ${code})"
code="$(api PUT "/api/v1/repositories/${R_FRESH}/stale-if-error-grace" "{\"stale_if_error_grace_seconds\":$((GRACE_MAX + 1))}")"
note "PUT ${GRACE_MAX}+1: HTTP ${code} $(abody | head -c 160)"
[ "$code" = "400" ] || fail_g "an out-of-range grace answered HTTP ${code}, expected 400"
R_LOCAL="sie-local-${SUF}"
api POST /api/v1/repositories "$(jq -nc --arg k "$R_LOCAL" '{key:$k,name:$k,format:"generic",repo_type:"local",is_public:false}')" >/dev/null
code="$(api PUT "/api/v1/repositories/${R_LOCAL}/stale-if-error-grace" '{"stale_if_error_grace_seconds":60}')"
note "PUT on a local repo: HTTP ${code} $(abody | head -c 160)"
[ "${code:0:1}" = "4" ] && [ "$code" != "404" ] || fail_g "PUT on a local repo answered HTTP ${code}, expected a 4xx refusal (Remote only)"
finish_case "#4581: the per-repository stale-if-error grace API is missing or wrong"

# FIX artifact-keeper#4815 (RED on main 2f08663f, GREEN from main adfa0206):
# the grace GET checks repository visibility, so an anonymous caller and a
# signed-in user with no grant on the private repo get 404, as for any other
# read of a repository they cannot see. Before the fix both got 200 with the
# grace config.
begin_test "FIX #4815: the grace GET on a private Remote is 404 to an anonymous and to a no-grant caller"
reset_case
for who in anonymous no-grant; do
  if [ "$who" = "anonymous" ]; then
    code="$(curl -s --max-time 10 -o "$W/who.body" -w '%{http_code}' "$BASE/api/v1/repositories/${R_FRESH}/stale-if-error-grace" || true)"
  else
    code="$(curl -s --max-time 10 -o "$W/who.body" -w '%{http_code}' -H "Authorization: Bearer $T_USER" \
      "$BASE/api/v1/repositories/${R_FRESH}/stale-if-error-grace" || true)"
  fi
  note "${who} GET on private ${R_FRESH}: HTTP ${code} $(head -c 200 "$W/who.body" 2>/dev/null)"
  [ "$code" = "404" ] || fail_g "#4815: ${who} GET of the private repo's grace answered HTTP ${code}, expected 404"
done
finish_case "#4815: the grace GET discloses a private repository's settings to a caller who cannot read it"

# =============================================================================
# #4581 FIX: a stale-if-error serve inside the grace is marked and counted.
# =============================================================================
begin_test "#4581: an expired entry whose upstream now answers 500 is served stale inside the default grace with Warning: 110 and X-AK-Stale-Since; the counter moves"
reset_case
R_STALE="sie-stale-${SUF}"
mk_remote_ttl "$R_STALE" || { infra_fail "could not create ${R_STALE} with a ${TTL_SECS}s TTL: $(abody | head -c 200)"; end_suite; }
N="s500-${SUF}.bin"
t0="$(prime "$R_STALE" "$N" s500)" || true
[ -n "$t0" ] || { infra_fail "could not prime ${N}"; end_suite; }
no_stale_markers s500.prime "the priming fetch"
m0="$(metric ak_proxy_stale_if_error_responses_total repo "$R_STALE")"
sleep $(( TTL_SECS + 2 ))
[ "$(mock_mode "$N" e500)" = "e500" ] || { infra_fail "could not set mock mode e500"; end_suite; }
c0="$(mock_count "$N")"
read -r code rc <<<"$(rget "$R_STALE" "$N" s500)"
c1="$(mock_count "$N")"
note "GET past TTL, upstream 500: HTTP ${code}, $(wc -c < "$W/s500.body" | tr -d ' ') bytes; upstream GETs ${c0} -> ${c1}"
[ "$code" = "200" ] && [ "$(sha_of "$W/s500.body")" = "$(sha_of "$W/s500.golden")" ] || fail_g "the stale body was not served (HTTP ${code})"
has_stale_markers s500 "the stale serve" "$(( t0 + TTL_SECS ))"
m1="$(metric ak_proxy_stale_if_error_responses_total repo "$R_STALE")"
note "ak_proxy_stale_if_error_responses_total{repo=\"${R_STALE}\"}: '${m0}' -> '${m1}'"
[ -n "$m1" ] && [ "${m1%.*}" -ge $(( ${m0%.*} + 1 )) ] 2>/dev/null || fail_g "the stale-if-error counter did not move ('${m0}' -> '${m1}')"
code="$(api GET "/api/v1/repositories/${R_STALE}/stale-if-error-grace")"
note "grace GET: HTTP ${code} $(abody | head -c 220)"
[ "$(abody | jqr '.last_stale_served_at // empty')" != "" ] || fail_g "the grace GET does not report last_stale_served_at after a stale serve"
finish_case "#4581: a stale-if-error serve is not marked or not counted"

begin_test "#4581: an upstream that times out (stalls 75 s, past the proxy's 60 s read timeout) on an expired entry is also served stale with the markers"
reset_case
N="stall-${SUF}.bin"
t0="$(prime "$R_STALE" "$N" stall)" || true
[ -n "$t0" ] || { infra_fail "could not prime ${N}"; end_suite; }
sleep $(( TTL_SECS + 2 ))
[ "$(mock_mode "$N" stall)" = "stall" ] || { infra_fail "could not set mock mode stall"; end_suite; }
ts="$(date +%s)"
read -r code rc <<<"$(rget "$R_STALE" "$N" stall)"
dt=$(( $(date +%s) - ts ))
note "GET past TTL, upstream stalled: HTTP ${code} after ${dt}s (the mock answers ok only after 75 s)"
[ "$dt" -lt 74 ] || fail_g "the GET waited ${dt}s, i.e. for the mock's late fresh answer, not the proxy's 60 s timeout"
[ "$(mock_mode "$N" ok)" = "ok" ] || true
[ "$code" = "200" ] && [ "$(sha_of "$W/stall.body")" = "$(sha_of "$W/stall.golden")" ] || fail_g "the stale body was not served on an upstream timeout (HTTP ${code}, curl rc ${rc})"
has_stale_markers stall "the stale serve on timeout" "$(( t0 + TTL_SECS ))"
finish_case "#4581: a stale-if-error serve after an upstream timeout is not marked"

# =============================================================================
# #4581 FIX: a short per-repository grace. Inside it: stale + markers. Past
# it: the upstream error, not the stale body.
# =============================================================================
begin_test "#4581: with a ${SHORT_GRACE} s per-repository grace, a GET inside it serves stale; a GET past it surfaces the upstream error"
reset_case
R_GRACE="sie-grace-${SUF}"
mk_remote_ttl "$R_GRACE" || { infra_fail "could not create ${R_GRACE}"; end_suite; }
code="$(api PUT "/api/v1/repositories/${R_GRACE}/stale-if-error-grace" "{\"stale_if_error_grace_seconds\":${SHORT_GRACE}}")"
note "PUT grace ${SHORT_GRACE}: HTTP ${code} $(abody | head -c 160)"
[ "$code" = "200" ] || fail_g "could not set the per-repository grace (HTTP ${code})"
N="grace-${SUF}.bin"
t0="$(prime "$R_GRACE" "$N" grace)" || true
[ -n "$t0" ] || { infra_fail "could not prime ${N}"; end_suite; }
[ "$(mock_mode "$N" e500)" = "e500" ] || { infra_fail "could not set mock mode e500"; end_suite; }
# inside the grace: expiry is t0+TTL, the grace ends at t0+TTL+SHORT_GRACE.
while [ "$(date +%s)" -lt $(( t0 + TTL_SECS + 2 )) ]; do sleep 0.5; done
read -r code rc <<<"$(rget "$R_GRACE" "$N" gin)"
note "GET at +$(( $(date +%s) - t0 ))s (inside the grace): HTTP ${code}"
[ "$code" = "200" ] && [ "$(sha_of "$W/gin.body")" = "$(sha_of "$W/grace.golden")" ] || fail_g "inside the grace the stale body was not served (HTTP ${code})"
has_stale_markers gin "the in-grace serve" "$(( t0 + TTL_SECS ))"
while [ "$(date +%s)" -lt $(( t0 + TTL_SECS + SHORT_GRACE + 3 )) ]; do sleep 0.5; done
c0="$(mock_count "$N")"
read -r code rc <<<"$(rget "$R_GRACE" "$N" gout)"
c1="$(mock_count "$N")"
note "GET at +$(( $(date +%s) - t0 ))s (past the grace): HTTP ${code}, $(wc -c < "$W/gout.body" | tr -d ' ') bytes, body $(head -c 120 "$W/gout.body" | tr -cd '[:print:]'); upstream GETs ${c0} -> ${c1}"
[ "$code" != "200" ] || fail_g "past the grace the stale body was still served (HTTP 200)"
[ "${code:0:1}" = "5" ] || fail_g "past the grace expected the upstream error as a 5xx, got HTTP ${code}"
[ "$(sha_of "$W/gout.body")" != "$(sha_of "$W/grace.golden")" ] || fail_g "past the grace the response body is the stale artifact"
[ -n "$c1" ] && [ "$c1" -gt "${c0:-0}" ] 2>/dev/null || fail_g "past the grace the upstream was not consulted (${c0} -> ${c1})"
finish_case "#4581: the per-repository grace is not honoured (stale served past it, or not inside it)"

# =============================================================================
# #4640 + the #4697 merge fix: a kept copy after a definitive 404/410 is
# served WITHOUT the stale markers and counted as kept, not stale.
# =============================================================================
begin_test "#4640/#4697: with on_upstream_not_found=keep, an expired entry whose upstream answers 404 / 410 is served without Warning or X-AK-Stale-Since"
reset_case
R_KEEP="sie-keep-${SUF}"
mk_remote_ttl "$R_KEEP" || { infra_fail "could not create ${R_KEEP}"; end_suite; }
code="$(api PUT "/api/v1/repositories/${R_KEEP}/on-upstream-not-found" '{"on_upstream_not_found":"keep"}')"
note "PUT keep: HTTP ${code} $(abody | head -c 160)"
[ "$code" = "200" ] && [ "$(abody | jqr '.on_upstream_not_found')" = "keep" ] || fail_g "could not set on_upstream_not_found=keep (HTTP ${code})"
k0="$(metric ak_proxy_kept_on_upstream_not_found_total repository "$R_KEEP")"
s0="$(metric ak_proxy_stale_if_error_responses_total repo "$R_KEEP")"
for MODE in e404 e410; do
  N="keep-${MODE}-${SUF}.bin"
  t0="$(prime "$R_KEEP" "$N" "k${MODE}")" || true
  [ -n "$t0" ] || { infra_fail "could not prime ${N}"; end_suite; }
  sleep $(( TTL_SECS + 2 ))
  [ "$(mock_mode "$N" "$MODE")" = "$MODE" ] || { infra_fail "could not set mock mode ${MODE}"; end_suite; }
  c0="$(mock_count "$N")"
  read -r code rc <<<"$(rget "$R_KEEP" "$N" "k${MODE}")"
  c1="$(mock_count "$N")"
  note "upstream ${MODE#e}: HTTP ${code}, Warning='$(hdr "k${MODE}" warning)', X-AK-Stale-Since='$(hdr "k${MODE}" x-ak-stale-since)'; upstream GETs ${c0} -> ${c1}"
  [ "$code" = "200" ] && [ "$(sha_of "$W/k${MODE}.body")" = "$(sha_of "$W/k${MODE}.golden")" ] || fail_g "upstream ${MODE#e}: the kept copy was not served (HTTP ${code})"
  [ -n "$c1" ] && [ "$c1" -gt "${c0:-0}" ] 2>/dev/null || fail_g "upstream ${MODE#e}: the expired entry was not revalidated (${c0} -> ${c1})"
  no_stale_markers "k${MODE}" "the kept copy after an upstream ${MODE#e}"
done
k1="$(metric ak_proxy_kept_on_upstream_not_found_total repository "$R_KEEP")"
s1="$(metric ak_proxy_stale_if_error_responses_total repo "$R_KEEP")"
note "kept counter '${k0}' -> '${k1}', stale counter '${s0}' -> '${s1}'"
[ -n "$k1" ] && [ "${k1%.*}" -ge $(( ${k0%.*} + 2 )) ] 2>/dev/null || fail_g "ak_proxy_kept_on_upstream_not_found_total did not count both kept serves"
[ "${s1:-0}" = "${s0:-0}" ] || fail_g "a kept serve was counted as stale-if-error ('${s0}' -> '${s1}')"
finish_case "#4640/#4697: a kept copy after a definitive 404/410 is missing or is marked stale"

# =============================================================================
# CONTROL (both images): the default policy deletes on a definitive 404.
# =============================================================================
begin_test "CONTROL: under the default policy an expired entry whose upstream answers 404 is not served (404, no stale body)"
reset_case
R_DEL="sie-del-${SUF}"
mk_remote_ttl "$R_DEL" || { infra_fail "could not create ${R_DEL}"; end_suite; }
N="del-${SUF}.bin"
t0="$(prime "$R_DEL" "$N" del)" || true
[ -n "$t0" ] || { infra_fail "could not prime ${N}"; end_suite; }
sleep $(( TTL_SECS + 2 ))
[ "$(mock_mode "$N" e404)" = "e404" ] || { infra_fail "could not set mock mode e404"; end_suite; }
read -r code rc <<<"$(rget "$R_DEL" "$N" del)"
note "upstream 404, default policy: HTTP ${code}, $(wc -c < "$W/del.body" | tr -d ' ') bytes"
[ "$code" = "404" ] || fail_g "expected 404, got HTTP ${code}"
[ "$(sha_of "$W/del.body")" != "$(sha_of "$W/del.golden")" ] || fail_g "the deleted entry's body was served"
no_stale_markers del "the 404"
finish_case "the default delete-on-404 policy changed"

end_suite
