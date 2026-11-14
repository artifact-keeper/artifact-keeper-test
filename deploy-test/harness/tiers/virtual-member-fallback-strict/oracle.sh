#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-member-fallback-strict/oracle.sh: a strict virtual answers 503
#   at the download deadline when a higher-priority Remote member hangs, and
#   never serves the lower member's copy (artifact-keeper#5810)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-files` and exported
# BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT, TRIVY_PORT (the mock's
# host port), RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH.
#
# Topology (keys suffixed per run; every Remote is a Maven Remote on the mock,
# each under its own path prefix; J is one jar coordinate):
#   HS  hung (J held 120 s), top member of VS      LO  healthy, J = "low" bytes
#   HD  hung (J held 120 s), top member of VD      NF  404 for J
#   OK  healthy, J = "top" bytes
#   VS  strict    [HS, LO]      VD  default (available) [HD, LO]
#   VN  strict    [NF, LO]      VH  strict    [OK, LO]
# HS and HD are separate Remotes so one member's breaker never shapes the
# other virtual's download.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe captures its status and asserts on it.
set +e

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"   # where the BACKEND reaches the mock
LIMIT_SECS=45                        # deadline 20 s + margin, under the 60 s read timeout

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

mock_put(){ # <path> <file>
  curl -s --max-time 10 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=application/java-archive" | jqr '.bytes // empty'
}
mock_delay(){ curl -s --max-time 5 -X POST "${MOCK}/__delay?path=$1&ms=$2" | jqr '.ms // empty'; }

# get <path> <out>: sets ST (HTTP status) and SECS (wall clock)
get(){
  local t0 t1
  t0="$(date +%s.%N)"
  ST="$(curl -s --max-time 75 -D "$2.h" -o "$2" -w '%{http_code}' \
    -H "Authorization: Bearer $TOK" "${BASE}$1" || true)"
  t1="$(date +%s.%N)"
  SECS="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')"
}
hdr(){ grep -i "^$2:" "$1.h" 2>/dev/null | head -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true; }
snip(){ head -c 200 "$1" 2>/dev/null | tr '\n' ' ' || true; }
under(){ awk -v s="$1" -v l="$2" 'BEGIN{exit !(s < l)}'; }

mk(){ # <key> <type> [upstream]
  local body
  body="$(jq -n --arg k "$1" --arg t "$2" --arg u "${3:-}" \
    '{key:$k,name:$k,format:"maven",repo_type:$t,is_public:false}
     + (if $u == "" then {} else {upstream_url:$u} end)')"
  [ "$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$body" | jqr '.key // empty')" = "$1" ] \
    || SETUP_ERR="${SETUP_ERR} create:$1"
}
virt(){ # <key> <member>...
  local key="$1" prio=1 m c; shift
  mk "$key" virtual
  for m in "$@"; do
    c="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories/${key}/members" \
      -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
      -d "{\"member_key\":\"${m}\",\"priority\":${prio}}" || true)"
    case "$c" in 200|201) ;; *) SETUP_ERR="${SETUP_ERR} member:${key}<-${m}:${c}";; esac
    prio=$((prio + 1))
  done
}
# patch_fallback <key> <json value> -> HTTP status of PATCH /api/v1/repositories/<key>;
# body in $W/put-<key>.json. (#5892's docs say PUT; the route is PATCH.)
patch_fallback(){
  curl -s --max-time 30 -o "$W/put-$1.json" -w '%{http_code}' -X PATCH \
    "$BASE/api/v1/repositories/$1" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "{\"virtual_member_fallback\":$2}" || echo 000
}
fallback_of(){ curl -s --max-time 30 -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/$1" \
  | jqr '.virtual_member_fallback // "absent"'; }

begin_suite "virtual-member-fallback-strict"

begin_test "setup: admin login, upstream jars, hung paths, Remote and virtual repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
SUF="${DTF_SLOT}x${RUN_ID##*-}"
P="vmfs${SUF}"   # mock path prefixes carry the run, so reruns never share state
SETUP_ERR=""
J="com/example/dtfvmfs/lib${SUF}/1.0/lib${SUF}-1.0.jar"
printf 'TOP-MEMBER-COPY %s\n' "$SUF" > "$W/top.jar"
printf 'LOW-MEMBER-COPY %s\n' "$SUF" > "$W/low.jar"
LOW_SHA="$(sha256sum "$W/low.jar" | cut -d' ' -f1)"
TOP_SHA="$(sha256sum "$W/top.jar" | cut -d' ' -f1)"
for pre in hs hd ok; do [ -n "$(mock_put "/${P}-${pre}/${J}" "$W/top.jar")" ] || SETUP_ERR="${SETUP_ERR} mock-put:${pre}"; done
[ -n "$(mock_put "/${P}-lo/${J}" "$W/low.jar")" ] || SETUP_ERR="${SETUP_ERR} mock-put:lo"
for pre in hs hd; do [ "$(mock_delay "/${P}-${pre}/${J}" 120000)" = "120000" ] || SETUP_ERR="${SETUP_ERR} mock-delay:${pre}"; done

HS="vmfs-hs-${SUF}"; HD="vmfs-hd-${SUF}"; LO="vmfs-lo-${SUF}"; NF="vmfs-nf-${SUF}"; OK="vmfs-ok-${SUF}"
VS="vmfs-vs-${SUF}"; VD="vmfs-vd-${SUF}"; VN="vmfs-vn-${SUF}"; VH="vmfs-vh-${SUF}"
for pair in "$HS:hs" "$HD:hd" "$LO:lo" "$NF:nf" "$OK:ok"; do mk "${pair%%:*}" remote "${UP}/${P}-${pair#*:}/"; done
virt "$VS" "$HS" "$LO"
virt "$VD" "$HD" "$LO"
virt "$VN" "$NF" "$LO"
virt "$VH" "$OK" "$LO"
# The controls' strict virtuals: an image without the setting ignores or
# refuses it; either way the control assertions below must hold.
for k in "$VN" "$VH"; do note "PATCH ${k} strict: HTTP $(patch_fallback "$k" '"strict"')"; done
if [ -n "$SETUP_ERR" ]; then fail "setup failed:${SETUP_ERR}"; else pass; fi

# -----------------------------------------------------------------------------
reset_case
begin_test "FIX #5810: virtual_member_fallback is stored and read back; an unknown value or a non-virtual is refused with 400"
c="$(patch_fallback "$VS" '"strict"')"
note "PATCH ${VS} strict: HTTP ${c} $(snip "$W/put-${VS}.json")"
[ "$c" = "200" ] || fail_g "setting strict on a virtual answered ${c}, expected 200"
v="$(fallback_of "$VS")"; d="$(fallback_of "$VD")"; r="$(fallback_of "$LO")"
note "read back: ${VS}=${v} ${VD}=${d} remote ${LO}=${r}"
[ "$v" = "strict" ] || fail_g "the strict virtual reads back '${v}', expected 'strict'"
[ "$d" = "available" ] || fail_g "an untouched virtual reads back '${d}', expected 'available'"
[ "$r" = "absent" ] || fail_g "a Remote reports virtual_member_fallback='${r}', expected it omitted"
c="$(patch_fallback "$VD" '"sometimes"')"
note "PATCH ${VD} sometimes: HTTP ${c}"
[ "$c" = "400" ] || fail_g "an unknown value answered ${c}, expected 400"
c="$(patch_fallback "$LO" '"strict"')"
note "PATCH remote ${LO} strict: HTTP ${c}"
[ "$c" = "400" ] || fail_g "setting it on a Remote answered ${c}, expected 400"
[ "$(fallback_of "$VD")" = "available" ] || fail_g "the refused value changed ${VD}"
finish_case "virtual_member_fallback is not stored, read back or validated"

# -----------------------------------------------------------------------------
reset_case
begin_test "FIX #5810: strict virtual [hung, healthy]: 503 + Retry-After at the download deadline, inside ${LIMIT_SECS}s, with none of the lower member's bytes"
get "/maven/${VS}/${J}" "$W/vs.jar"
ra="$(hdr "$W/vs.jar" retry-after)"
got_sha="$(sha256sum "$W/vs.jar" 2>/dev/null | cut -d' ' -f1)"
note "GET /maven/${VS}/…jar: HTTP ${ST} in ${SECS}s, Retry-After='${ra}', body: $(snip "$W/vs.jar")"
[ "$ST" = "503" ] || fail_g "answered ${ST}, expected 503"
[ -n "$ra" ] || fail_g "no Retry-After"
[ "$got_sha" != "$LOW_SHA" ] || fail_g "served the lower member's copy"
under "$SECS" "$LIMIT_SECS" || fail_g "took ${SECS}s, not inside ${LIMIT_SECS}s (the upstream read timeout is 60 s)"
finish_case "a strict virtual served past, or waited out, its hung top member"

# -----------------------------------------------------------------------------
reset_case
begin_test "CONTROL: default virtual [hung, healthy] serves the lower member's jar inside ${LIMIT_SECS}s"
get "/maven/${VD}/${J}" "$W/vd.jar"
got_sha="$(sha256sum "$W/vd.jar" 2>/dev/null | cut -d' ' -f1)"
note "GET /maven/${VD}/…jar: HTTP ${ST} in ${SECS}s, body: $(snip "$W/vd.jar")"
[ "$ST" = "200" ] || fail_g "answered ${ST}, expected 200"
[ "$got_sha" = "$LOW_SHA" ] || fail_g "did not serve the lower member's bytes"
under "$SECS" "$LIMIT_SECS" || fail_g "took ${SECS}s, not inside ${LIMIT_SECS}s"
finish_case "the default fallback changed"

# -----------------------------------------------------------------------------
reset_case
begin_test "CONTROL: strict virtual [404, healthy] serves the lower member's jar (a 404 is a miss)"
get "/maven/${VN}/${J}" "$W/vn.jar"
got_sha="$(sha256sum "$W/vn.jar" 2>/dev/null | cut -d' ' -f1)"
note "GET /maven/${VN}/…jar: HTTP ${ST} in ${SECS}s"
[ "$ST" = "200" ] || fail_g "answered ${ST}, expected 200"
[ "$got_sha" = "$LOW_SHA" ] || fail_g "did not serve the lower member's bytes"
finish_case "a 404 top member stopped the walk"

# -----------------------------------------------------------------------------
reset_case
begin_test "CONTROL: strict virtual [healthy, healthy] serves the top member's jar"
get "/maven/${VH}/${J}" "$W/vh.jar"
got_sha="$(sha256sum "$W/vh.jar" 2>/dev/null | cut -d' ' -f1)"
note "GET /maven/${VH}/…jar: HTTP ${ST} in ${SECS}s"
[ "$ST" = "200" ] || fail_g "answered ${ST}, expected 200"
[ "$got_sha" = "$TOP_SHA" ] || fail_g "did not serve the top member's bytes"
finish_case "a healthy top member did not serve"

end_suite
