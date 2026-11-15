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
#
# OCI (Docker Remotes on the same mock; image `app`, tag `latest`):
#   O5S answers 503 for /v2/app/manifests/latest, top member of OVS
#   O5D answers 503 for /v2/app/manifests/latest, top member of OVD
#   OLO healthy, `latest` = the "low" manifest
#   OTA anonymous; its `latest` answers 401 with a Bearer challenge whose
#       realm (on the mock) refuses the token request with 401
#   OVS strict    [O5S, OLO]     OVD default (available) [O5D, OLO]
#   OVT strict    [OTA, OLO]
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
mock_put_manifest(){ # <path> <file>
  curl -s --max-time 10 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=application%2Fvnd.oci.image.manifest.v1%2Bjson" | jqr '.bytes // empty'
}
mock_status(){ # <path> <code> [WWW-Authenticate]
  local ch=""
  [ -n "${3:-}" ] && ch="&challenge=$(jq -rn --arg v "$3" '$v|@uri')"
  curl -s --max-time 5 -X POST "${MOCK}/__status?path=$1&code=$2${ch}" | jqr '.code // empty'
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

mk(){ # <key> <type> [upstream] [format]
  local body
  body="$(jq -n --arg k "$1" --arg t "$2" --arg u "${3:-}" --arg f "${4:-maven}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false}
     + (if $u == "" then {} else {upstream_url:$u} end)')"
  [ "$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$body" | jqr '.key // empty')" = "$1" ] \
    || SETUP_ERR="${SETUP_ERR} create:$1"
}
virt(){ # <key> <member>...   (VFMT: the virtual's format, maven by default)
  local key="$1" prio=1 m c; shift
  mk "$key" virtual "" "${VFMT:-maven}"
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
OCI_ACCEPT='application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json'
# oci_get <virtual> <out>: GET /v2/<virtual>/app/manifests/latest; sets ST
oci_get(){
  ST="$(curl -s --max-time 75 -D "$2.h" -o "$2" -w '%{http_code}' -u "admin:${ADMIN_PASS}" \
    -H "Accept: ${OCI_ACCEPT}" "${BASE}/v2/$1/app/manifests/latest" || true)"
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
# OCI: two manifests that differ, the lower member's under `latest`, and the
# top members' `latest` forced to 503.
mf(){ jq -nc --arg m "$1" '{schemaVersion:2,mediaType:"application/vnd.oci.image.manifest.v1+json",
  config:{mediaType:"application/vnd.oci.image.config.v1+json",size:2,digest:"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
  layers:[],annotations:{"dtf.member":$m}}'; }
mf "low-${SUF}" > "$W/low.manifest"
OLOW_SHA="$(sha256sum "$W/low.manifest" | cut -d' ' -f1)"
OM="v2/app/manifests/latest"
[ -n "$(mock_put_manifest "/${P}-olo/${OM}" "$W/low.manifest")" ] || SETUP_ERR="${SETUP_ERR} mock-put:olo"
for pre in o5s o5d; do [ "$(mock_status "/${P}-${pre}/${OM}" 503)" = "503" ] || SETUP_ERR="${SETUP_ERR} mock-status:${pre}"; done
TREALM="${UP}/${P}-ota/token"
[ "$(mock_status "/${P}-ota/${OM}" 401 "Bearer realm=\"${TREALM}\",service=\"dtf-mock\",scope=\"repository:app:pull\"")" = "401" ] \
  || SETUP_ERR="${SETUP_ERR} mock-status:ota"
[ "$(mock_status "/${P}-ota/token" 401)" = "401" ] || SETUP_ERR="${SETUP_ERR} mock-status:ota-token"
O5S="vmfs-o5s-${SUF}"; O5D="vmfs-o5d-${SUF}"; OLO="vmfs-olo-${SUF}"; OTA="vmfs-ota-${SUF}"
OVS="vmfs-ovs-${SUF}"; OVD="vmfs-ovd-${SUF}"; OVT="vmfs-ovt-${SUF}"
for pair in "$O5S:o5s" "$O5D:o5d" "$OLO:olo" "$OTA:ota"; do mk "${pair%%:*}" remote "${UP}/${P}-${pair#*:}/" docker; done
VFMT=docker virt "$OVS" "$O5S" "$OLO"
VFMT=docker virt "$OVD" "$O5D" "$OLO"
VFMT=docker virt "$OVT" "$OTA" "$OLO"
for k in "$VN" "$VH" "$OVS" "$OVT"; do note "PATCH ${k} strict: HTTP $(patch_fallback "$k" '"strict"')"; done
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

# -----------------------------------------------------------------------------
reset_case
begin_test "FIX #5810: strict Docker virtual [5xx, healthy]: a manifest pull by tag answers 503 + Retry-After, not the lower member's manifest"
oci_get "$OVS" "$W/ovs.manifest"
ra="$(hdr "$W/ovs.manifest" retry-after)"
got_sha="$(sha256sum "$W/ovs.manifest" 2>/dev/null | cut -d' ' -f1)"
note "GET /v2/${OVS}/app/manifests/latest: HTTP ${ST}, Retry-After='${ra}', body: $(snip "$W/ovs.manifest")"
[ "$ST" = "503" ] || fail_g "answered ${ST}, expected 503"
[ -n "$ra" ] || fail_g "no Retry-After"
[ "$got_sha" != "$OLOW_SHA" ] || fail_g "served the lower member's manifest"
finish_case "a strict Docker virtual served a lower member's tag past its 5xx top member"

# -----------------------------------------------------------------------------
reset_case
begin_test "CONTROL: default Docker virtual [5xx, healthy] serves the lower member's manifest by tag"
oci_get "$OVD" "$W/ovd.manifest"
got_sha="$(sha256sum "$W/ovd.manifest" 2>/dev/null | cut -d' ' -f1)"
note "GET /v2/${OVD}/app/manifests/latest: HTTP ${ST}, body: $(snip "$W/ovd.manifest")"
[ "$ST" = "200" ] || fail_g "answered ${ST}, expected 200"
[ "$got_sha" = "$OLOW_SHA" ] || fail_g "did not serve the lower member's manifest"
asked="$(curl -s --max-time 5 "${MOCK}/__requests?path=/${P}-o5d/${OM}" | jqr '.get // 0')"
note "the 5xx top member was asked ${asked:-0} time(s)"
[ "${asked:-0}" -ge 1 ] 2>/dev/null || fail_g "the 5xx top member was never asked, so the walk did not pass over it"
finish_case "the default OCI fallback changed"

# -----------------------------------------------------------------------------
# A CONTROL, not a FIX: it holds on an image without strict mode too. It pins
# that strict mode reads an anonymous token refusal as a miss (#4527), which
# the first OCI strict commit (af614f19) got wrong.
reset_case
begin_test "CONTROL: strict Docker virtual [anonymous Remote whose token endpoint answers 401, healthy] walks on and serves the lower member's manifest"
oci_get "$OVT" "$W/ovt.manifest"
got_sha="$(sha256sum "$W/ovt.manifest" 2>/dev/null | cut -d' ' -f1)"
note "GET /v2/${OVT}/app/manifests/latest: HTTP ${ST}, body: $(snip "$W/ovt.manifest")"
[ "$ST" = "200" ] || fail_g "answered ${ST}, expected 200 (a token refusal is a miss)"
[ "$got_sha" = "$OLOW_SHA" ] || fail_g "did not serve the lower member's manifest"
asked="$(curl -s --max-time 5 "${MOCK}/__requests?path=/${P}-ota/token" | jqr '.get // 0')"
note "the refusing token endpoint was asked ${asked:-0} time(s)"
[ "${asked:-0}" -ge 1 ] 2>/dev/null || fail_g "the token endpoint was never asked, so the case did not exercise a token refusal"
finish_case "a strict virtual stopped at an anonymous token refusal"

end_suite
