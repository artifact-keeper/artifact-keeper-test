#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-member-metadata-timeout/oracle.sh: a blackholed Remote member
#   fails a virtual's metadata request promptly, naming the member
#   (artifact-keeper#4508)
# =============================================================================
# run.sh has stood up `storage.filesystem upstreams.mock-multi` with
# AK_VIRTUAL_MEMBER_METADATA_TIMEOUT_SECS=8 and exported BASE_URL,
# DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, DTF_DIR,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH. See the manifest for the bug.
#
# Topology (keys suffixed per run; mock = http://172.16.<slot>.91):
#   Maven  MH hosted (lib 1.0 jar + maven-metadata.xml)
#          MRH remote -> /hang/maven (never answers)
#          MV virtual {MH (1), MRH (2)}
#   Helm   HOK remote -> /ok/helm, HHANG remote -> /hang/helm
#          HVT virtual {HOK, HHANG} (strict)   HVP the same + partial merges
#
# Every FIX case is RED on 1.10.0 and GREEN on 1.11.0+; every CONTROL holds on
# both.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
# common.sh turns on errexit; every probe below captures its status and
# asserts on it explicitly.
set +e

SUF="${RUN_ID##*-}$$"
SLOT="${DTF_SLOT}"
MOCK="http://172.16.${SLOT}.91"
MOCK_CTR="ak-dtf${SLOT}-mock-multi"
DEADLINE="${AK_VIRTUAL_MEMBER_METADATA_TIMEOUT_SECS:-8}"
# The fixed image answers at the deadline; anything at or past this is the
# old behaviour (the upstream client's 60 s read timeout).
FAST_LIMIT=15
GIVE_UP=40

MH="vmt-mh-${SUF}";    MRH="vmt-mrh-${SUF}";  MV="vmt-mv-${SUF}"
HOK="vmt-hok-${SUF}";  HHANG="vmt-hhang-${SUF}"
HVT="vmt-hvt-${SUF}";  HVP="vmt-hvp-${SUF}"
GROUP="com/dtf/vmt${SUF}"
JAR="${GROUP}/lib/1.0/lib-1.0.jar"
META="${GROUP}/lib/maven-metadata.xml"

WORK="$(mktemp -d -t dtf-vmt-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# --- helpers ------------------------------------------------------------------
# timed_get PATH OUT -> "<status> <seconds>" (body in OUT, headers in OUT.h)
timed_get() {
  local o
  o="$(curl -s --max-time "$GIVE_UP" -D "$2.h" -o "$2" -w '%{http_code} %{time_total}' \
    "${BASE_URL}$1" 2>/dev/null)"
  echo "${o:-000 ${GIVE_UP}}"
}
send() {
  curl -s --max-time 60 -o "$WORK/send.out" -w '%{http_code}' -X "$1" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" -H 'Content-Type: application/json' \
    ${3:+-d "$3"} "${BASE_URL}$2" 2>/dev/null || echo 000
}
put_file() {  # put_file PATH FILE -> HTTP status
  curl -s --max-time 60 -o "$WORK/put.out" -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" --data-binary "@$2" "${BASE_URL}$1" 2>/dev/null || echo 000
}
hdr() { grep -i "^$2:" "$1.h" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }
ok2xx() { [ "$1" -ge 200 ] 2>/dev/null && [ "$1" -lt 300 ]; }
secs_lt() { awk -v t="$1" -v l="$2" 'BEGIN { exit !(t + 0 < l + 0) }'; }
mkrepo() {
  local st; st="$(send POST /api/v1/repositories "$1")"
  ok2xx "$st" || err+="create $(echo "$1" | jq -r .key) -> ${st} $(head -c 160 "$WORK/send.out" 2>/dev/null); "
}
remote() {  # remote KEY FORMAT UPSTREAM
  mkrepo "{\"key\":\"$1\",\"name\":\"$1\",\"format\":\"$2\",\"repo_type\":\"remote\",\"is_public\":true,\"upstream_url\":\"$3\"}"
}
virtual() {  # virtual KEY FORMAT MEMBER...
  local key="$1" fmt="$2" members="" prio=1 m; shift 2
  for m in "$@"; do
    members+="${members:+,}{\"repo_key\":\"${m}\",\"priority\":${prio}}"; prio=$((prio + 1))
  done
  mkrepo "{\"key\":\"${key}\",\"name\":\"${key}\",\"format\":\"${fmt}\",\"repo_type\":\"virtual\",\"is_public\":true,\"member_repos\":[${members}]}"
}

begin_suite "virtual-member-metadata-timeout (#4508)"

# =============================================================================
# SETUP
# =============================================================================
begin_test "setup: hosted + blackholed Maven members, Helm virtuals over a blackholed member"
auth_admin
err=""
mkrepo "{\"key\":\"${MH}\",\"name\":\"${MH}\",\"format\":\"maven\",\"repo_type\":\"local\",\"is_public\":true}"
remote "$MRH" maven "${MOCK}/hang/maven"
virtual "$MV" maven "$MH" "$MRH"
remote "$HOK" helm "${MOCK}/ok/helm"
remote "$HHANG" helm "${MOCK}/hang/helm"
virtual "$HVT" helm "$HOK" "$HHANG"
virtual "$HVP" helm "$HOK" "$HHANG"
printf 'vmt-jar-%s' "$SUF" > "$WORK/lib.jar"
cat > "$WORK/meta.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>${GROUP//\//.}</groupId>
  <artifactId>lib</artifactId>
  <versioning><latest>1.0</latest><release>1.0</release>
    <versions><version>1.0</version></versions><lastUpdated>20261020000000</lastUpdated></versioning>
</metadata>
XML
st="$(put_file "/maven/${MH}/${JAR}" "$WORK/lib.jar")"; ok2xx "$st" || err+="PUT jar -> ${st}; "
st="$(put_file "/maven/${MH}/${META}" "$WORK/meta.xml")"; ok2xx "$st" || err+="PUT metadata -> ${st}; "
if [ -n "$err" ]; then
  infra_fail "setup did not complete" "$err"
  end_suite
fi
pass
# 1.10.0 has no partial setting; the partial case is the red signal there.
PARTIAL_ST="$(send PATCH "/api/v1/repositories/${HVP}" '{"virtual_metadata_partial":true}')"

# =============================================================================
# CONTROLS: the healthy paths are fast on every image
# =============================================================================
begin_test "CONTROL: the hosted member serves its maven-metadata.xml directly"
read -r st t <<<"$(timed_get "/maven/${MH}/${META}" "$WORK/mh.xml")"
if [ "$st" = "200" ] && grep -q '<version>1.0</version>' "$WORK/mh.xml" && secs_lt "$t" 5; then
  pass
else
  fail "HTTP ${st} in ${t}s, want 200 listing 1.0 in <5s" "$(head -c 300 "$WORK/mh.xml" 2>/dev/null)"
fi

begin_test "CONTROL: an artifact download through the virtual is served by the hosted member, not held by the dead one"
read -r st t <<<"$(timed_get "/maven/${MV}/${JAR}" "$WORK/mv.jar")"
if [ "$st" = "200" ] && cmp -s "$WORK/mv.jar" "$WORK/lib.jar" && secs_lt "$t" 5; then
  pass
else
  fail "HTTP ${st} in ${t}s, want the hosted jar in <5s" "$(head -c 200 "$WORK/mv.jar" 2>/dev/null)"
fi

# =============================================================================
# FIX: the member deadline
# =============================================================================
begin_test "FIX #4508: Maven virtual maven-metadata.xml with a blackholed member answers 502 naming it within the ${DEADLINE}s deadline"
read -r st t <<<"$(timed_get "/maven/${MV}/${META}" "$WORK/mv.xml")"
if [ "$st" = "502" ] && secs_lt "$t" "$FAST_LIMIT" && grep -q "member '${MRH}'" "$WORK/mv.xml" \
   && grep -q "no answer within ${DEADLINE}s (AK_VIRTUAL_MEMBER_METADATA_TIMEOUT_SECS)" "$WORK/mv.xml"; then
  pass
else
  fail "HTTP ${st} after ${t}s; want 502 in <${FAST_LIMIT}s naming '${MRH}' and the ${DEADLINE}s deadline (000 = still waiting at ${GIVE_UP}s)" \
    "$(head -c 300 "$WORK/mv.xml" 2>/dev/null)"
fi

begin_test "FIX #4508: a Helm virtual with a blackholed member answers 502 naming it within the deadline"
read -r st t <<<"$(timed_get "/helm/${HVT}/index.yaml" "$WORK/hvt.yaml")"
if [ "$st" = "502" ] && secs_lt "$t" "$FAST_LIMIT" && grep -q "member '${HHANG}' failed" "$WORK/hvt.yaml" \
   && grep -q "no answer within ${DEADLINE}s" "$WORK/hvt.yaml"; then
  pass
else
  fail "HTTP ${st} after ${t}s; want 502 in <${FAST_LIMIT}s naming '${HHANG}'" "$(head -c 300 "$WORK/hvt.yaml" 2>/dev/null)"
fi

begin_test "FIX #4508: with partial merges the late member is reported in X-AK-Partial-Members and the healthy merge served in time"
read -r st t <<<"$(timed_get "/helm/${HVP}/index.yaml" "$WORK/hvp.yaml")"
pm="$(hdr "$WORK/hvp.yaml" x-ak-partial-members)"
if [ "$st" = "200" ] && secs_lt "$t" "$FAST_LIMIT" && [ "$pm" = "$HHANG" ] && grep -q 'dtfhelm-ok:' "$WORK/hvp.yaml"; then
  pass
else
  fail "HTTP ${st} after ${t}s X-AK-Partial-Members='${pm}' (PATCH ${PARTIAL_ST}); want 200 in <${FAST_LIMIT}s + '${HHANG}'" \
    "$(head -c 300 "$WORK/hvp.yaml" 2>/dev/null)"
fi

begin_test "FIX #4508: the timeouts are counted (ak_virtual_member_metadata_timeouts_total, failures_total reason=timeout)"
st="$(curl -s --max-time 30 -o "$WORK/metrics.txt" -w '%{http_code}' -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null || echo 000)"
mto="$(grep -E "^ak_virtual_member_metadata_timeouts_total\{[^}]*member=\"${MRH}\"" "$WORK/metrics.txt" 2>/dev/null \
  | awk '{s += $NF} END {printf "%d", s}')"
hto="$(grep -E "^ak_virtual_member_metadata_failures_total\{" "$WORK/metrics.txt" 2>/dev/null \
  | grep "member=\"${HHANG}\"" | grep 'reason="timeout"' | awk '{s += $NF} END {printf "%d", s}')"
if [ "$st" = "200" ] && [ "${mto:-0}" -ge 1 ] && [ "${hto:-0}" -ge 2 ]; then
  pass
else
  fail "metrics HTTP ${st}; timeouts_total{member=${MRH}}=${mto:-0} (want >=1), failures_total{member=${HHANG},reason=timeout}=${hto:-0} (want >=2)" \
    "$(grep -E '^ak_virtual_member_metadata_(timeouts|failures)_total' "$WORK/metrics.txt" 2>/dev/null | head -6)"
fi

begin_test "CONTROL: the blackholed members were really asked (the mock logged the hung requests)"
hung="$(docker logs "$MOCK_CTR" 2>&1 | grep -c '^MOCKMULTI GET /hang/.* HANG$')"
if [ "${hung:-0}" -ge 2 ]; then
  pass
else
  fail "mock logged ${hung:-0} hung requests, want >= 2 (the oracle would be hollow)" \
    "$(docker logs "$MOCK_CTR" 2>&1 | tail -5)"
fi

end_suite
