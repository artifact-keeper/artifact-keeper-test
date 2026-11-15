#!/usr/bin/env bash
# =============================================================================
# tiers/virtual-metadata-member-outage/oracle.sh
#   #5504 a virtual's artifact and checksum walks answer 503 for a member 5xx
#         (404 only for a miss or a permanent 4xx); a hosted member whose
#         object is gone answers .sha1 503
#   #5616 stale-if-error markers on a Remote's maven-metadata.xml and on a
#         generic Virtual serving through a stale member
#   #5621 virtual metadata merges step past an unavailable or refusing member
#   #5622 an Alpine Virtual's APKINDEX includes hosted members and answers 503
#         when no member can contribute
# See the manifest for the bugs and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# TRIVY_PORT (the mock's published control port), RELEASE_GATE=1,
# JUNIT_OUTPUT_DIR, COMMON_SH.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DB_CONTAINER:?}"
: "${DTF_SLOT:?}"; : "${TRIVY_PORT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

BASE="$BASE_URL"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
UP="http://172.16.${DTF_SLOT}.76"   # where the BACKEND reaches the mock
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
DBC="$DB_CONTAINER"

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

# --- mock upstream control (profiles/upstreams.mock-files.yml) ---------------
mock_put(){ # <path> <file> [content-type]
  curl -s --max-time 10 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}" | jqr '.bytes // empty'
}
mock_status(){ curl -s --max-time 5 -X POST "${MOCK}/__status?path=$1&code=$2" | jqr '.code // empty'; }
mock_delay(){ curl -s --max-time 5 -X POST "${MOCK}/__delay?path=$1&ms=$2" | jqr '.ms // empty'; }

# get <path> <out> -> sets ST (status) and SECS (wall time); headers in <out>.h
get(){
  local t0 t1
  t0="$(date +%s.%N)"
  ST="$(curl -s --max-time 60 -D "$2.h" -o "$2" -w '%{http_code}' \
    -H "Authorization: Bearer $TOK" "${BASE}$1" || true)"
  t1="$(date +%s.%N)"
  SECS="$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')"
}
hdr(){ grep -i "^$2:" "$1.h" 2>/dev/null | head -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true; }
snip(){ head -c 220 "$1" 2>/dev/null | tr '\n' ' ' || true; }

mk(){ # <key> <format> <type> [upstream]
  local body
  body="$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false}
     + (if $u == "" then {} else {upstream_url:$u} end)')"
  [ "$(curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$body" | jqr '.key // empty')" = "$1" ] \
    || SETUP_ERR="${SETUP_ERR} create:$1"
}
virt(){ # <key> <format> <member>...
  local key="$1" fmt="$2" prio=1 m c; shift 2
  mk "$key" "$fmt" virtual
  for m in "$@"; do
    c="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories/${key}/members" \
      -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
      -d "{\"member_key\":\"${m}\",\"priority\":${prio}}" || true)"
    case "$c" in 200|201) ;; *) SETUP_ERR="${SETUP_ERR} member:${key}<-${m}:${c}";; esac
    prio=$((prio + 1))
  done
}
set_ttl(){ # <key> <secs>
  local c
  c="$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$BASE/api/v1/repositories/$1/cache-ttl" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "{\"cache_ttl_seconds\":$2}" || true)"
  [ "$c" = "200" ] || SETUP_ERR="${SETUP_ERR} cache-ttl:$1:${c}"
}

# check_partial <file> <member-key> <label>: 200 + X-AK-Partial-Members names it + no-store
check_partial(){
  local pm cc
  pm="$(hdr "$1" x-ak-partial-members)"; cc="$(hdr "$1" cache-control)"
  case ",${pm// /}," in *",$2,"*) ;; *) fail_g "$3: X-AK-Partial-Members='${pm}', expected it to name '$2'";; esac
  case "$cc" in *no-store*) ;; *) fail_g "$3: Cache-Control='${cc}', expected no-store on a partial merge";; esac
}
check_stale(){ # <file> <label>
  local wv sv
  wv="$(hdr "$1" warning)"; sv="$(hdr "$1" x-ak-stale-since)"
  note "$2: Warning='${wv}' X-AK-Stale-Since='${sv}'"
  case "$wv" in 110*) ;; *) fail_g "$2: no 'Warning: 110' (got '${wv}')";; esac
  [ -n "$sv" ] || fail_g "$2: no X-AK-Stale-Since"
}

# =============================================================================
begin_suite "virtual-metadata-member-outage"

begin_test "setup: admin login, upstream documents, Remote / hosted / virtual repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
SUF="${DTF_SLOT}x${RUN_ID##*-}"
P="vmo${SUF}"   # every mock path prefix carries the run, so reruns never share state
SETUP_ERR=""

# --- Helm --------------------------------------------------------------------
helm_index(){ # <chart> <out>
  cat > "$2" <<Y
apiVersion: v1
entries:
  $1:
  - apiVersion: v2
    name: $1
    version: 1.0.0
    created: "2020-01-01T00:00:00Z"
    digest: 0000000000000000000000000000000000000000000000000000000000000000
    urls:
    - charts/$1-1.0.0.tgz
generated: "2020-01-01T00:00:00Z"
Y
}
CH_A="dtfha${SUF}"; CH_B="dtfhb${SUF}"
helm_index "$CH_A" "$W/ha.yaml"; helm_index "$CH_B" "$W/hb.yaml"
[ -n "$(mock_put "/${P}/hok/index.yaml" "$W/ha.yaml" application/x-yaml)" ] || SETUP_ERR="${SETUP_ERR} mock:hok"
[ -n "$(mock_put "/${P}/hok2/index.yaml" "$W/hb.yaml" application/x-yaml)" ] || SETUP_ERR="${SETUP_ERR} mock:hok2"
[ -n "$(mock_put "/${P}/hhang/index.yaml" "$W/hb.yaml" application/x-yaml)" ] || SETUP_ERR="${SETUP_ERR} mock:hhang"
[ "$(mock_status "/${P}/h503/index.yaml" 503)" = "503" ] || SETUP_ERR="${SETUP_ERR} mock:h503"
[ "$(mock_status "/${P}/h403/index.yaml" 403)" = "403" ] || SETUP_ERR="${SETUP_ERR} mock:h403"
[ "$(mock_delay "/${P}/hhang/index.yaml" 120000)" = "120000" ] || SETUP_ERR="${SETUP_ERR} mock:hhang-delay"
H_OK="vmo-hok-${SUF}"; H_OK2="vmo-hok2-${SUF}"; H_503="vmo-h503-${SUF}"; H_403="vmo-h403-${SUF}"; H_HANG="vmo-hhang-${SUF}"
mk "$H_OK" helm remote "${UP}/${P}/hok"
mk "$H_OK2" helm remote "${UP}/${P}/hok2"
mk "$H_503" helm remote "${UP}/${P}/h503"
mk "$H_403" helm remote "${UP}/${P}/h403"
mk "$H_HANG" helm remote "${UP}/${P}/hhang"
HV_OK="vmo-hvok-${SUF}"; HV_503="vmo-hv503-${SUF}"; HV_403="vmo-hv403-${SUF}"; HV_DOWN="vmo-hvdown-${SUF}"; HV_HANG="vmo-hvhang-${SUF}"
virt "$HV_OK" helm "$H_OK" "$H_OK2"
virt "$HV_503" helm "$H_503" "$H_OK"
virt "$HV_403" helm "$H_403" "$H_OK"
virt "$HV_DOWN" helm "$H_503"
virt "$HV_HANG" helm "$H_HANG" "$H_OK"

# --- Maven -------------------------------------------------------------------
G="com/dtf/${P}"
JAR_REL="w/1.0/w-1.0.jar"
for m in m503 m403; do
  code=503; [ "$m" = "m403" ] && code=403
  for f in "$JAR_REL" "${JAR_REL}.sha1"; do
    [ "$(mock_status "/${P}/${m}/${G}/${f}" "$code")" = "$code" ] || SETUP_ERR="${SETUP_ERR} mock:${m}:${f}"
  done
done
cat > "$W/meta.xml" <<X
<?xml version="1.0" encoding="UTF-8"?>
<metadata><groupId>com.dtf.${P}</groupId><artifactId>md</artifactId><versioning><latest>1.0</latest><release>1.0</release><versions><version>1.0</version></versions><lastUpdated>20200101000000</lastUpdated></versioning></metadata>
X
[ -n "$(mock_put "/${P}/mok/${G}/md/maven-metadata.xml" "$W/meta.xml" text/xml)" ] || SETUP_ERR="${SETUP_ERR} mock:mok"
[ -n "$(mock_put "/${P}/mhang/${G}/md/maven-metadata.xml" "$W/meta.xml" text/xml)" ] || SETUP_ERR="${SETUP_ERR} mock:mhang"
[ "$(mock_delay "/${P}/mhang/${G}/md/maven-metadata.xml" 120000)" = "120000" ] || SETUP_ERR="${SETUP_ERR} mock:mhang-delay"
[ "$(mock_status "/${P}/m503/${G}/md/maven-metadata.xml" 503)" = "503" ] || SETUP_ERR="${SETUP_ERR} mock:m503-meta"
cat > "$W/stale.xml" <<X
<?xml version="1.0" encoding="UTF-8"?>
<metadata><groupId>com.dtf.${P}</groupId><artifactId>st</artifactId><versioning><latest>2.0</latest><release>2.0</release><versions><version>2.0</version></versions><lastUpdated>20200101000000</lastUpdated></versioning></metadata>
X
[ -n "$(mock_put "/${P}/mstale/${G}/st/maven-metadata.xml" "$W/stale.xml" text/xml)" ] || SETUP_ERR="${SETUP_ERR} mock:mstale"
[ -n "$(mock_put "/${P}/mstale/${G}/st/maven-metadata.xml.sha1" <(printf '%s' "$(sha1sum "$W/stale.xml" | awk '{print $1}')") text/plain)" ] || SETUP_ERR="${SETUP_ERR} mock:mstale-sha1"
M_404="vmo-m404-${SUF}"; M_503="vmo-m503-${SUF}"; M_403="vmo-m403-${SUF}"; M_OK="vmo-mok-${SUF}"; M_HANG="vmo-mhang-${SUF}"
M_STALE="vmo-mstale-${SUF}"; M_HOST="vmo-mhost-${SUF}"
mk "$M_404" maven remote "${UP}/${P}/m404/"
mk "$M_503" maven remote "${UP}/${P}/m503/"
mk "$M_403" maven remote "${UP}/${P}/m403/"
mk "$M_OK" maven remote "${UP}/${P}/mok/"
mk "$M_HANG" maven remote "${UP}/${P}/mhang/"
mk "$M_STALE" maven remote "${UP}/${P}/mstale/"
mk "$M_HOST" maven local
MV_503="vmo-mv503-${SUF}"; MV_403="vmo-mv403-${SUF}"; MV_HANG="vmo-mvhang-${SUF}"; MV_DOWN="vmo-mvdown-${SUF}"; MV_HOST="vmo-mvhost-${SUF}"
virt "$MV_503" maven "$M_404" "$M_503"
virt "$MV_403" maven "$M_404" "$M_403"
virt "$MV_HANG" maven "$M_HANG" "$M_OK"
virt "$MV_DOWN" maven "$M_503"
virt "$MV_HOST" maven "$M_HOST"

# --- generic -----------------------------------------------------------------
[ "$(mock_status "/${P}/g503/v/f.bin" 503)" = "503" ] || SETUP_ERR="${SETUP_ERR} mock:g503"
head -c 4000 /dev/urandom > "$W/gstale.bin"
[ -n "$(mock_put "/${P}/gstale/s/direct.bin" "$W/gstale.bin")" ] || SETUP_ERR="${SETUP_ERR} mock:gstale-direct"
[ -n "$(mock_put "/${P}/gstale/s/virtual.bin" "$W/gstale.bin")" ] || SETUP_ERR="${SETUP_ERR} mock:gstale-virtual"
GR_404="vmo-g404-${SUF}"; GR_503="vmo-g503-${SUF}"; GR_STALE="vmo-gstale-${SUF}"
mk "$GR_404" generic remote "${UP}/${P}/g404/"
mk "$GR_503" generic remote "${UP}/${P}/g503/"
mk "$GR_STALE" generic remote "${UP}/${P}/gstale/"
GV_503="vmo-gv503-${SUF}"; GV_STALE="vmo-gvstale-${SUF}"
virt "$GV_503" generic "$GR_404" "$GR_503"
virt "$GV_STALE" generic "$GR_STALE"

# --- conda -------------------------------------------------------------------
CPKG="dtfc${SUF}"
jq -n --arg n "$CPKG" '{info:{subdir:"noarch"},repodata_version:1,
  packages:{($n+"-1.0-0.tar.bz2"):{name:$n,version:"1.0",build:"0",build_number:0,depends:[],subdir:"noarch",md5:"00000000000000000000000000000000",size:1}},
  "packages.conda":{}}' > "$W/repodata.json"
[ -n "$(mock_put "/${P}/cok/noarch/repodata.json" "$W/repodata.json" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:cok"
for f in repodata.json repodata.json.zst repodata.json.bz2; do
  [ "$(mock_status "/${P}/c500/noarch/${f}" 500)" = "500" ] || SETUP_ERR="${SETUP_ERR} mock:c500:${f}"
done
C_OK="vmo-cok-${SUF}"; C_500="vmo-c500-${SUF}"; CV="vmo-cv-${SUF}"
mk "$C_OK" conda remote "${UP}/${P}/cok"
mk "$C_500" conda remote "${UP}/${P}/c500"
virt "$CV" conda "$C_500" "$C_OK"

# --- alpine ------------------------------------------------------------------
APK_DIR="v3.20/main/x86_64"
APKN_H="dtfvh${SUF}"; APKN_R="dtfvr${SUF}"
d="$W/apkh"; mkdir -p "$d/usr/share/$APKN_H"; echo "dtf ${SUF}" > "$d/usr/share/$APKN_H/x"
cat > "$d/.PKGINFO" <<PI
pkgname = ${APKN_H}
pkgver = 1.0-r0
pkgdesc = DTF virtual APKINDEX fixture
url = https://example.invalid/${APKN_H}
builddate = 1700000000
packager = DTF <dtf@example.invalid>
size = 16
arch = x86_64
origin = ${APKN_H}
license = MIT
PI
(cd "$d" && tar -czf "$W/hosted.apk" .PKGINFO usr)
mkdir -p "$W/idx"
printf 'C:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\nP:%s\nV:1.0-r0\nA:x86_64\nS:16\nI:16\nT:DTF upstream fixture\nU:https://example.invalid\nL:MIT\no:%s\n\n' \
  "$APKN_R" "$APKN_R" > "$W/idx/APKINDEX"
printf 'dtf upstream index\n' > "$W/idx/DESCRIPTION"
(cd "$W/idx" && tar -czf "$W/APKINDEX.tar.gz" DESCRIPTION APKINDEX)
[ -n "$(mock_put "/${P}/apkok/${APK_DIR}/APKINDEX.tar.gz" "$W/APKINDEX.tar.gz" application/gzip)" ] || SETUP_ERR="${SETUP_ERR} mock:apkok"
[ "$(mock_status "/${P}/apkdown/${APK_DIR}/APKINDEX.tar.gz" 503)" = "503" ] || SETUP_ERR="${SETUP_ERR} mock:apkdown"
A_H="vmo-ah-${SUF}"; A_OK="vmo-aok-${SUF}"; A_DOWN="vmo-adown-${SUF}"; A_404="vmo-a404-${SUF}"
mk "$A_H" alpine local
mk "$A_OK" alpine remote "${UP}/${P}/apkok"
mk "$A_DOWN" alpine remote "${UP}/${P}/apkdown"
mk "$A_404" alpine remote "${UP}/${P}/apk404"
AV_H="vmo-avh-${SUF}"; AV_HD="vmo-avhd-${SUF}"; AV_HR="vmo-avhr-${SUF}"; AV_R="vmo-avr-${SUF}"; AV_D="vmo-avd-${SUF}"; AV_404="vmo-av404-${SUF}"
virt "$AV_H" alpine "$A_H"
virt "$AV_HD" alpine "$A_H" "$A_DOWN"
virt "$AV_HR" alpine "$A_H" "$A_OK"
virt "$AV_R" alpine "$A_OK"
virt "$AV_D" alpine "$A_DOWN"
virt "$AV_404" alpine "$A_404"

# Uploads: the hosted .apk and the hosted Maven jar.
up(){ # <path> <file>
  local c
  c="$(curl -s -o "$W/up.out" -w '%{http_code}' --max-time 60 -X PUT -H "Authorization: Bearer $TOK" \
    --data-binary @"$2" "${BASE}$1" || true)"
  case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} upload:$1:${c}:$(snip "$W/up.out")";; esac
}
up "/alpine/${A_H}/${APK_DIR}/${APKN_H}-1.0-r0.apk" "$W/hosted.apk"
head -c 3000 /dev/urandom > "$W/h.jar"
up "/maven/${M_HOST}/${G}/h/1.0/h-1.0.jar" "$W/h.jar"

set_ttl "$M_STALE" 2
set_ttl "$GR_STALE" 2
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
pass

# =============================================================================
# #5621: Helm index.yaml merges
# =============================================================================
begin_test "CONTROL: a Helm virtual over two healthy Remotes merges both charts, not partial"
reset_case
get "/helm/${HV_OK}/index.yaml" "$W/hv-ok.yaml"
[ "$ST" = "200" ] || fail_g "index.yaml answered ${ST}: $(snip "$W/hv-ok.yaml")"
grep -q "${CH_A}:" "$W/hv-ok.yaml" && grep -q "${CH_B}:" "$W/hv-ok.yaml" || fail_g "the merge lacks ${CH_A} or ${CH_B}: $(snip "$W/hv-ok.yaml")"
[ -z "$(hdr "$W/hv-ok.yaml" x-ak-partial-members)" ] || fail_g "a healthy merge carries X-AK-Partial-Members"
finish_case "a healthy Helm merge was not served"

begin_test "FIX #5621: a Helm virtual [503 member, healthy member] serves the healthy merge marked partial, not 502"
reset_case
get "/helm/${HV_503}/index.yaml" "$W/hv-503.yaml"
note "index.yaml -> ${ST}: $(snip "$W/hv-503.yaml")"
[ "$ST" = "200" ] || fail_g "index.yaml answered ${ST}, expected 200"
grep -q "${CH_A}:" "$W/hv-503.yaml" || fail_g "the healthy member's chart ${CH_A} is missing"
check_partial "$W/hv-503.yaml" "$H_503" "helm [503, ok]"
finish_case "one unavailable member failed the whole Helm index"

begin_test "FIX #5621: a Helm virtual [403 member, healthy member] treats the permanent 403 as a miss (200, not partial)"
reset_case
get "/helm/${HV_403}/index.yaml" "$W/hv-403.yaml"
note "index.yaml -> ${ST}: $(snip "$W/hv-403.yaml")"
[ "$ST" = "200" ] || fail_g "index.yaml answered ${ST}, expected 200"
grep -q "${CH_A}:" "$W/hv-403.yaml" || fail_g "the healthy member's chart ${CH_A} is missing"
[ -z "$(hdr "$W/hv-403.yaml" x-ak-partial-members)" ] || fail_g "a permanent 403 was reported partial: '$(hdr "$W/hv-403.yaml" x-ak-partial-members)'"
finish_case "a permanently refusing member failed the whole Helm index"

begin_test "FIX #5621: a Helm virtual whose only member is unavailable answers 503 with Retry-After"
reset_case
get "/helm/${HV_DOWN}/index.yaml" "$W/hv-down.yaml"
note "index.yaml -> ${ST} Retry-After='$(hdr "$W/hv-down.yaml" retry-after)': $(snip "$W/hv-down.yaml")"
[ "$ST" = "503" ] || fail_g "index.yaml answered ${ST}, expected 503"
[ -n "$(hdr "$W/hv-down.yaml" retry-after)" ] || fail_g "no Retry-After"
finish_case "an all-unavailable Helm virtual did not answer a retryable 503"

begin_test "FIX #5621: a Helm virtual [hung member, healthy member] serves the healthy merge marked partial within 40 s"
reset_case
get "/helm/${HV_HANG}/index.yaml" "$W/hv-hang.yaml"
note "index.yaml -> ${ST} after ${SECS}s: $(snip "$W/hv-hang.yaml")"
[ "$ST" = "200" ] || fail_g "index.yaml answered ${ST}, expected 200"
grep -q "${CH_A}:" "$W/hv-hang.yaml" || fail_g "the healthy member's chart ${CH_A} is missing"
check_partial "$W/hv-hang.yaml" "$H_HANG" "helm [hung, ok]"
awk -v s="$SECS" 'BEGIN{exit !(s < 40)}' || fail_g "took ${SECS}s, expected < 40 s"
finish_case "a hung member failed the whole Helm index"

# =============================================================================
# #5621: Maven maven-metadata.xml merges
# =============================================================================
begin_test "FIX #5621: Maven virtual metadata [hung member, healthy member] serves the healthy versions marked partial within 40 s"
reset_case
get "/maven/${MV_HANG}/${G}/md/maven-metadata.xml" "$W/mv-hang.xml"
note "maven-metadata.xml -> ${ST} after ${SECS}s: $(snip "$W/mv-hang.xml")"
[ "$ST" = "200" ] || fail_g "maven-metadata.xml answered ${ST}, expected 200"
grep -q "<version>1.0</version>" "$W/mv-hang.xml" || fail_g "the healthy member's version 1.0 is missing"
check_partial "$W/mv-hang.xml" "$M_HANG" "maven [hung, ok]"
awk -v s="$SECS" 'BEGIN{exit !(s < 40)}' || fail_g "took ${SECS}s, expected < 40 s"
finish_case "a hung member failed the Maven metadata merge"

begin_test "FIX #5621: Maven virtual metadata whose only member is unavailable answers 503, not 404 'Metadata not found' (fixed by #5670)"
reset_case
get "/maven/${MV_DOWN}/${G}/md/maven-metadata.xml" "$W/mv-down.xml"
note "maven-metadata.xml -> ${ST} Retry-After='$(hdr "$W/mv-down.xml" retry-after)': $(snip "$W/mv-down.xml")"
[ "$ST" = "503" ] || fail_g "maven-metadata.xml answered ${ST}, expected 503"
finish_case "an all-unavailable Maven virtual answered a cacheable miss"

# =============================================================================
# #5621: conda repodata.json merge and the API read side
# =============================================================================
begin_test "FIX #5621: a conda virtual [500 member, healthy member] serves the healthy repodata.json marked partial, not 502"
reset_case
get "/conda/${CV}/noarch/repodata.json" "$W/cv.json"
note "repodata.json -> ${ST}: $(snip "$W/cv.json")"
[ "$ST" = "200" ] || fail_g "repodata.json answered ${ST}, expected 200"
[ "$(jqr ".packages[\"${CPKG}-1.0-0.tar.bz2\"].name // empty" < "$W/cv.json")" = "$CPKG" ] || fail_g "the healthy member's package ${CPKG} is missing"
check_partial "$W/cv.json" "$C_500" "conda [500, ok]"
finish_case "one failing member failed the whole conda repodata"

begin_test "FIX #5621: GET /api/v1/repositories/{virtual} returns virtual_metadata_partial"
reset_case
curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/${HV_OK}" > "$W/repo.json" || true
v="$(jqr 'if has("virtual_metadata_partial") then (.virtual_metadata_partial|tostring) else "absent" end' < "$W/repo.json")"
note "virtual_metadata_partial=${v}"
[ "$v" = "false" ] || fail_g "virtual_metadata_partial is '${v}', expected false on a virtual that never set it"
finish_case "virtual_metadata_partial is not readable through the repository API"

# =============================================================================
# #5504: the artifact and checksum walks
# =============================================================================
begin_test "FIX #5504: a Maven virtual [404 member, 503 member] answers 503 for the jar and its .sha1, not a cacheable 404"
reset_case
get "/maven/${MV_503}/${G}/${JAR_REL}" "$W/mv503.jar"; s1="$ST"
get "/maven/${MV_503}/${G}/${JAR_REL}.sha1" "$W/mv503.sha1"; s2="$ST"
note "jar -> ${s1}, .jar.sha1 -> ${s2}"
[ "$s1" = "503" ] || fail_g "the jar answered ${s1}, expected 503: $(snip "$W/mv503.jar")"
[ "$s2" = "503" ] || fail_g "the .sha1 answered ${s2}, expected 503: $(snip "$W/mv503.sha1")"
finish_case "a member's upstream 5xx read as a miss"

begin_test "CONTROL (#5504): a Maven virtual [404 member, 403 member] answers 404 for the jar and its .sha1 (a permanent 4xx is a miss)"
reset_case
get "/maven/${MV_403}/${G}/${JAR_REL}" "$W/mv403.jar"; s1="$ST"
get "/maven/${MV_403}/${G}/${JAR_REL}.sha1" "$W/mv403.sha1"; s2="$ST"
note "jar -> ${s1}, .jar.sha1 -> ${s2}"
[ "$s1" = "404" ] || fail_g "the jar answered ${s1}, expected 404"
[ "$s2" = "404" ] || fail_g "the .sha1 answered ${s2}, expected 404"
finish_case "a permanent member 4xx did not read as a miss"

begin_test "FIX #5504: a generic virtual [404 member, 503 member] answers 503 on /download/, not 404"
reset_case
get "/api/v1/repositories/${GV_503}/download/v/f.bin" "$W/gv503.bin"
note "download -> ${ST}: $(snip "$W/gv503.bin")"
[ "$ST" = "503" ] || fail_g "the generic download answered ${ST}, expected 503"
finish_case "the generic route mapped a member 5xx to 404"

begin_test "FIX #5504: a Maven virtual over a hosted member whose stored object is gone answers .sha1 503, not 404"
reset_case
KEY="$(docker exec "$DBC" psql -U registry -d artifact_registry -tAc \
  "SELECT a.storage_key FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${M_HOST}' AND a.path='${G}/h/1.0/h-1.0.jar'" 2>/dev/null | tr -d '[:space:]' || true)"
ROOT="$(psql_q "SELECT storage_path FROM repositories WHERE key='${M_HOST}'")"
if [ -z "$KEY" ] || [ -z "$ROOT" ]; then
  infra_fail "no storage_key/storage_path for the hosted jar (key='${KEY}' root='${ROOT}')"
else
  docker exec "$BACKEND_CTR" rm -f "${ROOT}/${KEY}" >/dev/null 2>&1 || true
  if docker exec "$BACKEND_CTR" test -e "${ROOT}/${KEY}" 2>/dev/null; then
    infra_fail "could not remove ${ROOT}/${KEY} in ${BACKEND_CTR}"
  else
    get "/maven/${MV_HOST}/${G}/h/1.0/h-1.0.jar.sha1" "$W/mvh.sha1"; s1="$ST"
    get "/maven/${MV_HOST}/${G}/h/1.0/h-1.0.jar.md5" "$W/mvh.md5"; s2="$ST"
    note ".sha1 -> ${s1}, .md5 -> ${s2} (object ${ROOT}/${KEY} removed)"
    [ "$s1" = "503" ] || fail_g "the .sha1 answered ${s1}, expected 503: $(snip "$W/mvh.sha1")"
    [ "$s2" = "503" ] || fail_g "the .md5 answered ${s2}, expected 503: $(snip "$W/mvh.md5")"
    finish_case "a hosted member's storage failure read as a miss on the checksum walk"
  fi
fi

# =============================================================================
# #5616: stale-if-error markers
# =============================================================================
begin_test "setup: prime the stale-if-error entries, let them expire, make the upstreams answer 500"
SETUP_ERR=""
get "/api/v1/repositories/${GR_STALE}/download/s/direct.bin" "$W/p1"; [ "$ST" = "200" ] || SETUP_ERR="${SETUP_ERR} prime-direct:${ST}"
get "/api/v1/repositories/${GV_STALE}/download/s/virtual.bin" "$W/p2"; [ "$ST" = "200" ] || SETUP_ERR="${SETUP_ERR} prime-virtual:${ST}"
get "/maven/${M_STALE}/${G}/st/maven-metadata.xml" "$W/p3"; [ "$ST" = "200" ] || SETUP_ERR="${SETUP_ERR} prime-maven:${ST}"
get "/maven/${M_STALE}/${G}/st/maven-metadata.xml.sha1" "$W/p4"; [ "$ST" = "200" ] || SETUP_ERR="${SETUP_ERR} prime-maven-sha1:${ST}"
sleep 4
for p in "gstale/s/direct.bin" "gstale/s/virtual.bin" "mstale/${G}/st/maven-metadata.xml" "mstale/${G}/st/maven-metadata.xml.sha1"; do
  [ "$(mock_status "/${P}/${p}" 500)" = "500" ] || SETUP_ERR="${SETUP_ERR} mock:${p}"
done
if [ -n "$SETUP_ERR" ]; then infra_fail "stale setup failed:${SETUP_ERR}"; else pass; fi

# The direct Remote's markers (#4697) are main-only too, so the control
# asserts the stale serve itself and only reports the markers.
begin_test "CONTROL: a direct generic Remote serves its expired entry stale (200, the cached bytes) when the upstream answers 500"
reset_case
get "/api/v1/repositories/${GR_STALE}/download/s/direct.bin" "$W/s-direct"
[ "$ST" = "200" ] || fail_g "the expired entry answered ${ST}, expected 200 (stale)"
cmp -s "$W/s-direct" "$W/gstale.bin" || fail_g "the stale body is not the cached bytes"
note "generic remote (not asserted): Warning='$(hdr "$W/s-direct" warning)' X-AK-Stale-Since='$(hdr "$W/s-direct" x-ak-stale-since)'"
finish_case "the direct Remote did not serve its expired entry stale"

begin_test "FIX #5616: a generic Virtual serving through an expired member marks the stale serve"
reset_case
get "/api/v1/repositories/${GV_STALE}/download/s/virtual.bin" "$W/s-virtual"
[ "$ST" = "200" ] || fail_g "the expired entry answered ${ST}, expected 200 (stale)"
cmp -s "$W/s-virtual" "$W/gstale.bin" || fail_g "the stale body is not the cached bytes"
check_stale "$W/s-virtual" "generic virtual"
finish_case "the generic Virtual's stale serve was not marked"

begin_test "FIX #5616: a Remote's maven-metadata.xml and its .sha1 served stale carry Warning: 110 and X-AK-Stale-Since"
reset_case
get "/maven/${M_STALE}/${G}/st/maven-metadata.xml" "$W/s-meta"
[ "$ST" = "200" ] || fail_g "the expired maven-metadata.xml answered ${ST}, expected 200 (stale)"
grep -q "<version>2.0</version>" "$W/s-meta" || fail_g "the stale body is not the cached metadata: $(snip "$W/s-meta")"
check_stale "$W/s-meta" "maven-metadata.xml"
get "/maven/${M_STALE}/${G}/st/maven-metadata.xml.sha1" "$W/s-meta-sha1"
[ "$ST" = "200" ] || fail_g "the expired maven-metadata.xml.sha1 answered ${ST}, expected 200 (stale)"
check_stale "$W/s-meta-sha1" "maven-metadata.xml.sha1"
finish_case "the Remote maven-metadata.xml stale serve was not marked"

# =============================================================================
# #5622: Alpine Virtual APKINDEX
# =============================================================================
apk_index(){ # <virtual> <out> -> ST; APKINDEX text in <out>.txt
  get "/alpine/$1/${APK_DIR}/APKINDEX.tar.gz" "$2"
  : > "$2.txt"
  [ "$ST" = "200" ] && tar -xzOf "$2" APKINDEX > "$2.txt" 2>/dev/null || true
}
has_pkg(){ grep -qx "P:$2" "$1.txt" 2>/dev/null; }

begin_test "CONTROL: an Alpine virtual over one answering Remote passes its APKINDEX through byte for byte"
reset_case
apk_index "$AV_R" "$W/av-r"
[ "$ST" = "200" ] || fail_g "APKINDEX answered ${ST}"
cmp -s "$W/av-r" "$W/APKINDEX.tar.gz" || fail_g "the APKINDEX is not the upstream's bytes"
finish_case "a remote-only Alpine virtual did not pass its upstream index through"

begin_test "CONTROL: an Alpine virtual whose Remote answers 404 serves an empty 200 index (every member answered)"
reset_case
apk_index "$AV_404" "$W/av-404"
[ "$ST" = "200" ] || fail_g "APKINDEX answered ${ST}, expected 200"
grep -q '^P:' "$W/av-404.txt" && fail_g "the index lists packages: $(snip "$W/av-404.txt")"
finish_case "an all-404 Alpine virtual did not serve an empty index"

begin_test "FIX #5622: an Alpine virtual over a hosted member lists the hosted package"
reset_case
apk_index "$AV_H" "$W/av-h"
note "APKINDEX -> ${ST}; packages: $(grep '^P:' "$W/av-h.txt" | tr '\n' ' ' || true)"
[ "$ST" = "200" ] || fail_g "APKINDEX answered ${ST}"
has_pkg "$W/av-h" "$APKN_H" || fail_g "the hosted package ${APKN_H} is missing from the virtual's APKINDEX"
finish_case "the Alpine virtual's APKINDEX omitted the hosted member"

begin_test "FIX #5622: an Alpine virtual [hosted, Remote] lists both members' packages"
reset_case
apk_index "$AV_HR" "$W/av-hr"
note "APKINDEX -> ${ST}; packages: $(grep '^P:' "$W/av-hr.txt" | tr '\n' ' ' || true)"
[ "$ST" = "200" ] || fail_g "APKINDEX answered ${ST}"
has_pkg "$W/av-hr" "$APKN_H" || fail_g "the hosted package ${APKN_H} is missing"
has_pkg "$W/av-hr" "$APKN_R" || fail_g "the Remote's package ${APKN_R} is missing"
finish_case "the Alpine virtual's APKINDEX did not merge hosted and Remote members"

begin_test "FIX #5622: an Alpine virtual [hosted, down Remote] still lists the hosted package"
reset_case
apk_index "$AV_HD" "$W/av-hd"
note "APKINDEX -> ${ST}; packages: $(grep '^P:' "$W/av-hd.txt" | tr '\n' ' ' || true)"
[ "$ST" = "200" ] || fail_g "APKINDEX answered ${ST}"
has_pkg "$W/av-hd" "$APKN_H" || fail_g "the hosted package ${APKN_H} is missing"
finish_case "a partial outage hid the hosted member's package"

begin_test "FIX #5622: an Alpine virtual whose only member is down answers 503 with Retry-After, not an empty 200 index"
reset_case
apk_index "$AV_D" "$W/av-d"
note "APKINDEX -> ${ST} Retry-After='$(hdr "$W/av-d" retry-after)'"
[ "$ST" = "503" ] || fail_g "APKINDEX answered ${ST}, expected 503"
[ -n "$(hdr "$W/av-d" retry-after)" ] || fail_g "no Retry-After"
finish_case "an all-down Alpine virtual answered an empty index"

end_suite
