#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-download-ledger/oracle.sh
#   #4535 a virtual download answered by a Remote member is recorded once in
#         proxy_download_statistics, under the WINNING member's (id, path)
#   #4539 proxy download history survives cache eviction; /admin/downloads
#         lists proxy serves (source, repository_id, path, artifact_id null)
#         with source / repository_id filters; /admin/stats total_downloads
#         includes proxy serves with proxy_download_count as its breakdown
#   #4551 an over-quota Remote object is streamed and counted, and leaves no
#         0-byte proxy_cache_artifacts placeholder
#   #4267 a Maven download through a virtual from a hosted member is counted
#   #4341 an npm tarball GET through a Remote (no scan-on-proxy) is counted
# See the manifest for the bugs, the primitives and the gates.
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
# The address the BACKEND reaches the mock at (profiles/upstreams.mock-files.yml).
UP="http://172.16.${DTF_SLOT}.76"

setup_workdir
W="$WORK_DIR"

# common.sh may run under `set -e`: every probe below swallows its own failure
# and the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# --- mock upstream control (profiles/upstreams.mock-files.yml) -----------------
mock_put(){ # <path> <file> [content-type]
  curl -s --max-time 10 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}" | jqr '.bytes // empty'
}
mock_gets(){ curl -s --max-time 5 "${MOCK}/__requests?path=$1" | jqr '.get // empty'; }

# --- statistics rows ---------------------------------------------------------
# Every request of a case carries its own User-Agent, so the case counts only
# its own rows. user_agent exists in both tables on every image, so the count
# itself is portable; the (repository_id, path) history key is 1.11.0+ (#4539).
pds_ua(){ psql_q "SELECT count(*) FROM proxy_download_statistics WHERE user_agent = '$1'"; }
ds_ua(){ psql_q "SELECT count(*) FROM download_statistics WHERE user_agent = '$1'"; }
# wait_count <fn> <ua> <want>: the recorders are deferred off the response
# path (#3778), so poll up to ~10 s for the expected count. Echoes the last.
wait_count(){
  local _i n=""
  for _i in $(seq 1 20); do
    n="$("$1" "$2")"
    [ "$n" = "$3" ] && break
    sleep 0.5
  done
  echo "${n:-?}"
}

# get <url> <out> <ua> -> "<http_code>"; head <url> <ua> -> "<http_code>"
get(){ curl -s --max-time 30 -o "$2" -w '%{http_code}' -A "$3" -H "Authorization: Bearer $TOK" "$1" || true; }
head_req(){ curl -s --max-time 30 -I -o /dev/null -w '%{http_code}' -A "$2" -H "Authorization: Bearer $TOK" "$1" || true; }
# A HEAD must add nothing; the recorder is deferred, so give it time to (not) land.
HEAD_SETTLE_SECS=3

# =============================================================================
begin_suite "proxy-download-ledger"

begin_test "setup: admin login, upstream files on the mock, Remote / virtual / hosted repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
SUF="${RUN_ID##*-}-$$"
R_GEN="pdl-gen-${SUF}"        # generic Remote on ${UP}/g/
R_MISS="pdl-miss-${SUF}"      # generic Remote on ${UP}/nothere/ (every path 404s)
V_GEN="pdl-vgen-${SUF}"       # generic virtual: [R_MISS (1), R_GEN (2)]
R_QUOTA="pdl-quota-${SUF}"    # generic Remote on ${UP}/g/ with quota_bytes 1000
M_HOST="pdl-mvnh-${SUF}"      # Maven hosted
M_VIRT="pdl-mvnv-${SUF}"      # Maven virtual: [M_HOST]
N_REM="pdl-npm-${SUF}"        # npm Remote on ${UP}/npm/

mk(){ # <json body> -> key
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$1" | jqr '.key // empty'
}
repo_json(){ # <key> <format> <type> [upstream] [quota]
  jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" --arg q "${5:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false}
     + (if $u == "" then {} else {upstream_url:$u} end)
     + (if $q == "" then {} else {quota_bytes:($q|tonumber)} end)'
}
add_member(){ # <virtual> <member> <priority> -> http code
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories/$1/members" \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d "{\"member_key\":\"$2\",\"priority\":$3}" || true
}
repo_id(){ curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/$1" | jqr '.id // empty'; }

# Upstream files. Random bytes so a served body is provably the upstream's.
head -c 5000 /dev/urandom > "$W/virt.bin"
head -c 5000 /dev/urandom > "$W/direct.bin"
head -c 5000 /dev/urandom > "$W/evict.bin"
head -c 5000 /dev/urandom > "$W/big.bin"     # 5000 bytes > the 1000-byte quota
head -c 3000 /dev/urandom > "$W/lib.jar"
SETUP_ERR=""
[ "$(mock_put "/g/v/virt-${SUF}.bin" "$W/virt.bin")" = "5000" ] || SETUP_ERR="${SETUP_ERR} mock:virt"
[ "$(mock_put "/g/d/direct-${SUF}.bin" "$W/direct.bin")" = "5000" ] || SETUP_ERR="${SETUP_ERR} mock:direct"
[ "$(mock_put "/g/e/evict-${SUF}.bin" "$W/evict.bin")" = "5000" ] || SETUP_ERR="${SETUP_ERR} mock:evict"
[ "$(mock_put "/g/q/big-${SUF}.bin" "$W/big.bin")" = "5000" ] || SETUP_ERR="${SETUP_ERR} mock:big"

# An npm package the Remote can serve: packument + tarball, published in 2020
# (long before any age gate, and no scan-on-proxy is configured).
PKG="dtfpdl${DTF_SLOT}x$$"
mkdir -p "$W/npm/package"
printf '{"name":"%s","version":"1.0.0"}\n' "$PKG" > "$W/npm/package/package.json"
tar -czf "$W/pkg.tgz" -C "$W/npm" package
NPM_SHA1="$(sha1sum "$W/pkg.tgz" | awk '{print $1}')"
NPM_INT="sha512-$(openssl dgst -sha512 -binary "$W/pkg.tgz" | base64 | tr -d '\n')"
jq -n --arg n "$PKG" --arg u "${UP}/npm/${PKG}/-/${PKG}-1.0.0.tgz" --arg s "$NPM_SHA1" --arg i "$NPM_INT" \
  '{name:$n,"dist-tags":{latest:"1.0.0"},
    time:{created:"2020-01-01T00:00:00.000Z",modified:"2020-01-01T00:00:00.000Z","1.0.0":"2020-01-01T00:00:00.000Z"},
    versions:{"1.0.0":{name:$n,version:"1.0.0",dist:{tarball:$u,shasum:$s,integrity:$i}}}}' > "$W/packument.json"
[ -n "$(mock_put "/npm/${PKG}" "$W/packument.json" application/json)" ] || SETUP_ERR="${SETUP_ERR} mock:packument"
[ -n "$(mock_put "/npm/${PKG}/-/${PKG}-1.0.0.tgz" "$W/pkg.tgz")" ] || SETUP_ERR="${SETUP_ERR} mock:tarball"

[ "$(mk "$(repo_json "$R_GEN" generic remote "${UP}/g/")")" = "$R_GEN" ] || SETUP_ERR="${SETUP_ERR} ${R_GEN}"
[ "$(mk "$(repo_json "$R_MISS" generic remote "${UP}/nothere/")")" = "$R_MISS" ] || SETUP_ERR="${SETUP_ERR} ${R_MISS}"
[ "$(mk "$(repo_json "$V_GEN" generic virtual)")" = "$V_GEN" ] || SETUP_ERR="${SETUP_ERR} ${V_GEN}"
[ "$(mk "$(repo_json "$R_QUOTA" generic remote "${UP}/g/" 1000)")" = "$R_QUOTA" ] || SETUP_ERR="${SETUP_ERR} ${R_QUOTA}"
[ "$(mk "$(repo_json "$M_HOST" maven local)")" = "$M_HOST" ] || SETUP_ERR="${SETUP_ERR} ${M_HOST}"
[ "$(mk "$(repo_json "$M_VIRT" maven virtual)")" = "$M_VIRT" ] || SETUP_ERR="${SETUP_ERR} ${M_VIRT}"
[ "$(mk "$(repo_json "$N_REM" npm remote "${UP}/npm/")")" = "$N_REM" ] || SETUP_ERR="${SETUP_ERR} ${N_REM}"
case "$(add_member "$V_GEN" "$R_MISS" 1)" in 200|201) ;; *) SETUP_ERR="${SETUP_ERR} member:${R_MISS}";; esac
case "$(add_member "$V_GEN" "$R_GEN" 2)" in 200|201) ;; *) SETUP_ERR="${SETUP_ERR} member:${R_GEN}";; esac
case "$(add_member "$M_VIRT" "$M_HOST" 1)" in 200|201) ;; *) SETUP_ERR="${SETUP_ERR} member:${M_HOST}";; esac
MVN_PATH="com/dtf/pdl${DTF_SLOT}x$$/1.0/pdl${DTF_SLOT}x$$-1.0.jar"
code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
  --data-binary @"$W/lib.jar" "$BASE/maven/${M_HOST}/${MVN_PATH}" || true)"
case "$code" in 200|201|204) ;; *) SETUP_ERR="${SETUP_ERR} maven-deploy:${code}";; esac
ID_GEN="$(repo_id "$R_GEN")"; ID_MISS="$(repo_id "$R_MISS")"; ID_QUOTA="$(repo_id "$R_QUOTA")"
[ -n "$ID_GEN" ] && [ -n "$ID_MISS" ] && [ -n "$ID_QUOTA" ] || SETUP_ERR="${SETUP_ERR} repo-ids"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- upstream ${UP}; remotes ${R_GEN} ${R_MISS} ${R_QUOTA} ${N_REM}; virtuals ${V_GEN} ${M_VIRT}"
pass

# =============================================================================
# CONTROL (both images): a direct generic Remote GET returns the upstream bytes
# and is counted once in proxy_download_statistics (#2260/#2705); a HEAD adds
# nothing.
# =============================================================================
begin_test "CONTROL: a direct Remote GET serves the upstream bytes and is counted once; a HEAD is not counted"
reset_case
UA="pdl-direct-${SUF}"
code="$(get "$BASE/api/v1/repositories/${R_GEN}/download/d/direct-${SUF}.bin" "$W/o.bin" "$UA")"
[ "$code" = "200" ] || fail_g "direct Remote GET answered ${code}, expected 200"
[ "$(sha_of "$W/o.bin")" = "$(sha_of "$W/direct.bin")" ] || fail_g "direct Remote GET body is not the upstream's bytes"
n="$(wait_count pds_ua "$UA" 1)"
[ "$n" = "1" ] || fail_g "proxy_download_statistics rows for the direct GET = ${n}, expected 1"
code="$(head_req "$BASE/api/v1/repositories/${R_GEN}/download/d/direct-${SUF}.bin" "$UA")"
sleep "$HEAD_SETTLE_SECS"
n="$(pds_ua "$UA")"
[ "$n" = "1" ] || fail_g "after a HEAD (${code}) the row count is ${n}, expected still 1"
note "direct GET rows=1, after HEAD rows=${n}"
finish_case "a direct Remote GET was not counted exactly once"

# CONTROL (both images): a hosted Maven artifact fetched directly is counted
# once in download_statistics; a HEAD adds nothing.
begin_test "CONTROL: a direct hosted Maven GET is counted once in download_statistics; a HEAD is not"
reset_case
UA="pdl-mvn-direct-${SUF}"
code="$(get "$BASE/maven/${M_HOST}/${MVN_PATH}" "$W/o.jar" "$UA")"
[ "$code" = "200" ] || fail_g "direct Maven GET answered ${code}, expected 200"
[ "$(sha_of "$W/o.jar")" = "$(sha_of "$W/lib.jar")" ] || fail_g "direct Maven GET body is not the deployed jar"
n="$(wait_count ds_ua "$UA" 1)"
[ "$n" = "1" ] || fail_g "download_statistics rows for the direct Maven GET = ${n}, expected 1"
head_req "$BASE/maven/${M_HOST}/${MVN_PATH}" "$UA" >/dev/null
sleep "$HEAD_SETTLE_SECS"
n="$(ds_ua "$UA")"
[ "$n" = "1" ] || fail_g "after a HEAD the download_statistics count is ${n}, expected still 1"
finish_case "a direct hosted Maven GET was not counted exactly once"

# CONTROL (both images): an object larger than the Remote's quota is still
# served in full, every time from upstream (it is never cached), and each GET
# is counted.
begin_test "CONTROL: an over-quota Remote object is streamed in full from upstream on every GET and each GET is counted"
reset_case
UA="pdl-quota-${SUF}"
before="$(mock_gets "/g/q/big-${SUF}.bin")"
for i in 1 2; do
  code="$(get "$BASE/api/v1/repositories/${R_QUOTA}/download/q/big-${SUF}.bin" "$W/o.bin" "$UA")"
  [ "$code" = "200" ] || fail_g "over-quota GET #${i} answered ${code}, expected 200"
  [ "$(sha_of "$W/o.bin")" = "$(sha_of "$W/big.bin")" ] || fail_g "over-quota GET #${i} body is not the upstream's 5000 bytes"
done
after="$(mock_gets "/g/q/big-${SUF}.bin")"
[ "$((${after:-0} - ${before:-0}))" = "2" ] || fail_g "upstream GETs for the over-quota object went ${before} -> ${after}, expected +2 (never cached)"
n="$(wait_count pds_ua "$UA" 2)"
[ "$n" = "2" ] || fail_g "proxy_download_statistics rows for the two over-quota GETs = ${n}, expected 2"
note "upstream GETs ${before} -> ${after}; rows=${n}"
finish_case "the over-quota stream-through control did not hold"

# =============================================================================
# FIX #4535 (RED on 1.10.0): a virtual GET won by a Remote member.
# =============================================================================
begin_test "FIX #4535: a virtual GET won by a Remote member records one row under that member's (id, path); the losing member and a HEAD record none"
reset_case
UA="pdl-virt-${SUF}"
code="$(get "$BASE/api/v1/repositories/${V_GEN}/download/v/virt-${SUF}.bin" "$W/o.bin" "$UA")"
[ "$code" = "200" ] || fail_g "virtual GET answered ${code}, expected 200"
[ "$(sha_of "$W/o.bin")" = "$(sha_of "$W/virt.bin")" ] || fail_g "virtual GET body is not the upstream's bytes"
n="$(wait_count pds_ua "$UA" 1)"
[ "$n" = "1" ] || fail_g "proxy_download_statistics rows for the virtual GET = ${n}, expected 1 (1.10.0 records none: #4535)"
win="$(psql_q "SELECT count(*) FROM proxy_download_statistics WHERE user_agent = '${UA}' AND repository_id = '${ID_GEN}' AND path = 'v/virt-${SUF}.bin'")"
[ "$win" = "1" ] || fail_g "no row keyed on the winning member ${R_GEN} and path v/virt-${SUF}.bin (got '${win}')"
lose="$(psql_q "SELECT count(*) FROM proxy_download_statistics WHERE repository_id = '${ID_MISS}'")"
[ "$lose" = "0" ] || fail_g "the losing member ${R_MISS} has ${lose} rows, expected 0"
head_req "$BASE/api/v1/repositories/${V_GEN}/download/v/virt-${SUF}.bin" "$UA" >/dev/null
sleep "$HEAD_SETTLE_SECS"
n2="$(pds_ua "$UA")"
[ "$n2" = "1" ] || fail_g "after a HEAD through the virtual the row count is ${n2}, expected still 1"
note "rows=${n} winner-keyed=${win} loser=${lose} after-HEAD=${n2}"
finish_case "a Remote member's winning virtual serve was not recorded once under that member"

# =============================================================================
# FIX #4539 (RED on 1.10.0): history survives eviction.
# =============================================================================
begin_test "FIX #4539: evicting a cached entry keeps its download rows (proxy_cache_id NULL, keyed on repository_id + path)"
reset_case
UA="pdl-evict-${SUF}"
code="$(get "$BASE/api/v1/repositories/${R_GEN}/download/e/evict-${SUF}.bin" "$W/o.bin" "$UA")"
[ "$code" = "200" ] || fail_g "GET answered ${code}, expected 200"
n="$(wait_count pds_ua "$UA" 1)"
[ "$n" = "1" ] || fail_g "rows before eviction = ${n}, expected 1"
# The catalog row is published by the tee writer after the response; wait for it
# so the eviction has something to remove.
for _i in $(seq 1 20); do
  [ "$(psql_q "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id = '${ID_GEN}' AND path = 'e/evict-${SUF}.bin'")" = "1" ] && break
  sleep 0.5
done
inv="$(curl -s -X POST -H "Authorization: Bearer $TOK" \
  "$BASE/api/v1/repositories/${R_GEN}/cache/invalidate?path=e/evict-${SUF}.bin" | jqr '.invalidated // empty')"
[ "$inv" = "true" ] || fail_g "POST cache/invalidate did not answer invalidated:true (got '${inv}')"
cat_rows="$(psql_q "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id = '${ID_GEN}' AND path = 'e/evict-${SUF}.bin'")"
[ "$cat_rows" = "0" ] || fail_g "the catalog row is still there after eviction (${cat_rows}); the eviction did not happen"
sleep 1
n="$(pds_ua "$UA")"
[ "$n" = "1" ] || fail_g "download rows after eviction = ${n}, expected 1 (1.10.0 cascades the delete: #4539)"
kept="$(psql_q "SELECT count(*) FROM proxy_download_statistics WHERE user_agent = '${UA}' AND proxy_cache_id IS NULL AND repository_id = '${ID_GEN}' AND path = 'e/evict-${SUF}.bin'")"
[ "$kept" = "1" ] || fail_g "the surviving row is not (proxy_cache_id NULL, repository_id ${R_GEN}, path e/evict-${SUF}.bin) (got '${kept}')"
note "catalog rows after eviction=${cat_rows}; download rows=${n}; detached+keyed=${kept}"
finish_case "proxy download history did not survive eviction"

begin_test "FIX #4539: /admin/downloads lists proxy serves (source, repository_id, path, artifact_id null) and honours source / repository_id filters"
reset_case
resp="$(curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/admin/downloads?source=proxy&repository_id=${ID_GEN}&per_page=100")"
row="$(echo "$resp" | jq -c --arg ua "pdl-evict-${SUF}" '[.downloads[]? | select(.user_agent == $ua)][0] // empty' 2>/dev/null || true)"
if [ -z "$row" ]; then
  fail_g "source=proxy&repository_id=${R_GEN} does not list the evicted entry's download (1.10.0 lists hosted rows only: #4539); body: $(echo "$resp" | head -c 300)"
else
  [ "$(echo "$row" | jqr '.source')" = "proxy" ] || fail_g "row source is '$(echo "$row" | jqr '.source')', expected proxy"
  [ "$(echo "$row" | jqr '.artifact_id')" = "null" ] || fail_g "row artifact_id is '$(echo "$row" | jqr '.artifact_id')', expected null"
  [ "$(echo "$row" | jqr '.repository_id')" = "$ID_GEN" ] || fail_g "row repository_id is '$(echo "$row" | jqr '.repository_id')', expected ${ID_GEN}"
  [ "$(echo "$row" | jqr '.path')" = "e/evict-${SUF}.bin" ] || fail_g "row path is '$(echo "$row" | jqr '.path')', expected e/evict-${SUF}.bin"
  note "row: ${row}"
fi
others="$(echo "$resp" | jq '[.downloads[]? | select(.source != "proxy" or .repository_id != $id)] | length' --arg id "$ID_GEN" 2>/dev/null || echo '?')"
[ "$others" = "0" ] || fail_g "the source=proxy&repository_id filter returned ${others} rows from another source or repository"
hosted="$(curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/admin/downloads?source=hosted&repository_id=${ID_GEN}&per_page=100" \
  | jq -r --arg ua "pdl-evict-${SUF}" '[.downloads[]? | select(.user_agent == $ua)] | length' 2>/dev/null || echo '?')"
[ "$hosted" = "0" ] || fail_g "source=hosted lists the proxy serve (${hosted} rows)"
finish_case "/admin/downloads does not report proxy serves"

begin_test "FIX #4539: /admin/stats total_downloads includes a proxy serve; proxy_download_count is its breakdown"
reset_case
s0="$(curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/admin/stats")"
t0="$(echo "$s0" | jqr '.total_downloads // empty')"; p0="$(echo "$s0" | jqr '.proxy_download_count // empty')"
UA="pdl-stats-${SUF}"
get "$BASE/api/v1/repositories/${R_GEN}/download/d/direct-${SUF}.bin" "$W/o.bin" "$UA" >/dev/null
wait_count pds_ua "$UA" 1 >/dev/null
s1="$(curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/admin/stats")"
t1="$(echo "$s1" | jqr '.total_downloads // empty')"; p1="$(echo "$s1" | jqr '.proxy_download_count // empty')"
note "total_downloads ${t0} -> ${t1}; proxy_download_count ${p0:-absent} -> ${p1:-absent}"
if [ -z "$p0" ] || [ -z "$p1" ]; then
  fail_g "/admin/stats has no proxy_download_count (1.10.0: #4539)"
else
  [ "$((p1 - p0))" = "1" ] || fail_g "proxy_download_count moved by $((p1 - p0)), expected 1"
fi
if [ -z "$t0" ] || [ -z "$t1" ] || [ "$((t1 - t0))" != "1" ]; then
  fail_g "total_downloads moved ${t0} -> ${t1}, expected +1 for one proxy serve (1.10.0 counts hosted only: #4539)"
fi
finish_case "/admin/stats does not count proxy serves"

# =============================================================================
# FIX #4551 (RED on 1.10.0): no 0-byte placeholder for the over-quota object.
# =============================================================================
begin_test "FIX #4551: the over-quota object leaves no proxy_cache_artifacts row; its download rows carry the (repository_id, path) key"
reset_case
cat_rows="$(psql_q "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id = '${ID_QUOTA}'")"
zero_rows="$(psql_q "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id = '${ID_QUOTA}' AND size_bytes = 0")"
[ "$cat_rows" = "0" ] || fail_g "${R_QUOTA} has ${cat_rows} catalog rows (${zero_rows} of them 0-byte) for an object that was never cached (1.10.0 leaves a 0-byte placeholder: #4551)"
keyed="$(psql_q "SELECT count(*) FROM proxy_download_statistics WHERE user_agent = 'pdl-quota-${SUF}' AND repository_id = '${ID_QUOTA}' AND path = 'q/big-${SUF}.bin' AND proxy_cache_id IS NULL")"
[ "$keyed" = "2" ] || fail_g "the two over-quota downloads are not keyed on (${R_QUOTA}, q/big-${SUF}.bin) with no catalog link (got '${keyed}')"
note "catalog rows=${cat_rows} (0-byte=${zero_rows}); keyed download rows=${keyed}"
finish_case "an over-quota Remote serve left a catalog placeholder"

# =============================================================================
# FIX #4267 (RED on 1.10.0): Maven through a virtual from a hosted member.
# =============================================================================
begin_test "FIX #4267: a Maven GET through a virtual from a hosted member is counted once; a HEAD is not"
reset_case
UA="pdl-mvn-virt-${SUF}"
code="$(get "$BASE/maven/${M_VIRT}/${MVN_PATH}" "$W/o.jar" "$UA")"
[ "$code" = "200" ] || fail_g "Maven virtual GET answered ${code}, expected 200"
[ "$(sha_of "$W/o.jar")" = "$(sha_of "$W/lib.jar")" ] || fail_g "Maven virtual GET body is not the deployed jar"
n="$(wait_count ds_ua "$UA" 1)"
[ "$n" = "1" ] || fail_g "download_statistics rows for the virtual GET = ${n}, expected 1 (1.10.0 records none: #4267)"
art="$(psql_q "SELECT count(*) FROM download_statistics d JOIN artifacts a ON a.id = d.artifact_id JOIN repositories r ON r.id = a.repository_id WHERE d.user_agent = '${UA}' AND r.key = '${M_HOST}'")"
[ "$art" = "1" ] || fail_g "the row is not attributed to the hosted member's artifact (got '${art}')"
head_req "$BASE/maven/${M_VIRT}/${MVN_PATH}" "$UA" >/dev/null
sleep "$HEAD_SETTLE_SECS"
n2="$(ds_ua "$UA")"
[ "$n2" = "1" ] || fail_g "after a HEAD through the virtual the count is ${n2}, expected still 1"
note "rows=${n} attributed=${art} after-HEAD=${n2}"
finish_case "a Maven download through a virtual was not counted"

# =============================================================================
# FIX #4341 (RED on 1.10.0): npm tarball through a Remote.
# =============================================================================
begin_test "FIX #4341: an npm tarball GET through a Remote is counted once; a HEAD is not"
reset_case
UA="pdl-npm-${SUF}"
code="$(get "$BASE/npm/${N_REM}/${PKG}/-/${PKG}-1.0.0.tgz" "$W/o.tgz" "$UA")"
[ "$code" = "200" ] || fail_g "npm tarball GET answered ${code}, expected 200"
[ "$(sha_of "$W/o.tgz")" = "$(sha_of "$W/pkg.tgz")" ] || fail_g "npm tarball body is not the upstream tarball"
n="$(wait_count pds_ua "$UA" 1)"
[ "$n" = "1" ] || fail_g "proxy_download_statistics rows for the tarball GET = ${n}, expected 1 (1.10.0 records none: #4341)"
head_req "$BASE/npm/${N_REM}/${PKG}/-/${PKG}-1.0.0.tgz" "$UA" >/dev/null
sleep "$HEAD_SETTLE_SECS"
n2="$(pds_ua "$UA")"
[ "$n2" = "1" ] || fail_g "after a HEAD the count is ${n2}, expected still 1"
note "rows=${n} after-HEAD=${n2}"
finish_case "an npm Remote tarball download was not counted"

end_suite
