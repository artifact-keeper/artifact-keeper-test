#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-cache-cap-and-history/oracle.sh
#   #4660 a byte cap on a Remote's proxy cache, least recently used evicted
#   #4542 proxy pulls keep their digest, so blast radius survives a purge
#   #4541 scheduled retention for download_statistics and
#         proxy_download_statistics
#   #4573 X-Checksum-SHA1 on a proxied Maven jar
# See the manifest for the gaps and the gates.
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
MIB=1048576

setup_workdir
W="$WORK_DIR"

# common.sh may run under `set -e`: every probe below swallows its own failure
# and the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
psql_x(){ docker exec "$DBC" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAc "$1" >/dev/null 2>&1; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

mock_put(){ # <path> <file> [content-type]
  curl -s --max-time 30 -X PUT --data-binary @"$2" \
    "${MOCK}/__file?path=$1&ctype=${3:-application/octet-stream}" | jqr '.bytes // empty'
}

# get <url> <out> [ua] -> "<http_code>"
get(){ curl -s --max-time 60 -o "$2" -w '%{http_code}' -A "${3:-dtf-pcch}" -H "Authorization: Bearer $TOK" "$1" || true; }
api(){ # <method> <path> [json] -> body
  if [ -n "${3:-}" ]; then
    curl -s --max-time 30 -X "$1" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "$3" "$BASE$2" || true
  else
    curl -s --max-time 30 -X "$1" -H "Authorization: Bearer $TOK" "$BASE$2" || true
  fi
}
api_code(){ # <method> <path> [json] -> http code
  if [ -n "${3:-}" ]; then
    curl -s --max-time 30 -o /dev/null -w '%{http_code}' -X "$1" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "$3" "$BASE$2" || true
  else
    curl -s --max-time 30 -o /dev/null -w '%{http_code}' -X "$1" -H "Authorization: Bearer $TOK" "$BASE$2" || true
  fi
}

# =============================================================================
begin_suite "proxy-cache-cap-and-history"

begin_test "setup: admin login, upstream files on the mock, Remote and hosted repositories"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-files.yml)"; end_suite
fi
SUF="${RUN_ID##*-}-$$"
R_CAP="pcch-cap-${SUF}"     # generic Remote on ${UP}/c/, capped at 5 MiB
R_HIST="pcch-hist-${SUF}"   # generic Remote on ${UP}/h/
R_MVN="pcch-mvn-${SUF}"     # Maven Remote on ${UP}/m/
H_GEN="pcch-host-${SUF}"    # generic hosted, for a download_statistics row

mk(){ # <key> <format> <type> [upstream]
  jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false}
     + (if $u == "" then {} else {upstream_url:$u} end)' > "$W/repo.json"
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d @"$W/repo.json" | jqr '.key // empty'
}
repo_id(){ curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/repositories/$1" | jqr '.id // empty'; }

SETUP_ERR=""
for i in 0 1 2 3 4 5 6 7 8 9; do
  head -c "$MIB" /dev/urandom > "$W/obj-$i.bin"
  [ "$(mock_put "/c/obj-$i.bin" "$W/obj-$i.bin")" = "$MIB" ] || SETUP_ERR="${SETUP_ERR} mock:obj-$i"
done
head -c $((6 * MIB)) /dev/urandom > "$W/big.bin"
[ "$(mock_put "/c/big.bin" "$W/big.bin")" = "$((6 * MIB))" ] || SETUP_ERR="${SETUP_ERR} mock:big"
head -c 4096 /dev/urandom > "$W/hist.bin"
[ "$(mock_put "/h/pulled.bin" "$W/hist.bin")" = "4096" ] || SETUP_ERR="${SETUP_ERR} mock:hist"
MVN_PATH="com/dtf/pcch/1.0/pcch-1.0.jar"
head -c 3000 /dev/urandom > "$W/lib.jar"
JAR_SHA1="$(sha1sum "$W/lib.jar" | awk '{print $1}')"
printf '%s' "$JAR_SHA1" > "$W/lib.jar.sha1"
[ "$(mock_put "/m/${MVN_PATH}" "$W/lib.jar" application/java-archive)" = "3000" ] || SETUP_ERR="${SETUP_ERR} mock:jar"
[ -n "$(mock_put "/m/${MVN_PATH}.sha1" "$W/lib.jar.sha1" text/plain)" ] || SETUP_ERR="${SETUP_ERR} mock:sha1"

[ "$(mk "$R_CAP" generic remote "${UP}/c/")" = "$R_CAP" ] || SETUP_ERR="${SETUP_ERR} ${R_CAP}"
[ "$(mk "$R_HIST" generic remote "${UP}/h/")" = "$R_HIST" ] || SETUP_ERR="${SETUP_ERR} ${R_HIST}"
[ "$(mk "$R_MVN" maven remote "${UP}/m/")" = "$R_MVN" ] || SETUP_ERR="${SETUP_ERR} ${R_MVN}"
[ "$(mk "$H_GEN" generic local)" = "$H_GEN" ] || SETUP_ERR="${SETUP_ERR} ${H_GEN}"
head -c 512 /dev/urandom > "$W/hosted.bin"
code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
  --data-binary @"$W/hosted.bin" "$BASE/api/v1/repositories/${H_GEN}/artifacts/ret/hosted.bin" || true)"
case "$code" in 200|201) ;; *) SETUP_ERR="${SETUP_ERR} hosted-upload:${code}";; esac
ID_CAP="$(repo_id "$R_CAP")"; ID_HIST="$(repo_id "$R_HIST")"; ID_HOST="$(repo_id "$H_GEN")"
[ -n "$ID_CAP" ] && [ -n "$ID_HIST" ] && [ -n "$ID_HOST" ] || SETUP_ERR="${SETUP_ERR} repo-ids"
ART_ID="$(psql_q "SELECT id FROM artifacts WHERE repository_id = '${ID_HOST}' AND path LIKE '%hosted.bin' LIMIT 1")"
[ -n "$ART_ID" ] || SETUP_ERR="${SETUP_ERR} hosted-artifact-row"
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR}"; end_suite; fi
echo "-- upstream ${UP}; remotes ${R_CAP} ${R_HIST} ${R_MVN}; hosted ${H_GEN}"
pass

# =============================================================================
# #4660: a 5 MiB cap, ten 1 MiB pulls.
# =============================================================================
begin_test "FIX #4660: a Remote capped at 5 MiB keeps at most 5 MiB, evicting the least recently used"
reset_case
CAP=$((5 * MIB))
code="$(api_code PUT "/api/v1/repositories/${R_CAP}/proxy-cache-cap" "{\"cap_bytes\":${CAP}}")"
[ "$code" = "200" ] || fail_g "PUT proxy-cache-cap answered ${code}, expected 200 (no per-Remote cache cap)"
BAD_BODY=0
for i in 0 1 2 3 4 5 6 7 8 9; do
  code="$(get "$BASE/api/v1/repositories/${R_CAP}/download/obj-$i.bin" "$W/o.bin")"
  if [ "$code" != "200" ] || [ "$(sha_of "$W/o.bin")" != "$(sha_of "$W/obj-$i.bin")" ]; then BAD_BODY=1; fi
  # Let the fill commit before the next one, so the LRU order is the pull order.
  sleep 0.5
done
used=""
for _i in $(seq 1 40); do
  used="$(psql_q "SELECT COALESCE(SUM(size_bytes),0) FROM proxy_cache_artifacts WHERE repository_id = '${ID_CAP}'")"
  [ -n "$used" ] && [ "$used" -le "$CAP" ] && break
  sleep 0.5
done
note "catalogued bytes after ten 1 MiB pulls: ${used:-?} (cap ${CAP})"
[ -n "$used" ] && [ "$used" -le "$CAP" ] || fail_g "the Remote caches ${used:-?} bytes, over its ${CAP}-byte cap"
first="$(psql_q "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id = '${ID_CAP}' AND path = 'obj-0.bin' AND size_bytes > 0")"
last="$(psql_q "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id = '${ID_CAP}' AND path = 'obj-9.bin' AND size_bytes > 0")"
[ "$first" = "0" ] || fail_g "the least recently used object (obj-0) is still cached"
[ "$last" = "1" ] || fail_g "the most recent object (obj-9) is not cached (${last})"
body="$(api GET "/api/v1/repositories/${R_CAP}/proxy-cache-cap")"
got_cap="$(printf '%s' "$body" | jqr '.cap_bytes // empty')"
got_used="$(printf '%s' "$body" | jqr '.usage.bytes // empty')"
[ "$got_cap" = "$CAP" ] || fail_g "GET proxy-cache-cap reports cap ${got_cap:-none}, expected ${CAP}"
[ -n "$got_used" ] && [ "$got_used" -le "$CAP" ] || fail_g "GET proxy-cache-cap reports usage ${got_used:-none}"
note "GET proxy-cache-cap: cap=${got_cap:-none} usage=${got_used:-none} at_cap=$(printf '%s' "$body" | jqr '.at_cap // empty')"
code="$(get "$BASE/api/v1/repositories/${R_CAP}/download/big.bin" "$W/big.out")"
[ "$code" = "200" ] && [ "$(sha_of "$W/big.out")" = "$(sha_of "$W/big.bin")" ] || BAD_BODY=1
sleep 2
big_cached="$(psql_q "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id = '${ID_CAP}' AND path = 'big.bin' AND size_bytes > 0")"
[ "$big_cached" = "0" ] || fail_g "a 6 MiB object was cached under a 5 MiB cap"
used2="$(psql_q "SELECT COALESCE(SUM(size_bytes),0) FROM proxy_cache_artifacts WHERE repository_id = '${ID_CAP}'")"
[ -n "$used2" ] && [ "$used2" -le "$CAP" ] || fail_g "after the 6 MiB pull the Remote caches ${used2:-?} bytes"
finish_case "the Remote's proxy cache is not bounded by a cap"

begin_test "CONTROL: every capped pull returned the upstream bytes"
if [ "$BAD_BODY" = "0" ]; then pass; else fail "a proxied GET did not return the upstream bytes" ""; fi

# =============================================================================
# #4542: pulls keep their digest; blast radius survives a purge.
# =============================================================================
begin_test "FIX #4542: proxy pulls carry the served sha256 and stay attributed after the entry is purged"
reset_case
UA="pcch-hist-${SUF}"
HIST_SHA="$(sha_of "$W/hist.bin")"
for _n in 1 2; do
  code="$(get "$BASE/api/v1/repositories/${R_HIST}/download/pulled.bin" "$W/h.bin" "$UA")"
  [ "$code" = "200" ] && [ "$(sha_of "$W/h.bin")" = "$HIST_SHA" ] || fail_g "pull answered ${code} or the wrong bytes"
  sleep 1
done
with_digest=""
for _i in $(seq 1 20); do
  with_digest="$(psql_q "SELECT count(*) FROM proxy_download_statistics WHERE user_agent = '${UA}' AND checksum_sha256 = '${HIST_SHA}'")"
  [ "$with_digest" = "2" ] && break
  sleep 0.5
done
note "statistics rows carrying the served sha256: ${with_digest:-none (no checksum_sha256 column)}"
[ "$with_digest" = "2" ] || fail_g "${with_digest:-0} of 2 proxy download rows carry the served sha256"
CVE="CVE-4542-${DTF_SLOT}$$"
psql_x "INSERT INTO proxy_scan_findings (checksum_sha256, scan_type, cve_id, severity, package_name) VALUES ('${HIST_SHA}', 'grype', '${CVE}', 'critical', 'dtf-pcch')" \
  || fail_g "could not seed proxy_scan_findings"
inv="$(api POST "/api/v1/repositories/${R_HIST}/cache/invalidate?path=pulled.bin" | jqr '.invalidated // empty')"
[ "$inv" = "true" ] || fail_g "POST cache/invalidate did not answer invalidated:true (got '${inv}')"
left="$(psql_q "SELECT count(*) FROM proxy_cache_artifacts WHERE repository_id = '${ID_HIST}' AND path = 'pulled.bin'")"
[ "$left" = "0" ] || note "catalog row still present after the purge (${left})"
br="$(api GET "/api/v1/admin/security/cve/${CVE}/blast-radius")"
dl="$(printf '%s' "$br" | jqr '.proxy_exposure.download_count // empty')"
dg="$(printf '%s' "$br" | jqr '.proxy_exposure.affected_digest_count // empty')"
note "blast radius after the purge: download_count=${dl:-?} affected_digest_count=${dg:-?}"
[ "$dl" = "2" ] || fail_g "blast radius counts ${dl:-?} pulls of the purged digest, expected 2"
[ "$dg" = "1" ] || fail_g "blast radius reports ${dg:-?} affected digests, expected 1"
finish_case "proxy pulls lose their attribution when the cache entry is purged"

# =============================================================================
# #4541: retention (30 days, a 10 s pass) trims both statistics tables.
# =============================================================================
begin_test "FIX #4541: the retention pass deletes 40-day-old statistics rows from both tables and keeps recent ones"
reset_case
OLD_UA="pcch-old-${SUF}"; NEW_UA="pcch-new-${SUF}"
psql_x "INSERT INTO proxy_download_statistics (repository_id, path, user_agent, downloaded_at) VALUES ('${ID_HIST}', 'pulled.bin', '${OLD_UA}', NOW() - INTERVAL '40 days'), ('${ID_HIST}', 'pulled.bin', '${NEW_UA}', NOW() - INTERVAL '1 day')" \
  || fail_g "could not seed proxy_download_statistics"
psql_x "INSERT INTO download_statistics (artifact_id, user_agent, downloaded_at) VALUES ('${ART_ID}', '${OLD_UA}', NOW() - INTERVAL '40 days'), ('${ART_ID}', '${NEW_UA}', NOW() - INTERVAL '1 day')" \
  || fail_g "could not seed download_statistics"
old_p=""; old_h=""
# The pass runs every 10 s after a 10 to 40 s startup delay; allow two minutes.
for _i in $(seq 1 60); do
  old_p="$(psql_q "SELECT count(*) FROM proxy_download_statistics WHERE user_agent = '${OLD_UA}'")"
  old_h="$(psql_q "SELECT count(*) FROM download_statistics WHERE user_agent = '${OLD_UA}'")"
  [ "$old_p" = "0" ] && [ "$old_h" = "0" ] && break
  sleep 2
done
new_p="$(psql_q "SELECT count(*) FROM proxy_download_statistics WHERE user_agent = '${NEW_UA}'")"
new_h="$(psql_q "SELECT count(*) FROM download_statistics WHERE user_agent = '${NEW_UA}'")"
note "40-day-old rows left: proxy=${old_p:-?} hosted=${old_h:-?}; 1-day-old rows left: proxy=${new_p:-?} hosted=${new_h:-?}"
[ "$old_p" = "0" ] || fail_g "a 40-day-old proxy_download_statistics row survived a 30-day retention"
[ "$old_h" = "0" ] || fail_g "a 40-day-old download_statistics row survived a 30-day retention"
[ "$new_p" = "1" ] || fail_g "a 1-day-old proxy_download_statistics row was deleted"
[ "$new_h" = "1" ] || fail_g "a 1-day-old download_statistics row was deleted"
finish_case "download statistics have no retention"

# =============================================================================
# #4573: X-Checksum-SHA1 on a warm proxied jar.
# =============================================================================
begin_test "FIX #4573: a warm Maven jar from a Remote carries X-Checksum-SHA1 of its .sha1"
reset_case
code="$(get "$BASE/maven/${R_MVN}/${MVN_PATH}" "$W/j1.jar")"
[ "$code" = "200" ] && [ "$(sha_of "$W/j1.jar")" = "$(sha_of "$W/lib.jar")" ] || fail_g "cold jar GET answered ${code} or the wrong bytes"
sleep 2
hdr="$(curl -s --max-time 30 -D - -o "$W/j2.jar" -H "Authorization: Bearer $TOK" "$BASE/maven/${R_MVN}/${MVN_PATH}" \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="x-checksum-sha1"{print $2}' || true)"
[ "$(sha_of "$W/j2.jar")" = "$(sha_of "$W/lib.jar")" ] || fail_g "warm jar GET returned the wrong bytes"
note "warm jar X-Checksum-SHA1: ${hdr:-absent} (upstream .sha1 ${JAR_SHA1})"
[ "$hdr" = "$JAR_SHA1" ] || fail_g "warm jar X-Checksum-SHA1 is '${hdr:-absent}', expected ${JAR_SHA1}"
finish_case "a proxied Maven jar carries no checksum header Maven Resolver reads"

end_suite
