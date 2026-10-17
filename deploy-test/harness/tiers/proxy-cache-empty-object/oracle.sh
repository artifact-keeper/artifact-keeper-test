#!/usr/bin/env bash
# =============================================================================
# tiers/proxy-cache-empty-object/oracle.sh
#   #4630 a proxy-cache entry whose body is empty while its sidecar vouches for
#         N bytes must heal, not stream Content-Length: N over nothing forever
#   #4646 a stored OCI upload part shorter than its PATCH recorded is a storage
#         fault (500, names the part), not a client DIGEST_INVALID
# See the manifest for THE BUG, the primitives and the gates.
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
BACKEND_CTR="${DB_CONTAINER%-db}-backend"
MOCK="http://127.0.0.1:${TRIVY_PORT}"
# The address the BACKEND reaches the mock at (profiles/upstreams.mock-static.yml).
UPSTREAM="http://172.16.${DTF_SLOT}.70/"
FS_HELPER_IMAGE="postgres:16-alpine"   # already pulled by compose.base.yml
FILE_BYTES=262144                      # MOCK_FILE_BYTES in the profile
EMPTY_MD5='d41d8cd98f00b204e9800998ecf8427e'
# The backend keeps parsed sidecars in an in-process LRU for 30 s
# (PROXY_METADATA_LRU_TTL). A sidecar rewritten on disk is only seen once the
# LRU entry has expired, so every sidecar tamper waits this out.
LRU_SETTLE_SECS=32

setup_workdir
W="$WORK_DIR"

# common.sh may run under `set -e`: every probe below swallows its own failure
# and the assertion that reads the (possibly empty) value judges it.
jqr(){ jq -r "$1" 2>/dev/null || true; }
psql_q(){ docker exec "$DBC" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null || true; }
fsx(){ docker run --rm -i --volumes-from "$BACKEND_CTR" --entrypoint sh "$FS_HELPER_IMAGE" -c "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }
size_of(){ wc -c < "$1" 2>/dev/null | tr -d '[:space:]' || true; }

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

# --- the Remote repository ---------------------------------------------------
# remote_get <name> <outfile> -> "<http_code> <curl_rc>"
remote_get(){
  local code rc
  rm -f "$2"
  code="$(curl -s --max-time 30 -o "$2" -w '%{http_code}' -H "Authorization: Bearer $TOK" \
    "$BASE/api/v1/repositories/${R_REMOTE}/download/f/$1")"; rc=$?
  [ -f "$2" ] || : > "$2"
  echo "${code:-000} ${rc}"
}

# The on-disk directory of a proxy-cache entry. Layout (filesystem):
#   /data/storage/proxy-cache/<scope>/<repo-key>/<path>/{__content__,__cache_meta__.json}
entry_dir(){ fsx "for d in /data/storage/proxy-cache/*/${R_REMOTE}/f/$1; do [ -d \"\$d\" ] && echo \"\$d\"; done; true" | head -1 | tr -d '\r'; }
content_size(){ fsx "f=\$(ls -d /data/storage/proxy-cache/*/${R_REMOTE}/f/$1/__content__ 2>/dev/null | head -1); [ -n \"\$f\" ] && wc -c < \"\$f\"" | tr -d '[:space:]'; }
sidecar(){ fsx "cat /data/storage/proxy-cache/*/${R_REMOTE}/f/$1/__cache_meta__.json 2>/dev/null"; }

# wait_sidecar <name>: block until the writer task has published the sidecar
# (the response completes before the cache publish does). 0 when present.
wait_sidecar(){
  local _i
  for _i in $(seq 1 40); do
    [ -n "$(sidecar "$1" | jqr '.size_bytes // empty')" ] && return 0
    sleep 0.5
  done
  return 1
}

# wait_warm <name>: fetch until a fetch leaves the upstream counter unchanged,
# i.e. the entry is demonstrably served from cache (the explicit form of
# common.sh's wait_for_proxy_cache_warm, against this mock's counter API).
wait_warm(){
  local _i before after
  for _i in $(seq 1 40); do
    before="$(mock_count "$1")"
    remote_get "$1" "$W/warm.bin" >/dev/null
    after="$(mock_count "$1")"
    [ -n "$before" ] && [ "$before" = "$after" ] && return 0
    sleep 0.25
  done
  return 1
}

# =============================================================================
begin_suite "proxy-cache-empty-object"

begin_test "setup: admin login, Remote generic repo on the mock upstream, local OCI + generic repos"
TOK="$(curl -s -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // .token // empty')"
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
if [ "$(curl -s --max-time 5 "${MOCK}/__readyz" || true)" != "ok" ]; then
  infra_fail "mock upstream not reachable on ${MOCK} (profiles/upstreams.mock-static.yml)"; end_suite
fi
SUF="${RUN_ID##*-}-$$"
R_REMOTE="pce-remote-${SUF}"; R_OCI="pce-oci-${SUF}"; R_GEN="pce-gen-${SUF}"
mk(){ # <key> <format> <type> [upstream]
  local body
  body="$(jq -n --arg k "$1" --arg f "$2" --arg t "$3" --arg u "${4:-}" \
    '{key:$k,name:$k,format:$f,repo_type:$t,is_public:false} + (if $u == "" then {} else {upstream_url:$u} end)')"
  curl -s -X POST "$BASE/api/v1/repositories" -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d "$body" | jqr '.key // empty'
}
SETUP_ERR=""
[ "$(mk "$R_REMOTE" generic remote "$UPSTREAM")" = "$R_REMOTE" ] || SETUP_ERR="${SETUP_ERR} remote-generic"
[ "$(mk "$R_OCI" docker local)" = "$R_OCI" ] || SETUP_ERR="${SETUP_ERR} local-docker"
[ "$(mk "$R_GEN" generic local)" = "$R_GEN" ] || SETUP_ERR="${SETUP_ERR} local-generic"
if [ -n "$SETUP_ERR" ]; then infra_fail "could not create repositories:${SETUP_ERR}"; end_suite; fi
echo "-- repos: ${R_REMOTE} -> ${UPSTREAM}, ${R_OCI}, ${R_GEN}"
pass

# =============================================================================
# CONTROL (both images): cold fetch through the Remote caches; a second fetch
# is served from the cache without contacting the upstream.
# =============================================================================
begin_test "CONTROL: cold fetch through the Remote returns the upstream bytes and caches; the next fetch is a cache hit"
reset_case
N_CTL="ctl-${SUF}.bin"
golden "$N_CTL" "$W/ctl.golden"
if [ "$(size_of "$W/ctl.golden")" != "$FILE_BYTES" ]; then infra_fail "mock /__golden returned $(size_of "$W/ctl.golden") bytes"; end_suite; fi
read -r code rc <<<"$(remote_get "$N_CTL" "$W/ctl.1")"
note "cold GET: HTTP ${code}, curl rc ${rc}, $(size_of "$W/ctl.1") bytes"
[ "$code" = "200" ] && [ "$rc" = "0" ] || fail_g "cold fetch was HTTP ${code} / curl rc ${rc}, expected a complete 200"
[ "$(sha_of "$W/ctl.1")" = "$(sha_of "$W/ctl.golden")" ] || fail_g "cold fetch body sha $(sha_of "$W/ctl.1") != upstream $(sha_of "$W/ctl.golden")"
wait_warm "$N_CTL" || fail_g "the entry never became a cache hit (every fetch reached the upstream)"
c_before="$(mock_count "$N_CTL")"
read -r code rc <<<"$(remote_get "$N_CTL" "$W/ctl.2")"
c_after="$(mock_count "$N_CTL")"
note "cached GET: HTTP ${code}, curl rc ${rc}; upstream GETs ${c_before} -> ${c_after}"
[ "$code" = "200" ] && [ "$(sha_of "$W/ctl.2")" = "$(sha_of "$W/ctl.golden")" ] || fail_g "cache hit did not return the upstream bytes (HTTP ${code})"
[ -n "$c_before" ] && [ "$c_before" = "$c_after" ] || fail_g "cache hit contacted the upstream (${c_before} -> ${c_after})"
sz="$(content_size "$N_CTL")"; meta_sz="$(sidecar "$N_CTL" | jqr '.size_bytes // empty')"
note "stored __content__ ${sz:-absent} bytes, sidecar size_bytes ${meta_sz:-absent}"
[ "$sz" = "$FILE_BYTES" ] && [ "$meta_sz" = "$FILE_BYTES" ] || fail_g "cache entry on disk is not ${FILE_BYTES} bytes (content=${sz:-absent}, sidecar=${meta_sz:-absent})"
finish_case "proxy-cache control broken: a cold fetch does not cache, or a hit is not served from cache"

# =============================================================================
# #4630 READ SIDE: the poisoned entry from the issue, reproduced on disk.
# =============================================================================
begin_test "#4630: an entry whose __content__ is empty while its sidecar vouches for N bytes and pins the empty-object ETag is refetched and healed"
reset_case
N_RD="rd-${SUF}.bin"
golden "$N_RD" "$W/rd.golden"
read -r code rc <<<"$(remote_get "$N_RD" "$W/rd.0")"
if [ "$code" != "200" ] || ! wait_sidecar "$N_RD"; then
  infra_fail "could not prime the cache entry for ${N_RD} (HTTP ${code}, sidecar never written)"; end_suite
fi
DIR="$(entry_dir "$N_RD")"
c_primed="$(mock_count "$N_RD")"
note "primed ${DIR:-?} (upstream GETs ${c_primed})"
# The production sidecar from #4630: size_bytes and checksum_sha256 of the real
# body, storage_etag the MD5 of zero bytes, over a zero-byte __content__. The
# filesystem backend pins no ETag of its own, so the pin is written here; it is
# exactly what an S3-compatible backend pins when the publish copy lands empty.
sidecar "$N_RD" > "$W/rd.meta"
jq -c --arg e "\"${EMPTY_MD5}\"" '.storage_etag = $e' "$W/rd.meta" > "$W/rd.meta.bad" 2>/dev/null || true
if [ ! -s "$W/rd.meta.bad" ]; then infra_fail "could not read/rewrite the sidecar of ${N_RD}"; end_suite; fi
fsx "o=\$(stat -c %u:%g '${DIR}'); : > '${DIR}/__content__'; cat > '${DIR}/__cache_meta__.json'; chown \"\$o\" '${DIR}/__content__' '${DIR}/__cache_meta__.json'" < "$W/rd.meta.bad"
t_sz="$(content_size "$N_RD")"; t_pin="$(sidecar "$N_RD" | jqr '.storage_etag // empty')"; t_meta_sz="$(sidecar "$N_RD" | jqr '.size_bytes // empty')"
note "tampered: __content__ ${t_sz} bytes, sidecar size_bytes ${t_meta_sz}, storage_etag ${t_pin}"
if [ "$t_sz" != "0" ] || [ "$t_pin" != "\"${EMPTY_MD5}\"" ] || [ "$t_meta_sz" != "$FILE_BYTES" ]; then
  infra_fail "the tamper did not take on ${DIR}"; end_suite
fi
note "waiting ${LRU_SETTLE_SECS}s for the backend's sidecar LRU to expire"
sleep "$LRU_SETTLE_SECS"
read -r code rc <<<"$(remote_get "$N_RD" "$W/rd.1")"
c_heal="$(mock_count "$N_RD")"
note "GET after tamper: HTTP ${code}, curl rc ${rc}, $(size_of "$W/rd.1") bytes, sha $(sha_of "$W/rd.1"); upstream GETs ${c_primed} -> ${c_heal}"
[ "$code" = "200" ] && [ "$rc" = "0" ] || fail_g "GET over the poisoned entry was HTTP ${code} / curl rc ${rc} (18 = Content-Length promised, body never came)"
[ "$(sha_of "$W/rd.1")" = "$(sha_of "$W/rd.golden")" ] || fail_g "body is $(size_of "$W/rd.1") bytes with sha $(sha_of "$W/rd.1"), not the ${FILE_BYTES}-byte upstream object"
[ -n "$c_heal" ] && [ "$c_heal" -gt "${c_primed:-0}" ] 2>/dev/null || fail_g "the upstream was not contacted (${c_primed} -> ${c_heal}): the poisoned entry was served, not treated as a miss"
# The refetch republishes from a writer task that outlives the response.
for _i in $(seq 1 40); do [ "$(content_size "$N_RD")" = "$FILE_BYTES" ] && break; sleep 0.5; done
h_sz="$(content_size "$N_RD")"; h_pin="$(sidecar "$N_RD" | jqr '.storage_etag // "null"')"
note "after heal: __content__ ${h_sz:-absent} bytes, storage_etag ${h_pin}"
[ "$h_sz" = "$FILE_BYTES" ] || fail_g "the cache object was not rewritten (__content__ is ${h_sz:-absent} bytes, expected ${FILE_BYTES})"
[ "$h_pin" != "\"${EMPTY_MD5}\"" ] || fail_g "the sidecar still pins the empty-object ETag after the refetch"
if wait_warm "$N_RD"; then
  c_b="$(mock_count "$N_RD")"; read -r code rc <<<"$(remote_get "$N_RD" "$W/rd.2")"; c_a="$(mock_count "$N_RD")"
  note "post-heal GET: HTTP ${code}, upstream GETs ${c_b} -> ${c_a}"
  [ "$(sha_of "$W/rd.2")" = "$(sha_of "$W/rd.golden")" ] && [ "$c_b" = "$c_a" ] || fail_g "the healed entry is not served from cache with the upstream bytes"
else
  fail_g "the healed entry never became a cache hit"
fi
finish_case "#4630: a sidecar vouching for N bytes over an empty body (empty-object ETag pinned) is still served instead of refetched"

# =============================================================================
# #4630 COMMIT SIDE (both images): an upstream that promises N bytes and
# delivers none / half is never committed as a cache entry, and the path
# caches normally once the upstream is healthy.
# =============================================================================
for MODE in empty short; do
  begin_test "CONTROL (#4630 commit side, #1365/#1912 guards): an upstream body that ends ${MODE} of its Content-Length is not cached; a healthy refetch caches"
  reset_case
  N_LIE="lie-${MODE}-${SUF}.bin"
  golden "$N_LIE" "$W/lie.golden"
  [ "$(mock_mode "$N_LIE" "$MODE")" = "$MODE" ] || { infra_fail "could not set mock mode ${MODE}"; end_suite; }
  read -r code rc <<<"$(remote_get "$N_LIE" "$W/lie.1")"
  note "GET (upstream ${MODE}): HTTP ${code}, curl rc ${rc}, $(size_of "$W/lie.1") bytes"
  if [ "$rc" = "0" ] && [ "$(sha_of "$W/lie.1")" = "$(sha_of "$W/lie.golden")" ]; then
    fail_g "a complete transfer was reported for a body the upstream never sent"
  fi
  [ "$rc" != "0" ] || [ "${code:0:1}" != "2" ] || fail_g "a short body was delivered as a clean HTTP ${code} transfer (curl rc 0, $(size_of "$W/lie.1") of ${FILE_BYTES} bytes)"
  sleep 3
  l_meta="$(sidecar "$N_LIE")"; l_sz="$(content_size "$N_LIE")"
  note "on disk after the failed fetch: sidecar ${l_meta:+present}${l_meta:-absent}, __content__ ${l_sz:-absent}"
  [ -z "$l_meta" ] || fail_g "a sidecar was committed for a body the upstream never finished: ${l_meta}"
  c1="$(mock_count "$N_LIE")"
  read -r code rc <<<"$(remote_get "$N_LIE" "$W/lie.2")"
  c2="$(mock_count "$N_LIE")"
  note "second GET (upstream still ${MODE}): HTTP ${code}, curl rc ${rc}; upstream GETs ${c1} -> ${c2}"
  [ -n "$c2" ] && [ "$c2" -gt "${c1:-0}" ] 2>/dev/null || fail_g "the second GET did not go back upstream (${c1} -> ${c2}): something was cached"
  [ "$(mock_mode "$N_LIE" ok)" = "ok" ] || { infra_fail "could not reset mock mode"; end_suite; }
  read -r code rc <<<"$(remote_get "$N_LIE" "$W/lie.3")"
  note "GET (upstream healthy): HTTP ${code}, curl rc ${rc}, $(size_of "$W/lie.3") bytes"
  [ "$code" = "200" ] && [ "$(sha_of "$W/lie.3")" = "$(sha_of "$W/lie.golden")" ] || fail_g "healthy refetch did not return the upstream bytes (HTTP ${code})"
  wait_warm "$N_LIE" || fail_g "the healthy refetch never became a cache hit"
  [ "$(content_size "$N_LIE")" = "$FILE_BYTES" ] || fail_g "cache object is $(content_size "$N_LIE") bytes after the healthy refetch, expected ${FILE_BYTES}"
  finish_case "a ${MODE} upstream body was cached, or the entry never recovered once the upstream was healthy"
done

# =============================================================================
# OCI chunked upload helpers (#4646)
# =============================================================================
OCI_AUTH=(-u "admin:${ADMIN_PASS}")
# oci_start -> "<location> <uuid>"
oci_start(){
  local h loc id
  h="$(curl -s -D - -o /dev/null -X POST "${OCI_AUTH[@]}" "$BASE/v2/${R_OCI}/img/blobs/uploads/" || true)"
  loc="$(printf '%s' "$h" | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r')"
  id="$(printf '%s' "$h" | awk 'tolower($1)=="docker-upload-uuid:"{print $2}' | tr -d '\r')"
  echo "${loc} ${id}"
}
oci_patch(){ # <location> <start> <file> -> HTTP code
  local n; n="$(size_of "$3")"
  curl -s -o /dev/null -w '%{http_code}' -X PATCH "${OCI_AUTH[@]}" -H 'Content-Type: application/octet-stream' \
    -H "Content-Range: $2-$(( $2 + n - 1 ))" --data-binary "@$3" "$BASE$1" || true
}
oci_commit(){ # <location> <digest> <bodyfile> -> HTTP code
  curl -s -o "$3" -w '%{http_code}' -X PUT "${OCI_AUTH[@]}" "$BASE$1?digest=$2" || true
}
oci_blob_head(){ # <digest> -> "<code> <content-length> <docker-content-digest>"
  local h code len dg
  h="$(curl -s -I "${OCI_AUTH[@]}" "$BASE/v2/${R_OCI}/img/blobs/$1" || true)"
  code="$(printf '%s' "$h" | awk 'NR==1{print $2}')"
  len="$(printf '%s' "$h" | awk 'tolower($1)=="content-length:"{print $2}' | tr -d '\r')"
  dg="$(printf '%s' "$h" | awk 'tolower($1)=="docker-content-digest:"{print $2}' | tr -d '\r')"
  echo "${code:-000} ${len:--} ${dg:--}"
}
CHUNK=65536

# =============================================================================
begin_test "CONTROL: a two-PATCH OCI chunked upload commits (201) and the blob reads back with its digest and length"
reset_case
head -c "$CHUNK" /dev/urandom > "$W/ok.0"; head -c "$CHUNK" /dev/urandom > "$W/ok.1"
cat "$W/ok.0" "$W/ok.1" > "$W/ok.all"; DG_OK="sha256:$(sha_of "$W/ok.all")"
read -r LOC UUID <<<"$(oci_start)"
if [ -z "$LOC" ] || [ -z "$UUID" ]; then infra_fail "could not open an OCI upload session on ${R_OCI}"; end_suite; fi
p0="$(oci_patch "$LOC" 0 "$W/ok.0")"; p1="$(oci_patch "$LOC" "$CHUNK" "$W/ok.1")"
code="$(oci_commit "$LOC" "$DG_OK" "$W/ok.commit")"
note "PATCH ${p0}/${p1}, commit HTTP ${code}: $(head -c 300 "$W/ok.commit")"
[ "$p0" = "202" ] && [ "$p1" = "202" ] || fail_g "PATCHes were ${p0}/${p1}, expected 202/202"
[ "$code" = "201" ] || fail_g "commit of a clean chunked upload was HTTP ${code}, expected 201"
read -r hc hl hd <<<"$(oci_blob_head "$DG_OK")"
note "HEAD blob: ${hc}, Content-Length ${hl}, Docker-Content-Digest ${hd}"
[ "$hc" = "200" ] && [ "$hl" = "$(( CHUNK * 2 ))" ] && [ "$hd" = "$DG_OK" ] || fail_g "committed blob does not read back as ${DG_OK} / $(( CHUNK * 2 )) bytes"
curl -s -o "$W/ok.get" "${OCI_AUTH[@]}" -L "$BASE/v2/${R_OCI}/img/blobs/${DG_OK}" || true
[ "sha256:$(sha_of "$W/ok.get")" = "$DG_OK" ] || fail_g "GET blob body sha256:$(sha_of "$W/ok.get") != ${DG_OK}"
finish_case "OCI chunked upload control broken"

# =============================================================================
begin_test "#4646: a stored OCI upload part shorter than its PATCH recorded fails the commit as a storage fault (500, names the part), not 400 DIGEST_INVALID"
reset_case
head -c "$CHUNK" /dev/urandom > "$W/bad.0"; head -c "$CHUNK" /dev/urandom > "$W/bad.1"
cat "$W/bad.0" "$W/bad.1" > "$W/bad.all"; DG_BAD="sha256:$(sha_of "$W/bad.all")"
read -r LOC UUID <<<"$(oci_start)"
if [ -z "$LOC" ] || [ -z "$UUID" ]; then infra_fail "could not open an OCI upload session on ${R_OCI}"; end_suite; fi
p0="$(oci_patch "$LOC" 0 "$W/bad.0")"; p1="$(oci_patch "$LOC" "$CHUNK" "$W/bad.1")"
if [ "$p0" != "202" ] || [ "$p1" != "202" ]; then infra_fail "PATCHes were ${p0}/${p1}"; end_suite; fi
PART0="$(psql_q "SELECT storage_key FROM oci_upload_parts WHERE upload_session_id='${UUID}' AND part_index=0;" | tr -d '[:space:]')"
PART0_SZ="$(psql_q "SELECT size_bytes FROM oci_upload_parts WHERE upload_session_id='${UUID}' AND part_index=0;" | tr -d '[:space:]')"
ROOT="$(psql_q "SELECT storage_path FROM repositories WHERE key='${R_OCI}';" | tr -d '[:space:]')"
if [ -z "$PART0" ] || [ -z "$ROOT" ] || [ "$PART0_SZ" != "$CHUNK" ]; then
  infra_fail "no oci_upload_parts row for session ${UUID} (key='${PART0}', size='${PART0_SZ}', root='${ROOT}')"; end_suite
fi
# What a failed final write left behind: the part row says 65536, the stored
# object holds 4 KiB less (the unit test's shape).
KEEP=$(( CHUNK - 4096 ))
fsx "f='${ROOT}/${PART0}'; head -c ${KEEP} \"\$f\" > /tmp/p && cat /tmp/p > \"\$f\""
t_sz="$(fsx "wc -c < '${ROOT}/${PART0}'" | tr -d '[:space:]')"
note "part 0 ${PART0}: row size_bytes ${PART0_SZ}, stored now ${t_sz}"
if [ "$t_sz" != "$KEEP" ]; then infra_fail "could not truncate ${ROOT}/${PART0}"; end_suite; fi
code="$(oci_commit "$LOC" "$DG_BAD" "$W/bad.commit")"
body="$(head -c 600 "$W/bad.commit")"
note "commit HTTP ${code}: ${body}"
[ "$code" = "500" ] || fail_g "commit over a short stored part was HTTP ${code}, expected 500 (a storage fault)"
case "$body" in *DIGEST_INVALID*) fail_g "the server blamed the client's digest (DIGEST_INVALID) for its own short part";; esac
case "$body" in *BLOB_UPLOAD_UNKNOWN*) ;; *) fail_g "error code is not BLOB_UPLOAD_UNKNOWN";; esac
case "$body" in *"$PART0"*) ;; *) fail_g "the error does not name the short part (${PART0})";; esac
read -r hc _ _ <<<"$(oci_blob_head "$DG_BAD")"
note "HEAD blob ${DG_BAD}: ${hc}"
[ "$hc" = "404" ] || fail_g "a blob was published for the failed commit (HEAD ${hc})"
finish_case "#4646: a short stored upload part is reported as a client DIGEST_INVALID instead of a storage fault"

# =============================================================================
begin_test "CONTROL (#4646 regression guard): a generic upload's stored object equals the uploaded bytes and the download carries the right X-Checksum-Sha256"
reset_case
head -c 300000 /dev/urandom > "$W/gen.bin"; G_SHA="$(sha_of "$W/gen.bin")"
code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/octet-stream' --data-binary "@$W/gen.bin" \
  "$BASE/api/v1/repositories/${R_GEN}/artifacts/pce/gen.bin" || true)"
note "upload HTTP ${code}"
case "$code" in 2*) ;; *) fail_g "generic upload was HTTP ${code}";; esac
G_KEY="$(psql_q "SELECT a.storage_key FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${R_GEN}' AND a.path='pce/gen.bin' AND a.is_deleted=false LIMIT 1;" | tr -d '[:space:]')"
G_ROOT="$(psql_q "SELECT storage_path FROM repositories WHERE key='${R_GEN}';" | tr -d '[:space:]')"
G_ROW_SZ="$(psql_q "SELECT a.size_bytes FROM artifacts a JOIN repositories r ON r.id=a.repository_id WHERE r.key='${R_GEN}' AND a.path='pce/gen.bin' AND a.is_deleted=false LIMIT 1;" | tr -d '[:space:]')"
g_sz="$(fsx "wc -c < '${G_ROOT}/${G_KEY}'" | tr -d '[:space:]')"
g_disk_sha="$(fsx "sha256sum '${G_ROOT}/${G_KEY}'" | awk '{print $1}')"
note "row size_bytes ${G_ROW_SZ:-?}, stored ${g_sz:-absent} bytes, stored sha ${g_disk_sha:-?}"
[ "$g_sz" = "300000" ] && [ "$G_ROW_SZ" = "300000" ] || fail_g "stored object / row size is ${g_sz:-absent} / ${G_ROW_SZ:-?}, expected 300000"
[ "$g_disk_sha" = "$G_SHA" ] || fail_g "stored object sha ${g_disk_sha:-?} != uploaded ${G_SHA}"
hdr="$(curl -s -D "$W/gen.hdr" -o "$W/gen.get" -w '%{http_code}' -H "Authorization: Bearer $TOK" \
  "$BASE/api/v1/repositories/${R_GEN}/download/pce/gen.bin" || true)"
x_sha="$(awk 'tolower($1)=="x-checksum-sha256:"{print $2}' "$W/gen.hdr" | tr -d '\r')"
note "download HTTP ${hdr}, X-Checksum-Sha256 ${x_sha:-absent}, body sha $(sha_of "$W/gen.get")"
[ "$hdr" = "200" ] && [ "$(sha_of "$W/gen.get")" = "$G_SHA" ] || fail_g "download did not return the uploaded bytes"
[ "$x_sha" = "$G_SHA" ] || fail_g "X-Checksum-Sha256 is ${x_sha:-absent}, expected ${G_SHA}"
finish_case "a generic upload is not stored/served byte-exact"

end_suite
