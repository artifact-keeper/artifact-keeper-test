#!/usr/bin/env bash
# =============================================================================
# tiers/bounded-memory-streaming/oracle.sh
#   #5130 the shipped image runs with jemalloc (allocator facet only)
#   #5133 a whole-body OCI layer PUT is not re-read at finalize
#   #5126 hosted members of a PyPI virtual are streamed, not buffered
#   #5364 hosted Conan file downloads and uploads stream
#   #5336 backup and restore stream the archive
#   #4924 a cold hosted RPM repodata render follows a bounded batch
# See the manifest for the bugs, the sizes and the gates.
#
# run.sh exported BASE_URL, DB_CONTAINER, ADMIN_PASS, RUN_ID, DTF_SLOT,
# RELEASE_GATE=1, JUNIT_OUTPUT_DIR, COMMON_SH; the manifest exported
# LIMITS_MEMORY (profiles/limits.memory.yml caps the backend with it).
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${ADMIN_PASS:?}"; : "${DB_CONTAINER:?}"
: "${DTF_SLOT:?}"; : "${RUN_ID:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"
set +e

BASE="$BASE_URL"
BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
CAP="${LIMITS_MEMORY:-768m}"
# Sizes (MiB). The defaults are what the PR validated; see the manifest.
BIG_MIB="${BMS_BIG_MIB:-1024}"          # > CAP: OCI layer, Conan upload
WHEEL_MIB="${BMS_FILE_MIB:-160}"        # per download; x PARALLEL > CAP
PARALLEL="${BMS_PARALLEL:-8}"
RATE="${BMS_RATE:-16M}"                 # per-client rate: the downloads overlap
BACKUP_FILES="${BMS_BACKUP_FILES:-6}"   # x BACKUP_MIB > CAP
BACKUP_MIB="${BMS_BACKUP_MIB:-160}"
RPM_PACKAGES="${BMS_RPM_PACKAGES:-1000}"
RPM_FILES="${BMS_RPM_FILES:-8000}"
RPM_CAP="${BMS_RPM_MEMORY:-3g}"
HELPER_CAP="${BMS_HELPER_MEMORY:-6g}"

setup_workdir
W="$WORK_DIR"

jqr(){ jq -r "$1" 2>/dev/null || true; }
sha_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }
psql_q(){ docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAq "$@" 2>/dev/null; }
mib(){ awk -v b="${1:-0}" 'BEGIN{printf "%d", b/1048576}'; }

FAILS=0
DETAIL=""
fail_g(){ echo "   !!! GATE-FAIL: $1"; FAILS=$((FAILS+1)); DETAIL="${DETAIL}GATE-FAIL: $1
"; }
note(){ echo "   $1"; DETAIL="${DETAIL}$1
"; }
reset_case(){ FAILS=0; DETAIL=""; }
finish_case(){ if [ "$FAILS" -eq 0 ]; then pass; else fail "$1" "$DETAIL"; fi; }

# --- the backend container -----------------------------------------------------
started_at(){ docker inspect "$BACKEND_CTR" --format '{{.State.StartedAt}}' 2>/dev/null || true; }
running(){ [ "$(docker inspect "$BACKEND_CTR" --format '{{.State.Running}}' 2>/dev/null)" = "true" ]; }
cg_read(){ docker exec "$BACKEND_CTR" cat "/sys/fs/cgroup/$1" 2>/dev/null || true; }
anon_bytes(){ cg_read memory.stat | awk '/^anon /{print $2}'; }
rchar(){ docker exec "$BACKEND_CTR" cat /proc/1/io 2>/dev/null | awk '/^rchar:/{print $2}'; }

# Peak anonymous memory of the backend while a case runs, sampled every
# 0.25 s from its cgroup (a note for the reader; the gate is the container's
# survival plus the bytes). memory.peak is not used: it counts the page cache
# of the files the case writes, which the kernel reclaims under the cap.
SAMPLER=""
sample_start(){
  echo 0 > "$W/anon.max"
  ( m=0; while :; do
      a="$(anon_bytes)"
      if [ -n "$a" ] && [ "$a" -gt "$m" ] 2>/dev/null; then m="$a"; echo "$m" > "$W/anon.max"; fi
      sleep 0.25
    done ) >/dev/null 2>&1 &
  SAMPLER=$!
}
sample_stop(){
  [ -n "$SAMPLER" ] && { kill "$SAMPLER" 2>/dev/null; wait "$SAMPLER" 2>/dev/null; }
  SAMPLER=""
  echo "$(mib "$(cat "$W/anon.max" 2>/dev/null)")"
}
add_exit_handler '[ -n "$SAMPLER" ] && kill "$SAMPLER" 2>/dev/null'

wait_healthy(){ # [secs]
  local i
  for i in $(seq 1 "${1:-120}"); do
    curl -sf --max-time 3 -o /dev/null "$BASE/health" && return 0
    sleep 1
  done
  return 1
}

# case_start / case_survived: the backend must be the same process at the end
# of a case. When it was OOM-killed (or died), say so, then start it again so
# the next case is judged on its own.
CASE_STARTED=""; CASE_MAX=""
case_start(){ CASE_STARTED="$(started_at)"; CASE_MAX="$(cg_read memory.max | tr -d '[:space:]')"; sample_start; }
case_survived(){ # <label>; returns 1 (and records a gate failure) if it died
  local peak st
  peak="$(sample_stop)"
  st="$(docker inspect "$BACKEND_CTR" --format 'running={{.State.Running}} oomkilled={{.State.OOMKilled}} exit={{.State.ExitCode}}' 2>/dev/null)"
  if running && [ "$(started_at)" = "$CASE_STARTED" ]; then
    note "$1: backend stayed up under memory.max=$(cg_read memory.max) (sampled peak anon ${peak} MiB)"
    return 0
  fi
  fail_g "$1: the backend died during the case (${st}; last sampled anon ${peak} MiB, memory.max ${CASE_MAX})"
  restart_backend
  return 1
}
restart_backend(){
  if ! running; then docker start "$BACKEND_CTR" >/dev/null 2>&1; fi
  wait_healthy 180 || note "backend did not come back healthy within 180 s"
}

# --- API helpers ----------------------------------------------------------------
BASIC="Authorization: Basic $(printf 'admin:%s' "$ADMIN_PASS" | base64 | tr -d '\n')"
login(){
  TOK="$(curl -s --max-time 20 -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg p "$ADMIN_PASS" '{username:"admin",password:$p}')" | jqr '.access_token // .token // empty')"
  AH="Authorization: Bearer ${TOK}"
}
mk(){ # <key> <format> <type> -> prints the new repository id
  curl -s --max-time 30 -X POST "$BASE/api/v1/repositories" -H "$AH" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg f "$2" --arg t "$3" '{key:$k,name:$k,format:$f,repo_type:$t,is_public:true}')" \
    | jqr '.id // empty'
}
# put_file <url> <file> [auth-header] -> HTTP code
put_file(){
  curl -s -o "$W/put.out" -w '%{http_code}' --max-time 900 -X PUT -H "${3:-$BASIC}" \
    -H 'Content-Type: application/octet-stream' --data-binary @"$2" "$1" || true
}
# parallel_get <label> <url> <want-sha> [auth-header]: PARALLEL rate-limited
# GETs at once, so each response is in flight at the same time as the others.
# Every one must be 200 with the exact bytes.
parallel_get(){
  local label="$1" url="$2" want="$3" auth="${4:-$BASIC}" i pids="" ok=0 codes=""
  for i in $(seq 1 "$PARALLEL"); do
    ( c="$(curl -s --max-time 300 --limit-rate "$RATE" -H "$auth" -o "$W/dl.$i" -w '%{http_code}' "$url" || true)"
      echo "$c $(sha_of "$W/dl.$i")" > "$W/dl.$i.res"; rm -f "$W/dl.$i" ) &
    pids="$pids $!"
  done
  # shellcheck disable=SC2086
  wait $pids
  for i in $(seq 1 "$PARALLEL"); do
    read -r c s < "$W/dl.$i.res" 2>/dev/null || { c=000; s=""; }
    codes="${codes} ${c}"
    [ "$c" = "200" ] && [ "$s" = "$want" ] && ok=$((ok+1))
    rm -f "$W/dl.$i.res"
  done
  note "${label}: ${ok} of ${PARALLEL} parallel GETs were 200 with the exact bytes (codes:${codes})"
  [ "$ok" -eq "$PARALLEL" ] || fail_g "${label}: only ${ok} of ${PARALLEL} parallel GETs of the ${WHEEL_MIB} MiB file returned the exact bytes (codes:${codes})"
}
get_sha(){ # <url> [auth] -> "<code> <sha>"
  local c
  c="$(curl -s --max-time 900 -H "${2:-$BASIC}" -o "$W/get.bin" -w '%{http_code}' "$1" || true)"
  echo "$c $(sha_of "$W/get.bin")"; rm -f "$W/get.bin"
}

# =============================================================================
begin_suite "bounded-memory-streaming"

begin_test "setup: admin login, the memory cap is in force, fixtures"
login
if [ -z "$TOK" ]; then infra_fail "admin login failed at $BASE"; end_suite; fi
MAX="$(cg_read memory.max | tr -d '[:space:]')"
SWAPMAX="$(cg_read memory.swap.max | tr -d '[:space:]')"
if [ -z "$MAX" ] || [ "$MAX" = "max" ]; then
  infra_fail "the backend has no memory limit (memory.max='${MAX}'); profiles/limits.memory.yml was not applied"; end_suite
fi
SUF="${DTF_SLOT}x${RUN_ID##*-}"
head -c $((BIG_MIB * 1048576)) /dev/urandom > "$W/big.bin"
BIG_SHA="$(sha_of "$W/big.bin")"
head -c $((WHEEL_MIB * 1048576)) /dev/urandom > "$W/mid.bin"
head -c 1048576 /dev/urandom > "$W/small.bin"
pass "memory.max=${MAX} ($(mib "$MAX") MiB), memory.swap.max=${SWAPMAX:-?}; fixtures ${BIG_MIB} MiB and ${WHEEL_MIB} MiB generated"

# -----------------------------------------------------------------------------
begin_test "FIX #5130: the backend reports jemalloc as its global allocator at startup"
reset_case
ALLOC="$(docker logs "$BACKEND_CTR" 2>&1 | grep -o 'Global allocator: [a-z]*' | head -n1 || true)"
note "first startup line: '${ALLOC:-<none>}'"
case "$ALLOC" in
  "Global allocator: jemalloc") ;;
  "") fail_g "no 'Global allocator:' line in the backend log (is logging.json-file stacked?)" ;;
  *) fail_g "the shipped image runs '${ALLOC#Global allocator: }', expected jemalloc (glibc malloc keeps freed burst memory in per-thread arenas)" ;;
esac
finish_case "the image does not run jemalloc"

# -----------------------------------------------------------------------------
# Repositories for every case, and the small controls.
PYH="bms-pyh-${SUF}"; PYV="bms-pyv-${SUF}"; CN="bms-conan-${SUF}"
OCI="bms-oci-${SUF}"; GEN="bms-gen-${SUF}"; RPM="bms-rpm-${SUF}"
SETUP_ERR=""
for spec in "$PYH pypi local" "$PYV pypi virtual" "$CN conan local" "$OCI docker local" "$GEN generic local" "$RPM rpm local"; do
  # shellcheck disable=SC2086
  set -- $spec
  id="$(mk "$1" "$2" "$3")"
  [ -n "$id" ] || SETUP_ERR="${SETUP_ERR} create:$1"
  [ "$1" = "$GEN" ] && GEN_ID="$id"
done
c="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/repositories/${PYV}/members" -H "$AH" \
  -H 'Content-Type: application/json' -d "$(jq -nc --arg k "$PYH" '{member_key:$k,priority:1}')")"
case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} member:${c}" ;; esac

# A real wheel (stored, not deflated) around a payload file.
make_wheel(){ # <name> <payload> <out>
  python3 -I - "$1" "$2" "$3" <<'PY'
import sys, zipfile
name, payload, out = sys.argv[1:4]
with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
    z.write(payload, f"{name}/blob.bin")
    z.writestr(f"{name}-1.0.dist-info/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n")
    z.writestr(f"{name}-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: dtf\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    z.writestr(f"{name}-1.0.dist-info/RECORD", "")
PY
}
upload_wheel(){ # <name> <wheel> -> HTTP code
  curl -s -o "$W/up.out" -w '%{http_code}' --max-time 900 -H "$BASIC" \
    -F ':action=file_upload' -F "name=$1" -F 'version=1.0' -F "sha256_digest=$(sha_of "$2")" \
    -F "content=@$2" "$BASE/pypi/${PYH}/" || true
}
# Conan: a recipe revision with a package revision, through the v2 file API
# a client uses (conanfile.py + manifest, conaninfo.txt + conan_package.tgz
# + manifest).
RREV="0123456789abcdef0123456789abcdef"; PKGID="da39a3ee5e6b4b0d3255bfef95601890afd80709"
RU="$BASE/conan/${CN}/v2/conans/dtfmem/1.0/_/_/revisions/${RREV}"
printf 'from conan import ConanFile\nclass P(ConanFile):\n    name = "dtfmem"\n    version = "1.0"\n' > "$W/conanfile.py"
printf '[settings]\nos=Linux\n' > "$W/conaninfo.txt"
printf '1713000000\nconanfile.py: d41d8cd98f00b204e9800998ecf8427e\n' > "$W/m-recipe.txt"
printf '1713000000\nconaninfo.txt: d41d8cd98f00b204e9800998ecf8427e\nconan_package.tgz: d41d8cd98f00b204e9800998ecf8427e\n' > "$W/m-pkg.txt"
conan_pkg_url(){ echo "${RU}/packages/${PKGID}/revisions/$1/files"; }
conan_publish(){ # <prev> <package-file> -> "<code of the package file PUT>"
  local u c; u="$(conan_pkg_url "$1")"
  put_file "$u/conaninfo.txt" "$W/conaninfo.txt" >/dev/null
  c="$(put_file "$u/conan_package.tgz" "$2")"
  put_file "$u/conanmanifest.txt" "$W/m-pkg.txt" >/dev/null
  echo "$c"
}
for f in conanfile.py:conanfile.py m-recipe.txt:conanmanifest.txt; do
  c="$(put_file "${RU}/files/${f#*:}" "$W/${f%%:*}")"
  case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} conan-recipe:${c}" ;; esac
done
# oci_session -> absolute upload Location
oci_session(){
  local loc
  loc="$(curl -s -D- -o /dev/null -X POST -H "$BASIC" "$BASE/v2/${OCI}/app/blobs/uploads/" \
    | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')"
  [ -n "$loc" ] || return 1
  case "$loc" in http*) echo "$loc" ;; *) echo "${BASE}${loc}" ;; esac
}
# oci_put <file> <digest> -> sets OCI_CODE, OCI_POST (secs to last byte sent),
# OCI_TOTAL, OCI_RCHAR (bytes the backend process read during the PUT)
oci_put(){
  local loc sep r0 r1 out
  OCI_CODE=000; OCI_POST=""; OCI_TOTAL=""; OCI_RCHAR=""
  loc="$(oci_session)" || return 0
  case "$loc" in *\?*) sep='&' ;; *) sep='?' ;; esac
  r0="$(rchar)"
  out="$(curl -s -o "$W/oci.out" -w '%{http_code} %{time_posttransfer} %{time_total}' --max-time 900 -X PUT \
    -H "$BASIC" -H 'Content-Type: application/octet-stream' --data-binary @"$1" "${loc}${sep}digest=$2" || true)"
  r1="$(rchar)"
  read -r OCI_CODE OCI_POST OCI_TOTAL <<<"$out"
  [ -n "$r0" ] && [ -n "$r1" ] && OCI_RCHAR=$(( r1 - r0 ))
}

begin_test "CONTROL: 1 MiB files round-trip through the PyPI virtual, hosted Conan and an OCI push, byte-exact"
reset_case
if [ -n "$SETUP_ERR" ]; then infra_fail "setup failed:${SETUP_ERR} ($(head -c 300 "$W/put.out" 2>/dev/null))"; end_suite; fi
make_wheel dtfsmall "$W/small.bin" "$W/dtfsmall-1.0-py3-none-any.whl"
c="$(upload_wheel dtfsmall "$W/dtfsmall-1.0-py3-none-any.whl")"
[ "$c" = "200" ] || [ "$c" = "201" ] || fail_g "small wheel upload answered ${c}: $(head -c 200 "$W/up.out")"
read -r c s <<<"$(get_sha "$BASE/pypi/${PYV}/simple/dtfsmall/dtfsmall-1.0-py3-none-any.whl")"
[ "$c" = "200" ] && [ "$s" = "$(sha_of "$W/dtfsmall-1.0-py3-none-any.whl")" ] || fail_g "small wheel through the virtual: ${c}, bytes differ"
c="$(conan_publish 10000000000000000000000000000001 "$W/small.bin")"
case "$c" in 2??) ;; *) fail_g "small conan_package.tgz upload answered ${c}" ;; esac
read -r c s <<<"$(get_sha "$(conan_pkg_url 10000000000000000000000000000001)/conan_package.tgz")"
[ "$c" = "200" ] && [ "$s" = "$(sha_of "$W/small.bin")" ] || fail_g "small conan_package.tgz download: ${c}, bytes differ"
SD="sha256:$(sha_of "$W/small.bin")"
oci_put "$W/small.bin" "$SD"
[ "$OCI_CODE" = "201" ] || fail_g "small OCI blob PUT answered ${OCI_CODE}"
read -r c s <<<"$(get_sha "$BASE/v2/${OCI}/app/blobs/${SD}")"
[ "$c" = "200" ] && [ "sha256:$s" = "$SD" ] || fail_g "small OCI blob GET: ${c}, bytes differ"
note "small wheel, conan package and OCI blob round-tripped"
finish_case "the small round trips failed"

# -----------------------------------------------------------------------------
begin_test "CONTROL #5133: a ${BIG_MIB} MiB layer (more than the ${CAP} cap) pushed as one whole-body PUT is 201 and pulls byte-exact"
reset_case
BIG_D="sha256:${BIG_SHA}"
case_start
oci_put "$W/big.bin" "$BIG_D"
note "PUT ?digest= -> ${OCI_CODE}; last body byte sent at ${OCI_POST}s, response at ${OCI_TOTAL}s; backend read $(mib "${OCI_RCHAR:-0}") MiB during the PUT"
[ "$OCI_CODE" = "201" ] || fail_g "whole-body PUT of the ${BIG_MIB} MiB layer answered ${OCI_CODE}: $(head -c 200 "$W/oci.out")"
case_survived "whole-body ${BIG_MIB} MiB PUT" || true
read -r c s <<<"$(get_sha "$BASE/v2/${OCI}/app/blobs/${BIG_D}")"
[ "$c" = "200" ] && [ "$s" = "$BIG_SHA" ] || fail_g "GET of the pushed layer: ${c}, bytes differ"
finish_case "a layer larger than the cap could not be pushed and pulled"

begin_test "FIX #5133: finalizing that whole-body PUT did not re-read the layer (backend read < 1/8 of it; pre-fix about 2x)"
reset_case
if [ -z "$OCI_RCHAR" ]; then
  fail_g "could not read /proc/1/io of the backend around the PUT"
else
  note "backend read $(mib "$OCI_RCHAR") MiB (rchar) while finalizing a ${BIG_MIB} MiB layer; response $(awk -v t="${OCI_TOTAL:-0}" -v p="${OCI_POST:-0}" 'BEGIN{printf "%.2f", t-p}') s after the last body byte"
  [ "$OCI_RCHAR" -lt $(( BIG_MIB * 1048576 / 8 )) ] || \
    fail_g "the backend re-read $(mib "$OCI_RCHAR") MiB of the ${BIG_MIB} MiB layer before answering the final PUT (rehash/concat of a whole-body upload)"
fi
finish_case "the whole-body layer was re-read at finalize"

# -----------------------------------------------------------------------------
begin_test "FIX #5126: ${PARALLEL} parallel downloads of a ${WHEEL_MIB} MiB hosted wheel through a PyPI virtual (filesystem, no presign) stay under the ${CAP} cap"
reset_case
make_wheel dtfbig "$W/mid.bin" "$W/dtfbig-1.0-py3-none-any.whl"
WHL_SHA="$(sha_of "$W/dtfbig-1.0-py3-none-any.whl")"
c="$(upload_wheel dtfbig "$W/dtfbig-1.0-py3-none-any.whl")"
if [ "$c" != "200" ] && [ "$c" != "201" ]; then
  fail_g "wheel upload answered ${c}: $(head -c 200 "$W/up.out")"
else
  case_start
  parallel_get "PyPI virtual ${PYV}" "$BASE/pypi/${PYV}/simple/dtfbig/dtfbig-1.0-py3-none-any.whl" "$WHL_SHA"
  case_survived "PyPI virtual serves" || true
fi
rm -f "$W/dtfbig-1.0-py3-none-any.whl"
finish_case "hosted members of a PyPI virtual are buffered whole per request"

# -----------------------------------------------------------------------------
begin_test "FIX #5364: ${PARALLEL} parallel downloads of a ${WHEEL_MIB} MiB hosted conan_package.tgz stay under the ${CAP} cap"
reset_case
PREV_MID="20000000000000000000000000000002"
c="$(conan_publish "$PREV_MID" "$W/mid.bin")"
if [ "${c:0:1}" != "2" ]; then
  fail_g "conan_package.tgz upload (${WHEEL_MIB} MiB) answered ${c}: $(head -c 200 "$W/put.out")"
  restart_backend
else
  case_start
  parallel_get "Conan package file" "$(conan_pkg_url "$PREV_MID")/conan_package.tgz" "$(sha_of "$W/mid.bin")"
  case_survived "Conan package downloads" || true
fi
finish_case "hosted Conan package downloads are read whole into memory"

begin_test "FIX #5364: a ${BIG_MIB} MiB conan_package.tgz upload (more than the cap) streams: 201, then downloads byte-exact"
reset_case
PREV_BIG="30000000000000000000000000000003"
case_start
c="$(conan_publish "$PREV_BIG" "$W/big.bin")"
note "PUT conan_package.tgz (${BIG_MIB} MiB) -> ${c}"
[ "${c:0:1}" = "2" ] || fail_g "the ${BIG_MIB} MiB conan_package.tgz upload answered ${c}"
if case_survived "Conan ${BIG_MIB} MiB upload" && [ "${c:0:1}" = "2" ]; then
  read -r c s <<<"$(get_sha "$(conan_pkg_url "$PREV_BIG")/conan_package.tgz")"
  [ "$c" = "200" ] && [ "$s" = "$BIG_SHA" ] || fail_g "download of the uploaded package: ${c}, bytes differ"
fi
finish_case "hosted Conan uploads are buffered whole"

# -----------------------------------------------------------------------------
# Backup: BACKUP_FILES distinct random artifacts, more than the cap in all.
for i in $(seq 1 "$BACKUP_FILES"); do
  head -c $((BACKUP_MIB * 1048576)) /dev/urandom > "$W/bk$i.bin"
  sha_of "$W/bk$i.bin" > "$W/bk$i.sha"
  c="$(put_file "$BASE/api/v1/repositories/${GEN}/artifacts/data/bk$i.bin" "$W/bk$i.bin" "$AH")"
  rm -f "$W/bk$i.bin"
  case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} generic-put$i:${c}" ;; esac
done
BACKUP_TOTAL=$(( BACKUP_FILES * BACKUP_MIB ))
run_backup(){ # -> sets BK_ID BK_STATUS BK_COUNT BK_SIZE BK_ERR
  BK_ID="$(curl -s --max-time 30 -X POST "$BASE/api/v1/admin/backups" -H "$AH" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg r "$GEN_ID" '{type:"full",repository_ids:[$r]}')" | jqr '.id // empty')"
  [ -n "$BK_ID" ] || { BK_STATUS="create-failed"; return 0; }
  curl -s --max-time 900 -o "$W/bk.json" -X POST "$BASE/api/v1/admin/backups/${BK_ID}/execute" -H "$AH" || true
  BK_STATUS="$(psql_q -c "SELECT status FROM backups WHERE id='${BK_ID}'" | tr -d '[:space:]')"
  BK_COUNT="$(jqr '.artifact_count // empty' < "$W/bk.json")"
  BK_SIZE="$(jqr '.size_bytes // empty' < "$W/bk.json")"
  BK_ERR="$(jqr '.error_message // empty' < "$W/bk.json")"
}

begin_test "FIX #5336: a backup of ${BACKUP_FILES} x ${BACKUP_MIB} MiB artifacts (${BACKUP_TOTAL} MiB, more than the cap) completes under the ${CAP} cap"
reset_case
if [ -n "$SETUP_ERR" ]; then fail_g "generic uploads failed:${SETUP_ERR}"; else
  case_start
  run_backup
  note "backup ${BK_ID:-?}: status '${BK_STATUS}', artifact_count ${BK_COUNT:-?}, size $(mib "${BK_SIZE:-0}") MiB ${BK_ERR:+error '${BK_ERR}'}"
  case_survived "backup" || true
  [ "$BK_STATUS" = "completed" ] || fail_g "backup did not complete (status '${BK_STATUS}')"
  [ "${BK_COUNT:-0}" = "$BACKUP_FILES" ] || fail_g "backup artifact_count '${BK_COUNT}', expected ${BACKUP_FILES}"
fi
finish_case "backup buffers every artifact and the archive in memory"

begin_test "FIX #5336: restoring that backup's artifacts (stored objects removed first) completes under the ${CAP} cap and every artifact is byte-exact"
reset_case
RESTORE_BK="$BK_ID"
if [ "${BK_STATUS:-}" != "completed" ] && [ -z "$SETUP_ERR" ]; then
  # The buffering backup cannot run under the cap. Take the archive with the
  # cap raised (HELPER_CAP, this container only), then restart the backend
  # under the cap again, so the restore itself is still judged under it.
  note "no archive from the capped run: taking one with memory.max raised to ${HELPER_CAP} for the backup only"
  docker update --memory "$HELPER_CAP" --memory-swap "$HELPER_CAP" "$BACKEND_CTR" >/dev/null 2>&1
  restart_backend
  run_backup
  note "helper backup ${BK_ID:-?}: status '${BK_STATUS}', artifact_count ${BK_COUNT:-?}"
  docker stop "$BACKEND_CTR" >/dev/null 2>&1
  docker update --memory "$CAP" --memory-swap "$CAP" "$BACKEND_CTR" >/dev/null 2>&1
  restart_backend
  [ "$(cg_read memory.max | tr -d '[:space:]')" = "$MAX" ] || note "memory.max after re-capping: $(cg_read memory.max)"
  [ "$BK_STATUS" = "completed" ] && RESTORE_BK="$BK_ID"
fi
if [ -z "$RESTORE_BK" ] || [ "${BK_STATUS:-}" != "completed" ]; then
  fail_g "no completed backup to restore (status '${BK_STATUS:-}')"
else
  # Lose the stored objects (the disaster a restore is for).
  removed=0
  for k in $(psql_q -c "SELECT storage_key FROM artifacts WHERE repository_id='${GEN_ID}' AND NOT is_deleted"); do
    docker exec "$BACKEND_CTR" rm -f "/data/storage/${GEN}/${k}" && removed=$((removed+1))
  done
  read -r c s <<<"$(get_sha "$BASE/api/v1/repositories/${GEN}/download/data/bk1.bin" "$AH")"
  note "removed ${removed} stored objects; a download now answers ${c}"
  case_start
  rc="$(curl -s --max-time 900 -o "$W/rs.json" -w '%{http_code}' -X POST "$BASE/api/v1/admin/backups/${RESTORE_BK}/restore" \
    -H "$AH" -H 'Content-Type: application/json' -d '{"restore_database":false,"restore_artifacts":true}' || true)"
  note "restore -> ${rc}: $(jq -c '{artifacts_restored,status,errors}' < "$W/rs.json" 2>/dev/null | head -c 300)"
  if case_survived "restore"; then
    [ "$rc" = "200" ] || fail_g "restore answered ${rc}"
    [ "$(jqr '.artifacts_restored // 0' < "$W/rs.json")" = "$BACKUP_FILES" ] || fail_g "artifacts_restored '$(jqr '.artifacts_restored' < "$W/rs.json")', expected ${BACKUP_FILES}"
    exact=0
    for i in $(seq 1 "$BACKUP_FILES"); do
      read -r c s <<<"$(get_sha "$BASE/api/v1/repositories/${GEN}/download/data/bk$i.bin" "$AH")"
      [ "$c" = "200" ] && [ "$s" = "$(cat "$W/bk$i.sha")" ] && exact=$((exact+1))
    done
    note "${exact} of ${BACKUP_FILES} restored artifacts download byte-exact"
    [ "$exact" = "$BACKUP_FILES" ] || fail_g "only ${exact} of ${BACKUP_FILES} artifacts came back byte-exact"
  fi
fi
finish_case "restore buffers the whole archive in memory"

# -----------------------------------------------------------------------------
# Last: this case raises the cap (RPM_CAP) and leaves it raised.
begin_test "FIX #4924: a cold repodata render of a ${RPM_PACKAGES}-package hosted RPM root answers 200 under a ${RPM_CAP} cap, and the documents are complete"
reset_case
# The render reads artifacts + artifact_metadata rows, never package bytes,
# so the root is seeded straight into Postgres (the artifact-keeper-test#621
# approach). Every package carries the same RPM_FILES-entry file list in a
# current (v2) repodata block, so neither image heals it from storage.
# repodata_mode=on_request keeps the root on the request path (the code #4924
# fixed) on images that have the precomputed builder; older images ignore it.
psql_q -c "INSERT INTO repository_config (repository_id, key, value) SELECT id, 'repodata_mode', 'on_request' FROM repositories WHERE key = '${RPM}'" >/dev/null
seed_t0=$(date +%s); SEED_ERR=""
for first in $(seq 1 250 "$RPM_PACKAGES"); do
  last=$((first + 249)); [ "$last" -gt "$RPM_PACKAGES" ] && last="$RPM_PACKAGES"
  docker exec -i "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -tAq >/dev/null 2>&1 <<SQL || SEED_ERR="${SEED_ERR} ${first}-${last}"
WITH ins AS (
  INSERT INTO artifacts (repository_id, path, name, version, size_bytes,
                         checksum_sha256, content_type, storage_key, uploaded_by)
  SELECT r.id,
         'packages/dtf-large-' || lpad(g::text, 5, '0') || '-1.0-1.x86_64.rpm',
         'dtf-large-' || lpad(g::text, 5, '0'), '1.0-1', 65536,
         encode(sha256(('dtf-large-' || g)::bytea), 'hex'),
         'application/x-rpm', 'rpm/${RPM}/dtf-large-' || g || '.rpm',
         (SELECT id FROM users WHERE username = 'admin')
  FROM repositories r, generate_series(${first}, ${last}) g
  WHERE r.key = '${RPM}'
  RETURNING id, name
)
INSERT INTO artifact_metadata (artifact_id, format, metadata)
SELECT ins.id, 'rpm', jsonb_build_object(
         'name', ins.name, 'version', '1.0', 'release', '1', 'arch', 'x86_64',
         'summary', 'DTF synthetic package with a long file list',
         'repodata', jsonb_build_object('v', 2, 'header_start', 280, 'header_end', 60000,
           'files', fl.files))
FROM ins, (SELECT jsonb_agg(jsonb_build_object('path',
             '/usr/share/dtf-large/data/file-' || lpad(f::text, 6, '0') || '.dat')) AS files
           FROM generate_series(1, ${RPM_FILES}) f) fl;
SQL
done
n="$(psql_q -c "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${RPM}'")"
meta="$(psql_q -c "SELECT sum(octet_length(m.metadata::text)) / 1048576 FROM artifact_metadata m JOIN artifacts a ON a.id = m.artifact_id JOIN repositories r ON r.id = a.repository_id WHERE r.key = '${RPM}'")"
note "seeded ${n} packages, ${meta} MiB of metadata JSON, in $(( $(date +%s) - seed_t0 ))s${SEED_ERR:+ (errors:${SEED_ERR})}"
if [ "$n" != "$RPM_PACKAGES" ]; then
  fail_g "expected ${RPM_PACKAGES} seeded rows, found '${n}'"
else
  docker update --memory "$RPM_CAP" --memory-swap "$RPM_CAP" "$BACKEND_CTR" >/dev/null 2>&1 || note "docker update to ${RPM_CAP} failed"
  case_start
  t0=$(date +%s)
  c="$(curl -s --max-time 900 -o "$W/repomd.xml" -w '%{http_code}' "$BASE/rpm/${RPM}/repodata/repomd.xml" || true)"
  note "cold repomd.xml -> ${c} after $(( $(date +%s) - t0 ))s"
  if case_survived "cold RPM render"; then
    [ "$c" = "200" ] || fail_g "cold repomd.xml answered ${c}"
    for doc in primary filelists; do
      c="$(curl -s --max-time 300 -o "$W/$doc.xml.gz" -w '%{http_code}' "$BASE/rpm/${RPM}/repodata/$doc.xml.gz" || true)"
      sha="$(sha_of "$W/$doc.xml.gz")"
      adv="$(grep -A3 "<data type=\"$doc\">" "$W/repomd.xml" | grep -o '<checksum type="sha256">[0-9a-f]*' | sed 's/.*>//')"
      cnt="$(gzip -dc "$W/$doc.xml.gz" 2>/dev/null | grep -c '<package ')"
      note "${doc}.xml.gz -> ${c}, ${cnt} packages, sha ${sha:0:12} (repomd.xml says ${adv:0:12})"
      [ "$c" = "200" ] && [ "$sha" = "$adv" ] && [ "$cnt" = "$RPM_PACKAGES" ] || fail_g "${doc}.xml.gz incomplete or not the document repomd.xml describes"
    done
    files="$(gzip -dc "$W/filelists.xml.gz" 2>/dev/null | grep -c '<file>')"
    [ "$files" = "$(( RPM_PACKAGES * RPM_FILES ))" ] || fail_g "filelists lists ${files} files, expected $(( RPM_PACKAGES * RPM_FILES ))"
    rm -f "$W/primary.xml.gz" "$W/filelists.xml.gz"
  fi
fi
finish_case "a cold repodata render of a large root does not fit"

end_suite
