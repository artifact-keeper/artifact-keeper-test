#!/usr/bin/env bash
# =============================================================================
# tiers/disk-usage-thresholds/oracle.sh: the storage volume's disk usage
# thresholds warn, then refuse writes with 403 DISK_THRESHOLD_EXCEEDED while
# reads keep working, and writes resume once disk is freed
# (artifact-keeper#5191)
# =============================================================================
# run.sh has stood up storage.filesystem + storage.disk-thresholds (a 64 MiB
# tmpfs at STORAGE_PATH, warn 60 %, block 80 %, measured every second) with
# RATE_LIMIT_ENABLED=false, and exported BASE_URL, DB_CONTAINER, COMMON_SH,
# DTF_SLOT, RUN_ID. See the manifest for the gate list.
#
# The volume is filled and freed from a helper container that mounts the same
# tmpfs volume (ak-dtf<slot>_disk): the backend image has no shell.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

require_cmd jq
require_cmd sha256sum

BACKEND_CTR="ak-dtf${DTF_SLOT}-backend"
DISK_VOL="ak-dtf${DTF_SLOT}_disk"
HELPER_IMAGE="postgres:16-alpine"   # already pulled by compose.base.yml
FILL=".dtf-5191-fill"
SUF="$(printf '%s' "${RUN_ID}" | tr -cd '[:alnum:]' | tail -c 8)"
GEN="dut-gen-${DTF_SLOT}-${SUF}"
MVN="dut-mvn-${DTF_SLOT}-${SUF}"
OCI="dut-oci-${DTF_SLOT}-${SUF}"
WANT_CODE="DISK_THRESHOLD_EXCEEDED"
WANT_MSG="server storage nearly full: free disk or add storage"
# Seconds to wait for the backend's next reading (it measures every second).
SETTLE=15

setup_workdir
W="$WORK_DIR"

# helper <sh -c script>: run in a container that mounts the tmpfs at /fill.
helper() {
  docker run --rm -v "${DISK_VOL}:/fill" --entrypoint sh "$HELPER_IMAGE" -c "$1" 2>/dev/null || true
}
# Under common.sh's set -e: every helper below answers 0.
# used_pct: the volume's usage as df counts it (used / (used + available)).
used_pct() {
  helper "df -Pk /fill | awk 'NR==2 { printf \"%d\", (\$3 * 100) / (\$3 + \$4) }'"
}
# fill_to <percent>: add a fill file (one per call, named by <percent>: the
# helper is PID 1 in every container) until the volume is at <percent>.
fill_to() {
  helper "set -e; f=/fill/${FILL}; df -Pk /fill | awk 'NR==2 {print \$3, \$4}' | {
    read used avail; cap=\$((used + avail)); want=\$((cap * $1 / 100 - used));
    [ \$want -gt 0 ] && dd if=/dev/zero of=\$f.$1 bs=1024 count=\$want 2>/dev/null; true; }"
}
free_fill() { helper "rm -f /fill/${FILL}*" || true; }
add_exit_handler 'free_fill >/dev/null 2>&1 || true'

# disk_state -> the backend's .disk.state ("" before #5191).
disk_state() {
  curl -s $CURL_TIMEOUT -H "$(auth_header)" "${BASE_URL}/api/v1/system/quota" 2>/dev/null \
    | jq -r '.disk.state // empty' 2>/dev/null || true
}
# wait_state <state>: until the backend reports <state>, at most SETTLE s.
wait_state() {
  local _i
  for _i in $(seq 1 "$SETTLE"); do
    [ "$(disk_state)" = "$1" ] && return 0
    sleep 1
  done
  return 1
}
gauge_state() {
  curl -s --max-time 30 -H "$(auth_header)" "${BASE_URL}/api/v1/admin/metrics" 2>/dev/null \
    | grep -E '^ak_storage_disk_state(\{[^}]*\})? ' | awk '{print $2}' | head -1 || true
}

# req <label> <method> <url> [curl args...]: headers, body, code and the
# bytes curl sent land in $W/<label>.{hdr,body,res}.
req() {
  local l="$1" m="$2" url="$3"; shift 3
  curl -s --max-time 60 -X "$m" -D "$W/$l.hdr" -o "$W/$l.body" \
    -w '%{http_code} %{size_upload}' "$@" "$url" > "$W/$l.res" 2>/dev/null \
    || echo "000 0" > "$W/$l.res"
}
code_of() { cut -d' ' -f1 "$W/$1.res"; }
sent_of() { cut -d' ' -f2 "$W/$1.res" | cut -d. -f1; }
body_of() { head -c 400 "$W/$1.body" 2>/dev/null | tr -d '\0'; }
json_of() { jq -r "$2 // empty" "$W/$1.body" 2>/dev/null || true; }
reason_of() { head -1 "$W/$1.hdr" 2>/dev/null | tr -d '\r' | cut -d' ' -f3-; }
ev() { printf '%s: HTTP %s (%s) sent=%s body: %s' "$1" "$(code_of "$1")" "$(reason_of "$1")" "$(sent_of "$1")" "$(body_of "$1")"; }

# disk_refused <label>: 403, the disk code and message, its reason phrase.
disk_refused() {
  [ "$(code_of "$1")" = "403" ] \
    && [ "$(json_of "$1" .code)" = "$WANT_CODE" ] \
    && [[ "$(json_of "$1" .message)" == "${WANT_MSG}"* ]] \
    && [ "$(reason_of "$1")" = "Disk Threshold Exceeded" ]
}
# oci_disk_refused <label>: 403 in the /v2 envelope, DENIED, the disk message.
oci_disk_refused() {
  [ "$(code_of "$1")" = "403" ] \
    && [ "$(json_of "$1" '.errors[0].code')" = "DENIED" ] \
    && [[ "$(json_of "$1" '.errors[0].message')" == "${WANT_MSG}"* ]]
}

put_gen() { # <label> <name> <file> [curl args...]
  local l="$1" n="$2" f="$3"; shift 3
  req "$l" PUT "${BASE_URL}/api/v1/repositories/${GEN}/artifacts/dut/$n" \
    -H "$(auth_header)" -H 'Content-Type: application/octet-stream' --data-binary "@$f" "$@"
}
get_gen() { # <label> <name>
  req "$1" GET "${BASE_URL}/api/v1/repositories/${GEN}/download/dut/$2" -H "$(auth_header)"
}
put_mvn() { # <label> <version> <file>
  req "$1" PUT "${BASE_URL}/maven/${MVN}/com/example/dut/$2/dut-$2.jar" \
    -H "$(auth_header)" --data-binary "@$3"
}
create_repo() { # KEY FORMAT -> http code
  curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST "${BASE_URL}/api/v1/repositories" \
    -H "$(auth_header)" -H 'Content-Type: application/json' \
    -d "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"${2}\",\"repo_type\":\"local\",\"is_public\":false}" \
    2>/dev/null || echo 000
}
backend_log_count() { # <ERE> -> matching backend log lines since <since>
  docker logs --since "$2" "$BACKEND_CTR" 2>&1 | grep -cE "$1" || true
}

begin_suite "disk-usage-thresholds"
auth_admin   # sets ADMIN_TOKEN

head -c 65536 /dev/urandom > "$W/small.bin"
head -c $((12 * 1024 * 1024)) /dev/urandom > "$W/big.bin"

# --- setup -------------------------------------------------------------------
begin_test "SETUP: generic, maven and docker repositories on a 64 MiB tmpfs storage volume"
SETUP_ERR=""
for spec in "$GEN generic" "$MVN maven" "$OCI docker"; do
  set -- $spec
  c="$(create_repo "$1" "$2")"
  case "$c" in 2??) ;; *) SETUP_ERR="${SETUP_ERR} create($1:$c)" ;; esac
done
free_fill
pct0="$(used_pct)"
cap_kb="$(helper "df -Pk /fill | awk 'NR==2 {print \$3 + \$4}'")"
[[ "$pct0" =~ ^[0-9]+$ ]] && [ "$pct0" -lt 50 ] || SETUP_ERR="${SETUP_ERR} volume(${pct0:-?}%)"
[[ "$cap_kb" =~ ^[0-9]+$ ]] && [ "$cap_kb" -le 70000 ] || SETUP_ERR="${SETUP_ERR} capacity(${cap_kb:-?} KiB, want the 64 MiB tmpfs)"
if [ -z "$SETUP_ERR" ]; then
  pass "repos ${GEN}, ${MVN}, ${OCI}; volume ${cap_kb} KiB, ${pct0}% used"
else
  infra_fail "setup failed:${SETUP_ERR}"
  end_suite
fi

# --- (CONTROL) below every threshold ------------------------------------------
begin_test "CONTROL: below the thresholds a 64 KiB generic upload and a Maven upload succeed and download"
put_gen c-put pre.bin "$W/small.bin"
put_mvn c-mvn 1.0 "$W/small.bin"
get_gen c-get pre.bin
case "$(code_of c-put)/$(code_of c-mvn)/$(code_of c-get)" in
  2??/2??/200)
    if cmp -s "$W/small.bin" "$W/c-get.body"; then pass "uploads 2xx, download byte-identical"
    else fail "download differs from the upload"; fi ;;
  *) fail "below the thresholds: $(ev c-put); $(ev c-mvn); $(ev c-get)" ;;
esac

# --- (CONTROL cost) the check adds nothing measurable to an upload -------------
# 50 sequential 64 KiB uploads below the thresholds; p50/p95 are reported for
# the before/after comparison (the backend reads a cached reading, no statvfs
# per request).
begin_test "CONTROL: 50 sequential 64 KiB uploads below the thresholds all succeed (latency reported)"
: > "$W/lat.txt"; perf_bad=0
for n in $(seq 1 50); do
  put_gen p-put "perf-${n}.bin" "$W/small.bin" -w '%{http_code} %{size_upload} %{time_total}'
  read -r pc _ pt < "$W/p-put.res" || true
  [[ "$pc" == 2?? ]] || perf_bad=$((perf_bad + 1))
  echo "${pt:-0}" >> "$W/lat.txt"
done
lat="$(sort -n "$W/lat.txt" | awk '{a[NR]=$1} END {printf "p50=%.1fms p95=%.1fms", a[int(NR*0.5)]*1000, a[int(NR*0.95)]*1000}')"
echo "  upload latency (50 x 64 KiB, below the thresholds): ${lat}"
if [ "$perf_bad" = "0" ]; then pass "50/50 uploads 2xx, ${lat}"
else fail "${perf_bad}/50 uploads not 2xx (${lat})"; fi

# --- OCI fixtures, below the thresholds ------------------------------------------
# An image pushed to $OCI/img (its layer is mounted into $OCI/other while
# blocked: on filesystem storage each repository has its own root, so a
# mount is honoured within a repository), and an upload
# session opened now and fed a chunk while blocked.
begin_test "CONTROL: below the thresholds an OCI image push succeeds and an upload session opens"
BLOB_DIGEST="sha256:$(sha256sum "$W/small.bin" | cut -d' ' -f1)"
req c-oci-blob POST "${BASE_URL}/v2/${OCI}/img/blobs/uploads/?digest=${BLOB_DIGEST}" \
  -H "$(auth_header)" -H 'Content-Type: application/octet-stream' --data-binary "@$W/small.bin"
# A manifest over the blob, so the image holds it and a mount from it is
# honoured (a mount needs the source image to reference the blob).
printf '{}' > "$W/cfg.json"
CFG_DIGEST="sha256:$(sha256sum "$W/cfg.json" | cut -d' ' -f1)"
req c-oci-cfg POST "${BASE_URL}/v2/${OCI}/img/blobs/uploads/?digest=${CFG_DIGEST}" \
  -H "$(auth_header)" -H 'Content-Type: application/octet-stream' --data-binary "@$W/cfg.json"
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":2},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"%s","size":65536}]}' \
  "$CFG_DIGEST" "$BLOB_DIGEST" > "$W/manifest.json"
req c-oci-man PUT "${BASE_URL}/v2/${OCI}/img/manifests/v1" -H "$(auth_header)" \
  -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "@$W/manifest.json"
req c-oci-sess POST "${BASE_URL}/v2/${OCI}/img/blobs/uploads/" -H "$(auth_header)"
SESS_LOC="$(grep -i '^location:' "$W/c-oci-sess.hdr" | head -1 | cut -d' ' -f2- | tr -d '\r')"
case "$SESS_LOC" in http*) ;; "") ;; *) SESS_LOC="${BASE_URL}${SESS_LOC}" ;; esac
if [ "$(code_of c-oci-blob)" = "201" ] && [ "$(code_of c-oci-cfg)" = "201" ] \
   && [ "$(code_of c-oci-man)" = "201" ] && [ "$(code_of c-oci-sess)" = "202" ] && [ -n "$SESS_LOC" ]; then
  pass "blob ${BLOB_DIGEST:0:19}... 201, manifest img:v1 201, session 202"
else
  fail "$(ev c-oci-blob); $(ev c-oci-cfg); $(ev c-oci-man); $(ev c-oci-sess); Location='${SESS_LOC}'"
fi

# --- warning band: 70 % --------------------------------------------------------
fill_to 70
begin_test "FIX #5191: at 70% (warn 60%, block 80%) the state is warning, and a small upload still succeeds"
wait_state warning || true; st="$(disk_state)"
put_gen w-put warn.bin "$W/small.bin"
if [ "$st" = "warning" ] && [[ "$(code_of w-put)" == 2?? ]]; then
  pass "state=warning at $(used_pct)%, 64 KiB upload $(code_of w-put)"
else
  fail "at $(used_pct)%: /api/v1/system/quota .disk.state='${st:-<absent>}' (want warning); $(ev w-put)"
fi

begin_test "FIX #5191: in the warning band an upload whose Content-Length would cross the block threshold is refused 403 before its body is read"
# Expect: 100-continue, so a server that refuses before reading the body
# answers before curl sends it (curl waits for the 100 that never comes).
put_gen w-big big.bin "$W/big.bin" -H 'Expect: 100-continue'
sent="$(sent_of w-big)"
echo "  12 MiB upload crossing the threshold: HTTP $(code_of w-big), request body bytes sent ${sent:-?} of 12582912"
if disk_refused w-big && [ "${sent:-0}" -lt $((12 * 1024 * 1024)) ]; then
  pass "12 MiB upload at $(used_pct)%: 403 ${WANT_CODE}, curl sent ${sent} of 12582912 bytes"
else
  fail "12 MiB upload at $(used_pct)% (would reach ~89%): $(ev w-big) (want 403 ${WANT_CODE} with reason 'Disk Threshold Exceeded', refused before the body is sent)"
fi

# --- blocked: 90 % --------------------------------------------------------------
BLOCK_SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fill_to 90
begin_test "FIX #5191: at 90% the state is blocked and ak_storage_disk_state is 2"
wait_state blocked || true; st="$(disk_state)"; g="$(gauge_state)"
if [ "$st" = "blocked" ] && [ "${g%.*}" = "2" ]; then
  pass "state=blocked at $(used_pct)%, gauge=${g}"
else
  fail "at $(used_pct)%: .disk.state='${st:-<absent>}' (want blocked), ak_storage_disk_state='${g:-<absent>}' (want 2)"
fi

begin_test "FIX #5191: blocked, a 64 KiB generic REST upload is refused 403 DISK_THRESHOLD_EXCEEDED"
put_gen b-put blocked.bin "$W/small.bin"
if disk_refused b-put; then pass "$(ev b-put)"
else fail "$(ev b-put) (want 403 ${WANT_CODE}, reason 'Disk Threshold Exceeded', message '${WANT_MSG}...'; never 507)"; fi

begin_test "FIX #5191: blocked, a Maven PUT is refused 403 DISK_THRESHOLD_EXCEEDED"
put_mvn b-mvn 2.0 "$W/small.bin"
if disk_refused b-mvn; then pass "$(ev b-mvn)"
else fail "$(ev b-mvn) (want 403 ${WANT_CODE})"; fi

begin_test "FIX #5191: blocked, an OCI blob upload start is refused 403 DENIED with the disk message"
req b-oci POST "${BASE_URL}/v2/${OCI}/img/blobs/uploads/" -H "$(auth_header)"
if oci_disk_refused b-oci; then pass "$(ev b-oci)"
else fail "$(ev b-oci) (want 403, errors[0].code DENIED, message '${WANT_MSG}...')"; fi

begin_test "FIX #5191: blocked, a chunk PATCH to an OCI upload session opened before the block is refused 403 DENIED"
if [ -n "$SESS_LOC" ]; then
  req b-oci-patch PATCH "$SESS_LOC" -H "$(auth_header)" -H 'Content-Type: application/octet-stream' \
    -H "Content-Range: 0-65535" --data-binary "@$W/small.bin"
  if oci_disk_refused b-oci-patch; then pass "$(ev b-oci-patch)"
  else fail "$(ev b-oci-patch) (want 403, errors[0].code DENIED, the disk message)"; fi
else
  fail "no upload session was opened before the block"
fi

begin_test "CONTROL: blocked, an OCI blob mount from another image (no bytes written) still succeeds"
req b-mount POST "${BASE_URL}/v2/${OCI}/other/blobs/uploads/?mount=${BLOB_DIGEST}&from=${OCI}/img" \
  -H "$(auth_header)"
if [ "$(code_of b-mount)" = "201" ]; then pass "$(ev b-mount)"
else fail "$(ev b-mount) (want 201 Created: a mount writes no bytes)"; fi

begin_test "FIX #5191: blocked, a chunked body without Content-Length is refused 403 too"
req b-chunk PUT "${BASE_URL}/api/v1/repositories/${GEN}/artifacts/dut/chunked.bin" \
  -H "$(auth_header)" -H 'Content-Type: application/octet-stream' -H 'Transfer-Encoding: chunked' \
  --data-binary "@$W/small.bin"
if disk_refused b-chunk; then pass "$(ev b-chunk)"
else fail "$(ev b-chunk) (want 403 ${WANT_CODE})"; fi

begin_test "CONTROL: blocked, downloads, listing and a delete keep working"
get_gen b-get pre.bin
req b-mvn-get GET "${BASE_URL}/maven/${MVN}/com/example/dut/1.0/dut-1.0.jar" -H "$(auth_header)"
req b-list GET "${BASE_URL}/api/v1/repositories/${GEN}/artifacts" -H "$(auth_header)"
req b-del DELETE "${BASE_URL}/api/v1/repositories/${GEN}/artifacts/dut/warn.bin" -H "$(auth_header)"
if [ "$(code_of b-get)" = "200" ] && cmp -s "$W/small.bin" "$W/b-get.body" \
   && [ "$(code_of b-mvn-get)" = "200" ] && [ "$(code_of b-list)" = "200" ] \
   && [[ "$(code_of b-del)" == 2?? ]]; then
  pass "generic GET 200 (byte-identical), Maven GET 200, listing 200, DELETE $(code_of b-del)"
else
  fail "while blocked: $(ev b-get); $(ev b-mvn-get); listing HTTP $(code_of b-list); DELETE HTTP $(code_of b-del)"
fi

sleep 4   # several more readings while blocked
begin_test "FIX #5191: the blocked state is logged as a warning"
n="$(backend_log_count 'storage volume is .*full.*writes are refused' "$BLOCK_SINCE")"
echo "  blocked warn lines: ${n:-0} over ~$(( $(date +%s) - $(date -d "$BLOCK_SINCE" +%s) )) s of 1 s readings"
if [ "${n:-0}" -ge 1 ]; then pass "${n} warn line(s) while blocked"
else fail "no 'storage volume is ... full ... writes are refused' line while blocked (want at least 1)"; fi

# --- freed -------------------------------------------------------------------
free_fill
begin_test "FIX #5191: after the fill is removed the block clears and uploads work again"
wait_state ok || true; st="$(disk_state)"
put_gen f-put after.bin "$W/small.bin"
put_mvn f-mvn 3.0 "$W/small.bin"
get_gen f-get after.bin
if [ "$st" = "ok" ] && [[ "$(code_of f-put)" == 2?? ]] && [[ "$(code_of f-mvn)" == 2?? ]] \
   && [ "$(code_of f-get)" = "200" ] && cmp -s "$W/small.bin" "$W/f-get.body"; then
  pass "state=ok at $(used_pct)%, generic $(code_of f-put), Maven $(code_of f-mvn), download 200"
else
  fail "after freeing ($(used_pct)%): .disk.state='${st:-<absent>}'; $(ev f-put); $(ev f-mvn); $(ev f-get)"
fi

for _k in "$GEN" "$MVN" "$OCI"; do
  curl -s -o /dev/null -X DELETE -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${_k}" 2>/dev/null || true
done

end_suite
