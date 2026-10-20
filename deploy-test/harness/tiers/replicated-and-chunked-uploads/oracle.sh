#!/usr/bin/env bash
# =============================================================================
# tiers/replicated-and-chunked-uploads/oracle.sh: chunked completions that
# finalize natively across replicas, and object-storage uploads that never
# spool to local disk (artifact-keeper#4403/#1846, #4404/#3916)
# =============================================================================
# run.sh has stood up `storage.s3 topology.two-replica topology.two-replica-s3`
# (backend = replica A on BASE_URL; backend-b = replica B, reached through
# backend's network namespace at 127.0.0.1:8081; both on MinIO and one
# Postgres) with RATE_LIMIT_ENABLED=false.
#
# Test PR #415 (tests/platform/test-chunked-upload-multi-replica.sh) covers the
# generic cross-replica chunked upload (#3918) and staging cleanup (#3922).
# This tier covers what it does not:
#
#   #4403/#1846 (1.11.0) `PUT /api/v1/uploads/{id}/complete` into an Incus or
#     Debian repository runs the format's native finalize. The session is
#     created on A, chunk 0 sent to A, chunk 1 and the completion to B:
#       incus  the row takes the image's product/version, its artifact_metadata
#              (arch/os/release from metadata.yaml) is written, and images.json
#              lists the product with that metadata;
#       debian the row is the control file's package/version, the Packages
#              index carries its Depends and Description, and a .deb whose
#              control disagrees with its file name is refused with 400.
#     1.10.0 wrote a bare row named after the file: no metadata, "No
#     description available", and the mismatch accepted.
#   #4404 / #3916 (1.11.0) a multipart POST and a raw PUT into an S3-backed
#     repository stream into a `generic-upload-staging/<uuid>` object tracked
#     by a `generic_upload_staging` row, and write no scratch file under
#     STORAGE_PATH. Each 8 MiB body is sent at 1 MiB/s while a watcher lists
#     the replicas' /data volume; 1.10.0 spooled the body to
#     $STORAGE_PATH/... first.
#
# CONTROLS (pass on 1.10.0 too): a generic chunked upload across the replicas
# downloads byte-identical; both slow uploads complete and download
# byte-identical; the incus and debian chunked uploads complete (200) and the
# bytes download intact.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${S3_PORT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

SLOT="$DTF_SLOT"
A_CTR="ak-dtf${SLOT}-backend"
B_URL="http://127.0.0.1:8081"
TIER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUF="${RUN_ID##*-}$$"
CHUNK=1048576
read -r -a CURLF <<< "--path-as-is ${CURL_TIMEOUT}"

W="$(mktemp -d -t dtf-rcu-XXXXXX)"
add_exit_handler "rm -rf '${W}'"
add_exit_handler "docker exec '${A_CTR}' rm -rf /tmp/dtf-rcu >/dev/null 2>&1 || true"

jqr() { jq -r "$1" 2>/dev/null || true; }
psq() { docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null | tr -d '[:space:]' || true; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
size_of() { wc -c < "$1" 2>/dev/null | tr -d '[:space:]'; }

# --- replica A (host port) and replica B (curl inside A's netns) --------------
on_a() { # METHOD PATH OUTFILE [curl args...] -> http code
  local m="$1" p="$2" o="$3"; shift 3
  curl -s "${CURLF[@]}" -o "$o" -w '%{http_code}' -X "$m" "${BASE_URL}${p}" \
    -H "Authorization: Bearer ${TOK}" "$@" || echo 000
}
on_b() { # METHOD PATH [curl args...] -> "<http code> <body head>"; files must be under /tmp/dtf-rcu in A
  local m="$1" p="$2"; shift 2
  docker exec "$A_CTR" curl -s --max-time 60 -o /tmp/dtf-rcu/b.out -w '%{http_code}' -X "$m" \
    "${B_URL}${p}" -H "Authorization: Bearer ${TOK}" "$@" 2>/dev/null || echo 000
}
b_body() { docker exec "$A_CTR" cat /tmp/dtf-rcu/b.out 2>/dev/null | head -c 400; }

mk_repo() { # KEY FORMAT -> the key on success
  local o="${W}/mk.json"
  on_a POST /api/v1/repositories "$o" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg k "$1" --arg f "$2" '{key:$k,name:$k,format:$f,repo_type:"local",is_public:false}')" >/dev/null
  jqr '.key // empty' < "$o"
}

# chunked FILE REPO ARTIFACT_PATH -> sets C_SID, C_P0, C_P1, C_DONE (code), C_DONE_BODY
# Session and chunk 0 on A; chunk 1 and the completion on B.
chunked() {
  local f="$1" repo="$2" path="$3" total sum
  total="$(size_of "$f")"; sum="$(sha_of "$f")"
  C_SID=""; C_P0=""; C_P1=""; C_DONE=""; C_DONE_BODY=""
  head -c "$CHUNK" "$f" > "${W}/c0"
  tail -c +$((CHUNK + 1)) "$f" > "${W}/c1"
  docker cp "${W}/c1" "${A_CTR}:/tmp/dtf-rcu/c1" >/dev/null 2>&1 || true
  on_a POST /api/v1/uploads "${W}/sess.json" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg r "$repo" --arg p "$path" --argjson t "$total" --argjson c "$CHUNK" --arg s "$sum" \
      '{repository_key:$r,artifact_path:$p,total_size:$t,chunk_size:$c,checksum_sha256:$s}')" >/dev/null
  C_SID="$(jqr '.session_id // .id // empty' < "${W}/sess.json")"
  [ -n "$C_SID" ] || { C_DONE_BODY="create: $(head -c 300 "${W}/sess.json")"; return 0; }
  C_P0="$(on_a PATCH "/api/v1/uploads/${C_SID}" "${W}/p0.json" -H 'Content-Type: application/octet-stream' \
    -H "Content-Range: bytes 0-$((CHUNK - 1))/${total}" --data-binary "@${W}/c0")"
  C_P1="$(on_b PATCH "/api/v1/uploads/${C_SID}" -H 'Content-Type: application/octet-stream' \
    -H "Content-Range: bytes ${CHUNK}-$((total - 1))/${total}" --data-binary @/tmp/dtf-rcu/c1)"
  C_DONE="$(on_b PUT "/api/v1/uploads/${C_SID}/complete" -H 'Content-Type: application/json')"
  C_DONE_BODY="$(b_body)"
}

begin_suite "replicated-and-chunked-uploads"

# =============================================================================
# SETUP
# =============================================================================
TOK="$(curl -s "${CURLF[@]}" -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PASS}\"}" | jqr '.access_token // empty')"
if [ -z "$TOK" ]; then begin_test "setup: admin login"; infra_fail "admin login failed"; end_suite; fi
B_HEALTH="$(docker exec "$A_CTR" curl -s -o /dev/null -w '%{http_code}' "${B_URL}/health" 2>/dev/null || echo 000)"
docker exec "$A_CTR" mkdir -p /tmp/dtf-rcu >/dev/null 2>&1 || true
PAY="${W}/pay"
python3 -I "${TIER_DIR}/fixtures/build_payloads.py" "$PAY" 2>"${W}/build.err" || true
GEN="dtf-rcu-gen-${SUF}"; INC="dtf-rcu-incus-${SUF}"; DEB="dtf-rcu-deb-${SUF}"; S3R="dtf-rcu-s3-${SUF}"
SETUP_ERR=""
[ "$B_HEALTH" = "200" ] || SETUP_ERR="${SETUP_ERR} replica-B-health=${B_HEALTH}"
[ -s "${PAY}/big.bin" ] || SETUP_ERR="${SETUP_ERR} payloads:$(head -c 200 "${W}/build.err")"
[ "$(mk_repo "$GEN" generic)" = "$GEN" ] || SETUP_ERR="${SETUP_ERR} repo:${GEN}"
[ "$(mk_repo "$INC" incus)" = "$INC" ] || SETUP_ERR="${SETUP_ERR} repo:${INC}"
[ "$(mk_repo "$DEB" debian)" = "$DEB" ] || SETUP_ERR="${SETUP_ERR} repo:${DEB}"
[ "$(mk_repo "$S3R" generic)" = "$S3R" ] || SETUP_ERR="${SETUP_ERR} repo:${S3R}"
S3R_BACKEND="$(psq "SELECT storage_backend FROM repositories WHERE key='${S3R}';")"
[ "$S3R_BACKEND" = "s3" ] || SETUP_ERR="${SETUP_ERR} ${S3R}.storage_backend=${S3R_BACKEND}(want s3)"
if [ -n "$SETUP_ERR" ]; then
  begin_test "setup: replica B, payloads, repositories on MinIO"
  infra_fail "setup failed:${SETUP_ERR}"
  end_suite
fi

# =============================================================================
# CONTROL: a generic chunked upload across the replicas
# =============================================================================
chunked "${PAY}/generic.bin" "$GEN" "dtf/generic.bin"
G_DL="$(on_a GET "/api/v1/repositories/${GEN}/download/dtf/generic.bin" "${W}/g.out")"
begin_test "CONTROL: a generic chunked upload created on replica A and completed on replica B downloads intact"
if [ "$C_DONE" = "200" ] && [ "$G_DL" = "200" ] && cmp -s "${W}/g.out" "${PAY}/generic.bin"; then
  pass
else
  fail "session=${C_SID:-none} chunk0(A)=${C_P0} chunk1(B)=${C_P1} complete(B)=${C_DONE} download=${G_DL}" "${C_DONE_BODY}"
fi

# =============================================================================
# #4403 / #1846: Incus
# =============================================================================
INC_PATH="dtfimg/20261020/incus.tar.gz"
chunked "${PAY}/incus.tar.gz" "$INC" "$INC_PATH"
I_DONE="$C_DONE"; I_BODY="$C_DONE_BODY"
I_ROW="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT a.name || '|' || COALESCE(a.version,'') FROM artifacts a JOIN repositories r ON r.id = a.repository_id
   WHERE r.key='${INC}' AND a.path='${INC_PATH}' AND a.is_deleted=false;" 2>/dev/null | head -1)"
I_META="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT am.metadata::text FROM artifact_metadata am JOIN artifacts a ON a.id = am.artifact_id
   JOIN repositories r ON r.id = a.repository_id WHERE r.key='${INC}' AND a.path='${INC_PATH}' AND am.format='incus';" 2>/dev/null | head -1)"
I_DL="$(on_a GET "/api/v1/repositories/${INC}/download/${INC_PATH}" "${W}/i.out")"
on_a GET "/incus/${INC}/streams/v1/images.json" "${W}/images.json" >/dev/null
I_PRODUCT="$(jq -c '.products // {} | to_entries | map(select(.key | startswith("dtfimg"))) | .[0].value // empty' "${W}/images.json" 2>/dev/null)"

begin_test "CONTROL: the incus chunked upload (A, then B) completes and the image downloads intact"
if [ "$I_DONE" = "200" ] && [ "$I_DL" = "200" ] && cmp -s "${W}/i.out" "${PAY}/incus.tar.gz"; then
  pass
else
  fail "complete(B)=${I_DONE} download=${I_DL}" "${I_BODY}"
fi
begin_test "FIX #4403: the chunked incus completion names the row after the product and version, not the file"
if [ "$I_ROW" = "dtfimg|20261020" ]; then
  pass
else
  fail "artifacts row for ${INC_PATH}: name|version=${I_ROW:-<none>}, want dtfimg|20261020. The chunked completion \
wrote a bare row named after its file, so images.json pointed at a product that does not exist (#4403, #1846)."
fi
begin_test "FIX #4403: the chunked incus completion records metadata.yaml and images.json lists the product with it"
if echo "$I_META" | grep -q 'DTFOS' && echo "$I_META" | grep -q 'dtfrel' \
   && echo "$I_PRODUCT" | grep -q 'DTFOS' && echo "$I_PRODUCT" | grep -q 'dtfrel'; then
  pass
else
  fail "artifact_metadata(incus)=${I_META:-<none>}; images.json dtfimg product=${I_PRODUCT:-<absent>}. Want os DTFOS and \
release dtfrel from the image's metadata.yaml in both (#4403)." "$(head -c 800 "${W}/images.json" 2>/dev/null)"
fi

# =============================================================================
# #4403 / #1846: Debian
# =============================================================================
DEB_PATH="pool/main/d/dtfchunk/dtfchunk_1.0_amd64.deb"
chunked "${PAY}/dtfchunk_1.0_amd64.deb" "$DEB" "$DEB_PATH"
D_DONE="$C_DONE"; D_BODY="$C_DONE_BODY"
D_ROW="$(docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc \
  "SELECT a.name || '|' || COALESCE(a.version,'') FROM artifacts a JOIN repositories r ON r.id = a.repository_id
   WHERE r.key='${DEB}' AND a.path='${DEB_PATH}' AND a.is_deleted=false;" 2>/dev/null | head -1)"
D_DL="$(on_a GET "/debian/${DEB}/${DEB_PATH}" "${W}/d.out")"
on_a GET "/debian/${DEB}/dists/stable/main/binary-amd64/Packages" "${W}/Packages" >/dev/null
D_STANZA="$(awk 'BEGIN{RS=""} /(^|\n)Package: dtfchunk(\n|$)/ {print; exit}' "${W}/Packages" 2>/dev/null)"
begin_test "CONTROL: the debian chunked upload (A, then B) completes and the package downloads intact from its pool path"
if [ "$D_DONE" = "200" ] && [ "$D_DL" = "200" ] && cmp -s "${W}/d.out" "${PAY}/dtfchunk_1.0_amd64.deb"; then
  pass
else
  fail "complete(B)=${D_DONE} download=${D_DL}" "${D_BODY}"
fi
begin_test "FIX #1846: the chunked .deb is catalogued as its control file's package and indexed with Depends and Description"
if [ "$D_ROW" = "dtfchunk|1.0" ] \
   && echo "$D_STANZA" | grep -qxF 'Depends: libc6 (>= 2.31), dtf-runtime' \
   && echo "$D_STANZA" | grep -qxF 'Description: DTF chunked debian fixture for artifact-keeper 1846'; then
  pass
else
  fail "row name|version=${D_ROW:-<none>} (want dtfchunk|1.0); Packages stanza for dtfchunk lacks the control file's \
Depends/Description. The chunked completion named the package after its file, versioned it by its pool directory and \
indexed it with 'No description available' and no Depends (#4403, #1846)." "stanza:
${D_STANZA:-<absent>}"
fi

BAD_PATH="pool/main/d/dtfbad/dtfbad_1.0_amd64.deb"
chunked "${PAY}/dtfbad_1.0_amd64.deb" "$DEB" "$BAD_PATH"
BAD_LIVE="$(psq "SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
  WHERE r.key='${DEB}' AND a.path='${BAD_PATH}' AND a.is_deleted=false;")"
begin_test "FIX #1846: a chunked .deb whose control file disagrees with its file name is refused with 400 and not stored"
if [ "$C_DONE" = "400" ] && [ "$BAD_LIVE" = "0" ]; then
  pass
else
  fail "complete of ${BAD_PATH} (control says Package: dtfother) -> ${C_DONE}, live rows=${BAD_LIVE} (want 400, 0). \
The native PUT refuses this package; the chunked completion must validate the control file the same way." "${C_DONE_BODY}"
fi

# =============================================================================
# #4404 / #3916: no local spool for uploads into an S3-backed repository
# =============================================================================
DATA_VOL="$(docker inspect "$A_CTR" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' 2>/dev/null)"
WATCH_IMG="python:3.12-slim"

# slow_upload KIND -> sets U_CODE, U_SPOOL (new non-empty files seen under /data
# during the upload), U_STAGING_MAX (most generic_upload_staging rows seen)
slow_upload() {
  local kind="$1" path="spool/${1}.bin" pid i n
  U_CODE=""; U_SPOOL=""; U_STAGING_MAX=0
  # Watcher: lists every non-empty file under the shared /data volume (both
  # replicas' STORAGE_PATH) every 0.25 s for 14 s and prints the new ones.
  docker run --rm --name "ak-dtf${SLOT}-rcu-watch" --security-opt label=disable \
    -v "${DATA_VOL}:/data:ro" "$WATCH_IMG" python3 -c '
import os, time
def scan():
    out = {}
    for d, _, fs in os.walk("/data"):
        for f in fs:
            p = os.path.join(d, f)
            try:
                s = os.path.getsize(p)
            except OSError:
                continue
            if s > 0:
                out[p] = s
    return out
base = scan()
seen = {}
end = time.time() + 14
while time.time() < end:
    for p, s in scan().items():
        if p not in base:
            seen[p] = max(s, seen.get(p, 0))
    time.sleep(0.25)
for p, s in sorted(seen.items()):
    print(f"{p} {s}")
' > "${W}/watch-${kind}.out" 2>&1 &
  pid=$!
  sleep 2
  if [ "$kind" = "multipart" ]; then
    curl -s --path-as-is --max-time 60 --limit-rate 1M -o "${W}/up-${kind}.json" -w '%{http_code}' \
      -X POST "${BASE_URL}/api/v1/repositories/${S3R}/artifacts/${path}" \
      -H "Authorization: Bearer ${TOK}" -F "file=@${PAY}/big.bin;type=application/octet-stream" \
      > "${W}/code-${kind}" 2>/dev/null &
  else
    curl -s --path-as-is --max-time 60 --limit-rate 1M -o "${W}/up-${kind}.json" -w '%{http_code}' \
      -X PUT "${BASE_URL}/api/v1/repositories/${S3R}/artifacts/${path}" \
      -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/octet-stream' \
      --data-binary "@${PAY}/big.bin" > "${W}/code-${kind}" 2>/dev/null &
  fi
  local up=$!
  for i in $(seq 1 40); do
    n="$(psq "SELECT count(*) FROM generic_upload_staging;")"
    case "$n" in ''|*[!0-9]*) n=0 ;; esac
    [ "$n" -gt "$U_STAGING_MAX" ] && U_STAGING_MAX="$n"
    kill -0 "$up" 2>/dev/null || break
    sleep 0.25
  done
  : "$i"
  wait "$up" 2>/dev/null || true
  U_CODE="$(cat "${W}/code-${kind}" 2>/dev/null || true)"
  wait "$pid" 2>/dev/null || true
  U_SPOOL="$(cat "${W}/watch-${kind}.out" 2>/dev/null || true)"
}

# MinIO's root credentials as storage.s3.yml sets them (MINIO_ROOT_USER /
# MINIO_ROOT_PASSWORD on a throwaway per-slot container), read from the
# container so they live in one place.
S3_USER="$(docker exec "ak-dtf${SLOT}-minio" printenv MINIO_ROOT_USER 2>/dev/null || true)"
S3_PASS="$(docker exec "ak-dtf${SLOT}-minio" printenv MINIO_ROOT_PASSWORD 2>/dev/null || true)"
s3_staging_objects() { # -> number of objects under generic-upload-staging/ in the bucket
  curl -s --max-time 20 --aws-sigv4 "aws:amz:us-east-1:s3" --user "${S3_USER}:${S3_PASS}" \
    "http://127.0.0.1:${S3_PORT}/ak-artifacts?list-type=2&prefix=generic-upload-staging/" 2>/dev/null \
    | sed -n 's/.*<KeyCount>\([0-9][0-9]*\)<\/KeyCount>.*/\1/p' || true
}

for KIND in multipart put; do
  slow_upload "$KIND"
  DL="$(on_a GET "/api/v1/repositories/${S3R}/download/spool/${KIND}.bin" "${W}/dl-${KIND}.out")"
  LEFT_ROWS="$(psq "SELECT count(*) FROM generic_upload_staging;")"
  LEFT_OBJ="$(s3_staging_objects)"
  if [ "$KIND" = "multipart" ]; then ISSUE="#4404"; ROUTE="multipart POST /api/v1/repositories/{key}/artifacts/{path}";
  else ISSUE="#3916"; ROUTE="raw PUT /api/v1/repositories/{key}/artifacts/{path}"; fi
  begin_test "CONTROL: an 8 MiB ${KIND} upload into the MinIO-backed repository, sent at 1 MiB/s, completes and downloads intact"
  case "$U_CODE" in
    200|201) if [ "$DL" = "200" ] && cmp -s "${W}/dl-${KIND}.out" "${PAY}/big.bin"; then pass
             else fail "${ROUTE} -> ${U_CODE}, download -> ${DL} (bytes differ or missing)"; fi ;;
    *) fail "${ROUTE} -> ${U_CODE:-none}" "$(head -c 400 "${W}/up-${KIND}.json" 2>/dev/null)" ;;
  esac
  begin_test "FIX ${ISSUE}: the ${KIND} upload into an S3 repository writes no scratch file under STORAGE_PATH"
  if [ -z "$DATA_VOL" ]; then
    infra_fail "could not find the backend's /data volume to watch"
  elif [ -z "$U_SPOOL" ]; then
    pass
  else
    fail "while the ${KIND} body streamed in, new files appeared on the replicas' /data volume (path size):
${U_SPOOL}
An upload into an object-storage repository must stream into a generic-upload-staging/<uuid> object on that \
backend, not spool to local disk (${ISSUE})."
  fi
  begin_test "FIX ${ISSUE}: the ${KIND} upload is staged through generic_upload_staging, and nothing is left behind"
  if [ "${U_STAGING_MAX:-0}" -ge 1 ] && [ "$LEFT_ROWS" = "0" ] && [ "${LEFT_OBJ:-x}" = "0" ]; then
    pass
  else
    fail "generic_upload_staging rows seen during the upload: max ${U_STAGING_MAX} (want >= 1); rows left after: \
${LEFT_ROWS:-<no table>} (want 0); generic-upload-staging/ objects left in MinIO: ${LEFT_OBJ:-?} (want 0)"
  fi
done

end_suite
