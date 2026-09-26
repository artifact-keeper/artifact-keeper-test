#!/usr/bin/env bash
# test-chunked-upload-multi-replica.sh - chunked uploads across backend replicas
#
# Regression suite for artifact-keeper#3918 (a chunked upload session only
# worked when every PATCH and the completion reached the replica that created
# the session, because chunks were staged on that replica's local disk) and
# artifact-keeper#3922 (a failed completion left the staged data behind).
#
# Topology this suite is meant for: two or more backend replicas, each with
# its own local STORAGE_PATH (emptyDir, no shared PVC), and a shared object
# store (the MinIO "s3" backend from helm/storage-emulators.yaml) that the
# test repository opts into via storage_backend. Point BASE_URL_A and
# BASE_URL_B at two DIFFERENT replicas (for example two kubectl port-forwards
# to two pods) so the suite can pin each request to a replica. When only
# BASE_URL is set every request goes to the same place and the cross-replica
# assertions degrade to single-replica ones (still valid, weaker).
#
# Contract exercised:
#   1. session created on A, chunk 0 on A, chunk 1 on B, completion on B:
#      200, and the artifact downloaded from either replica has the source
#      sha256
#   2. the mirror image (created on B, completed on A)
#   3. a PATCH whose Content-Range does not cover exactly its chunk is
#      rejected with 4xx (chunks are staged as whole objects and concatenated)
#   4. staged chunks live in the shared object store while the session is
#      open; a completion with a wrong checksum fails with 409 and afterwards
#      no staged object for the session remains
#
# Environment:
#   BASE_URL_A / BASE_URL_B       replica endpoints (default: BASE_URL)
#   CHUNKED_STORAGE_BACKEND       storage backend for the test repo
#                                 (default: s3 when registered, else the
#                                 deployment default)
#   STAGING_S3_ENDPOINT           S3 endpoint used to list staged objects
#                                 (default http://storage-minio:9000); the
#                                 staging assertions skip when unreachable
#   STAGING_S3_BUCKET / STAGING_S3_ACCESS_KEY / STAGING_S3_SECRET_KEY /
#   STAGING_S3_REGION / STAGING_S3_PREFIX
#                                 defaults match helm/values-test-full.yaml
#
# Requires: curl (>= 7.75 for --aws-sigv4), jq, sha256sum or shasum, dd

source "$(dirname "$0")/../lib/common.sh"

begin_suite "chunked-upload-multi-replica"
auth_admin
setup_workdir

BASE_URL_A="${BASE_URL_A:-$BASE_URL}"
BASE_URL_B="${BASE_URL_B:-$BASE_URL}"
STAGING_S3_ENDPOINT="${STAGING_S3_ENDPOINT:-http://storage-minio:9000}"
STAGING_S3_BUCKET="${STAGING_S3_BUCKET:-ak-e2e}"
STAGING_S3_ACCESS_KEY="${STAGING_S3_ACCESS_KEY:-ak-test-access}"
STAGING_S3_SECRET_KEY="${STAGING_S3_SECRET_KEY:-ak-test-secret-2026}"
STAGING_S3_REGION="${STAGING_S3_REGION:-us-east-1}"
STAGING_S3_PREFIX="${STAGING_S3_PREFIX:-}"

CHUNK_SIZE=1048576          # backend minimum chunk size
TOTAL_SIZE=$(( 2 * CHUNK_SIZE ))
REPO_KEY="chunked-mr-${RUN_ID}"

echo "  replica A: ${BASE_URL_A}"
echo "  replica B: ${BASE_URL_B}"
if [ "$BASE_URL_A" = "$BASE_URL_B" ]; then
  echo "  NOTE: BASE_URL_A == BASE_URL_B; requests are not pinned to distinct replicas"
fi

_mr_sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

dd if=/dev/urandom of="${WORK_DIR}/src.bin" bs="$CHUNK_SIZE" count=2 2>/dev/null
dd if="${WORK_DIR}/src.bin" of="${WORK_DIR}/c0" bs="$CHUNK_SIZE" count=1 2>/dev/null
dd if="${WORK_DIR}/src.bin" of="${WORK_DIR}/c1" bs="$CHUNK_SIZE" skip=1 count=1 2>/dev/null
SRC_SHA=$(_mr_sha256 "${WORK_DIR}/src.bin")

# create_session BASE ARTIFACT_PATH CHECKSUM -> prints session id, rc 1 on error
create_session() {
  local base="$1" path="$2" sum="$3" code
  code=$(curl -s -o "${WORK_DIR}/create.json" -w '%{http_code}' $CURL_TIMEOUT -X POST \
    -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "{\"repository_key\":\"${REPO_KEY}\",\"artifact_path\":\"${path}\",\"total_size\":${TOTAL_SIZE},\"chunk_size\":${CHUNK_SIZE},\"checksum_sha256\":\"${sum}\"}" \
    "${base}/api/v1/uploads") || code="000"
  if [ "$code" != "201" ]; then
    echo "create session on ${base}: HTTP ${code} $(head -c 300 "${WORK_DIR}/create.json")" >&2
    return 1
  fi
  jq -r '.session_id // .id // empty' "${WORK_DIR}/create.json"
}

# patch_chunk BASE SESSION FILE START END -> prints "HTTP body"
patch_chunk() {
  local base="$1" sid="$2" file="$3" start="$4" end="$5" code
  code=$(curl -s -o "${WORK_DIR}/patch.json" -w '%{http_code}' $CURL_TIMEOUT -X PATCH \
    -H "$(auth_header)" -H "Content-Type: application/octet-stream" \
    -H "Content-Range: bytes ${start}-${end}/${TOTAL_SIZE}" \
    --data-binary "@${file}" "${base}/api/v1/uploads/${sid}") || code="000"
  echo "${code} $(head -c 300 "${WORK_DIR}/patch.json" 2>/dev/null)"
}

# complete BASE SESSION -> prints "HTTP body"
complete_session() {
  local base="$1" sid="$2" code
  code=$(curl -s -o "${WORK_DIR}/complete.json" -w '%{http_code}' $CURL_TIMEOUT -X PUT \
    -H "$(auth_header)" -H "Content-Type: application/json" \
    "${base}/api/v1/uploads/${sid}/complete") || code="000"
  echo "${code} $(head -c 300 "${WORK_DIR}/complete.json" 2>/dev/null)"
}

cancel_session() {
  curl -s -o /dev/null $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${1}/api/v1/uploads/${2}" 2>/dev/null || true
}

# download_matches BASE PATH -> rc 0 when the download's sha256 == SRC_SHA
download_matches() {
  local base="$1" path="$2" code got
  code=$(curl -s -o "${WORK_DIR}/down.bin" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${base}/api/v1/repositories/${REPO_KEY}/download/${path}") || code="000"
  if [ "$code" != "200" ]; then
    echo "download ${path} from ${base}: HTTP ${code}"
    return 1
  fi
  got=$(_mr_sha256 "${WORK_DIR}/down.bin")
  if [ "$got" != "$SRC_SHA" ]; then
    echo "download ${path} from ${base}: sha256 ${got} != source ${SRC_SHA}"
    return 1
  fi
  return 0
}

# staged_object_count SESSION -> prints the number of objects under the
# session's staging prefix, rc 1 when the object store cannot be listed.
staged_object_count() {
  local sid="$1" prefix code
  prefix="${STAGING_S3_PREFIX:+${STAGING_S3_PREFIX%/}/}upload-staging/${sid}/"
  code=$(curl -s -o "${WORK_DIR}/list.xml" -w '%{http_code}' --max-time 20 \
    --aws-sigv4 "aws:amz:${STAGING_S3_REGION}:s3" \
    --user "${STAGING_S3_ACCESS_KEY}:${STAGING_S3_SECRET_KEY}" \
    "${STAGING_S3_ENDPOINT}/${STAGING_S3_BUCKET}?list-type=2&prefix=${prefix}" 2>/dev/null) || code="000"
  [ "$code" = "200" ] || return 1
  local n
  n=$(sed -n 's/.*<KeyCount>\([0-9][0-9]*\)<\/KeyCount>.*/\1/p' "${WORK_DIR}/list.xml")
  [ -n "$n" ] || return 1
  echo "$n"
}

# ---------------------------------------------------------------------------
# Repository on the shared backend
# ---------------------------------------------------------------------------

if [ -z "${CHUNKED_STORAGE_BACKEND:-}" ]; then
  if api_get "/api/v1/admin/storage-backends" 2>/dev/null | jq -e '
      (if type == "array" then . elif (.backends | type == "array") then .backends
       elif (.items | type == "array") then .items else [] end)
      | map(if type == "string" then . else (.name // .key // .backend_type // "") end)
      | index("s3") != null' > /dev/null 2>&1; then
    CHUNKED_STORAGE_BACKEND="s3"
  fi
fi
echo "  storage backend: ${CHUNKED_STORAGE_BACKEND:-<deployment default>}"

begin_test "Create generic repository on the shared backend"
payload="{\"key\":\"${REPO_KEY}\",\"name\":\"${REPO_KEY}\",\"format\":\"generic\",\"repo_type\":\"local\",\"is_public\":true"
[ -n "${CHUNKED_STORAGE_BACKEND:-}" ] && payload="${payload},\"storage_backend\":\"${CHUNKED_STORAGE_BACKEND}\""
payload="${payload}}"
code=$(curl -s -o "${WORK_DIR}/repo.json" -w '%{http_code}' $CURL_TIMEOUT -X POST \
  -H "$(auth_header)" -H "Content-Type: application/json" -d "$payload" \
  "${BASE_URL_A}/api/v1/repositories") || code="000"
if [ "$code" = "201" ] || [ "$code" = "200" ]; then
  pass
else
  fail "repo create returned ${code}: $(head -c 300 "${WORK_DIR}/repo.json")"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# 1. Created on A, chunk 0 on A, chunk 1 on B, completed on B (#3918)
# ---------------------------------------------------------------------------

run_cross_replica_upload() {
  local create_base="$1" other_base="$2" path="$3" sid r0 r1 rc
  sid=$(create_session "$create_base" "$path" "$SRC_SHA") || { echo "create failed"; return 1; }
  r0=$(patch_chunk "$create_base" "$sid" "${WORK_DIR}/c0" 0 $(( CHUNK_SIZE - 1 )))
  echo "  chunk 0 via ${create_base}: ${r0%% *}"
  r1=$(patch_chunk "$other_base" "$sid" "${WORK_DIR}/c1" "$CHUNK_SIZE" $(( TOTAL_SIZE - 1 )))
  echo "  chunk 1 via ${other_base}: ${r1%% *}"
  rc=$(complete_session "$other_base" "$sid")
  echo "  complete via ${other_base}: ${rc}"
  case "${r0%% *}" in 200|202) ;; *) echo "chunk 0 HTTP ${r0}"; return 1 ;; esac
  case "${r1%% *}" in 200|202) ;; *) echo "chunk 1 HTTP ${r1}"; return 1 ;; esac
  [ "${rc%% *}" = "200" ] || { echo "complete HTTP ${rc}"; return 1; }
  return 0
}

begin_test "#3918 session created on A, chunk 1 and completion on B"
if out=$(run_cross_replica_upload "$BASE_URL_A" "$BASE_URL_B" "mr/a-to-b.bin" 2>&1); then
  echo "$out"
  pass
else
  echo "$out"
  fail "cross-replica upload A->B failed: $(echo "$out" | tail -1)"
fi

begin_test "#3918 artifact uploaded A->B downloads with the source sha256 from both replicas"
if o1=$(download_matches "$BASE_URL_A" "mr/a-to-b.bin") && o2=$(download_matches "$BASE_URL_B" "mr/a-to-b.bin"); then
  pass
else
  fail "${o1:-}${o2:-}"
fi

begin_test "#3918 session created on B, chunk 1 and completion on A"
if out=$(run_cross_replica_upload "$BASE_URL_B" "$BASE_URL_A" "mr/b-to-a.bin" 2>&1); then
  echo "$out"
  pass
else
  echo "$out"
  fail "cross-replica upload B->A failed: $(echo "$out" | tail -1)"
fi

begin_test "#3918 artifact uploaded B->A downloads with the source sha256"
if o1=$(download_matches "$BASE_URL_B" "mr/b-to-a.bin"); then
  pass
else
  fail "$o1"
fi

# ---------------------------------------------------------------------------
# 2. A PATCH must cover exactly its chunk
# ---------------------------------------------------------------------------

begin_test "#3918 PATCH shorter than its chunk is rejected with 4xx"
if SID=$(create_session "$BASE_URL_A" "mr/misaligned.bin" "$SRC_SHA"); then
  head -c $(( CHUNK_SIZE / 2 )) "${WORK_DIR}/c0" > "${WORK_DIR}/half"
  r=$(patch_chunk "$BASE_URL_A" "$SID" "${WORK_DIR}/half" 0 $(( CHUNK_SIZE / 2 - 1 )))
  echo "  half-chunk PATCH bytes 0-$(( CHUNK_SIZE / 2 - 1 )): ${r}"
  code="${r%% *}"
  if [ "$code" -ge 400 ] 2>/dev/null && [ "$code" -lt 500 ] 2>/dev/null; then
    pass
  else
    fail "expected 4xx for a PATCH covering half of chunk 0, got ${r}"
  fi
else
  fail "could not create session"
fi

begin_test "#3918 PATCH starting mid-chunk is rejected with 4xx"
if [ -n "${SID:-}" ]; then
  # Starts inside chunk 1 (offset 1.5 MiB) and runs to the end of the file:
  # its index resolves to chunk 1 but its offset is not chunk 1's offset.
  tail -c $(( CHUNK_SIZE / 2 )) "${WORK_DIR}/c1" > "${WORK_DIR}/tailhalf"
  r=$(patch_chunk "$BASE_URL_B" "$SID" "${WORK_DIR}/tailhalf" $(( CHUNK_SIZE + CHUNK_SIZE / 2 )) $(( TOTAL_SIZE - 1 )))
  echo "  mid-chunk PATCH bytes $(( CHUNK_SIZE + CHUNK_SIZE / 2 ))-$(( TOTAL_SIZE - 1 )): ${r}"
  code="${r%% *}"
  if [ "$code" -ge 400 ] 2>/dev/null && [ "$code" -lt 500 ] 2>/dev/null; then
    pass
  else
    fail "expected 4xx for a PATCH starting mid-chunk, got ${r}"
  fi
  cancel_session "$BASE_URL_A" "$SID"
else
  skip "no session from the previous test"
fi

# ---------------------------------------------------------------------------
# 3. Failed completion leaves no staged data (#3922)
# ---------------------------------------------------------------------------

STAGING_LISTABLE=true
if ! staged_object_count "00000000-0000-0000-0000-000000000000" > /dev/null; then
  STAGING_LISTABLE=false
  echo "  object store at ${STAGING_S3_ENDPOINT} not listable; staging assertions will skip"
fi

BAD_SUM="0000000000000000000000000000000000000000000000000000000000000000"
BAD_SID=""
PRE_N=""
begin_test "#3922 staged chunks are in the shared object store before completion"
if BAD_SID=$(create_session "$BASE_URL_A" "mr/bad-checksum.bin" "$BAD_SUM"); then
  r0=$(patch_chunk "$BASE_URL_A" "$BAD_SID" "${WORK_DIR}/c0" 0 $(( CHUNK_SIZE - 1 )))
  r1=$(patch_chunk "$BASE_URL_A" "$BAD_SID" "${WORK_DIR}/c1" "$CHUNK_SIZE" $(( TOTAL_SIZE - 1 )))
  echo "  chunk 0: ${r0%% *}  chunk 1: ${r1%% *}"
  if ! $STAGING_LISTABLE; then
    skip "object store not listable at ${STAGING_S3_ENDPOINT}"
  else
    n=$(staged_object_count "$BAD_SID") || n="?"
    PRE_N="$n"
    echo "  staged objects under upload-staging/${BAD_SID}/: ${n}"
    if [ "$n" = "2" ]; then
      pass
    else
      fail "expected 2 staged chunk objects in the shared store, found ${n}"
    fi
  fi
else
  fail "could not create session"
fi

begin_test "#3922 completion with a wrong checksum fails with 409"
if [ -n "$BAD_SID" ]; then
  # Completed on the replica that took the chunks, so this isolates #3922
  # from the cross-replica path covered above.
  rc=$(complete_session "$BASE_URL_A" "$BAD_SID")
  echo "  complete via A: ${rc}"
  if [ "${rc%% *}" = "409" ]; then
    pass
  else
    fail "expected 409 checksum mismatch, got ${rc}"
  fi
else
  skip "no session"
fi

begin_test "#3922 failed session reports a terminal status"
if [ -n "$BAD_SID" ]; then
  code=$(curl -s -o "${WORK_DIR}/status.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" "${BASE_URL_A}/api/v1/uploads/${BAD_SID}") || code="000"
  st=$(jq -r '.status // empty' "${WORK_DIR}/status.json" 2>/dev/null)
  echo "  GET session: HTTP ${code} status=${st}"
  if [ "$code" = "404" ] || [ "$st" = "failed" ] || [ "$st" = "cancelled" ]; then
    pass
  else
    fail "expected a failed/cancelled (or gone) session, got HTTP ${code} status=${st}"
  fi
else
  skip "no session"
fi

begin_test "#3922 no staged data remains after the failed completion"
if [ -z "$BAD_SID" ]; then
  skip "no session"
elif ! $STAGING_LISTABLE; then
  skip "object store not listable at ${STAGING_S3_ENDPOINT}"
elif [ "$PRE_N" != "2" ]; then
  fail "staged chunks were never observed in the shared store (${PRE_N}); cannot show they were removed"
else
  n="?"
  for _ in $(seq 1 10); do
    n=$(staged_object_count "$BAD_SID") || n="?"
    [ "$n" = "0" ] && break
    sleep 1
  done
  echo "  staged objects under upload-staging/${BAD_SID}/: ${n}"
  if [ "$n" = "0" ]; then
    pass
  else
    fail "staged chunk objects remain after the failed completion: ${n}"
  fi
fi

begin_test "#3922 no staged data remains after a successful completion"
if ! $STAGING_LISTABLE; then
  skip "object store not listable at ${STAGING_S3_ENDPOINT}"
elif GOOD_SID=$(create_session "$BASE_URL_A" "mr/purged-after-success.bin" "$SRC_SHA"); then
  patch_chunk "$BASE_URL_A" "$GOOD_SID" "${WORK_DIR}/c0" 0 $(( CHUNK_SIZE - 1 )) > /dev/null
  patch_chunk "$BASE_URL_B" "$GOOD_SID" "${WORK_DIR}/c1" "$CHUNK_SIZE" $(( TOTAL_SIZE - 1 )) > /dev/null
  rc=$(complete_session "$BASE_URL_A" "$GOOD_SID")
  n=$(staged_object_count "$GOOD_SID") || n="?"
  echo "  complete: ${rc%% *}; staged objects left: ${n}"
  if [ "${rc%% *}" = "200" ] && [ "$n" = "0" ]; then
    pass
  else
    fail "expected completion 200 and 0 staged objects, got ${rc} / ${n}"
  fi
else
  fail "could not create session"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

[ -n "$BAD_SID" ] && cancel_session "$BASE_URL_A" "$BAD_SID"
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
