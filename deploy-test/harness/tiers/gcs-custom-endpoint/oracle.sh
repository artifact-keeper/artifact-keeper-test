#!/usr/bin/env bash
# =============================================================================
# tiers/gcs-custom-endpoint/oracle.sh -- GCS emulator round-trip oracle (#2646)
# =============================================================================
# run.sh has stood up the gcs-emulator profile: postgres + backend
# (STORAGE_BACKEND=gcs, GCS_ENDPOINT=http://fake-gcs:4443, bucket pre-created)
# + the fake-gcs-server emulator (published on the slot's S3_PORT). It exported
# BASE_URL, DB_CONTAINER, ADMIN_USER/ADMIN_PASS, S3_PORT, RELEASE_GATE=1,
# COMMON_SH, JUNIT_OUTPUT_DIR.
#
# WHAT IT TESTS: the custom-GCS-endpoint support added by #2646 / PR #2842
# (backend/src/storage/gcs.rs). With GCS_ENDPOINT set, the backend routes all
# JSON/XML API calls at the emulator and uses a static bearer token (no real
# Google token/metadata endpoint). The oracle creates a maven repo (which
# inherits the stack's STORAGE_BACKEND=gcs), uploads an artifact, downloads it
# back, and asserts the bytes round-trip -- AND that the object physically
# landed in the emulator bucket (queried directly on S3_PORT).
#
# DISCRIMINATION: pre-#2646 GCS_ENDPOINT is ignored, so the backend targets
# https://storage.googleapis.com with ADC/metadata auth. The upload cannot
# reach the emulator (real Google endpoint + no creds / blocked metadata token),
# so the PUT fails (non-201) and the emulator bucket stays empty -> RED. On the
# fix the round-trip succeeds and the bucket holds the object -> GREEN.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${DB_CONTAINER:?}"; : "${COMMON_SH:?}"; : "${S3_PORT:?}"
# shellcheck source=/dev/null
source "$COMMON_SH"

ADMPASS="${ADMIN_PASS:-TestRunner!2026secure}"
SUF="$(date +%s)-${DTF_SLOT:-x}"
REPO="gcs-emu-${SUF}"
COORD="com/dtf/gcsapp/1.0.0/gcsapp-1.0.0.jar"
PAYLOAD="GCS-EMULATOR-ROUNDTRIP-${SUF}"
EMU="http://127.0.0.1:${S3_PORT}"   # fake-gcs-server host publish

login() {
  curl -s -X POST "${BASE_URL}/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jq -r '.access_token // empty'
}
# code <method> <path> <token> [body] [content-type] -> HTTP status
code() {
  local m="$1" p="$2" t="$3" b="${4:-}" ct="${5:-application/octet-stream}"
  if [ -n "$b" ]; then
    curl -s -o /dev/null -w '%{http_code}' -X "$m" "${BASE_URL}${p}" \
      -H "Authorization: Bearer $t" -H "Content-Type: $ct" --data-binary "$b"
  else
    curl -s -o /dev/null -w '%{http_code}' -X "$m" "${BASE_URL}${p}" -H "Authorization: Bearer $t"
  fi
}
# body <method> <path> <token> -> response body
body() { curl -s -X "$1" "${BASE_URL}${2}" -H "Authorization: Bearer $3"; }
# docker exec psql helper (single scalar).
db() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -tAc "$1" 2>/dev/null \
    | tr -d '[:space:]'
}
# storage_backend of the repo under test -> 'gcs' | 'filesystem' | ''
db_storage_backend() {
  db "SELECT storage_backend FROM repositories WHERE key='${REPO}' LIMIT 1"
}
# emulator object count for the bucket -> integer string
emu_object_count() {
  curl -s "${EMU}/storage/v1/b/ak-artifacts/o" | jq -r '(.items // []) | length' 2>/dev/null
}

begin_suite "gcs-custom-endpoint"

# ---- bootstrap -------------------------------------------------------------
TOK="$(login "${ADMIN_USER:-admin}" "$ADMPASS")"
if [ -z "$TOK" ]; then
  begin_test "admin login"
  fail "admin login to ${BASE_URL} failed (no access_token)"
  end_suite
fi

# ---------------------------------------------------------------------------
# CASE 0 -- PREMISE: the emulator is reachable and the bucket exists (so the
# tier is testing the AK<->emulator path, not a missing-bucket artifact).
# ---------------------------------------------------------------------------
begin_test "CASE 0 premise: fake-gcs emulator serves the ak-artifacts bucket on :${S3_PORT}"
BKT="$(curl -s "${EMU}/storage/v1/b/ak-artifacts" | jq -r '.name // empty' 2>/dev/null)"
if [ "$BKT" = "ak-artifacts" ]; then
  pass
else
  fail "emulator bucket ak-artifacts not found on ${EMU} (got '${BKT}')" \
       "storage.gcs-emulator's create-bucket sidecar must provision ak-artifacts in fake-gcs-server before the backend starts."
  end_suite
fi

# ---------------------------------------------------------------------------
# CASE 1 -- STORAGE BACKEND PREMISE: the repo we create is gcs-backed (so the
# round-trip actually flows through the GCS backend at GCS_ENDPOINT).
# ---------------------------------------------------------------------------
begin_test "CASE 1 premise: maven repo '${REPO}' created and stored on the gcs backend"
RC_CREATE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/api/v1/repositories" \
  -H "Authorization: Bearer ${TOK}" -H 'Content-Type: application/json' \
  -d "{\"key\":\"${REPO}\",\"name\":\"${REPO}\",\"format\":\"maven\",\"repo_type\":\"local\"}")
REPO_BACKEND="$(db_storage_backend)"
if { [ "$RC_CREATE" = "201" ] || [ "$RC_CREATE" = "200" ]; } && [ "$REPO_BACKEND" = "gcs" ]; then
  pass
else
  fail "repo create / backend premise failed (create_status=$RC_CREATE storage_backend='$REPO_BACKEND')" \
       "The repo must be created and inherit STORAGE_BACKEND=gcs so the upload flows through the GCS backend."
fi

# ---------------------------------------------------------------------------
# CASE 2 -- HEADLINE (#2646): upload an artifact -> the GCS backend PUTs it to
# the emulator (201).
# ---------------------------------------------------------------------------
begin_test "CASE 2 (#2646 HEADLINE): upload artifact to gcs-backed repo -> emulator PUT succeeds (201)"
PRE_CNT="$(emu_object_count)"; PRE_CNT="${PRE_CNT:-0}"
UP=$(code PUT "/maven/${REPO}/${COORD}" "$TOK" "$PAYLOAD")
if [ "$UP" = "201" ] || [ "$UP" = "200" ]; then
  pass
else
  fail "artifact upload to the gcs emulator failed (PUT status=$UP, expected 201)" \
       "With GCS_ENDPOINT set (#2646) the PUT must reach fake-gcs-server. On a pre-#2646 image GCS_ENDPOINT is ignored, so the backend targets real Google storage (no creds / blocked metadata token) and the PUT fails -- the RED this tier catches."
fi

# ---------------------------------------------------------------------------
# CASE 3 (#2646): download the artifact back -> bytes match (round-trip).
# ---------------------------------------------------------------------------
begin_test "CASE 3 (#2646): download the artifact back from the emulator -> bytes match"
DL=$(body GET "/maven/${REPO}/${COORD}" "$TOK")
if [ "$DL" = "$PAYLOAD" ]; then
  pass
else
  fail "gcs emulator round-trip byte mismatch (got '$DL', expected '$PAYLOAD')" \
       "The download must return the exact uploaded bytes from fake-gcs-server. RED on a pre-#2646 image (upload never reached the emulator)."
fi

# ---------------------------------------------------------------------------
# CASE 4 (#2646): the object physically landed in the emulator bucket (queried
# directly on the emulator, independent of AK's DB) -- proves the bytes went to
# GCS_ENDPOINT, not just AK's metadata layer.
# ---------------------------------------------------------------------------
begin_test "CASE 4 (#2646): the uploaded object is present in the emulator bucket (direct emulator query)"
POST_CNT="$(emu_object_count)"; POST_CNT="${POST_CNT:-0}"
if [ "$POST_CNT" -gt "$PRE_CNT" ] 2>/dev/null; then
  pass
else
  fail "no new object in the emulator bucket (pre=$PRE_CNT post=$POST_CNT)" \
       "A successful gcs-backed upload must create an object in fake-gcs-server. RED on a pre-#2646 image (nothing ever reached the emulator, so the bucket stays empty)."
fi

# ---- discrimination summary (printed, not a gate) --------------------------
echo ""
echo "=== DISCRIMINATION SUMMARY (why this tier guards #2646 / PR #2842) ==="
echo "  Backend booted STORAGE_BACKEND=gcs GCS_ENDPOINT=http://fake-gcs:4443:"
echo "    upload PUT status         = ${UP}          (fix: 201; pre-fix: fails, endpoint ignored)"
echo "    download bytes match      = $([ "$DL" = "$PAYLOAD" ] && echo yes || echo no)"
echo "    emulator objects pre/post = ${PRE_CNT}/${POST_CNT}   (fix: post>pre; pre-fix: stays 0)"
echo "  Pre-#2646 GCS_ENDPOINT is ignored -> backend targets real Google GCS ->"
echo "  the round-trip cannot reach the emulator and CASE 2/3/4 flip RED."

end_suite
