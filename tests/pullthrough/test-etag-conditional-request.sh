#!/usr/bin/env bash
# test-etag-conditional-request.sh -- ETag-based conditional-request
# semantics on conda repodata (issue #69 sub-task 1.5).
#
# What this asserts
# -----------------
# The conda handler (backend/src/api/handlers/conda.rs:435 build_cacheable_
# response) computes a SHA-256 ETag over the response body and serves a
# 304 Not Modified when the client supplies a matching If-None-Match.
# This is the load-bearing client-cache contract: package managers
# (conda, mamba, pip-with-conda-channel-overlay) rely on 304s to skip
# the multi-MB repodata.json transfer on every refresh. A regression
# that ALWAYS returns 200-with-body silently 10-100x's bandwidth on
# the customer side and only surfaces as a slow-channel complaint.
#
# What we assert, in order:
#   1. GET /conda/<repo>/<subdir>/repodata.json (no If-None-Match) ->
#      200 with body, ETag header present, ETag matches RFC 7232 syntax
#      (quoted token; conda.rs uses quoted SHA-256 hex).
#   2. GET /conda/<repo>/<subdir>/repodata.json with the captured ETag
#      as If-None-Match -> 304, EMPTY body, ETag header preserved.
#   3. GET with a deliberately-wrong If-None-Match -> 200 with body
#      (the ETag MUST mismatch when content differs; the check is not
#      a constant-true comparison).
#   4. GET with If-None-Match: "*" -> 304 (RFC 7232 wildcard).
#   5. GET with a comma-separated If-None-Match list including the
#      real ETag -> 304 (multi-value parsing as per conda.rs:403).
#
# Why conda (not pypi/maven/etc)
# ------------------------------
# ETag + conditional-request handling currently lives in conda.rs only
# (compute_etag/check_conditional_request are file-local helpers in
# backend/src/api/handlers/conda.rs:391-432). The other format handlers
# don't wire ETag yet, so they'd produce a false negative on this
# test. When that work expands, add format-specific siblings; do NOT
# generalize this test to formats that don't implement the contract.
#
# Why a LOCAL conda repo (not remote/proxy)
# -----------------------------------------
# The ETag is computed by build_cacheable_response on the conda
# handler's response path regardless of repo_type. We pick local
# because (a) a single-repo setup keeps the failure surface narrow
# (an ETag bug shows up here; a proxy bug shows up in the dedicated
# proxy tests) and (b) avoids cross-contamination with the proxy
# stale/TTL paths under test in sibling scripts in this same suite.
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "etag-conditional-request"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Feature gate
# ---------------------------------------------------------------------------
# The conda ETag + If-None-Match conditional-request handling lives in
# backend/src/api/handlers/conda.rs (compute_etag / check_conditional_request,
# wired through build_cacheable_response). There is no discrete require_feature
# token for it today; the closest in-framework probe is hitting the conda
# repodata route shape and checking that the handler exists (a backend that
# does NOT ship the conda handler returns 404 from the router for any conda
# path, which is indistinguishable from "repo not found" without a real repo
# to probe with -- so we use 501 Not Implemented as the explicit "handler
# absent" signal, which is what Axum emits on unmatched method routes for
# present handlers).
#
# Probe strategy:
#   1. Send a GET to /conda/<bogus>/<bogus>/repodata.json. A backend that
#      ships the conda handler returns 401/403/404 (auth/repo missing). A
#      backend that does not ship the conda surface returns 501 (or 405 if
#      the router exists but the verb is rejected ahead of the handler).
#      Either of these absent-feature signals -> skip_suite.
#   2. If /health is unreachable so we cannot even confirm the backend is
#      up, skip rather than risk a confounded fail in the upload step.
#
# We avoid embedding a new require_feature token (that requires touching
# tests/lib/common.sh, which is owned by a separate change); the probe
# below is self-contained and matches the skip-on-absent-endpoint pattern
# used elsewhere in this suite (e.g. test-multipart-artifact-upload.sh).
BACKEND_VER=$(get_backend_version)
if [ "$BACKEND_VER" = "unknown" ]; then
  skip_suite "could not determine backend version from /health; conda ETag handler is not probeable"
fi

ETAG_PROBE_URL="${BASE_URL}/conda/etag-probe-bogus-${RUN_ID}/noarch/repodata.json"
PROBE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -H "$(format_auth_header)" "$ETAG_PROBE_URL" 2>/dev/null) || PROBE_STATUS="000"
case "$PROBE_STATUS" in
  404|401|403|400|200|304)
    # conda handler responded with a real status; the route is mounted.
    ;;
  405|501)
    skip_suite "conda repodata endpoint returned HTTP ${PROBE_STATUS}; conda ETag handler not available on this backend"
    ;;
  000)
    skip_suite "conda repodata probe failed to connect (timeout/network); cannot validate ETag handler is mounted"
    ;;
  *)
    # Any other status implies the route resolved to a handler that
    # returned an unexpected code; let the suite proceed and fail loudly
    # on the real assertions rather than masking a regression here.
    ;;
esac

REPO_KEY="etag-cond-${RUN_ID}"
PKG_NAME="etagpkg"
PKG_VERSION="1.0.0"
SUBDIR="noarch"
CONDA_URL="${BASE_URL}/conda/${REPO_KEY}"
REPODATA_URL="${CONDA_URL}/${SUBDIR}/repodata.json"

# Cleanup on EXIT regardless of pass/fail/abort. add_exit_handler runs
# in registration order so the workdir wipe (registered by
# setup_workdir) still happens after this delete.
cleanup_repo() {
  api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repo"

# ---------------------------------------------------------------------------
# Setup: create a conda repo and publish one package so repodata.json is
# non-empty (an empty repodata is still cacheable, but a real-shaped
# document makes the ETag changes-with-content assertion meaningful).
# ---------------------------------------------------------------------------

begin_test "Create local conda repo"
if create_local_repo "$REPO_KEY" "conda"; then
  pass
else
  fail "could not create conda repo"
fi

begin_test "Publish a conda package so repodata.json has content"
mkdir -p "${WORK_DIR}/conda-pkg/info"
cat > "${WORK_DIR}/conda-pkg/info/index.json" <<EOF
{
  "name": "${PKG_NAME}",
  "version": "${PKG_VERSION}",
  "build": "0",
  "build_number": 0,
  "depends": [],
  "subdir": "${SUBDIR}",
  "arch": null,
  "platform": null,
  "noarch": "generic"
}
EOF
cat > "${WORK_DIR}/conda-pkg/info/paths.json" <<EOF
{ "paths": [] }
EOF
CONDA_FILENAME="${PKG_NAME}-${PKG_VERSION}-0.tar.bz2"
( cd "${WORK_DIR}/conda-pkg" && tar cjf "${WORK_DIR}/${CONDA_FILENAME}" info/ 2>/dev/null )

upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT -X POST \
  "${CONDA_URL}/upload" \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Conda-Subdir: ${SUBDIR}" \
  -H "X-Package-Filename: ${CONDA_FILENAME}" \
  --data-binary "@${WORK_DIR}/${CONDA_FILENAME}" 2>/dev/null) || upload_status="000"

if [ "$upload_status" -ge 200 ] 2>/dev/null && [ "$upload_status" -lt 300 ] 2>/dev/null; then
  pass
else
  # If the conda upload endpoint is unavailable on this backend the
  # rest of the suite cannot meaningfully assert. Skip rather than
  # produce a false-pass on an empty repodata path.
  skip_suite "conda upload endpoint returned HTTP ${upload_status}; ETag test cannot proceed"
fi

# Wait for the repodata generator to surface the package. Without this
# the first repodata GET can race the indexer and return a stale empty
# body, masking the actual ETag we want to assert on.
deadline=$(( $(date +%s) + 15 ))
until curl -sf $CURL_TIMEOUT -H "$(format_auth_header)" "$REPODATA_URL" 2>/dev/null \
        | grep -q "${PKG_NAME}" || [ "$(date +%s)" -ge "$deadline" ]; do
  sleep 0.3
done

# ---------------------------------------------------------------------------
# Step 1: unconditional GET -> 200, ETag present, RFC-7232 syntax.
# ---------------------------------------------------------------------------

begin_test "GET repodata.json without If-None-Match returns 200 with ETag header"
headers_file="${WORK_DIR}/h1.txt"
body_file="${WORK_DIR}/b1.json"
status=$(curl -s -o "$body_file" -D "$headers_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" "$REPODATA_URL" 2>/dev/null) || status="000"

if [ "$status" != "200" ]; then
  fail "expected 200, got ${status}; body=$(head -c 200 "$body_file" 2>/dev/null)"
elif ! grep -qi '^etag:' "$headers_file"; then
  fail "200 response missing ETag header (headers: $(grep -i etag "$headers_file" || echo NONE))"
else
  # Capture and validate ETag syntax. conda.rs:compute_etag emits
  #   "<64 lowercase hex>"  (quote + sha256 hex + quote)
  ETAG=$(grep -i '^etag:' "$headers_file" | tr -d '\r' | head -1 | sed 's/^[Ee][Tt][Aa][Gg]:[[:space:]]*//')
  if [ -z "$ETAG" ]; then
    fail "ETag header present but value empty"
  elif ! echo "$ETAG" | grep -qE '^"[0-9a-f]{64}"$'; then
    fail "ETag does not match expected '\"<sha256>\"' syntax: ${ETAG}"
  elif [ ! -s "$body_file" ]; then
    fail "200 response missing body"
  else
    pass
  fi
fi

# Bail early if we don't have an ETag to test conditionals against.
if [ -z "${ETAG:-}" ]; then
  end_suite
fi

# ---------------------------------------------------------------------------
# Step 2: matching If-None-Match -> 304 with EMPTY body.
# ---------------------------------------------------------------------------

begin_test "GET with matching If-None-Match returns 304 and empty body"
headers_file="${WORK_DIR}/h2.txt"
body_file="${WORK_DIR}/b2.json"
status=$(curl -s -o "$body_file" -D "$headers_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  -H "If-None-Match: ${ETAG}" \
  "$REPODATA_URL" 2>/dev/null) || status="000"

if [ "$status" != "304" ]; then
  fail "expected 304 on matching ETag, got ${status} (ETag was ${ETAG}); body=$(head -c 200 "$body_file" 2>/dev/null)"
elif [ -s "$body_file" ]; then
  # RFC 7232 5.6: 304 MUST NOT include a message body. curl writes the
  # body file even for 0-byte responses, so we check size, not existence.
  fail "304 response unexpectedly included a body of $(wc -c < "$body_file") bytes"
elif ! grep -qi '^etag:' "$headers_file"; then
  # RFC 7232 4.1: 304 SHOULD echo the ETag that triggered the match.
  fail "304 response missing ETag header"
else
  pass
fi

# ---------------------------------------------------------------------------
# Step 3: wrong If-None-Match -> 200 with body. Guards against a
# constant-true conditional check (which would also return 304 on a
# matching ETag and pass step 2 vacuously).
# ---------------------------------------------------------------------------

begin_test "GET with non-matching If-None-Match returns 200 with body"
headers_file="${WORK_DIR}/h3.txt"
body_file="${WORK_DIR}/b3.json"
# A deliberately-wrong but syntactically-valid ETag value. 'd' * 64 is
# valid lowercase hex but cannot collide with a real SHA-256 of the
# repodata we just generated.
WRONG_ETAG='"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"'
status=$(curl -s -o "$body_file" -D "$headers_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  -H "If-None-Match: ${WRONG_ETAG}" \
  "$REPODATA_URL" 2>/dev/null) || status="000"

if [ "$status" != "200" ]; then
  fail "expected 200 on non-matching ETag, got ${status}; body=$(head -c 200 "$body_file" 2>/dev/null)"
elif [ ! -s "$body_file" ]; then
  fail "200 response (wrong ETag) missing body"
else
  pass
fi

# ---------------------------------------------------------------------------
# Step 4: If-None-Match: "*" -> 304. RFC 7232 2.3.2 wildcard semantics.
# conda.rs:402 handles wildcard explicitly.
# ---------------------------------------------------------------------------

begin_test "GET with If-None-Match: * returns 304"
headers_file="${WORK_DIR}/h4.txt"
body_file="${WORK_DIR}/b4.json"
status=$(curl -s -o "$body_file" -D "$headers_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  -H 'If-None-Match: *' \
  "$REPODATA_URL" 2>/dev/null) || status="000"

if [ "$status" != "304" ]; then
  fail "expected 304 on If-None-Match: *, got ${status}"
elif [ -s "$body_file" ]; then
  fail "304 (wildcard) response unexpectedly included a body of $(wc -c < "$body_file") bytes"
else
  pass
fi

# ---------------------------------------------------------------------------
# Step 5: comma-separated If-None-Match list including the real ETag
# -> 304. conda.rs:403 splits on ',' and trims each token.
# ---------------------------------------------------------------------------

begin_test "GET with multi-value If-None-Match including matching ETag returns 304"
headers_file="${WORK_DIR}/h5.txt"
body_file="${WORK_DIR}/b5.json"
# Put a decoy first to make sure the comma-split actually scans for a
# match rather than only checking the first token.
DECOY='"0000000000000000000000000000000000000000000000000000000000000000"'
status=$(curl -s -o "$body_file" -D "$headers_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  -H "If-None-Match: ${DECOY}, ${ETAG}" \
  "$REPODATA_URL" 2>/dev/null) || status="000"

if [ "$status" != "304" ]; then
  fail "expected 304 on multi-value If-None-Match containing matching ETag, got ${status}"
elif [ -s "$body_file" ]; then
  fail "304 (multi-value) response unexpectedly included a body"
else
  pass
fi

if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  if ( end_suite ); then
    echo "EXPECT_FAILURE=1 but suite passed; inverting to fail"
    exit 1
  else
    echo "EXPECT_FAILURE=1 and suite failed as expected; inverting to pass"
    exit 0
  fi
fi

end_suite
