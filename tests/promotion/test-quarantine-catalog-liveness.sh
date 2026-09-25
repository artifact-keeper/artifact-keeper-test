#!/usr/bin/env bash
# test-quarantine-catalog-liveness.sh -- held uploads are not listed on the
# Packages page, rejection delists, release re-lists (#4196).
#
# The upload path applies the quarantine hold AND registers the package in the
# catalog regardless. Before the fix the read-side liveness check filtered on
# is_deleted alone, so a held upload was listed from the moment it published,
# a rejection never delisted it, and a release never re-registered it.
#
# Fails against the unfixed backend: the held package shows up in
# /api/v1/packages immediately, and the rejected one never leaves.
#
# Requires: curl, jq
source "$(dirname "$0")/../lib/common.sh"

begin_suite "quarantine-catalog-liveness"
auth_admin
setup_workdir

REPO_KEY="qcat-${RUN_ID}"
PKG_NAME="q4196held${RUN_ID//-/}"

begin_test "Create local repo with quarantine enabled"
if create_local_repo "$REPO_KEY" "generic"; then
  # PATCH quarantine_enabled + a long hold window.
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PATCH \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d '{"quarantine_enabled":true,"quarantine_duration_minutes":360}' \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" 2>/dev/null) || status="000"
  if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "could not enable quarantine on the repo (HTTP ${status})"
  fi
else
  fail "could not create repo"
fi

begin_test "Upload a package (the hold is applied at publish time)"
echo "quarantine-liveness-${RUN_ID}" > "${WORK_DIR}/${PKG_NAME}-1.0.0.bin"
# The generic flat convention is {name}/{version}/{filename}: the first
# segment is the catalog name, so PKG_NAME leads the path.
if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${PKG_NAME}/1.0.0/${PKG_NAME}-1.0.0.bin" \
    "${WORK_DIR}/${PKG_NAME}-1.0.0.bin"; then
  pass
else
  fail "upload failed"
fi

# Resolve the artifact id for the quarantine API calls.
ARTIFACT_ID=""
if resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
  ARTIFACT_ID=$(echo "$resp" | jq -r '
    if type == "array" then .[0].id // .[0].artifact_id // empty
    elif .items then .items[0].id // .items[0].artifact_id // empty
    else .id // .artifact_id // empty
    end' 2>/dev/null) || true
fi

# Control: the upload really is held (otherwise the liveness assertions are
# meaningless).
begin_test "The upload is quarantined (control)"
if [ -z "${ARTIFACT_ID:-}" ] || [ "$ARTIFACT_ID" = "null" ]; then
  skip "no artifact id"
else
  if resp=$(api_get "/api/v1/quarantine/${ARTIFACT_ID}" 2>/dev/null); then
    if [ "$(echo "$resp" | jq -r '.quarantine_status // empty')" = "quarantined" ]; then
      pass
    else
      fail "expected quarantine_status=quarantined after upload into a quarantined repo" "$resp"
    fi
  else
    fail "could not read quarantine status"
  fi
fi

# THE BUG (part 1): a held upload must not be listed.
begin_test "Held upload is NOT listed on the Packages page"
if resp=$(api_get "/api/v1/packages?repository_key=${REPO_KEY}&search=${PKG_NAME}" 2>/dev/null); then
  if echo "$resp" | grep -q "$PKG_NAME"; then
    fail "a quarantined (held) package is listed on the Packages page" "$resp"
  else
    pass
  fi
else
  # An empty listing is a 200 with no matches on a healthy backend; a request
  # error here is infra, not the bug.
  fail "packages listing request failed"
fi

# Release it: the package becomes visible with no re-upload.
begin_test "Release from quarantine registers the package"
if [ -z "${ARTIFACT_ID:-}" ] || [ "$ARTIFACT_ID" = "null" ]; then
  skip "no artifact id"
else
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" \
    "${BASE_URL}/api/v1/quarantine/${ARTIFACT_ID}/release" 2>/dev/null) || status="000"
  if [ "$status" != "200" ]; then
    fail "release endpoint returned HTTP ${status}"
  elif resp=$(api_get "/api/v1/packages?repository_key=${REPO_KEY}&search=${PKG_NAME}" 2>/dev/null); then
    if echo "$resp" | grep -q "$PKG_NAME"; then
      pass
    else
      fail "a released package must be listed" "$resp"
    fi
  else
    fail "packages listing request failed"
  fi
fi

# THE BUG (part 2): rejection after publish must delist.
begin_test "Re-quarantine then rejection delists the package"
if [ -z "${ARTIFACT_ID:-}" ] || [ "$ARTIFACT_ID" = "null" ]; then
  skip "no artifact id"
else
  curl -s -o /dev/null $CURL_TIMEOUT -X POST -H "$(auth_header)" \
    -H "Content-Type: application/json" -d '{}' \
    "${BASE_URL}/api/v1/quarantine/${ARTIFACT_ID}/quarantine" 2>/dev/null || true
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" \
    -H "Content-Type: application/json" -d '{"reason":"e2e rejection"}' \
    "${BASE_URL}/api/v1/quarantine/${ARTIFACT_ID}/reject" 2>/dev/null) || status="000"
  if [ "$status" != "200" ]; then
    fail "reject endpoint returned HTTP ${status}"
  elif resp=$(api_get "/api/v1/packages?repository_key=${REPO_KEY}&search=${PKG_NAME}" 2>/dev/null); then
    if echo "$resp" | grep -q "$PKG_NAME"; then
      fail "a rejected package is still listed on the Packages page" "$resp"
    else
      pass
    fi
  else
    fail "packages listing request failed"
  fi
fi

# Cleanup
api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true

end_suite
