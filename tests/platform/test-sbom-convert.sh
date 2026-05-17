#!/usr/bin/env bash
# test-sbom-convert.sh - SBOM format conversion E2E test
#
# Covers Epic 2 sub-task 2.5 (artifact-keeper-test#68):
#   POST /api/v1/sbom/{id}/convert
# Converts a CycloneDX SBOM to SPDX and back, asserting:
#   - the SPDX output carries SPDX-conformant top-level keys
#   - converting SPDX back to CycloneDX preserves the original
#     component-name set (round-trip invariant)
#
# Flow:
#   1. Create a generic repo and upload a small artifact.
#   2. Generate a CycloneDX SBOM for the artifact, capture the SBOM id and
#      the component names from .content.components.
#   3. POST /sbom/{id}/convert with target=spdx and assert the response
#      carries SPDX shape (spdxVersion / SPDXID).
#   4. POST /sbom/{id}/convert with target=cyclonedx (or use the SPDX
#      sbom's id if the backend returns a new row) and assert the
#      component-name set equals the original.
#
# If conversion is not yet enabled on this backend, the POST returns
# 404/501; we skip cleanly.
#
# Requires: curl, jq

set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbom-convert"
auth_admin
setup_workdir

REPO_KEY="test-sbom-conv-${RUN_ID}"
ARTIFACT_PATH="sbom-${RUN_ID}.tgz"
ARTIFACT_ID=""
CDX_SBOM_ID=""
SPDX_RESP=""
ORIG_COMPONENT_NAMES=""

cleanup_repo() {
  # shellcheck disable=SC2086
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler 'cleanup_repo'

begin_test "Create repo and upload artifact"
if create_local_repo "$REPO_KEY" "generic"; then
  # A small payload is enough; the SBOM generator parses metadata, not bytes.
  printf 'sbom-convert-fixture-%s\n' "$RUN_ID" > "${WORK_DIR}/payload.bin"
  if api_upload "/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" \
       "${WORK_DIR}/payload.bin" > /dev/null 2>&1; then
    pass
  else
    fail "artifact upload failed"
  fi
else
  fail "could not create repo"
fi

begin_test "Resolve artifact_id"
list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || true
ARTIFACT_ID=$(echo "$list_resp" | jq -r '
  if type == "array" then .[0].id // empty
  elif .items then .items[0].id // empty
  else empty
  end' 2>/dev/null) || true
if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  pass
else
  fail "could not resolve artifact_id"
fi

begin_test "Generate CycloneDX SBOM"
if [ -z "$ARTIFACT_ID" ]; then
  skip "no artifact_id"
else
  gen_resp=$(api_post "/api/v1/sbom" \
    "{\"artifact_id\":\"${ARTIFACT_ID}\",\"format\":\"cyclonedx\"}" 2>/dev/null) || true
  if [ -z "$gen_resp" ]; then
    skip "SBOM generation not available"
  else
    CDX_SBOM_ID=$(echo "$gen_resp" | jq -r '.id // .sbom.id // empty')
    ORIG_COMPONENT_NAMES=$(echo "$gen_resp" | jq -r '
      (.content.components // .components // []) | map(.name) | sort | .[]
    ' 2>/dev/null | tr '\n' ',')
    if [ -n "$CDX_SBOM_ID" ] && [ "$CDX_SBOM_ID" != "null" ]; then
      pass
    else
      # Fall back to by-artifact retrieval (some backends return only metadata
      # on POST and require a GET to fetch the full document).
      content_resp=$(api_get "/api/v1/sbom/by-artifact/${ARTIFACT_ID}" 2>/dev/null) || true
      CDX_SBOM_ID=$(echo "$content_resp" | jq -r '.id // empty')
      ORIG_COMPONENT_NAMES=$(echo "$content_resp" | jq -r '
        (.content.components // .components // []) | map(.name) | sort | .[]
      ' 2>/dev/null | tr '\n' ',')
      if [ -n "$CDX_SBOM_ID" ] && [ "$CDX_SBOM_ID" != "null" ]; then
        pass
      else
        skip "could not determine SBOM id after generate"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.5.a -- Convert CycloneDX -> SPDX and assert SPDX-conformant structure.
# Required SPDX 2.x top-level keys (per https://spdx.github.io/spdx-spec/v2.3/):
#   spdxVersion, SPDXID, dataLicense, name
# We check spdxVersion + SPDXID as the load-bearing pair: a successful
# conversion that returned the CycloneDX document unchanged would fail this.
# ---------------------------------------------------------------------------

begin_test "Convert CycloneDX -> SPDX returns SPDX-shaped document"
if [ -z "$CDX_SBOM_ID" ]; then
  skip "no CycloneDX SBOM id to convert"
else
  conv_status=$(curl -s -o "$WORK_DIR/spdx.json" -w '%{http_code}' \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d '{"target_format":"spdx"}' \
    "${BASE_URL}/api/v1/sbom/${CDX_SBOM_ID}/convert") || conv_status=000
  if [ "$conv_status" = "404" ] || [ "$conv_status" = "501" ]; then
    skip "SBOM convert endpoint not available (HTTP ${conv_status})"
  elif [[ ! "$conv_status" =~ ^2[0-9][0-9]$ ]]; then
    fail "POST /sbom/${CDX_SBOM_ID}/convert returned HTTP ${conv_status} (body: $(head -c 200 "$WORK_DIR/spdx.json"))"
  else
    SPDX_RESP=$(cat "$WORK_DIR/spdx.json")
    spdx_version=$(echo "$SPDX_RESP" | jq -r '
      .content.spdxVersion // .spdxVersion // .document.spdxVersion // empty
    ')
    spdx_id=$(echo "$SPDX_RESP" | jq -r '
      .content.SPDXID // .SPDXID // .document.SPDXID // empty
    ')
    if [ -z "$spdx_version" ] || [ "$spdx_version" = "null" ]; then
      fail "converted document missing spdxVersion (body: $(echo "$SPDX_RESP" | head -c 200))"
    elif [[ ! "$spdx_version" =~ ^SPDX- ]]; then
      fail "spdxVersion='${spdx_version}' does not start with 'SPDX-'"
    elif [ -z "$spdx_id" ] || [ "$spdx_id" = "null" ]; then
      fail "converted document missing SPDXID"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.5.b -- Round-trip: SPDX back to CycloneDX preserves the component set.
# The SBOM id used here is the original CycloneDX id; the convert endpoint
# is idempotent w.r.t. target_format. If the backend returned a new id on
# the previous conversion, we honor it.
# ---------------------------------------------------------------------------

begin_test "Round-trip SPDX -> CycloneDX preserves component name set"
if [ -z "$CDX_SBOM_ID" ] || [ -z "$SPDX_RESP" ]; then
  skip "no SPDX document to round-trip"
else
  # If the SPDX response carried a new sbom id, prefer that for the reverse
  # conversion; otherwise reuse the original CDX id.
  rt_id=$(echo "$SPDX_RESP" | jq -r '.id // empty')
  if [ -z "$rt_id" ] || [ "$rt_id" = "null" ]; then rt_id="$CDX_SBOM_ID"; fi

  rt_status=$(curl -s -o "$WORK_DIR/cdx-rt.json" -w '%{http_code}' \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d '{"target_format":"cyclonedx"}' \
    "${BASE_URL}/api/v1/sbom/${rt_id}/convert") || rt_status=000
  if [[ ! "$rt_status" =~ ^2[0-9][0-9]$ ]]; then
    fail "reverse convert returned HTTP ${rt_status} (body: $(head -c 200 "$WORK_DIR/cdx-rt.json"))"
  else
    rt_body=$(cat "$WORK_DIR/cdx-rt.json")
    bom_format=$(echo "$rt_body" | jq -r '.content.bomFormat // .bomFormat // empty')
    rt_names=$(echo "$rt_body" | jq -r '
      (.content.components // .components // []) | map(.name) | sort | .[]
    ' 2>/dev/null | tr '\n' ',')
    if [ "$bom_format" != "CycloneDX" ]; then
      fail "reverse convert did not return CycloneDX (bomFormat='${bom_format}')"
    elif [ -z "$ORIG_COMPONENT_NAMES" ] && [ -z "$rt_names" ]; then
      # Both empty: SBOM had no components to begin with. Accept as a valid
      # outcome of a metadata-only generic artifact rather than a failure.
      pass
    elif [ "$rt_names" != "$ORIG_COMPONENT_NAMES" ]; then
      fail "component set drifted on round-trip: orig='${ORIG_COMPONENT_NAMES}' got='${rt_names}'"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.5.c -- Unknown SBOM id returns 404 (not 5xx).
# ---------------------------------------------------------------------------

begin_test "Convert with unknown SBOM id returns 404"
fake_id="00000000-0000-0000-0000-000000000000"
status=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d '{"target_format":"spdx"}' \
  "${BASE_URL}/api/v1/sbom/${fake_id}/convert") || status=000
if [ "$status" = "404" ]; then
  pass
elif [ "$status" = "501" ]; then
  skip "convert endpoint not available"
elif [[ "$status" =~ ^5[0-9][0-9]$ ]]; then
  fail "unknown SBOM id returned ${status} (5xx); expected 404"
else
  fail "unknown SBOM id returned HTTP ${status}; expected 404"
fi

end_suite
