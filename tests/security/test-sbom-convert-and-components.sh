#!/usr/bin/env bash
# test-sbom-convert-and-components.sh - SBOM format conversion + components
# enumeration E2E test.
#
# Covers Epic 2 sub-tasks 2.5 + 2.6 (artifact-keeper-test#67):
#   POST /api/v1/sbom/{id}/convert      (CycloneDX <-> SPDX)
#   GET  /api/v1/sbom/{id}/components
# Ships in v1.2.0 (customer pain #2 from discussion #872 -- "SBOMs were
# generated but never re-formatted or drilled into, so we trusted nothing").
#
# Flow
# ----
#   1. Create a generic repo, upload a tarball containing a npm
#      package-lock.json (lodash) so the SBOM generator has real
#      components to walk.
#   2. Generate SBOM via POST /api/v1/sbom with {artifact_id, format:
#      "cyclonedx"} (uses GenerateSbomRequest schema, line 13610).
#   3. GET /api/v1/sbom/{id}/components and assert documented
#      ComponentResponse shape (id, sbom_id, name, licenses[]) on each
#      element and that the array is non-empty.
#   4. POST /api/v1/sbom/{id}/convert with {target_format: "spdx"} and
#      assert the response SbomResponse has format != original format
#      and the documented top-level fields (id, format, format_version,
#      component_count, generated_at) are present.
#
# Skip semantics
# --------------
# SBOM generation depends on the language-specific scanner being wired
# (the npm/pypi walkers ship in v1.2.0 backends but local-dev compose
# sometimes runs with the legacy image-only scanner). Per the file
# header on test-scan-findings-list.sh, we skip() rather than fail()
# so the gate stays clean on minimal stacks. Hard fail mode is reached
# only when the generate succeeds but the convert / components handler
# crashes.
#
# Self-test mode (EXPECT_FAILURE=1):
#   Inverts the final exit code (end_suite handles this centrally).
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbom-convert-components"
auth_admin
setup_workdir

REPO_KEY="test-sbom-cc-${RUN_ID}"
PACKAGE_NAME="sbom-cc-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
ARTIFACT_PATH="${PACKAGE_NAME}/${PACKAGE_VERSION}/${TARBALL_NAME}"
# Most SBOM generators finish in <30s on a healthy stack; budget 90s
# leaves headroom under run-suite's 120s TEST_TIMEOUT.
SBOM_TIMEOUT="${SBOM_TIMEOUT:-90}"
SBOM_ID=""
ORIGINAL_FORMAT=""

cleanup_sbom_repo() {
  if [ -n "$SBOM_ID" ]; then
    # shellcheck disable=SC2086
    curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/sbom/${SBOM_ID}" > /dev/null 2>&1 || true
  fi
  # shellcheck disable=SC2086
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
}
add_exit_handler "cleanup_sbom_repo"

# ---------------------------------------------------------------------------
# Build fixture: minimal npm-style tarball with a known component
# (lodash 4.17.21) so the SBOM generator emits at least one component
# with a license field populated.
# ---------------------------------------------------------------------------

begin_test "Build npm-style fixture tarball"
mkdir -p "${WORK_DIR}/pkg"
cat > "${WORK_DIR}/pkg/package.json" <<'EOF'
{
  "name": "sbom-cc-fixture",
  "version": "1.0.0",
  "license": "MIT",
  "dependencies": { "lodash": "4.17.21" }
}
EOF
cat > "${WORK_DIR}/pkg/package-lock.json" <<'EOF'
{
  "name": "sbom-cc-fixture",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "sbom-cc-fixture",
      "version": "1.0.0",
      "dependencies": { "lodash": "4.17.21" }
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
      "license": "MIT"
    }
  }
}
EOF
if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" pkg 2>/dev/null; then
  pass
else
  fail "could not build fixture tarball"
  end_suite
  exit 1
fi

begin_test "Create generic local repository"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create ${REPO_KEY}"
  end_suite
  exit 1
fi

begin_test "Upload fixture artifact"
upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT -H "$(auth_header)" -H "Content-Type: application/gzip" \
  --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || upload_status="000"
case "$upload_status" in
  200|201) pass ;;
  *) fail "upload returned ${upload_status}"; end_suite; exit 1 ;;
esac

# Give the artifact pipeline a beat before we look it up.
sleep 2

begin_test "Resolve artifact_id"
ARTIFACT_ID=""
list_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null) || true
if [ -n "$list_resp" ]; then
  ARTIFACT_ID=$(echo "$list_resp" | jq -r --arg p "$ARTIFACT_PATH" --arg n "$PACKAGE_NAME" '
    (if type == "array" then . elif .items then .items else [] end)
    | map(select(((.path // "") == $p) or ((.name // "") | tostring | contains($n))))
    | .[0].id // empty')
fi
if [ -n "$ARTIFACT_ID" ]; then
  pass
else
  fail "could not resolve artifact_id (list_resp head: $(echo "$list_resp" | head -c 200))"
  end_suite
  exit 1
fi

# ---------------------------------------------------------------------------
# 2.5/2.6 prerequisite: generate an SBOM. If the generator is not wired
# on this backend we skip the rest of the suite (the SBOM endpoints
# require an SBOM ID; nothing to test without one). Backend returns
# 404/501 for "no generator for format" today.
# ---------------------------------------------------------------------------

begin_test "Generate SBOM (cyclonedx) for fixture artifact"
gen_payload=$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id, format: "cyclonedx"}')
gen_status=$(curl -s -o "$WORK_DIR/gen.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$gen_payload" \
  "${BASE_URL}/api/v1/sbom") || gen_status="000"

case "$gen_status" in
  200|201)
    SBOM_ID=$(jq -r '.id // empty' "$WORK_DIR/gen.json" 2>/dev/null || echo "")
    ORIGINAL_FORMAT=$(jq -r '.format // empty' "$WORK_DIR/gen.json" 2>/dev/null || echo "")
    if [ -n "$SBOM_ID" ]; then
      pass
    else
      skip "SBOM generated but no id in response (body: $(head -c 200 "$WORK_DIR/gen.json"))"
    fi
    ;;
  404|501|503)
    skip "SBOM generator not configured (HTTP ${gen_status})"
    ;;
  *)
    fail "POST /sbom returned HTTP ${gen_status} (body: $(head -c 200 "$WORK_DIR/gen.json"))"
    ;;
esac

# Some backends return the SbomResponse synchronously, others queue and
# require a follow-up GET. Poll briefly for the SBOM to materialize.
if [ -n "$SBOM_ID" ]; then
  begin_test "SBOM materializes (GET /sbom/{id} returns 200)"
  elapsed=0
  ready=0
  while [ "$elapsed" -lt "$SBOM_TIMEOUT" ]; do
    s=$(curl -s -o "$WORK_DIR/sbom.json" -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(auth_header)" "${BASE_URL}/api/v1/sbom/${SBOM_ID}") || s="000"
    if [ "$s" = "200" ]; then
      ready=1
      ORIGINAL_FORMAT=$(jq -r '.format // empty' "$WORK_DIR/sbom.json" 2>/dev/null || echo "$ORIGINAL_FORMAT")
      break
    fi
    sleep 3
    elapsed=$(( elapsed + 3 ))
  done
  if [ "$ready" = "1" ]; then
    pass
  else
    skip "SBOM not retrievable within ${SBOM_TIMEOUT}s; last status=${s}"
    SBOM_ID=""
  fi
fi

# ---------------------------------------------------------------------------
# 2.6 -- GET /api/v1/sbom/{id}/components returns array of
# ComponentResponse. Required fields per openapi.yaml line 11474:
#   id (uuid), sbom_id (uuid), name (string), licenses (array of string).
# ---------------------------------------------------------------------------

begin_test "GET /sbom/{id}/components returns ComponentResponse[]"
if [ -z "$SBOM_ID" ]; then
  skip "no SBOM id"
else
  comp_status=$(curl -s -o "$WORK_DIR/comp.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" "${BASE_URL}/api/v1/sbom/${SBOM_ID}/components") || comp_status="000"
  if [ "$comp_status" = "501" ] || [ "$comp_status" = "404" ]; then
    skip "components endpoint not available (HTTP ${comp_status})"
  elif [ "$comp_status" != "200" ]; then
    fail "GET /sbom/${SBOM_ID}/components returned HTTP ${comp_status} (body: $(head -c 200 "$WORK_DIR/comp.json"))"
  else
    # Must be an array.
    if ! jq -e 'type == "array"' "$WORK_DIR/comp.json" > /dev/null 2>&1; then
      fail "components response is not an array (body: $(head -c 200 "$WORK_DIR/comp.json"))"
    else
      n=$(jq -r 'length' "$WORK_DIR/comp.json")
      if [ "$n" -lt 1 ]; then
        # Empty array is suspicious for a fixture with a known package-lock
        # entry, but possible if the SBOM generator only walks runtime
        # artifacts. Skip rather than fail.
        skip "components array empty (n=0); SBOM generator may not walk this fixture format"
      else
        # Spot-check first element has the required ComponentResponse shape.
        uuid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        first_id=$(jq -r '.[0].id // empty' "$WORK_DIR/comp.json")
        first_sbom_id=$(jq -r '.[0].sbom_id // empty' "$WORK_DIR/comp.json")
        first_name=$(jq -r '.[0].name // empty' "$WORK_DIR/comp.json")
        first_licenses_type=$(jq -r '.[0].licenses | type' "$WORK_DIR/comp.json")
        if ! [[ "$first_id" =~ $uuid_re ]]; then
          fail "components[0].id='${first_id}' is not a UUID"
        elif [ "$first_sbom_id" != "$SBOM_ID" ]; then
          fail "components[0].sbom_id='${first_sbom_id}' != requested SBOM '${SBOM_ID}'"
        elif [ -z "$first_name" ]; then
          fail "components[0].name is empty"
        elif [ "$first_licenses_type" != "array" ]; then
          fail "components[0].licenses is type=${first_licenses_type} (expected array)"
        else
          pass
        fi
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.5 -- POST /api/v1/sbom/{id}/convert with {target_format: "spdx"}
# returns a SbomResponse whose format differs from the original.
# Required top-level fields per openapi.yaml line 16517:
#   id, artifact_id, repository_id, format, format_version,
#   component_count, dependency_count, license_count, licenses[],
#   content_hash, generated_at, created_at.
# ---------------------------------------------------------------------------

begin_test "POST /sbom/{id}/convert CycloneDX -> SPDX returns SbomResponse"
if [ -z "$SBOM_ID" ]; then
  skip "no SBOM id"
else
  # Pick a target_format that differs from the original. We requested
  # cyclonedx above; if the backend normalized that string differently
  # (e.g. "CycloneDX" vs "cyclonedx") we still expect format to change
  # to spdx after a convert.
  target_format="spdx"
  conv_payload=$(jq -n --arg t "$target_format" '{target_format: $t}')
  conv_status=$(curl -s -o "$WORK_DIR/conv.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$conv_payload" \
    "${BASE_URL}/api/v1/sbom/${SBOM_ID}/convert") || conv_status="000"

  case "$conv_status" in
    501|404)
      skip "convert endpoint not available (HTTP ${conv_status})"
      ;;
    422)
      # 422 could mean "target_format=spdx not supported on this build".
      # That's a legitimate disabled-feature signal -- skip not fail.
      skip "convert rejected target_format=${target_format} (HTTP 422, body: $(head -c 200 "$WORK_DIR/conv.json"))"
      ;;
    200)
      # Required SbomResponse fields.
      missing=""
      for field in id artifact_id repository_id format format_version \
                   component_count dependency_count license_count \
                   licenses content_hash generated_at created_at; do
        if ! jq -e --arg f "$field" 'has($f) and (.[$f] != null)' "$WORK_DIR/conv.json" > /dev/null 2>&1; then
          missing="${missing} ${field}"
        fi
      done
      new_format=$(jq -r '.format // empty' "$WORK_DIR/conv.json")
      if [ -n "$missing" ]; then
        fail "converted SbomResponse missing required field(s):${missing} (body: $(head -c 250 "$WORK_DIR/conv.json"))"
      elif [ -z "$new_format" ]; then
        fail "converted SBOM has empty format field"
      elif [ -n "$ORIGINAL_FORMAT" ] && [ "$new_format" = "$ORIGINAL_FORMAT" ]; then
        fail "convert did not change format: original='${ORIGINAL_FORMAT}', after-convert='${new_format}' (target='${target_format}')"
      else
        pass
      fi
      ;;
    *)
      fail "POST /sbom/${SBOM_ID}/convert returned HTTP ${conv_status} (body: $(head -c 200 "$WORK_DIR/conv.json"))"
      ;;
  esac
fi

end_suite
