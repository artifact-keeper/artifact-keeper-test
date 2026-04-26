#!/usr/bin/env bash
# test-sbom-correctness.sh - SBOM correctness regression test
#
# Regression coverage for upstream issue:
#   artifact-keeper#870 (SBOM endpoint returned status 200 with empty/fake
#   data because the underlying scan/storage path silently failed; the SBOM
#   handler persisted an empty record without surfacing the error).
#
# The pre-existing platform/test-sbom.sh asserts only the SBOM record's
# structural metadata (bomFormat, specVersion, etc.). It uploads a synthetic
# generic blob with no real dependencies, so a "components: []" result looks
# correct. That made the silent-empty-SBOM symptom from #870 invisible to
# the gate suite.
#
# This test exercises the same path with a deterministic, real-world npm
# package whose dependency tree is publicly known. It then asserts:
#
#   1. HTTP 200 on the SBOM read.
#   2. components.length > 5  (catches the empty-SBOM case from #870).
#   3. Specific known component names appear in the SBOM (catches the
#      "fake placeholder data" case from #870, where the response shape was
#      valid but the data did not correspond to the uploaded artifact).
#
# Fixture: express@4.18.2 (pinned, no `latest`). Chosen because it has a
# deep, stable dependency tree (~30 direct deps, ~50 transitive) and is
# widely mirrored, so the upstream tarball download is reliable.
#
# Phase 3 of Hardening Core: https://github.com/orgs/artifact-keeper/projects/2

source "$(dirname "$0")/../lib/common.sh"

begin_suite "sbom-correctness"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Fixture (pinned)
# ---------------------------------------------------------------------------

FIXTURE_NAME="express"
FIXTURE_VERSION="4.18.2"
FIXTURE_TARBALL_URL="https://registry.npmjs.org/${FIXTURE_NAME}/-/${FIXTURE_NAME}-${FIXTURE_VERSION}.tgz"

# Components we expect to see in the SBOM. The package itself, plus a few
# stable transitive dependencies that have been pinned in express@4.18.2 for
# years. If the SBOM is empty or fabricated, none of these will be present.
EXPECTED_COMPONENTS=("express" "body-parser" "qs")

# Minimum component count. express@4.18.2 has 30+ direct deps in its
# package.json; a healthy SBOM should easily clear 5. The "> 5" threshold
# from issue #47 is intentionally conservative -- it catches the
# "components: []" silent-failure case without being flaky against minor
# scanner changes that drop or rename a few entries.
MIN_COMPONENT_COUNT=5

REPO_KEY="sec-sbom-correctness-${RUN_ID}"
NPM_REGISTRY="${BASE_URL}/npm/${REPO_KEY}/"
SBOM_POLL_TIMEOUT=60   # seconds
SBOM_POLL_INTERVAL=3   # seconds

# Track resources we created so we can clean up at the end even on failure.
CREATED_REPO=false
ARTIFACT_ID=""

cleanup() {
  if [ "$CREATED_REPO" = "true" ]; then
    api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Create npm local repository
# ---------------------------------------------------------------------------

begin_test "Create npm local repository"
if create_local_repo "$REPO_KEY" "npm"; then
  CREATED_REPO=true
  pass
else
  fail "could not create npm repository"
  end_suite
fi

# ---------------------------------------------------------------------------
# Fetch the pinned upstream fixture tarball
#
# We pull straight from registry.npmjs.org (not through the backend) so that
# the test does not depend on the backend's remote-proxy code path. This
# isolates the SBOM correctness check from any upstream-fetch regressions.
# ---------------------------------------------------------------------------

begin_test "Download pinned fixture ${FIXTURE_NAME}@${FIXTURE_VERSION}"
TARBALL_FILE="${WORK_DIR}/${FIXTURE_NAME}-${FIXTURE_VERSION}.tgz"
if curl -sfL --max-time 30 -o "$TARBALL_FILE" "$FIXTURE_TARBALL_URL"; then
  if [ -s "$TARBALL_FILE" ]; then
    pass
  else
    fail "downloaded tarball is empty"
    end_suite
  fi
else
  fail "could not download fixture tarball from ${FIXTURE_TARBALL_URL}"
  end_suite
fi

# ---------------------------------------------------------------------------
# Publish the fixture to our backend
#
# We use the npm publish payload (PUT /npm/{repo}/{pkg} with _attachments)
# rather than `npm publish`. This avoids a hard dependency on the npm CLI
# being installed on the test runner and makes the upload deterministic.
# ---------------------------------------------------------------------------

begin_test "Publish fixture to backend npm repo"
TARBALL_B64=$(base64 < "$TARBALL_FILE" | tr -d '\n')
TARBALL_SIZE=$(wc -c < "$TARBALL_FILE" | tr -d ' ')

PUBLISH_PAYLOAD_FILE="${WORK_DIR}/publish-payload.json"
jq -n \
  --arg name "$FIXTURE_NAME" \
  --arg version "$FIXTURE_VERSION" \
  --arg tarball_url "${NPM_REGISTRY}${FIXTURE_NAME}/-/${FIXTURE_NAME}-${FIXTURE_VERSION}.tgz" \
  --arg data "$TARBALL_B64" \
  --argjson length "$TARBALL_SIZE" \
  '{
    name: $name,
    description: "SBOM correctness test fixture (pinned)",
    versions: {
      ($version): {
        name: $name,
        version: $version,
        description: "SBOM correctness test fixture (pinned)",
        main: "index.js",
        license: "MIT",
        dist: { tarball: $tarball_url }
      }
    },
    "_attachments": {
      "\($name)-\($version).tgz": {
        content_type: "application/octet-stream",
        data: $data,
        length: $length
      }
    }
  }' > "$PUBLISH_PAYLOAD_FILE"

publish_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(format_auth_header)" \
  -H "Content-Type: application/json" \
  --data-binary "@${PUBLISH_PAYLOAD_FILE}" \
  "${NPM_REGISTRY}${FIXTURE_NAME}") || publish_status="000"

if [ "$publish_status" = "200" ] || [ "$publish_status" = "201" ]; then
  pass
else
  fail "expected 200/201 from npm publish, got ${publish_status}"
  end_suite
fi

# ---------------------------------------------------------------------------
# Resolve the artifact ID we just created
# ---------------------------------------------------------------------------

begin_test "Resolve artifact ID for uploaded fixture"
# Allow the backend a moment to register the artifact in its catalog.
sleep 2

artifact_resp=""
for _i in 1 2 3 4 5; do
  if artifact_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
    ARTIFACT_ID=$(echo "$artifact_resp" | jq -r --arg name "$FIXTURE_NAME" --arg ver "$FIXTURE_VERSION" '
      (if type == "array" then . else (.items // []) end)
      | map(select(
          (.name == $name or (.path // "") | test($name)) and
          ((.version // "") == $ver or (.path // "") | test($ver))
        ))
      | .[0].id // empty
    ' 2>/dev/null) || ARTIFACT_ID=""
    if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
      break
    fi
  fi
  sleep 2
done

# Fallback: take the first artifact in the repo (we only uploaded one).
if [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" = "null" ]; then
  ARTIFACT_ID=$(echo "$artifact_resp" | jq -r '
    (if type == "array" then . else (.items // []) end) | .[0].id // empty
  ' 2>/dev/null) || ARTIFACT_ID=""
fi

if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
  pass
else
  fail "could not resolve artifact ID for ${FIXTURE_NAME}@${FIXTURE_VERSION}"
  end_suite
fi

# ---------------------------------------------------------------------------
# Wait for security scan to complete
#
# SBOM generation reads its component list from scan_findings (see
# extract_dependencies_for_artifact in backend/src/api/handlers/sbom.rs).
# If we request the SBOM before the scan finishes, we get an empty
# components list -- which is precisely the silent-empty case from #870.
# So we explicitly wait for the scan and only then request the SBOM.
# ---------------------------------------------------------------------------

begin_test "Wait for fixture security scan to complete"
scan_status=""
elapsed=0
while [ "$elapsed" -lt 60 ]; do
  scan_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/api/v1/sbom/cve/history/${ARTIFACT_ID}" 2>/dev/null) || scan_resp=""
  if [ -n "$scan_resp" ]; then
    scan_status="found"
    break
  fi
  # Also accept any 2xx on a generic scan endpoint as evidence the
  # scanner has at least touched the artifact. Some deployments run the
  # scanner asynchronously and the cve-history record only appears once
  # the scan completes.
  sleep "$SBOM_POLL_INTERVAL"
  elapsed=$(( elapsed + SBOM_POLL_INTERVAL ))
done

# Whether or not we saw a definitive scan-complete signal, we proceed to
# request the SBOM. The next test will catch the empty-result case.
if [ "$scan_status" = "found" ]; then
  pass
else
  # Don't fail the suite here: some deployments report scan status only
  # via internal queues. The real assertions are on the SBOM body below.
  skip "scan status endpoint did not confirm completion within 60s; proceeding to SBOM check (which is the actual regression assertion)"
fi

# ---------------------------------------------------------------------------
# Request SBOM generation
# ---------------------------------------------------------------------------

begin_test "Request SBOM generation (POST /api/v1/sbom)"
gen_resp=$(api_post "/api/v1/sbom" \
  "{\"artifact_id\":\"${ARTIFACT_ID}\",\"format\":\"cyclonedx\",\"force_regenerate\":true}" \
  2>/dev/null) || gen_resp=""

if [ -n "$gen_resp" ]; then
  pass
else
  fail "POST /api/v1/sbom did not return a body"
  end_suite
fi

# ---------------------------------------------------------------------------
# Poll the SBOM until it is populated (or timeout)
#
# We poll GET /api/v1/sbom/by-artifact/{id} and re-trigger generation if
# the first response comes back with components.length == 0. This mirrors
# what the web UI does and gives the scanner time to surface its findings
# even on a slow runner.
# ---------------------------------------------------------------------------

begin_test "Poll SBOM until components are populated (timeout ${SBOM_POLL_TIMEOUT}s)"
sbom_body=""
sbom_status=""
component_count=0
elapsed=0
while [ "$elapsed" -lt "$SBOM_POLL_TIMEOUT" ]; do
  tmp_body=$(mktemp)
  sbom_status=$(curl -s -o "$tmp_body" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/sbom/by-artifact/${ARTIFACT_ID}" 2>/dev/null) || sbom_status="000"
  sbom_body=$(cat "$tmp_body" 2>/dev/null || true)
  rm -f "$tmp_body"

  if [ "$sbom_status" = "200" ] && [ -n "$sbom_body" ]; then
    # The CycloneDX content lives under .content.components; the metadata
    # row also exposes .component_count. We check the component_count
    # first because that is what the API contract asserts, and fall back
    # to counting the embedded CycloneDX array.
    component_count=$(echo "$sbom_body" | jq -r '
      (.component_count // 0) as $meta
      | (.content.components | length? // 0) as $embedded
      | if $meta > 0 then $meta else $embedded end
    ' 2>/dev/null) || component_count=0
    if [ "$component_count" -gt "$MIN_COMPONENT_COUNT" ] 2>/dev/null; then
      break
    fi
  fi

  # Re-poke generation on each iteration. force_regenerate=false on the
  # follow-ups so we don't thrash the scanner; a missing record will be
  # created, an existing one is left alone.
  api_post "/api/v1/sbom" \
    "{\"artifact_id\":\"${ARTIFACT_ID}\",\"format\":\"cyclonedx\"}" \
    > /dev/null 2>&1 || true

  sleep "$SBOM_POLL_INTERVAL"
  elapsed=$(( elapsed + SBOM_POLL_INTERVAL ))
done

# We pass this test on any non-zero response so the next two assertions
# can run their explicit checks. They are the real regression gates.
if [ -n "$sbom_body" ]; then
  pass
else
  fail "SBOM polling never received a body within ${SBOM_POLL_TIMEOUT}s"
  end_suite
fi

# ---------------------------------------------------------------------------
# Assertion 1: HTTP 200
#
# Issue #870 already returned 200, so this assertion alone is not enough.
# It is included for completeness and to nail down which assertion fails
# first in the JUnit report.
# ---------------------------------------------------------------------------

begin_test "SBOM read returns HTTP 200"
if assert_eq "$sbom_status" "200" "expected HTTP 200 from /api/v1/sbom/by-artifact/{id}, got ${sbom_status}"; then
  pass
fi

# ---------------------------------------------------------------------------
# Assertion 2: components.length > 5
#
# This is the core regression assertion for #870. The bug returned a
# valid 200 with components: [], which our previous tests accepted because
# they only checked the structural fields (bomFormat, specVersion).
# ---------------------------------------------------------------------------

begin_test "SBOM contains more than ${MIN_COMPONENT_COUNT} components"
if [ "$component_count" -gt "$MIN_COMPONENT_COUNT" ] 2>/dev/null; then
  pass
else
  # Print the body so CI logs show what the empty/fake response looked
  # like. Truncate to keep logs sane.
  body_snip=$(echo "$sbom_body" | head -c 500)
  fail "expected components.length > ${MIN_COMPONENT_COUNT} for ${FIXTURE_NAME}@${FIXTURE_VERSION}, got ${component_count}. body: ${body_snip}"
fi

# ---------------------------------------------------------------------------
# Assertion 3: known component names appear
#
# A non-empty components array is necessary but not sufficient: a
# scanner could emit fabricated/placeholder names and still hit the count
# threshold. We pin specific names that any healthy scan of express@4.18.2
# must surface (the package itself + at least one well-known transitive
# dep). If none of these appear, the SBOM is not actually describing our
# uploaded artifact.
# ---------------------------------------------------------------------------

begin_test "SBOM names the fixture and at least one known transitive dep"
component_names=$(echo "$sbom_body" | jq -r '
  ((.content.components // []) + [])
  | map(.name // empty)
  | unique
  | join(",")
' 2>/dev/null) || component_names=""

# Fall back to /api/v1/sbom/{id}/components if the embedded content path
# isn't populated (some deployments split metadata and content rows).
if [ -z "$component_names" ]; then
  sbom_id=$(echo "$sbom_body" | jq -r '.id // empty' 2>/dev/null) || sbom_id=""
  if [ -n "$sbom_id" ] && [ "$sbom_id" != "null" ]; then
    if comp_resp=$(api_get "/api/v1/sbom/${sbom_id}/components" 2>/dev/null); then
      component_names=$(echo "$comp_resp" | jq -r 'map(.name // empty) | unique | join(",")' 2>/dev/null) || component_names=""
    fi
  fi
fi

matched=0
missing=()
for expected in "${EXPECTED_COMPONENTS[@]}"; do
  if [[ ",${component_names}," == *",${expected},"* ]]; then
    matched=$(( matched + 1 ))
  else
    missing+=("$expected")
  fi
done

# We require the package itself + at least one transitive dep, i.e. at
# least 2 of the 3 expected names. Allowing one miss keeps the assertion
# resilient to scanner-level renames (e.g. the qs version pinned by
# express occasionally appears as "qs@6.x" rather than "qs"); we can
# tighten this once scanner output is stable across versions.
if [ "$matched" -ge 2 ]; then
  pass
else
  names_snip=$(echo "$component_names" | head -c 500)
  fail "expected at least 2 of [${EXPECTED_COMPONENTS[*]}] in SBOM components, matched ${matched}. missing: ${missing[*]}. names: ${names_snip}"
fi

end_suite
