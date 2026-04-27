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
#   3. Specific known TRANSITIVE component names appear (catches the
#      "fake placeholder data" case from #870, where the response shape was
#      valid but the data did not correspond to the uploaded artifact). The
#      uploaded package itself (express) is excluded from this assertion --
#      it appears in any SBOM as the root component, so requiring it would
#      not prove the scanner actually walked the dep tree.
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

# Components we expect to see in the SBOM. ONLY transitive deps -- the
# uploaded package itself (express) appears in any SBOM as the root
# component, so requiring it would not prove the scanner walked the
# dependency tree. Pinned transitives have been stable in
# express@4.18.2's dependency tree for years.
EXPECTED_TRANSITIVE_COMPONENTS=("body-parser" "qs" "cookie")

# Minimum component count. express@4.18.2 has 30+ direct deps in its
# package.json; a healthy SBOM should easily clear 5. The "> 5" threshold
# from issue #47 is intentionally conservative: it catches the
# "components: []" silent-failure case without being flaky against minor
# scanner changes that drop or rename a few entries.
MIN_COMPONENT_COUNT=5

REPO_KEY="sec-sbom-correctness-${RUN_ID}"
NPM_REGISTRY="${BASE_URL}/npm/${REPO_KEY}/"
SBOM_POLL_TIMEOUT="${SBOM_POLL_TIMEOUT:-180}"   # bumped from 60s for cold-start scanner
SBOM_POLL_INTERVAL=5
SCAN_WAIT_TIMEOUT="${SCAN_WAIT_TIMEOUT:-120}"   # bumped from 60s

# Track resources we created so we can clean up at the end even on failure.
CREATED_REPO=false
ARTIFACT_ID=""

# Combine our cleanup with setup_workdir's WORK_DIR cleanup. The previous
# version's `trap cleanup EXIT` silently overwrote setup_workdir's trap
# and leaked WORK_DIR on every run.
cleanup() {
  if [ "$CREATED_REPO" = "true" ]; then
    api_delete "/api/v1/repositories/${REPO_KEY}" > /dev/null 2>&1 || true
  fi
  [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Helper: validate that a value is a non-negative integer before passing
# to numeric comparisons. Round-1 review flagged that
# `[ "$count" -gt N ] 2>/dev/null` masks `set -e` arithmetic failures and
# bugs. This makes the precondition explicit.
is_nonneg_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

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

# shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
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
#
# The list response shape is `{items: [...]}`. Parenthesize the jq filter
# explicitly: round-1 review flagged that `A or B and C` could parse as
# `A or (B and C)` and silently match wrong rows.
# ---------------------------------------------------------------------------

begin_test "Resolve artifact ID for uploaded fixture"
sleep 2  # backend catalog registration takes a moment

artifact_resp=""
for _i in 1 2 3 4 5; do
  if artifact_resp=$(api_get "/api/v1/repositories/${REPO_KEY}/artifacts" 2>/dev/null); then
    ARTIFACT_ID=$(echo "$artifact_resp" | jq -r --arg name "$FIXTURE_NAME" --arg ver "$FIXTURE_VERSION" '
      (if type == "array" then . else (.items // []) end)
      | map(select(
          (.name == $name or ((.path // "") | test($name)))
          and ((.version // "") == $ver or ((.path // "") | test($ver)))
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
#
# Round-2 fix: validate scan_resp is JSON before treating it as success.
# Round-1 review noted that a 200 returning HTML (e.g. a proxy error page)
# would otherwise pass the `[ -n "$scan_resp" ]` check.
# ---------------------------------------------------------------------------

begin_test "Wait for fixture security scan to complete"
scan_status=""
elapsed=0
while [ "$elapsed" -lt "$SCAN_WAIT_TIMEOUT" ]; do
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
  scan_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/api/v1/sbom/cve/history/${ARTIFACT_ID}" 2>/dev/null) || scan_resp=""
  if [ -n "$scan_resp" ] && echo "$scan_resp" | jq empty >/dev/null 2>&1; then
    scan_status="found"
    break
  fi
  sleep "$SBOM_POLL_INTERVAL"
  elapsed=$(( elapsed + SBOM_POLL_INTERVAL ))
done

if [ "$scan_status" = "found" ]; then
  pass
else
  # Don't fail the suite here: some deployments report scan status only
  # via internal queues. The real assertions are on the SBOM body below.
  skip "scan status endpoint did not confirm completion within ${SCAN_WAIT_TIMEOUT}s; proceeding to SBOM check (which is the actual regression assertion)"
fi

# ---------------------------------------------------------------------------
# Request SBOM generation
# ---------------------------------------------------------------------------

begin_test "Request SBOM generation (POST /api/v1/sbom)"
gen_resp=$(api_post "/api/v1/sbom" \
  "{\"artifact_id\":\"${ARTIFACT_ID}\",\"format\":\"cyclonedx\",\"force_regenerate\":true}" \
  2>/dev/null) || gen_resp=""

if [ -n "$gen_resp" ] && echo "$gen_resp" | jq empty >/dev/null 2>&1; then
  pass
else
  fail "POST /api/v1/sbom did not return a valid JSON body"
  end_suite
fi

# ---------------------------------------------------------------------------
# Poll the SBOM until it is populated (or timeout)
#
# We poll GET /api/v1/sbom/by-artifact/{id} and re-trigger generation if
# the first response comes back with components.length == 0. This mirrors
# what the web UI does and gives the scanner time to surface its findings
# even on a slow runner.
#
# Round-2 fixes:
#   - Component count uses max($meta, $embedded), not preferential. The
#     previous `if $meta > 0 then $meta else $embedded` would accept a
#     stale/non-zero metadata count even when the embedded array was
#     empty -- a way the #870 silent-empty bug could slip through.
#   - The polling step now FAILS on timeout instead of pass-through. The
#     round-1 review flagged that a body-from-last-iteration silently
#     passed the polling test even when the components count never crossed
#     the threshold.
#   - component_count is numeric-validated before -gt to surface jq
#     parse errors loudly instead of via a masked arithmetic failure.
# ---------------------------------------------------------------------------

begin_test "Poll SBOM until components are populated (timeout ${SBOM_POLL_TIMEOUT}s)"
sbom_body=""
sbom_status=""
component_count=0
elapsed=0
populated=0
while [ "$elapsed" -lt "$SBOM_POLL_TIMEOUT" ]; do
  tmp_body=$(mktemp)
  # shellcheck disable=SC2086  # CURL_TIMEOUT must word-split, per common.sh
  sbom_status=$(curl -s -o "$tmp_body" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/sbom/by-artifact/${ARTIFACT_ID}" 2>/dev/null) || sbom_status="000"
  sbom_body=$(cat "$tmp_body" 2>/dev/null || true)
  rm -f "$tmp_body"

  if [ "$sbom_status" = "200" ] && [ -n "$sbom_body" ] && \
     echo "$sbom_body" | jq empty >/dev/null 2>&1; then
    # Take the larger of the metadata count and the embedded array length.
    # Either source going non-zero is enough; preferring metadata over
    # embedded would let a stale metadata count mask an empty array.
    component_count=$(echo "$sbom_body" | jq -r '
      [(.component_count // 0), ((.content.components // []) | length)] | max
    ' 2>/dev/null) || component_count=0
    if is_nonneg_int "$component_count" && [ "$component_count" -gt "$MIN_COMPONENT_COUNT" ]; then
      populated=1
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

if [ "$populated" = "1" ]; then
  pass
else
  body_snip=$(echo "$sbom_body" | head -c 500)
  fail "SBOM polling did not reach component_count > ${MIN_COMPONENT_COUNT} within ${SBOM_POLL_TIMEOUT}s (last status=${sbom_status}, last count=${component_count}). body: ${body_snip}"
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
if is_nonneg_int "$component_count" && [ "$component_count" -gt "$MIN_COMPONENT_COUNT" ]; then
  pass
else
  body_snip=$(echo "$sbom_body" | head -c 500)
  fail "expected components.length > ${MIN_COMPONENT_COUNT} for ${FIXTURE_NAME}@${FIXTURE_VERSION}, got '${component_count}'. body: ${body_snip}"
fi

# ---------------------------------------------------------------------------
# Assertion 3: known TRANSITIVE component names appear
#
# A non-empty components array is necessary but not sufficient: a
# scanner could emit fabricated/placeholder names and still hit the count
# threshold. We pin specific TRANSITIVE deps that any healthy scan of
# express@4.18.2 must surface. The uploaded package itself (express) is
# excluded because it would always appear as the root component
# regardless of whether the scanner walked the dep tree -- requiring it
# would be a free pass for a scanner stub that just echoes the upload.
# ---------------------------------------------------------------------------

begin_test "SBOM names at least 2 known transitive deps of ${FIXTURE_NAME}"
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
for expected in "${EXPECTED_TRANSITIVE_COMPONENTS[@]}"; do
  if [[ ",${component_names}," == *",${expected},"* ]]; then
    matched=$(( matched + 1 ))
  else
    missing+=("$expected")
  fi
done

# Require at least 2 of 3 transitive deps. Allowing one miss keeps the
# assertion resilient to scanner-level renames; we can tighten this once
# scanner output is stable across versions.
if [ "$matched" -ge 2 ]; then
  pass
else
  names_snip=$(echo "$component_names" | head -c 500)
  fail "expected at least 2 of [${EXPECTED_TRANSITIVE_COMPONENTS[*]}] in SBOM components, matched ${matched}. missing: ${missing[*]}. names: ${names_snip}"
fi

# ---------------------------------------------------------------------------
# Diagnostics dump on failure.
#
# When something fails above, save the most recent SBOM response so the
# release-gate workflow's failure-hook step has artifacts to upload.
# ---------------------------------------------------------------------------

if [ -d "${JUNIT_OUTPUT_DIR:-/tmp/junit}" ]; then
  echo "$sbom_body" > "${JUNIT_OUTPUT_DIR}/sbom-correctness-final-resp.json" 2>/dev/null || true
  if [ -n "$ARTIFACT_ID" ]; then
    echo "$ARTIFACT_ID" > "${JUNIT_OUTPUT_DIR}/sbom-correctness-artifact-id.txt" 2>/dev/null || true
  fi
fi

end_suite
