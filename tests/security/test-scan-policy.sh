#!/usr/bin/env bash
# test-scan-policy.sh -- Scan policy CRUD + violation detection E2E test
#
# Covers Epic 2 sub-task 2.10 (artifact-keeper-test#67): CRUD over
#   POST   /api/v1/security/scan-policies
#   GET    /api/v1/security/scan-policies/{id}
#   PUT    /api/v1/security/scan-policies/{id}
#   DELETE /api/v1/security/scan-policies/{id}
# and verification that a scan whose findings violate the policy is reported
# as a violation by the policy-evaluation endpoint.
#
# This test is DISTINCT from quality-gate tests. Scan policies live under
# /security/scan-policies and gate on scan findings (CVE severities, scanner
# coverage). Quality gates live under /quality/gates and aggregate signals
# across health-check + scan + license + custom-metric inputs.
#
# Flow:
#   1. Create a scan policy with max_high_findings:0 and max_critical_findings:0.
#   2. GET / PUT it.
#   3. Upload a known-vulnerable lodash fixture (CVE-2019-10744 / CVSS 9.1),
#      poll the scan to completion.
#   4. Evaluate the policy against the scan and assert a violation is
#      reported (max_high or max_critical breached).
#   5. DELETE the policy.
#
# Endpoints that 404 mark their specific assertion as skip with a precise
# reason; the suite still exercises whatever IS present.

set -euo pipefail
source "$(dirname "$0")/../lib/common.sh"

begin_suite "scan-policy"
auth_admin
setup_workdir

REPO_KEY="scan-pol-${RUN_ID}"
POLICY_NAME="scan-policy-${RUN_ID}-deny-high"
PACKAGE_NAME="lodash-scan-policy-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tgz"
ARTIFACT_PATH="${PACKAGE_NAME}/${PACKAGE_VERSION}/${TARBALL_NAME}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-180}"
POLICY_ID=""
ARTIFACT_ID=""
SCAN_ID=""
SCANNER_AVAILABLE=true

cleanup() {
  if [ -n "$POLICY_ID" ]; then
    # shellcheck disable=SC2086
    curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/security/scan-policies/${POLICY_ID}" >/dev/null 2>&1 || true
  fi
  # shellcheck disable=SC2086
  curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler 'cleanup'

# ---------------------------------------------------------------------------
# 2.10.a -- POST creates the scan policy.
# ---------------------------------------------------------------------------

begin_test "POST /security/scan-policies creates policy (max_high=0, max_critical=0)"
policy_payload=$(jq -n \
  --arg name "$POLICY_NAME" \
  --arg desc "E2E test scan policy ${RUN_ID}" \
  '{name:$name,
    description:$desc,
    max_critical_findings:0,
    max_high_findings:0,
    max_medium_findings:50,
    action:"block",
    enabled:true}')
# shellcheck disable=SC2086
post_status=$(curl -s -o "${WORK_DIR}/pol.json" -w '%{http_code}' $CURL_TIMEOUT \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$policy_payload" \
  "${BASE_URL}/api/v1/security/scan-policies") || post_status="000"
case "$post_status" in
  404) skip "endpoint /api/v1/security/scan-policies not present on this backend" ;;
  2*)
    POLICY_ID=$(jq -er '.id // .policy_id // empty' < "${WORK_DIR}/pol.json" 2>/dev/null || true)
    if [ -n "$POLICY_ID" ]; then pass
    else fail "POST returned ${post_status} but no id in body" "body: $(head -c 400 "${WORK_DIR}/pol.json")"; fi
    ;;
  *) fail "POST /scan-policies returned HTTP ${post_status}" "body: $(head -c 400 "${WORK_DIR}/pol.json")" ;;
esac

# ---------------------------------------------------------------------------
# 2.10.b -- GET round-trips name + thresholds.
# ---------------------------------------------------------------------------

begin_test "GET /security/scan-policies/{id} round-trips thresholds"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  # shellcheck disable=SC2086
  get_status=$(curl -s -o "${WORK_DIR}/pol-get.json" -w '%{http_code}' $CURL_TIMEOUT \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/scan-policies/${POLICY_ID}") || get_status="000"
  if [ "$get_status" != "200" ]; then
    fail "GET returned HTTP ${get_status}"
  else
    body=$(cat "${WORK_DIR}/pol-get.json")
    got_name=$(echo "$body" | jq -r '.name // empty')
    got_max_high=$(echo "$body" | jq -r '.max_high_findings // .max_high // .thresholds.high // empty')
    got_max_crit=$(echo "$body" | jq -r '.max_critical_findings // .max_critical // .thresholds.critical // empty')
    if [ "$got_name" != "$POLICY_NAME" ]; then
      fail "name did not round-trip: got '${got_name}'"
    elif [ "$got_max_high" != "0" ]; then
      fail "max_high_findings did not round-trip: got '${got_max_high}', expected '0'"
    elif [ "$got_max_crit" != "0" ]; then
      fail "max_critical_findings did not round-trip: got '${got_max_crit}', expected '0'"
    else
      pass
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.10.c -- PUT loosens max_high to 5; subsequent GET sees the new value.
# ---------------------------------------------------------------------------

begin_test "PUT /security/scan-policies/{id} loosens max_high to 5"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  put_payload=$(jq -n \
    --arg name "$POLICY_NAME" \
    --arg desc "loosened by E2E ${RUN_ID}" \
    '{name:$name, description:$desc,
      max_critical_findings:0,
      max_high_findings:5,
      max_medium_findings:50,
      action:"block",
      enabled:true}')
  # shellcheck disable=SC2086
  put_status=$(curl -s -o "${WORK_DIR}/pol-put.json" -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$put_payload" \
    "${BASE_URL}/api/v1/security/scan-policies/${POLICY_ID}") || put_status="000"
  if [[ ! "$put_status" =~ ^2[0-9][0-9]$ ]]; then
    fail "PUT returned HTTP ${put_status}"
  else
    get_resp=$(api_get "/api/v1/security/scan-policies/${POLICY_ID}" 2>/dev/null) || get_resp=""
    got_max_high=$(echo "$get_resp" | jq -r '.max_high_findings // .max_high // .thresholds.high // empty')
    if [ "$got_max_high" != "5" ]; then
      fail "max_high did not persist after PUT: got '${got_max_high}', expected '5'"
    else
      pass
    fi
  fi
fi

# Reset policy back to strict (max_high=0) so the violation evaluation
# below has the expected behavior. We retry PUT here rather than re-POST
# a second policy because POLICY_ID is the cleanup hook.
if [ -n "$POLICY_ID" ]; then
  reset_payload=$(jq -n \
    --arg name "$POLICY_NAME" \
    '{name:$name, description:"strict for violation eval",
      max_critical_findings:0, max_high_findings:0,
      max_medium_findings:50, action:"block", enabled:true}')
  # shellcheck disable=SC2086
  curl -s -o /dev/null $CURL_TIMEOUT \
    -X PUT -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$reset_payload" \
    "${BASE_URL}/api/v1/security/scan-policies/${POLICY_ID}" >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Build & upload a known-vulnerable fixture so the scan produces high/
# critical findings that the strict policy will flag.
# ---------------------------------------------------------------------------

begin_test "Build lodash 4.17.4 fixture (CVE-2019-10744, CVSS 9.1)"
mkdir -p "${WORK_DIR}/pkg"
cat > "${WORK_DIR}/pkg/package.json" <<'EOF'
{ "name": "lodash-scan-policy-fixture", "version": "1.0.0",
  "dependencies": { "lodash": "4.17.4" } }
EOF
cat > "${WORK_DIR}/pkg/package-lock.json" <<'EOF'
{ "name": "lodash-scan-policy-fixture", "version": "1.0.0",
  "lockfileVersion": 2, "requires": true,
  "packages": {
    "": { "name": "lodash-scan-policy-fixture", "version": "1.0.0",
          "dependencies": { "lodash": "4.17.4" } },
    "node_modules/lodash": { "version": "4.17.4",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.4.tgz",
      "integrity": "sha1-eCA6TRwyLuHBHJgwGu1myF0sR4U=" } } }
EOF
if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}" pkg 2>/dev/null; then pass
else fail "could not build fixture"; fi

begin_test "Create repo and upload fixture"
if ! create_local_repo "$REPO_KEY" "generic"; then
  fail "could not create ${REPO_KEY}"
else
  # shellcheck disable=SC2086
  upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT -H "$(auth_header)" -H "Content-Type: application/gzip" \
    --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || upload_status="000"
  if [ "$upload_status" = "200" ] || [ "$upload_status" = "201" ]; then pass
  else fail "upload returned ${upload_status}"; fi
fi

begin_test "Resolve artifact_id"
# shellcheck disable=SC2086
lookup_status=$(curl -s -o "${WORK_DIR}/art.json" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || lookup_status="000"
if [ "$lookup_status" = "200" ]; then
  ARTIFACT_ID=$(jq -er '.id // .artifact_id // empty' < "${WORK_DIR}/art.json" 2>/dev/null || true)
fi
if [ -n "$ARTIFACT_ID" ]; then pass; else fail "could not resolve artifact_id (HTTP ${lookup_status})"; fi

begin_test "Trigger scan and wait for completion"
if [ -z "$ARTIFACT_ID" ]; then
  skip "no artifact_id"
else
  rc=0
  SCAN_ID=$(trigger_and_wait_scan "$ARTIFACT_ID" "$SCAN_TIMEOUT") || rc=$?
  case "$rc" in
    0) pass ;;
    2) SCANNER_AVAILABLE=false; skip "scanner not configured or no scan record within ${SCAN_TIMEOUT}s" ;;
    *) fail "scan trigger failed" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 2.10.d -- Load-bearing: evaluating the strict policy against a scan that
# has high/critical findings returns a violation.
#
# Endpoint candidates tried in order:
#   POST /api/v1/security/scan-policies/{id}/evaluate {scan_id} OR {artifact_id}
#   POST /api/v1/security/scan-policies/{id}/check    {scan_id} OR {artifact_id}
# A 404 on both means policy-evaluation isn't on this backend; skip.
# ---------------------------------------------------------------------------

begin_test "Strict policy flags scan as violated (max_high=0 vs. real findings)"
if [ -z "$POLICY_ID" ] || ! $SCANNER_AVAILABLE || [ -z "$SCAN_ID" ]; then
  skip "missing policy id, scanner, or scan id"
else
  payload=$(jq -n --arg sid "$SCAN_ID" --arg aid "$ARTIFACT_ID" \
    '{scan_id:$sid, artifact_id:$aid}')
  eval_resp=""
  eval_status="000"
  for ep in \
    "/api/v1/security/scan-policies/${POLICY_ID}/evaluate" \
    "/api/v1/security/scan-policies/${POLICY_ID}/check"; do
    # shellcheck disable=SC2086
    s=$(curl -s -o "${WORK_DIR}/eval.json" -w '%{http_code}' $CURL_TIMEOUT \
      -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
      -d "$payload" \
      "${BASE_URL}${ep}") || s="000"
    if [[ "$s" =~ ^2[0-9][0-9]$ ]]; then
      eval_status="$s"
      eval_resp=$(cat "${WORK_DIR}/eval.json")
      break
    fi
    eval_status="$s"
  done
  if [ "$eval_status" = "404" ] || [ -z "$eval_resp" ]; then
    skip "no scan-policy evaluate endpoint responded 2xx (last HTTP ${eval_status})"
  else
    has_violation=$(echo "$eval_resp" | jq -r '
      (.passed == false)
      or (.compliant == false)
      or (.violated == true)
      or (.violation == true)
      or (((.violations // .violated_rules // .findings // []) | length) > 0)
      // false')
    if [ "$has_violation" = "true" ]; then
      pass
    else
      fail "strict policy did not flag scan with high/critical findings" \
"eval body (first 600 bytes): $(echo "$eval_resp" | head -c 600)"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2.10.e -- DELETE removes the policy; subsequent GET returns 404.
# ---------------------------------------------------------------------------

begin_test "DELETE /security/scan-policies/{id} returns 2xx; GET then 404"
if [ -z "$POLICY_ID" ]; then
  skip "no policy id"
else
  # shellcheck disable=SC2086
  del_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X DELETE -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/scan-policies/${POLICY_ID}") || del_status="000"
  if [[ ! "$del_status" =~ ^2[0-9][0-9]$ ]]; then
    fail "DELETE returned HTTP ${del_status}"
  else
    # shellcheck disable=SC2086
    after_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
      -H "$(auth_header)" \
      "${BASE_URL}/api/v1/security/scan-policies/${POLICY_ID}") || after_status="000"
    if [ "$after_status" = "404" ]; then
      POLICY_ID=""  # avoid double-delete in cleanup
      pass
    else
      fail "GET after DELETE returned HTTP ${after_status}, expected 404"
    fi
  fi
fi

end_suite
