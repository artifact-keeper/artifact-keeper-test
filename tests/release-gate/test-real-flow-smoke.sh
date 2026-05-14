#!/usr/bin/env bash
# test-real-flow-smoke.sh - Real artifact push, pull, and scan end-to-end.
#
# This is the user's actual flow as a single gate check: helm install,
# push an artifact through a native client, pull it back, trigger a
# scan, poll until completion. Regressions in any step fail the release
# gate before the broader matrix even runs.
#
# Why npm rather than maven (the issue's example): the runner pods ship
# node + npm out of the box (system-packages batch in format-tests
# already exercises that). Maven would add ~120s of apt-get install and
# an HTTPS dance against a private maven settings.xml on every run.
# We picked npm so the gate stays under the 5-minute target in #45.
#
# Steps:
#   1. Confirm backend is reachable (wait-for-ready.sh)
#   2. Create a local npm repository via the management API
#   3. Publish a tarball through `npm publish` (real client wire format)
#   4. Pull the tarball through `npm pack <name>@<version>`
#   5. Look up the artifact's UUID via GET /api/v1/repositories/{key}/artifacts
#   6. POST /api/v1/security/scan with {artifact_id, force:true}
#   7. Poll GET /api/v1/security/artifacts/{id}/scans until terminal status (completed/failed) or 60s timeout
#   8. Assert scan status is `completed` and findings_count is numeric
#
# Backend route sources of truth (verified against
# artifact-keeper/backend/src/api/handlers/security.rs at this branch):
#   - trigger_scan       POST /api/v1/security/scan         (line ~474)
#   - list_artifact_scans GET /api/v1/security/artifacts/{artifact_id}/scans  (line ~920)
#   - list_artifacts     GET /api/v1/repositories/{key}/artifacts  (handlers/repositories.rs ~1172)
# artifact_id is a Uuid, not an integer.
#
# Exit codes:
#   0 - All steps passed
#   non-zero - Any step failed; end_suite emits the final outcome
#
# Required env:
#   BASE_URL   - Backend service URL (set by the workflow's needs.deploy.outputs)
#   ADMIN_PASS - Bootstrap admin password (defaults to common.sh value)
#   RUN_ID     - Unique run identifier so the repo key doesn't collide

# shellcheck source=../lib/common.sh disable=SC1091
source "$(dirname "$0")/../lib/common.sh"

begin_suite "real-flow-smoke"
auth_admin
setup_workdir
require_cmd npm
require_cmd jq

REPO_KEY="rfs-${RUN_ID}"
PKG_NAME="rfs-pkg-${RUN_ID//[^a-z0-9]/}"
# npm package names must be lower-case; trim again in case RUN_ID has caps.
PKG_NAME=$(echo "$PKG_NAME" | tr '[:upper:]' '[:lower:]')
PKG_VERSION="1.0.$(date +%s)"
NPM_REGISTRY="${BASE_URL}/npm/${REPO_KEY}/"

# -------------------------------------------------------------------------
# 1. Backend reachability gate
#
# auth_admin already exercised /readyz (or /health), but we re-check
# /health here so a flaky backend at the moment of suite-start surfaces
# as a clear "backend unreachable" message rather than a downstream
# 500 on the first management-API call.
# -------------------------------------------------------------------------

begin_test "Backend health probe"
health_status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${BASE_URL}/health" 2>/dev/null || echo "000")
if [ "$health_status" = "200" ]; then
  pass
else
  fail "GET ${BASE_URL}/health returned HTTP ${health_status}"
fi

# -------------------------------------------------------------------------
# 2. Create the target repository
# -------------------------------------------------------------------------

begin_test "Create npm local repository"
if create_local_repo "$REPO_KEY" "npm"; then
  pass
else
  fail "could not create npm repository ${REPO_KEY}"
fi

# -------------------------------------------------------------------------
# 3. Build the package and configure npm with both auth modes
#
# Same dual-auth shape used by test-npm.sh: some npm client versions
# emit _auth (basic), others emit _authToken (bearer). The backend
# accepts both. Writing both keeps this test stable across runner
# image upgrades.
# -------------------------------------------------------------------------

begin_test "Publish package with npm"
cd "$WORK_DIR" || fail "cd to WORK_DIR failed"
mkdir -p pkg-src
cd pkg-src || fail "cd to pkg-src failed"

cat > package.json <<EOF
{
  "name": "${PKG_NAME}",
  "version": "${PKG_VERSION}",
  "description": "Release-gate real-flow smoke package",
  "main": "index.js",
  "license": "MIT"
}
EOF

cat > index.js <<EOF
module.exports = { version: "${PKG_VERSION}" };
EOF

AUTH_B64=$(printf '%s:%s' "${ADMIN_USER}" "${ADMIN_PASS}" | base64)
REGISTRY_HOST=$(echo "$NPM_REGISTRY" | sed -E 's|https?:||')
REGISTRY_HOST_NOSLASH="${REGISTRY_HOST%/}"

cat > .npmrc <<EOF
registry=${NPM_REGISTRY}
${REGISTRY_HOST_NOSLASH}/:_auth=${AUTH_B64}
${REGISTRY_HOST_NOSLASH}/:_authToken=${AUTH_B64}
${REGISTRY_HOST}:_auth=${AUTH_B64}
${REGISTRY_HOST}:_authToken=${AUTH_B64}
always-auth=true
EOF

publish_log="${WORK_DIR}/npm-publish.log"
if npm publish --registry "$NPM_REGISTRY" > "$publish_log" 2>&1; then
  pass
else
  fail "npm publish failed; tail: $(tail -n 10 "$publish_log" | tr '\n' ' ')"
fi

# -------------------------------------------------------------------------
# 4. Pull the artifact back
#
# `npm pack` against the same registry downloads the tarball without
# evaluating package scripts, so it's the safest equivalent of a real
# `npm install` for byte-level round-trip assertions.
# -------------------------------------------------------------------------

begin_test "Pull package with npm pack"
PULL_DIR="${WORK_DIR}/pull"
mkdir -p "$PULL_DIR"
cd "$PULL_DIR" || fail "cd to PULL_DIR failed"
# Reuse the same .npmrc so auth flows through.
cp "${WORK_DIR}/pkg-src/.npmrc" .

pack_log="${WORK_DIR}/npm-pack.log"
if npm pack "${PKG_NAME}@${PKG_VERSION}" \
    --registry "$NPM_REGISTRY" > "$pack_log" 2>&1; then
  PULLED_TARBALL=$(find . -maxdepth 1 -name "${PKG_NAME}-*.tgz" -print -quit)
  if [ -n "$PULLED_TARBALL" ] && [ -s "$PULLED_TARBALL" ]; then
    pass
  else
    fail "npm pack reported success but no tarball was written (log: $(tail -n 5 "$pack_log" | tr '\n' ' '))"
  fi
else
  fail "npm pack failed; tail: $(tail -n 10 "$pack_log" | tr '\n' ' ')"
fi

# -------------------------------------------------------------------------
# 5. Resolve the artifact's UUID
#
# The scan trigger endpoint keys against artifact_id (a Uuid),
# not the repo-key + path tuple. We look it up via the repo's
# artifact listing endpoint. The path npm published lives under
# `<name>/-/<name>-<version>.tgz` for scoped-package layout.
# -------------------------------------------------------------------------

begin_test "Resolve artifact UUID via repository listing"
ARTIFACT_PATH="${PKG_NAME}/-/${PKG_NAME}-${PKG_VERSION}.tgz"
ARTIFACT_ID=""
# Poll briefly: npm publish returns when the index update commits,
# but the artifact row may take a beat to appear in the listing.
for _ in 1 2 3 4 5; do
  list_resp=$(curl -s --max-time 15 -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts?per_page=100" \
    2>/dev/null || echo "{}")
  ARTIFACT_ID=$(echo "$list_resp" | jq -r --arg p "$ARTIFACT_PATH" \
    '.items[]? | select(.path == $p) | .id' 2>/dev/null | head -n1)
  if [ -n "$ARTIFACT_ID" ] && [ "$ARTIFACT_ID" != "null" ]; then
    break
  fi
  sleep 2
done

if [ -z "$ARTIFACT_ID" ] || [ "$ARTIFACT_ID" = "null" ]; then
  fail "could not resolve artifact UUID for path ${ARTIFACT_PATH}; resp: $(echo "$list_resp" | head -c 300)"
else
  echo "  artifact_id: ${ARTIFACT_ID}"
  pass
fi

# -------------------------------------------------------------------------
# 6. Trigger a scan
#
# POST /api/v1/security/scan with {artifact_id, force:true}.
# Verified against backend handler `trigger_scan` in
# backend/src/api/handlers/security.rs line ~474.
#
# The handler returns 200 with `{message, artifacts_queued}` and
# spawns the scan in a background task. There is no 202: the queue-
# vs-finish split is handled by polling the scans endpoint below.
# -------------------------------------------------------------------------

begin_test "Trigger scan via POST /api/v1/security/scan"
trigger_body=$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id, force: true}')
trigger_status=$(curl -s -o /tmp/rfs-trigger-resp.json -w '%{http_code}' --max-time 15 \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$trigger_body" \
  "${BASE_URL}/api/v1/security/scan" \
  2>/dev/null || echo "000")

if [ "$trigger_status" = "200" ]; then
  pass
else
  trigger_resp=$(head -c 300 /tmp/rfs-trigger-resp.json 2>/dev/null || echo "")
  fail "POST /api/v1/security/scan returned HTTP ${trigger_status}; body: ${trigger_resp}"
fi

# -------------------------------------------------------------------------
# 7. Poll scan status until completion or timeout
#
# GET /api/v1/security/artifacts/{artifact_id}/scans returns a
# ScanListResponse {items, total}. The most recent scan is the
# first item (the service sorts by created_at desc). Terminal
# statuses are `completed` and `failed`. `pending` and `scanning`
# are in-flight.
# -------------------------------------------------------------------------

begin_test "Scan reaches a terminal state within 60s"
final_status=""
elapsed=0
LATEST_SCAN_JSON=""
while [ "$elapsed" -lt 60 ]; do
  scans_resp=$(curl -s --max-time 15 -H "$(auth_header)" \
    "${BASE_URL}/api/v1/security/artifacts/${ARTIFACT_ID}/scans?per_page=5" \
    2>/dev/null || echo "{}")
  # Pick the most recent scan (the handler returns items in
  # descending created_at order; tolerate either field name in case
  # the backend re-orders later).
  LATEST_SCAN_JSON=$(echo "$scans_resp" | jq -c '.items[0] // empty' 2>/dev/null || echo "")
  if [ -n "$LATEST_SCAN_JSON" ]; then
    final_status=$(echo "$LATEST_SCAN_JSON" | jq -r '.status // "unknown"')
    if [ "$final_status" = "completed" ] || [ "$final_status" = "failed" ]; then
      break
    fi
  fi
  sleep 3
  elapsed=$(( elapsed + 3 ))
done

echo "  scan terminal status: ${final_status:-unknown}"
if [ "$final_status" = "completed" ]; then
  pass
elif [ "$final_status" = "failed" ]; then
  err_msg=$(echo "$LATEST_SCAN_JSON" | jq -r '.error_message // "(none)"')
  fail "scan ended with status='failed', error_message: ${err_msg}"
else
  fail "scan did not reach a terminal state within 60s (last status: ${final_status:-unknown})"
fi

# -------------------------------------------------------------------------
# 8. findings_count is a number (any value)
#
# The acceptance criteria in #45 is "findings_count is a number (any
# value)", not "non-zero". The npm tarball we built is a trivial
# package with no vulnerable deps; expecting findings would flap.
# Backend ScanResponse always emits findings_count (i32) per
# security.rs:125, so the field MUST be a number on a healthy backend.
# -------------------------------------------------------------------------

begin_test "Scan response includes a numeric findings_count"
findings_count=$(echo "$LATEST_SCAN_JSON" | jq -r '.findings_count // "null"' 2>/dev/null || echo "null")

if [ "$findings_count" = "null" ] || [ -z "$findings_count" ]; then
  fail "scan response has no findings_count field; resp: $(echo "$LATEST_SCAN_JSON" | head -c 300)"
elif [[ "$findings_count" =~ ^[0-9]+$ ]]; then
  echo "  findings_count: ${findings_count}"
  pass
else
  fail "findings_count is not numeric: '${findings_count}'"
fi

end_suite
