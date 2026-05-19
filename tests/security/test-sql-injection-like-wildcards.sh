#!/usr/bin/env bash
# test-sql-injection-like-wildcards.sh - Regression for artifact-keeper#1004
#
# Bug summary
# -----------
# User-supplied path components (filenames, package names) from URL
# segments were interpolated into SQL LIKE patterns without escaping
# the wildcard characters `%` (multi-char wildcard) and `_` (single-
# char wildcard). An attacker who could read one artifact under a
# repo could read any other artifact under the same repo by crafting
# a URL whose path includes `%` or `_` -- the LIKE match would
# resolve their crafted path against the wrong row in the artifacts
# table.
#
# 15 call sites were fixed in artifact-keeper#1004 (merged
# 2026-05-04, commit 23d9743) across pypi, proxy_helpers, ansible,
# cran, hex, puppet, alpine, huggingface, debian, terraform, helm,
# rpm, rubygems, npm. Three helpers added: escape_filename_for_like,
# escape_like_literal, escape_path_prefix. Each call site got
# `ESCAPE '\'` appended to the SQL LIKE clause.
#
# Same threat class as #881 (maven), #984 (rubygems/rpm/helm/npm,
# never merged so #1004 absorbed it), #998 (pypi/proxy_helpers on
# release/1.1.x).
#
# What this test pins
# -------------------
# Plant an artifact with a fixed name. Query with each LIKE wildcard
# in turn. Pre-fix: the wildcard query returns the planted artifact
# (info disclosure). Post-fix: the wildcard query returns 404 (or
# at worst returns NON-MATCHING content -- never the planted bytes
# when the literal name does not match).
#
# We target the generic-format path because it routes through the
# same proxy_helpers.rs lookup family that #1004 hardened, AND
# because the upload protocol is a single PUT with a body (no
# format-specific signing / multipart). If a future #1004 follow-up
# moves generic onto a different lookup path that doesn't hit the
# LIKE clause, this test becomes a sanity check rather than a
# regression-guard; that is a strict improvement over no test at
# all and we can extend to format-specific suites in a later PR.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "sql-injection-like-wildcards"
auth_admin
setup_workdir

REPO_KEY="sec-likeinj-${RUN_ID}"
PLANT_NAME="pkg-target-${RUN_ID}.bin"
PLANT_BODY="planted-${RUN_ID}-do-not-leak-via-wildcard-query"
DECOY_NAME="pkg-decoy-${RUN_ID}.bin"
DECOY_BODY="decoy-${RUN_ID}"

# Encoded query forms. URL-decoder in the server converts %25 -> %
# before the value reaches the SQL LIKE clause; `_` is a valid URL
# character and passes through literally. We send each form with
# `--path-as-is` so curl does not normalize.
#
# Each entry: <encoded_path>|<description>
#
# We deliberately include forms that, pre-fix, would have matched
# the planted name via LIKE wildcard semantics:
#   pkg-target-${RUN_ID}.bin
#   ----^-----------
#   pkg-_arget-${RUN_ID}.bin  (the `_` matches the literal `t`)
#   pkg-%25.bin                (the `%` matches `target-${RUN_ID}`)
#   _kg-target-${RUN_ID}.bin  (leading `_` matches `p`)
#   %25kg-target-${RUN_ID}.bin (leading `%` matches `p`)
WILDCARD_PROBES=(
  "pkg-_arget-${RUN_ID}.bin|underscore in middle"
  "pkg-%25.bin|percent in middle"
  "_kg-target-${RUN_ID}.bin|underscore at start"
  "%25kg-target-${RUN_ID}.bin|percent at start"
  "pkg-target-${RUN_ID}.%25|percent at end (extension)"
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create generic local repo"
if create_local_repo "$REPO_KEY" "generic"; then
  pass
else
  fail "could not create generic repo (${REPO_KEY})"
fi

begin_test "Upload planted artifact"
printf '%s' "$PLANT_BODY" > "${WORK_DIR}/${PLANT_NAME}"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/${PLANT_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${PLANT_NAME}") || status=000
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "upload of planted artifact returned ${status}; cannot exercise the LIKE-wildcard surface"
fi

begin_test "Upload decoy artifact (control)"
printf '%s' "$DECOY_BODY" > "${WORK_DIR}/${DECOY_NAME}"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X PUT \
  -H "$(auth_header)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/${DECOY_NAME}" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${DECOY_NAME}") || status=000
if [ "$status" = "200" ] || [ "$status" = "201" ]; then
  pass
else
  fail "upload of decoy artifact returned ${status}"
fi

# ---------------------------------------------------------------------------
# Sanity: exact-match GET returns the planted bytes
# ---------------------------------------------------------------------------

begin_test "Sanity: exact-match GET returns planted artifact"
body_file=$(mktemp -t plant-fetch.XXXXXXXX)
status=$(curl -s -o "$body_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${PLANT_NAME}") || status=000
fetched=$(cat "$body_file" 2>/dev/null || echo "")
rm -f "$body_file"
if [ "$status" = "200" ] && [ "$fetched" = "$PLANT_BODY" ]; then
  pass
else
  fail "exact-match GET returned status=${status} body=$(head -c 80 <<< "$fetched"); cannot proceed -- the planted artifact is not reachable so wildcard assertions are meaningless"
fi

# ---------------------------------------------------------------------------
# The actual regression-guard: each wildcard probe MUST NOT return
# the planted bytes. 404 is the expected post-fix outcome; 200 with
# any other content (e.g. the decoy) is acceptable; 200 with the
# PLANTED body is the bug.
# ---------------------------------------------------------------------------

for probe_spec in "${WILDCARD_PROBES[@]}"; do
  IFS='|' read -r encoded_path desc <<< "$probe_spec"
  begin_test "Wildcard probe (${desc}): must NOT return planted bytes"

  body_file=$(mktemp -t wild-fetch.XXXXXXXX)
  status=$(curl -s -o "$body_file" -w '%{http_code}' $CURL_TIMEOUT --path-as-is \
    -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${encoded_path}") || status=000
  fetched=$(cat "$body_file" 2>/dev/null || echo "")
  rm -f "$body_file"

  if [ "$status" = "200" ] && [ "$fetched" = "$PLANT_BODY" ]; then
    fail "wildcard probe (${desc}) returned 200 with PLANTED BODY -- LIKE-wildcard escape regressed (#1004); attacker could enumerate other artifacts via URL crafting"
  elif [ "$status" = "200" ]; then
    # Returned 200 with some other content. Most likely the path
    # didn't reach the LIKE clause and the request was routed
    # elsewhere (e.g. a different artifact happened to match
    # exactly because of URL canonicalization). Not the regression.
    pass
  else
    # 4xx / 5xx -- the planted bytes were definitely not served.
    pass
  fi
done

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/${PLANT_NAME}" >/dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}/artifacts/${DECOY_NAME}" >/dev/null 2>&1 || true
api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true

end_suite
