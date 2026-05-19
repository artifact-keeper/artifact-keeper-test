#!/usr/bin/env bash
# test-sql-injection-like-wildcards-helm.sh
#
# Closes artifact-keeper-test#181 (which itself was a follow-up filed
# from PR #180's judge review after the original generic-format
# version of this test was identified as a fantasy-pass: the generic
# route uses exact-equality SQL `WHERE repository_id = $1 AND path = $2`
# and never reaches a LIKE clause).
#
# Bug guarded against
# -------------------
# artifact-keeper#1004 (commit 18b1fa87, merged 2026-05-04) extended
# the LIKE-wildcard escape to 15 call sites across pypi, ansible, cran,
# hex, puppet, alpine, huggingface, debian, terraform, helm, rpm,
# rubygems, npm, and proxy_helpers. Before that fix, the helm chart
# download path (helm.rs::download_chart) interpolated the URL filename
# segment into a SQL LIKE pattern WITHOUT escaping `%` or `_`. An
# attacker who could read one chart under a repo could read any other
# chart under the same repo by crafting a URL whose filename includes
# `%` or `_`:
#
#   GET /helm/{repo}/charts/pkg-target-1.0.0.tgz         # the real artifact
#   GET /helm/{repo}/charts/pkg-_arget-1.0.0.tgz         # `_` = wildcard
#   GET /helm/{repo}/charts/pkg-%25.tgz                  # `%` = wildcard
#
# Pre-fix all three queries return the same bytes via LIKE wildcard
# matching. Post-fix only the exact-name query returns 200; the
# wildcard probes 404.
#
# Why helm
# --------
# Of the 15 fixed call sites, helm has the simplest upload protocol
# (ChartMuseum-compatible POST multipart on /helm/{repo}/api/charts)
# and a download URL pattern (/helm/{repo}/charts/{filename}.tgz)
# whose filename segment is the value that flows directly into the
# LIKE clause inside `download_chart`. That keeps the test free of
# format-specific signing / multi-part assembly noise and pins the
# exact pre-fix bug class.
#
# What we pin
# -----------
# The negative control here is the load-bearing assertion: the
# wildcard query MUST NOT return the bytes of the planted chart.
# 404, 400, or 200-with-other-content are all acceptable post-fix
# outcomes; 200-with-planted-bytes is the regression.
#
# Requires: curl, helm (v3+), jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "sql-injection-like-wildcards-helm"
require_cmd helm
auth_admin
setup_workdir

REPO_KEY="sec-likeinj-helm-${RUN_ID}"
PLANT_NAME="pkg-target-${RUN_ID}"
DECOY_NAME="pkg-decoy-${RUN_ID}"
PLANT_VERSION="1.0.0"
DECOY_VERSION="1.0.0"
PLANT_BODY_SIGIL="planted-${RUN_ID}-do-not-leak-via-wildcard-query"
DECOY_BODY_SIGIL="decoy-${RUN_ID}"

# Wildcard probes. Each entry: <encoded_filename>|<description>.
# Both `%` (multi-char) and `_` (single-char) are LIKE wildcards in
# Postgres. `%25` is the URL-encoded form of `%`; `_` passes through
# unencoded. We send each probe with `--path-as-is` so curl does not
# normalise the URL before transmission.
#
# Each probe is constructed so that, pre-fix, the SQL LIKE pattern
# matches the planted chart filename. Post-fix the ESCAPE '\' clause
# makes the wildcard literal and the query returns 404.
WILDCARD_PROBES=(
  "pkg-_arget-${RUN_ID}-${PLANT_VERSION}.tgz|underscore mid-name"
  "pkg-target-${RUN_ID}-%25.tgz|percent on version suffix"
  "_kg-target-${RUN_ID}-${PLANT_VERSION}.tgz|underscore at start"
  "%25kg-target-${RUN_ID}-${PLANT_VERSION}.tgz|percent at start"
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

begin_test "Create helm local repo"
if create_local_repo "$REPO_KEY" "helm"; then
  # Register server-side cleanup via add_exit_handler so the repo is
  # removed even if the script aborts mid-way (set -e tripping on
  # `helm package` failure, an unexpected `curl` exit, etc.). Linear
  # cleanup at end-of-file would leak the repo on the backend in
  # those cases.
  add_exit_handler "api_delete /api/v1/repositories/${REPO_KEY} >/dev/null 2>&1 || true"
  pass
else
  fail "could not create helm repo (${REPO_KEY})"
fi

# Build two minimal but distinct charts so wildcard matching has
# something to potentially-incorrectly resolve to.
#
# Returns 0 on success, 1 on failure. We avoid letting `set -e` rip
# the script down on `helm package` failure because the test framework
# wants a structured `fail` row in the JUnit output, not a bare exit.
build_chart() {
  local chart_name="$1"
  local version="$2"
  local sigil="$3"
  local chart_dir="${WORK_DIR}/${chart_name}"
  mkdir -p "${chart_dir}/templates"
  cat >"${chart_dir}/Chart.yaml" <<EOF
apiVersion: v2
name: ${chart_name}
description: ${sigil}
type: application
version: ${version}
appVersion: "1.0.0"
EOF
  cat >"${chart_dir}/values.yaml" <<EOF
sigil: ${sigil}
EOF
  # A trivial template so helm package will accept the chart.
  cat >"${chart_dir}/templates/configmap.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Chart.Name }}-sigil
data:
  sigil: {{ .Chart.Description | quote }}
EOF
  if ! helm package "${chart_dir}" -d "${WORK_DIR}" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

upload_chart() {
  local chart_file="$1"
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(format_auth_header)" \
    -F "chart=@${chart_file}" \
    "${BASE_URL}/helm/${REPO_KEY}/api/charts") || status=000
  echo "$status"
}

begin_test "Package + upload planted chart"
PLANT_FILE="${WORK_DIR}/${PLANT_NAME}-${PLANT_VERSION}.tgz"
if ! build_chart "$PLANT_NAME" "$PLANT_VERSION" "$PLANT_BODY_SIGIL"; then
  fail "helm package failed for planted chart"
elif [ ! -f "$PLANT_FILE" ]; then
  fail "helm package did not produce ${PLANT_FILE}"
else
  upload_status=$(upload_chart "$PLANT_FILE")
  case "$upload_status" in
    200 | 201)
      pass
      ;;
    *)
      fail "upload of planted chart returned ${upload_status}; cannot exercise the LIKE-wildcard surface"
      ;;
  esac
fi

begin_test "Package + upload decoy chart"
DECOY_FILE="${WORK_DIR}/${DECOY_NAME}-${DECOY_VERSION}.tgz"
if ! build_chart "$DECOY_NAME" "$DECOY_VERSION" "$DECOY_BODY_SIGIL"; then
  fail "helm package failed for decoy chart"
elif [ ! -f "$DECOY_FILE" ]; then
  fail "helm package did not produce ${DECOY_FILE}"
else
  upload_status=$(upload_chart "$DECOY_FILE")
  case "$upload_status" in
    200 | 201)
      pass
      ;;
    *)
      fail "upload of decoy chart returned ${upload_status}"
      ;;
  esac
fi

# ---------------------------------------------------------------------------
# Sanity: exact-match GET returns the planted bytes.
# ---------------------------------------------------------------------------

PLANT_FILENAME="${PLANT_NAME}-${PLANT_VERSION}.tgz"
PLANT_URL="${BASE_URL}/helm/${REPO_KEY}/charts/${PLANT_FILENAME}"

begin_test "Sanity: exact-match GET returns planted chart"
fetched_file=$(mktemp -p "$WORK_DIR" plant-fetch.XXXXXXXX)
status=$(curl -s -o "$fetched_file" -w '%{http_code}' $CURL_TIMEOUT \
  -H "$(format_auth_header)" \
  "${PLANT_URL}") || status=000
# Compare against the on-disk planted .tgz; helm packages are
# deterministic given the same inputs, but the simplest check is
# "the bytes the server returned are exactly what we uploaded".
fetched_sha=$(sha256sum "$fetched_file" 2>/dev/null | awk '{print $1}')
planted_sha=$(sha256sum "$PLANT_FILE" 2>/dev/null | awk '{print $1}')
rm -f "$fetched_file"
if [ "$status" = "200" ] && [ -n "$fetched_sha" ] && [ "$fetched_sha" = "$planted_sha" ]; then
  pass
else
  fail "exact-match GET returned status=${status} sha=${fetched_sha:-<empty>} (expected planted_sha=${planted_sha}); cannot proceed -- the planted chart is not reachable so wildcard assertions are meaningless"
  skip_suite "exact-match unreachable; wildcard probes would all trivially 'pass'"
fi

# ---------------------------------------------------------------------------
# Negative control: a filename that should never match anything,
# pre-fix or post-fix. If this returns 200 the test environment has a
# substrate problem (e.g. catch-all wildcard route) and the wildcard
# assertions below are meaningless.
# ---------------------------------------------------------------------------

NEVER_NAME="never-was-here-${RUN_ID}-9.9.9.tgz"
begin_test "Negative control: non-existent filename returns 4xx"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT --path-as-is \
  -H "$(format_auth_header)" \
  "${BASE_URL}/helm/${REPO_KEY}/charts/${NEVER_NAME}") || status=000
case "$status" in
  4*)
    pass
    ;;
  *)
    fail "non-existent filename returned ${status}; environment has a catch-all matcher and the LIKE probes below would not exercise #1004"
    skip_suite "substrate broken; cannot pin #1004"
    ;;
esac

# ---------------------------------------------------------------------------
# The actual regression-guard: each wildcard probe MUST NOT return
# the planted bytes. Post-fix the LIKE ESCAPE '\' clause makes `%` and
# `_` in the URL filename literal, so 404 is the expected outcome.
# A different chart's bytes (e.g. the decoy) is also acceptable -- only
# the planted chart's bytes are the bug signature.
# ---------------------------------------------------------------------------

for probe_spec in "${WILDCARD_PROBES[@]}"; do
  IFS='|' read -r encoded_filename desc <<<"$probe_spec"
  begin_test "Wildcard probe (${desc}): must NOT return planted chart bytes"

  fetched_file=$(mktemp -p "$WORK_DIR" wild-fetch.XXXXXXXX)
  status=$(curl -s -o "$fetched_file" -w '%{http_code}' $CURL_TIMEOUT --path-as-is \
    -H "$(format_auth_header)" \
    "${BASE_URL}/helm/${REPO_KEY}/charts/${encoded_filename}") || status=000
  fetched_sha=$(sha256sum "$fetched_file" 2>/dev/null | awk '{print $1}')
  rm -f "$fetched_file"

  if [ "$status" = "200" ] && [ -n "$fetched_sha" ] && [ "$fetched_sha" = "$planted_sha" ]; then
    fail "wildcard probe (${desc}) returned 200 with PLANTED chart bytes -- LIKE-wildcard escape regressed (#1004); attacker could enumerate other charts via URL crafting"
  elif [ "$status" = "200" ]; then
    # 200 with some other content. Most likely the path resolved to
    # the decoy chart because the wildcard happened to match its
    # name pattern. Not the bug.
    pass
  else
    # 4xx / 5xx -- the planted bytes were definitely not served.
    pass
  fi
done

# ---------------------------------------------------------------------------
# Cleanup
#
# The server-side repo delete is registered via add_exit_handler at
# suite start so it runs even on mid-script abort. Nothing further to
# do here.
# ---------------------------------------------------------------------------

end_suite
