#!/usr/bin/env bash
# =============================================================================
# tiers/oci-conformance/oracle.sh — OCI distribution-spec conformance vs AK /v2
# =============================================================================
# run.sh has stood up `filesystem` and exported BASE_URL (http://127.0.0.1:PORT),
# DB_CONTAINER, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, JUNIT_OUTPUT_DIR,
# COMMON_SH, DTF_SLOT.
#
# We run the upstream OCI conformance suite (opencontainers/distribution-spec,
# conformance/) inside a golang container on --network host so it reaches AK at
# BASE_URL, then assert zero failures/errors across the enabled workflows and
# copy its junit.xml into the tier results.
#
# This is a conformance ADOPTION tier, not a fixed-vs-prefix discriminator: it
# proves AK implements the OCI registry protocol as specified. A regression that
# breaks any covered workflow turns the corresponding suite case red.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

require_cmd jq

GO_IMAGE="${OCI_CONFORMANCE_GO_IMAGE:-golang:1.23-bookworm}"
CONF_REF="${OCI_CONFORMANCE_REF:-v1.1.0}"        # pinned distribution-spec release
ENABLE_DELETE="${OCI_CONFORMANCE_DELETE:-0}"     # AK blob-delete gap: opt-in
SUF="${RUN_ID##*-}-$$"
NS1="ociconf/repo1-${DTF_SLOT:-x}-${SUF}"        # OCI_NAMESPACE
NS2="ociconf/repo2-${DTF_SLOT:-x}-${SUF}"        # OCI_CROSSMOUNT_NAMESPACE

begin_suite "oci-conformance"

# --- preflight: docker + network reachability + auth -------------------------
if ! command -v docker >/dev/null 2>&1; then
  begin_test "preflight: docker available"; skip "docker not on PATH; conformance suite cannot run"; end_suite
fi
auth_admin
setup_workdir

# AK auto-resolves /v2/<name> to a repo; create two hosted OCI repos so pushes
# land in real, isolated repositories (keys == the namespaces).
create_oci_repo() { # KEY
  api_post "/api/v1/repositories" \
    "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"docker\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null 2>&1 \
  || api_post "/api/v1/repositories" \
    "{\"key\":\"${1}\",\"name\":\"${1}\",\"format\":\"oci\",\"repo_type\":\"local\",\"is_public\":false}" >/dev/null 2>&1
}
if ! create_oci_repo "$NS1" || ! create_oci_repo "$NS2"; then
  begin_test "setup: create hosted OCI repos"; fail "could not create OCI repos ${NS1} / ${NS2}"; end_suite
fi

OUT="${WORK_DIR}/ociout"; mkdir -p "$OUT"; chmod 777 "$OUT" 2>/dev/null || true

# Workflow toggles: pull + push + content-discovery always; delete opt-in.
DELETE_ENV=""
[ "$ENABLE_DELETE" = "1" ] && DELETE_ENV="-e OCI_TEST_CONTENT_MANAGEMENT=1"

# The suite reads OCI_ROOT_URL + OCI_NAMESPACE and, with creds, performs the
# /v2/token dance itself. --network host lets 127.0.0.1:PORT resolve to AK.
run_suite() {
  docker run --rm --network host \
    -e OCI_ROOT_URL="${BASE_URL}" \
    -e OCI_NAMESPACE="${NS1}" \
    -e OCI_CROSSMOUNT_NAMESPACE="${NS2}" \
    -e OCI_USERNAME="${ADMIN_USER}" \
    -e OCI_PASSWORD="${ADMIN_PASS}" \
    -e OCI_TEST_PULL=1 -e OCI_TEST_PUSH=1 -e OCI_TEST_CONTENT_DISCOVERY=1 \
    ${DELETE_ENV} \
    -e OCI_HIDE_SKIPPED_WORKFLOWS=1 \
    -e OCI_DEBUG=1 \
    -e CONF_REF="${CONF_REF}" \
    -v "${OUT}:/out" \
    "${GO_IMAGE}" bash -c '
      set -e
      git clone --depth 1 --branch "${CONF_REF}" \
        https://github.com/opencontainers/distribution-spec /src >/dev/null 2>&1
      cd /src/conformance
      # Build the ginkgo suite into a test binary, then run it in /out so it
      # drops junit.xml + report.html there.
      go test -c -o /out/conformance.test . >/out/build.log 2>&1
      cd /out
      ./conformance.test >/out/run.log 2>&1 || true
    ' >/dev/null 2>&1
}

begin_test "run: OCI distribution-spec conformance (${CONF_REF}) against AK /v2"
if run_suite && [ -f "${OUT}/junit.xml" ]; then
  pass
else
  fail "conformance suite did not produce junit.xml (docker/internet/build issue)" \
       "build.log: $(tail -c 400 "${OUT}/build.log" 2>/dev/null); run.log: $(tail -c 400 "${OUT}/run.log" 2>/dev/null)"
  end_suite
fi

# Ship the raw suite report into the tier results for the dashboard.
cp "${OUT}/junit.xml" "${JUNIT_OUTPUT_DIR}/oci-conformance-suite.xml" 2>/dev/null || true

# Parse the ginkgo junit: <testsuites tests= failures= errors= ...>
attr() { grep -oE "$1=\"[0-9]+\"" "${OUT}/junit.xml" | head -1 | grep -oE '[0-9]+'; }
T_TESTS="$(attr tests)"; T_FAIL="$(attr failures)"; T_ERR="$(attr errors)"

begin_test "conformance: the suite executed at least one workflow test"
if [ -n "$T_TESTS" ] && [ "$T_TESTS" -gt 0 ] 2>/dev/null; then pass; else fail "junit reported tests='${T_TESTS}' (suite ran nothing; check env-var contract for ref ${CONF_REF})"; fi

begin_test "conformance: zero failures across PULL + PUSH + CONTENT_DISCOVERY (delete=${ENABLE_DELETE})"
if [ "${T_FAIL:-1}" = "0" ] && [ "${T_ERR:-1}" = "0" ]; then
  pass
else
  # Surface the failing case names so triage does not require re-running.
  FAILS="$(grep -oE '<testcase[^>]*name="[^"]*"' "${OUT}/junit.xml" 2>/dev/null | head -20 || true)"
  fail "OCI conformance: failures=${T_FAIL} errors=${T_ERR} of ${T_TESTS} tests" \
       "$(tail -c 800 "${OUT}/run.log" 2>/dev/null); cases: ${FAILS}"
fi

end_suite
