#!/usr/bin/env bash
# test-path-traversal-encodings.sh - encoded traversal payloads never return
# host filesystem content
#
# Ported from tests/security/redteam/test-08-path-traversal.sh, which could
# not fail: it sourced tests/security/redteam/lib.sh (fail() only incremented
# an unread counter) and ended in `exit 0`. See
# tests/security/README-redteam-port.md.
#
# Relationship to tests/security/test-path-traversal.sh
# -----------------------------------------------------
# The sibling asserts on STATUS CODES for five payloads against a repository
# it creates. This file is the other half and is deliberately kept separate:
#
#   - It carries the CONTENT oracle. The sibling documents (correctly) that a
#     2xx can be benign, because Axum normalises the path and the storage
#     layer keeps only Normal components, so a "traversal" upload lands
#     harmlessly inside the repository. That reasoning makes a status-code
#     assertion unable to distinguish benign normalisation from a real escape.
#     Reading the BYTES can: /etc/passwd content in a 200 is unambiguous.
#
#   - It carries the encoding matrix the sibling does not exercise: double URL
#     encoding, overlong UTF-8 (%c0%af), and fullwidth solidus (%ef%bc%8f).
#     Those are the variants that survive one decode pass and reach a second.
#
# Every probe runs against a repository this suite creates and populates, and
# the suite proves the download route is live by fetching its own artifact
# first. The original ran against hardcoded keys (`test-pypi`, `test-npm`)
# that this repo never creates, so every request 404'd and the content oracle
# had nothing to read.
#
# Known-open defect NOT asserted here
# -----------------------------------
# A NUL byte in the artifact path (`a%00b`) reaches Postgres and returns
# HTTP 500 DATABASE_ERROR ("invalid byte sequence for encoding UTF8: 0x00")
# instead of being rejected at the path boundary, for authenticated AND
# anonymous callers. Reproduced on 1.6.2, 1.8.1 and dev, so it is long-
# standing rather than a regression. The vector is kept in the matrix below
# and its SECURITY property (no file content returned) is asserted, but the
# status code is deliberately not, because turning a blocking gate red on a
# known-open defect trains operators to override the gate.
#
# Tracked in artifact-keeper#3545 (test-side: artifact-keeper-test#388). The
# status assertion should land in the same change as the backend fix. Note
# that tests/security/test-path-traversal.sh:130 already sends this input and
# records the 500 as a pass via its final `else pass` branch.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "path-traversal-encodings"
auth_admin
setup_workdir

REPO_KEY="sec-traversal-enc-${RUN_ID}"
ARTIFACT_PATH="probe/1.0.0/probe.txt"
ARTIFACT_BODY="traversal-probe-${RUN_ID}"

cleanup_repo() {
  curl -s -o /dev/null "${CURL_TIMEOUT_ARGS[@]}" -X DELETE \
    -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repo"

# ---------------------------------------------------------------------------
# Fixture + positive control
# ---------------------------------------------------------------------------

begin_test "Create and populate a generic repository"
if ! create_local_repo "$REPO_KEY" "generic"; then
  fail_fatal "could not create repository ${REPO_KEY}" \
    "Without a live repository every probe below 404s at the router and the content oracle reads nothing, which is how the original version of this script passed for five months."
fi
printf '%s' "$ARTIFACT_BODY" > "${WORK_DIR}/probe.txt"
up_status=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -X PUT -H "$(auth_header)" -H "Content-Type: application/octet-stream" \
  --data-binary "@${WORK_DIR}/probe.txt" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" 2>/dev/null) || up_status="000"
if [ "$up_status" -ge 200 ] 2>/dev/null && [ "$up_status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail_fatal "could not upload the probe artifact (HTTP ${up_status})"
fi

begin_test "Download route serves the repository's own artifact (positive control)"
dl_status=$(curl -s -o "${WORK_DIR}/legit.out" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/repositories/${REPO_KEY}/download/${ARTIFACT_PATH}" 2>/dev/null) || dl_status="000"
if [ "$dl_status" = "200" ] && grep -q "$ARTIFACT_BODY" "${WORK_DIR}/legit.out" 2>/dev/null; then
  pass
else
  fail_fatal "the download route did not serve the probe artifact (HTTP ${dl_status})" \
    "Every traversal probe below targets this route. If it does not serve bytes for a path that definitely exists, 'no file content returned' says nothing about traversal. Body: $(head -c 200 "${WORK_DIR}/legit.out" 2>/dev/null)"
fi

# ---------------------------------------------------------------------------
# Traversal matrix
# ---------------------------------------------------------------------------

# Signatures of files an escape would land on: /etc/passwd, the backend's own
# Cargo manifest / sources, and /proc/self/environ.
HOST_FILE_SIGNATURES='root:[^:]*:0:0:|daemon:[^:]*:/usr/sbin|nobody:[^:]*:/nonexistent|^\[package\]|^\[dependencies\]|DATABASE_URL=|JWT_SECRET=|POSTGRES_PASSWORD='

PAYLOADS=(
  "raw-dot-dot|../../../../etc/passwd"
  "url-encoded-slash|..%2f..%2f..%2f..%2fetc%2fpasswd"
  "url-encoded-dots-and-slash|%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
  "double-url-encoded|..%252f..%252f..%252f..%252fetc%252fpasswd"
  "double-url-encoded-dots|%252e%252e%252f%252e%252e%252fetc%252fpasswd"
  "overlong-utf8-solidus|..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
  "fullwidth-solidus|..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd"
  "dot-truncation|....//....//....//....//etc/passwd"
  "proc-self-environ|../../../../proc/self/environ"
  "nul-byte-truncation|probe.txt%00../../../../etc/passwd"
)

ROUTES=(
  "management-download|/api/v1/repositories/${REPO_KEY}/download/"
  "management-artifacts|/api/v1/repositories/${REPO_KEY}/artifacts/"
  "format-native|/generic/${REPO_KEY}/"
)

for route_def in "${ROUTES[@]}"; do
  route_label="${route_def%%|*}"
  route_prefix="${route_def#*|}"

  for payload_def in "${PAYLOADS[@]}"; do
    payload_label="${payload_def%%|*}"
    payload="${payload_def#*|}"

    begin_test "${route_label}: ${payload_label} does not return host file content"
    status=$(curl -s --path-as-is -o "${WORK_DIR}/probe.out" -w '%{http_code}' \
      "${CURL_TIMEOUT_ARGS[@]}" -H "$(auth_header)" \
      "${BASE_URL}${route_prefix}${payload}" 2>/dev/null) || status="000"

    if [ "$status" = "000" ]; then
      fail "${route_label}/${payload_label}: request did not complete (curl status 000); nothing was certified"
      continue
    fi

    if grep -qE "$HOST_FILE_SIGNATURES" "${WORK_DIR}/probe.out" 2>/dev/null; then
      fail "PATH TRAVERSAL: ${route_prefix}${payload} returned host filesystem content (HTTP ${status})" \
        "The response matched a signature of /etc/passwd, the backend's Cargo manifest, or /proc/self/environ. Response (truncated): $(head -c 500 "${WORK_DIR}/probe.out" 2>/dev/null)"
      continue
    fi

    # A 2xx is acceptable only if it is not serving foreign bytes: Axum
    # normalises the path and the storage layer keeps Normal components only,
    # so a traversal can legitimately resolve to a harmless in-repository
    # path. What must never happen is a 2xx carrying content this repository
    # does not hold.
    if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
      if grep -q "$ARTIFACT_BODY" "${WORK_DIR}/probe.out" 2>/dev/null; then
        # Resolved back to our own artifact: normalised, not escaped.
        pass
      elif [ -s "${WORK_DIR}/probe.out" ] && ! jq -e . "${WORK_DIR}/probe.out" >/dev/null 2>&1; then
        fail "${route_label}/${payload_label}: HTTP ${status} returned non-JSON bytes this repository does not hold" \
          "$(wc -c < "${WORK_DIR}/probe.out" | tr -d '[:space:]') bytes of unrecognised content. Truncated: $(head -c 500 "${WORK_DIR}/probe.out" 2>/dev/null)"
      else
        pass
      fi
      continue
    fi

    pass
  done
done

end_suite
