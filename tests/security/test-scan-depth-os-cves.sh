#!/usr/bin/env bash
# test-scan-depth-os-cves.sh -- Scanner depth, OS-level CVE class.
#
# Tracks issue #67 sub-task 2.5+2.16 (the scanner must walk OS-level
# package databases inside container layers, not just language
# manifests). This is a known coverage gap flagged in the multi-agent
# review of #67.
#
# Why this is separate from the dependency-CVEs test
# --------------------------------------------------
# OS package metadata (apt /var/lib/dpkg/status, rpm rpmdb) lives in
# a different code path inside Trivy than language manifests. A
# regression in OS-DB parsing (Trivy version bump, container-layer
# walker change) wouldn't surface in the dependency-CVE test even
# though the wire-format and policy gates are identical.
#
# Fixture
# -------
# A tarball containing a minimal `var/lib/dpkg/status` listing a
# known-vulnerable apt package. We deliberately pick the dpkg path
# (not the rpm equivalent) because:
#
#   1. The status file format is plain text; we can hand-write it
#      without needing dpkg-installed.
#   2. Trivy detects dpkg-format vulnerabilities via the same module
#      that parses real Debian/Ubuntu container layers, so a hit here
#      proves the OS-DB walker works end-to-end.
#
# We pin `bash 4.3-7ubuntu1.5` (CVE-2014-6271 Shellshock, CVSS 10.0)
# because it is one of the most universally-detected CVEs in any
# Trivy DB shipped in the last decade. False-negative risk is
# effectively zero on a working scanner.
#
# What this script does NOT cover
# -------------------------------
# - Real container-layer scanning (extracting from an OCI manifest
#   and walking each layer's filesystem). The current scan endpoint
#   takes a stored artifact_id; we'd need the OCI-image extraction
#   path to test that. Deferred to the OCI-scan epic.
# - rpm-format scanning. Same code-path family but a different
#   parser; if dpkg works, rpm "should" work but a real assertion
#   would need a rpmdb binary fixture. Deferred.
#
# Requires: curl, jq, tar

source "$(dirname "$0")/../lib/common.sh"

begin_suite "scan-depth-os-cves"
auth_admin
setup_workdir

REPO_KEY="sdoc-${RUN_ID}"
PACKAGE_NAME="os-fixture"
PACKAGE_VERSION="1.0.0"
TARBALL_NAME="${PACKAGE_NAME}-${PACKAGE_VERSION}.tar.gz"
ARTIFACT_PATH="${PACKAGE_NAME}/${PACKAGE_VERSION}/${TARBALL_NAME}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-180}"
ALLOW_SCANNER_SKIP="${ALLOW_SCANNER_SKIP:-0}"

scanner_unavailable() {
  local reason="$1"
  if [ "$ALLOW_SCANNER_SKIP" = "1" ]; then
    skip "scanner unavailable (${reason}); local-dev skip"
    end_suite
    exit 0
  fi
  fail "scanner unavailable (${reason}); release-gate must fail (#888 class)"
  end_suite
  exit 1
}

# ---------------------------------------------------------------------------
# Build a minimal "OS layer" fixture: a tar with var/lib/dpkg/status
# in dpkg format listing bash 4.3-7ubuntu1.5 (Shellshock, CVE-2014-6271).
#
# /etc/debian_version is included because Trivy's OS detector keys off
# distro identification (it won't try the dpkg parser on a tar that
# doesn't declare itself as Debian-family). Without this file, the
# scan would return 0 findings for entirely uninteresting reasons.
#
# We also include /etc/os-release because newer Trivy versions prefer
# it over /etc/debian_version for distro fingerprinting.
# ---------------------------------------------------------------------------

begin_test "Build OS-layer fixture (dpkg status with vulnerable bash)"
mkdir -p "${WORK_DIR}/layer/var/lib/dpkg"
mkdir -p "${WORK_DIR}/layer/etc"

cat > "${WORK_DIR}/layer/etc/debian_version" <<'EOF'
14.04
EOF

cat > "${WORK_DIR}/layer/etc/os-release" <<'EOF'
NAME="Ubuntu"
VERSION="14.04, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="14.04"
EOF

# Hand-rolled dpkg status entry. The Package/Version/Architecture
# trio is what Trivy fingerprints; everything else is filler to make
# the entry well-formed. We pin a SPECIFIC pre-Shellshock-patch bash
# version so the assertion is reproducible.
cat > "${WORK_DIR}/layer/var/lib/dpkg/status" <<'EOF'
Package: bash
Status: install ok installed
Priority: required
Section: shells
Installed-Size: 1396
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 4.3-7ubuntu1.5
Replaces: bash-completion (<= 20060301-0), bash-doc (<= 2.05-1)
Depends: base-files (>= 2.1.12), debianutils (>= 2.15)
Description: GNU Bourne Again SHell
 Bash is an sh-compatible command language interpreter that
 executes commands read from the standard input or from a file.

EOF

if tar -czf "${WORK_DIR}/${TARBALL_NAME}" -C "${WORK_DIR}/layer" . 2>/dev/null; then
  pass
else
  fail "could not build OS-layer fixture"
fi

# ---------------------------------------------------------------------------
# Upload + scan
# ---------------------------------------------------------------------------

begin_test "Create repo + upload"
if create_local_repo "$REPO_KEY" "generic"; then
  upload_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X PUT -H "$(auth_header)" \
    -H "Content-Type: application/gzip" \
    --data-binary "@${WORK_DIR}/${TARBALL_NAME}" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}") || upload_status="000"
  case "$upload_status" in
    200|201) pass ;;
    000)     scanner_unavailable "upload network failure" ;;
    *)       fail "upload returned ${upload_status}" ;;
  esac
else
  fail "could not create ${REPO_KEY}"
fi

begin_test "Resolve artifact_id"
artifact_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/api/v1/repositories/${REPO_KEY}/artifacts/${ARTIFACT_PATH}" 2>/dev/null) || artifact_resp=""
ARTIFACT_ID=$(echo "$artifact_resp" | jq -er '.id // .artifact_id // empty' 2>/dev/null || echo "")
if [ -z "$ARTIFACT_ID" ]; then
  fail "could not resolve artifact_id"
else
  pass
fi

begin_test "Trigger scan + wait for completion"
curl -sf $CURL_TIMEOUT -X POST -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg id "$ARTIFACT_ID" '{artifact_id: $id}')" \
  "${BASE_URL}/api/v1/security/scan" >/dev/null 2>&1 || true

elapsed=0
final_status=""
final_body=""
final_scan_id=""
while [ "$elapsed" -lt "$SCAN_TIMEOUT" ]; do
  resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      "${BASE_URL}/api/v1/security/artifacts/${ARTIFACT_ID}/scans" 2>/dev/null) || resp=""
  state=$(echo "$resp" | jq -r '.items[0].status // "" | ascii_downcase' 2>/dev/null || echo "")
  case "$state" in
    queued|pending|in_progress|scanning|running|"") ;;
    *) final_status="$state"
       final_body=$(echo "$resp" | jq -c '.items[0]' 2>/dev/null || echo "")
       final_scan_id=$(echo "$resp" | jq -r '.items[0].id // empty' 2>/dev/null || echo "")
       break ;;
  esac
  sleep 5
  elapsed=$(( elapsed + 5 ))
done
if [ -n "$final_status" ]; then
  pass
else
  fail "scan did not complete within ${SCAN_TIMEOUT}s"
fi

# ---------------------------------------------------------------------------
# Assertions: scan completed AND emitted findings AND the findings
# mention bash or CVE-2014-6271 (the OS-DB-walker path).
# ---------------------------------------------------------------------------

begin_test "Scan terminal status is 'completed'"
case "$final_status" in
  completed) pass ;;
  failed|error|timeout)
    err=$(echo "$final_body" | jq -r '.error_message // "none"' 2>/dev/null)
    fail "scan terminal status '${final_status}' (error_message: ${err})"
    ;;
  *) fail "unexpected terminal status '${final_status}'" ;;
esac

begin_test "Scan emitted at least one finding (OS-DB walker reached bash)"
findings_count=$(echo "$final_body" | jq -r '.findings_count // "null"' 2>/dev/null || echo "null")
if [ "$findings_count" = "null" ]; then
  fail "missing findings_count"
elif ! [[ "$findings_count" =~ ^[0-9]+$ ]]; then
  fail "non-integer findings_count '${findings_count}'"
elif [ "$findings_count" -lt 1 ]; then
  fail "findings_count=0 on dpkg-status fixture; OS package DB walker did not parse the fixture"
else
  pass
fi

# ---------------------------------------------------------------------------
# Drilldown: assert the findings reference bash or Shellshock. The
# findings endpoint shape varies across backend versions, so a
# tolerant grep over the response body is more robust than pinning a
# specific JSON path. Skip (do not fail) if the endpoint isn't there.
# ---------------------------------------------------------------------------

begin_test "Findings include bash / Shellshock OS-level CVE"
if [ -z "$final_scan_id" ]; then
  skip "no scan_id; cannot fetch findings detail"
else
  findings_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      "${BASE_URL}/api/v1/security/scans/${final_scan_id}/findings" 2>/dev/null) || findings_resp=""
  if [ -z "$findings_resp" ]; then
    skip "findings endpoint not available; per-finding drilldown deferred"
  else
    blob=$(echo "$findings_resp" | tr '[:upper:]' '[:lower:]')
    if echo "$blob" | grep -Eq 'bash|cve-2014-6271|shellshock'; then
      pass
    else
      fail "findings response does not mention bash/Shellshock/CVE-2014-6271; OS-DB walker hit something else: $(echo "$findings_resp" | head -c 400)"
    fi
  fi
fi

api_delete "/api/v1/repositories/${REPO_KEY}" >/dev/null 2>&1 || true

end_suite
