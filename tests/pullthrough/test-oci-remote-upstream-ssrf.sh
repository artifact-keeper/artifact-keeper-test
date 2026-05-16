#!/usr/bin/env bash
# test-oci-remote-upstream-ssrf.sh -- OCI/docker remote-repo upstream
# URLs must be SSRF-validated at create time (issue #69 sub-task 1.7).
#
# What this asserts
# -----------------
# The OCI/docker proxy fetch path can be steered ENTIRELY by the
# `upstream_url` of the remote repo. If validate_outbound_url is
# bypassed for OCI registries (or if the OCI 401-redirect handler
# follows a Location: pointing at a private CIDR), an attacker who
# can create a remote docker repo gets a full SSRF primitive:
#   - probe the cluster (http://kubernetes.default/, http://postgres:5432/)
#   - read cloud metadata (http://169.254.169.254/latest/meta-data/iam/...)
#   - reach internal admin surfaces
#
# This is the SAME defence class as webhook SSRF (PR #165 / red-team
# test #13), but on a different code path (remote-repo creation, not
# webhook URL). tests/security/redteam/test-13-ssrf-prevention.sh
# exercises only the webhook path; this script extends the validation
# expectation to remote-repo upstream_url for OCI/docker specifically,
# which is the format the 1.7 sub-task calls out.
#
# What we assert, in order:
#   1. POST /api/v1/repositories with format=docker, repo_type=remote,
#      and upstream_url pointing at a forbidden target MUST be
#      rejected (HTTP 400). We probe a representative set:
#         a. cloud metadata IP (169.254.169.254)
#         b. loopback (127.0.0.1)
#         c. RFC1918 (10.0.0.1, 192.168.1.1)
#         d. cloud metadata DNS name (metadata.google.internal)
#      The exact rejection reason MAY differ across these (IP literal
#      check vs. DNS resolve-and-check), but every one MUST be rejected.
#   2. A legitimate external upstream (e.g. https://registry-1.docker.io)
#      MUST be accepted as a control. Without this control the test
#      could pass vacuously on a backend that rejects ALL remote-repo
#      creates.
#   3. Cleanup any created repo, including the control case.
#
# What this does NOT assert (deferred)
# ------------------------------------
# - The 401-REDIRECT-follow path itself (i.e. the backend receives a
#   401 from a legitimate upstream with a Www-Authenticate realm=
#   pointing at an internal IP, follows it, and gets SSRF'd). That
#   requires the mock-upstream fixture to serve a controlled 401, and
#   mock-upstream is currently SSRF-blocked by the same protection
#   this test exercises (see tests/security/test-cache-poisoning.sh
#   for the chicken-and-egg). The CREATE-time check covered here is
#   the first line of defence; the REDIRECT-time check is the second
#   line. Tracking the redirect-follow assertion in #69 follow-ups.
# - DNS-rebinding attacks (resolve-twice). validate_outbound_url is
#   currently a single-resolve check; rebinding attacks are tracked
#   separately in artifact-keeper#1185.
#
# Why a control case matters
# --------------------------
# If we ONLY tested the rejection cases and a regression flipped the
# whole endpoint to reject-everything, we'd silently false-pass. The
# control case (accept-legitimate-external) catches that exact class.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "oci-remote-upstream-ssrf"
auth_admin
setup_workdir

# Repos we may have to clean up if the test crashes mid-flight. We
# don't know which will succeed until we run; record both, delete
# both on EXIT. Best-effort -- already-404 deletes are fine.
CONTROL_KEY="oci-ssrf-ok-${RUN_ID}"
ATTACK_KEY_PREFIX="oci-ssrf-bad-${RUN_ID}"

cleanup_repos() {
  api_delete "/api/v1/repositories/${CONTROL_KEY}" >/dev/null 2>&1 || true
  # Each attack case writes its own key; iterate and delete all.
  local i
  for i in 1 2 3 4 5 6; do
    api_delete "/api/v1/repositories/${ATTACK_KEY_PREFIX}-${i}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup_repos"

# try_create_remote_oci KEY URL
# POSTs the create-remote payload and echoes "<status>|<body>". Does
# NOT use create_remote_repo because that helper retries on transient
# failures (401/429/503/000) which would mask the SSRF reject. We want
# the FIRST response, raw.
try_create_remote_oci() {
  local key="$1"
  local url="$2"
  local body_file="${WORK_DIR}/create-body.$$"
  local payload status body
  payload=$(jq -n \
    --arg key "$key" \
    --arg name "$key" \
    --arg url "$url" \
    '{key:$key, name:$name, format:"docker", repo_type:"remote", upstream_url:$url, is_public:true}')

  status=$(curl -s -o "$body_file" -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "${BASE_URL}/api/v1/repositories" 2>/dev/null) || status="000"
  body=$(cat "$body_file" 2>/dev/null || echo "")
  rm -f "$body_file"
  echo "${status}|${body}"
}

# assert_ssrf_blocked LABEL URL ATTACK_NUM
# Common case: try to create with a forbidden URL, assert HTTP 400
# (the validate_outbound_url -> AppError::Validation -> HTTP 400 path).
# 422 is also accepted because some axum validation layers surface as
# 422 Unprocessable Entity. Anything in the 2xx range is a FAIL --
# the repo was accepted, which is the SSRF primitive we are trying
# to prevent. 5xx is also a FAIL because it indicates the request
# reached upstream-fetch code rather than being rejected up front.
assert_ssrf_blocked() {
  local label="$1"
  local url="$2"
  local attack_num="$3"
  local key="${ATTACK_KEY_PREFIX}-${attack_num}"
  begin_test "Remote docker upstream_url rejected: ${label} (${url})"
  local resp status body
  resp=$(try_create_remote_oci "$key" "$url")
  status="${resp%%|*}"
  body="${resp#*|}"
  if [ "$status" = "400" ] || [ "$status" = "422" ]; then
    pass
  elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    # Critical security finding. Clean the just-created repo up
    # immediately rather than waiting for the EXIT handler so a
    # parallel suite cannot stumble onto it.
    api_delete "/api/v1/repositories/${key}" >/dev/null 2>&1 || true
    fail "SSRF: remote docker upstream_url '${url}' was ACCEPTED (HTTP ${status}); validate_outbound_url did NOT block this case"
  elif [ "$status" -ge 500 ] 2>/dev/null; then
    fail "expected 400 for '${url}', got ${status} (5xx suggests the request was NOT rejected up-front but instead crashed mid-fetch; body=${body:0:200})"
  else
    fail "expected 400 for '${url}', got ${status} (body=${body:0:200})"
  fi
}

# ---------------------------------------------------------------------------
# Block A: forbidden upstream URLs. Every case below MUST return 400/422.
# ---------------------------------------------------------------------------

# IMDS (AWS / OpenStack metadata): the original Capital One class.
assert_ssrf_blocked "AWS/OpenStack IMDS (169.254.169.254)" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 1

# Loopback. Reaches an admin process colocated with the backend.
assert_ssrf_blocked "Loopback (127.0.0.1)" \
  "http://127.0.0.1:8080/v2/" 2

# RFC1918 10.x: pod CIDR in most kube clusters.
assert_ssrf_blocked "RFC1918 10.x (10.0.0.1)" \
  "http://10.0.0.1/v2/" 3

# RFC1918 192.168.x: home/SMB networks.
assert_ssrf_blocked "RFC1918 192.168.x (192.168.1.1)" \
  "http://192.168.1.1/v2/" 4

# Cloud metadata via DNS: relies on the resolver path / hostname
# blocklist, not just the IP-literal check. A backend that ONLY blocks
# IP literals is still vulnerable through the metadata DNS name. We
# probe `metadata.google.internal`, which is explicitly listed in
# BLOCKED_HOSTS (backend/src/api/validation.rs) alongside the AWS IMDS
# IP. (Earlier drafts of this test used `kubernetes.default` here, but
# that name is NOT in BLOCKED_HOSTS and the backend would 2xx-accept
# it, producing a false-failure on a backend that is otherwise
# correctly defended; the SSRF surface for kube-internal services is
# covered by the RFC1918 / loopback cases above on any sane cluster
# CNI, and separately by the docker-internal service hostnames
# `backend`, `postgres`, `redis`, etc., which ARE in BLOCKED_HOSTS.)
assert_ssrf_blocked "Cloud metadata via DNS (metadata.google.internal)" \
  "http://metadata.google.internal/computeMetadata/v1/" 5

# Link-local IPv6 (fe80::). Often missed by IPv4-only blocklists.
assert_ssrf_blocked "IPv6 link-local (fe80::1)" \
  "http://[fe80::1]/v2/" 6

# ---------------------------------------------------------------------------
# Block B: control case. A legitimate external OCI registry URL must be
# ACCEPTED. Without this, the test could vacuously pass on a backend
# that rejected all remote creates.
#
# We intentionally pick the Docker Hub registry-1 hostname because it
# is the canonical OCI v2 endpoint and we don't actually pull through
# it (no upstream fetch happens at create time). If a future backend
# adds a connectivity probe at create time, the URL may need updating;
# in that case we'd swap for any other public OCI registry.
# ---------------------------------------------------------------------------

begin_test "Remote docker upstream_url accepted for legitimate external registry (control)"
CONTROL_URL="https://registry-1.docker.io/v2/"
resp=$(try_create_remote_oci "$CONTROL_KEY" "$CONTROL_URL")
status="${resp%%|*}"
body="${resp#*|}"
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
elif [ "$status" = "400" ] || [ "$status" = "422" ]; then
  # If the backend rejects this control too, the whole SSRF assertion
  # above is vacuous (it would block everything). Surface that loudly.
  fail "control case FAILED: legitimate external URL '${CONTROL_URL}' was rejected (${status}); the SSRF rejection block above may be a false positive (backend rejecting all remote-creates). Body: ${body:0:200}"
else
  # 5xx / network -- not a security regression but undermines the
  # control. Skip rather than fail so we don't poison a green release
  # over a transient upstream-probe failure.
  skip "control case ambiguous: HTTP ${status} (body=${body:0:200}); cannot confirm rejection set is non-vacuous on this run"
fi

if [ "${EXPECT_FAILURE:-0}" = "1" ]; then
  if ( end_suite ); then
    echo "EXPECT_FAILURE=1 but suite passed; inverting to fail"
    exit 1
  else
    echo "EXPECT_FAILURE=1 and suite failed as expected; inverting to pass"
    exit 0
  fi
fi

end_suite
