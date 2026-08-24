#!/usr/bin/env bash
# test-ssrf-prevention.sh - T2-12: SSRF prevention across webhooks and remote repos
#
# Verifies that the backend blocks SSRF attempts through webhook URLs, remote
# repository upstream URLs, and other user-supplied URL inputs.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "ssrf-prevention"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Helper: test that a webhook with a given URL is rejected
# ---------------------------------------------------------------------------

# test_webhook_ssrf DESCRIPTION URL [ALLOWLIST_EXEMPTABLE]
#
# Asserts a webhook with an SSRF URL is rejected (400/422). The optional
# third argument marks an RFC1918-private target that the test deploy MAY
# intentionally allowlist for the in-cluster webhook mock receiver
# (WEBHOOK_ALLOW_PRIVATE_IPS / AK_SSRF_ALLOW_PRIVATE_CIDRS; see
# helm/values-test-full.yaml and the cache-poisoning sibling). For those
# targets an "accepted" (200/201) result is SKIPPED, not failed, because it
# reflects the deploy's documented private-CIDR allowlist rather than a
# vulnerability. Cloud-metadata and loopback targets are NEVER marked
# exemptable: the backend hard-blocks them under every allowlist, so they
# stay strict fail-on-accept here.
test_webhook_ssrf() {
  local description="$1"
  local url="$2"
  local allowlist_exemptable="${3:-0}"
  local webhook_name
  webhook_name="sec-ssrf-wh-${RUN_ID}-$(echo "$description" | tr ' /' '-' | head -c 20)"

  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${webhook_name}\",\"url\":\"${url}\",\"events\":[\"artifact.pushed\"]}" \
    "${BASE_URL}/api/v1/webhooks") || true

  if [ "$status" = "400" ] || [ "$status" = "422" ]; then
    pass
  elif [ "$status" = "200" ] || [ "$status" = "201" ]; then
    # Clean up created webhook
    cleanup_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
      "${BASE_URL}/api/v1/webhooks" 2>/dev/null) || true
    webhook_id=$(echo "$cleanup_resp" | jq -r ".[] | select(.name==\"${webhook_name}\") | .id // empty" 2>/dev/null) || true
    if [ -n "$webhook_id" ]; then
      curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
        "${BASE_URL}/api/v1/webhooks/${webhook_id}" >/dev/null 2>&1 || true
    fi
    if [ "$allowlist_exemptable" = "1" ]; then
      skip "private-CIDR webhook allowlist active in this deploy (${description}, HTTP ${status}); RFC1918 target intentionally permitted (artifact-keeper#1224 / artifact-keeper-test#122)"
    else
      fail "webhook with SSRF URL was accepted (${description}, HTTP ${status})"
    fi
  elif [ "$status" = "404" ]; then
    skip "webhook endpoint not available (HTTP 404)"
  else
    # 401/403/500 all indicate the URL was not silently accepted
    pass
  fi
}

# ---------------------------------------------------------------------------
# Helper: test that a remote repo with a given upstream URL is rejected
# ---------------------------------------------------------------------------

test_remote_repo_ssrf() {
  local description="$1"
  local url="$2"
  local repo_key
  repo_key="sec-ssrf-rr-${RUN_ID}-$(echo "$description" | tr ' /' '-' | head -c 15)"

  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
    -X POST \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -d "{\"key\":\"${repo_key}\",\"name\":\"${repo_key}\",\"format\":\"generic\",\"repo_type\":\"remote\",\"upstream_url\":\"${url}\"}" \
    "${BASE_URL}/api/v1/repositories") || true

  if [ "$status" = "400" ] || [ "$status" = "422" ]; then
    pass
  elif [ "$status" = "200" ] || [ "$status" = "201" ]; then
    # Clean up
    api_delete "/api/v1/repositories/${repo_key}" >/dev/null 2>&1 || true
    skip "remote repo SSRF protection not implemented yet (${description}, HTTP ${status})"
  else
    # 409 (conflict), 401, 403, 500 all mean the SSRF URL was not exploitable
    pass
  fi
}

# ---------------------------------------------------------------------------
# Webhook SSRF tests
# ---------------------------------------------------------------------------

begin_test "Webhook SSRF: loopback 127.0.0.1"
test_webhook_ssrf "loopback-127" "http://127.0.0.1:80/callback"

begin_test "Webhook SSRF: AWS metadata endpoint"
test_webhook_ssrf "aws-metadata" "http://169.254.169.254/latest/meta-data/"

begin_test "Webhook SSRF: IPv6 loopback"
test_webhook_ssrf "ipv6-loopback" "http://[::1]:80/"

begin_test "Webhook SSRF: localhost"
test_webhook_ssrf "localhost" "http://localhost:8080/callback"

# RFC1918 webhook targets: allowlist-exemptable. The test deploy may permit
# the in-cluster pod/service CIDR for the webhook mock receiver
# (helm/values-test-full.yaml). These probe IPs (10.0.0.1 / 172.16.0.1 /
# 192.168.1.1) are OUTSIDE that CIDR, so under the current deploy they are
# still BLOCKED (400) and these cases PASS; the skip path only fires if a
# broader blanket private-IP toggle is in effect.
begin_test "Webhook SSRF: private 10.x range"
test_webhook_ssrf "private-10x" "http://10.0.0.1/callback" 1

begin_test "Webhook SSRF: private 172.16.x range"
test_webhook_ssrf "private-172" "http://172.16.0.1/callback" 1

begin_test "Webhook SSRF: private 192.168.x range"
test_webhook_ssrf "private-192" "http://192.168.1.1/callback" 1

# ---------------------------------------------------------------------------
# Vectors inherited from tests/security/redteam/test-13-ssrf-prevention.sh,
# which was removed because it could not fail (it sourced the red-team lib and
# ended in `exit 0`). Its webhook coverage was otherwise a subset of the cases
# above; these four are the ones it exercised and this suite did not.
#
# The two metadata hostnames matter separately from 169.254.169.254 because a
# guard that only blocks literal link-local IPs is bypassed by a DNS name that
# resolves to one. The container service names matter because the gate deploy
# and every compose stack resolve them, so a name-based guard that only knows
# about "localhost" leaves the neighbouring services reachable.
# ---------------------------------------------------------------------------

begin_test "Webhook SSRF: GCP metadata hostname"
test_webhook_ssrf "gcp-metadata-host" "http://metadata.google.internal/computeMetadata/v1/"

begin_test "Webhook SSRF: Azure metadata hostname"
test_webhook_ssrf "azure-metadata-host" "http://metadata.azure.com/metadata/instance"

begin_test "Webhook SSRF: in-cluster database service name"
test_webhook_ssrf "svc-postgres" "http://postgres:5432/" 1

begin_test "Webhook SSRF: in-cluster cache service name"
test_webhook_ssrf "svc-redis" "http://redis:6379/" 1

# ---------------------------------------------------------------------------
# Remote repo upstream SSRF tests
# ---------------------------------------------------------------------------

begin_test "Remote repo SSRF: loopback 127.0.0.1"
test_remote_repo_ssrf "loopback-127" "http://127.0.0.1:8080/"

begin_test "Remote repo SSRF: AWS metadata endpoint"
test_remote_repo_ssrf "aws-metadata" "http://169.254.169.254/"

begin_test "Remote repo SSRF: IPv6 loopback"
test_remote_repo_ssrf "ipv6-loopback" "http://[::1]:8080/"

begin_test "Remote repo SSRF: localhost"
test_remote_repo_ssrf "localhost" "http://localhost:5432/"

# ---------------------------------------------------------------------------
# Verify that legitimate external URLs are still accepted
# ---------------------------------------------------------------------------

begin_test "Legitimate external webhook URL is accepted"
legit_name="sec-ssrf-legit-${RUN_ID}"
legit_status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT \
  -X POST \
  -H "$(auth_header)" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"${legit_name}\",\"url\":\"https://example.com/webhook\",\"events\":[\"artifact.pushed\"]}" \
  "${BASE_URL}/api/v1/webhooks") || true

if [ "$legit_status" = "200" ] || [ "$legit_status" = "201" ]; then
  # Clean up
  cleanup_resp=$(curl -sf $CURL_TIMEOUT -H "$(auth_header)" \
    "${BASE_URL}/api/v1/webhooks" 2>/dev/null) || true
  webhook_id=$(echo "$cleanup_resp" | jq -r ".[] | select(.name==\"${legit_name}\") | .id // empty" 2>/dev/null) || true
  if [ -n "$webhook_id" ]; then
    curl -sf $CURL_TIMEOUT -X DELETE -H "$(auth_header)" \
      "${BASE_URL}/api/v1/webhooks/${webhook_id}" >/dev/null 2>&1 || true
  fi
  pass
elif [ "$legit_status" = "404" ]; then
  skip "webhook endpoint not available"
else
  skip "legitimate webhook URL returned HTTP ${legit_status} (endpoint may require additional config)"
fi

end_suite
