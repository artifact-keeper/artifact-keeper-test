#!/usr/bin/env bash
# test-webhook-ssrf-prevention.sh
#
# Issue #75 sub-task 7.8: server-side request forgery prevention on
# webhook URLs. A webhook destination is one of the few places where a
# tenant-controlled URL is fetched server-side; if the backend allows the
# tenant to point a webhook at a private IP, a loopback address, or a
# cloud metadata endpoint, the resulting POSTs can be used to exfiltrate
# data, scan internal services, or steal IAM credentials from the
# instance metadata service.
#
# The load-bearing assertions of this suite split into two groups:
#
#   1. HARD-BLOCKED classes -- cloud metadata (169.254.169.254 and the
#      well-known metadata hostnames), loopback (127.0.0.0/8, ::1,
#      localhost), link-local 169.254.0.0/16, the unspecified address
#      0.0.0.0, and non-http(s) schemes (file://, gopher://). POST
#      /api/v1/webhooks with any of these must be rejected with a 4xx.
#      These are never unblocked by any toggle (backend
#      validation::is_hard_blocked_ipv4 / BLOCKED_HOSTS / scheme check),
#      so a 2xx here is a critical security regression: the webhook is
#      stored and the backend will fan out events to an internal target
#      at delivery time.
#
#   2. RFC1918 private space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
#      Whether these are rejected is configuration-dependent. Backend
#      issue #1435 split the single SSRF toggle into per-surface env
#      vars: WEBHOOK_ALLOW_PRIVATE_IPS gates RFC1918 for the webhook
#      delivery path, UPSTREAM_ALLOW_PRIVATE_IPS gates it for the
#      remote-proxy path. The release-gate test cluster sets
#      WEBHOOK_ALLOW_PRIVATE_IPS=1 (helm/values-test-full.yaml, renamed
#      from the older single-var name in test-repo #204) BECAUSE the
#      webhook mock receiver binds inside the runner pod and the webhook
#      target is the pod's own RFC1918 IP. On the webhook surface in this
#      cluster, RFC1918 is therefore INTENTIONALLY ALLOWED, so a correct
#      create returns 2xx, not 4xx. We assert success for these three.
#
#      This is a test-side calibration only: it does NOT weaken SSRF
#      protection. The remote-proxy SSRF suite still asserts RFC1918 is
#      rejected (UPSTREAM_ALLOW_PRIVATE_IPS is deliberately NOT set), and
#      metadata / loopback / link-local stay hard-blocked on the webhook
#      surface regardless of WEBHOOK_ALLOW_PRIVATE_IPS.
#
#      Note (backend #1478, "B4"): before that fix, an RFC1918 webhook
#      create returned an ambiguous 500 when AK_WEBHOOK_SECRET_KEY was
#      unset. It now returns a clean 2xx (the URL passes SSRF validation
#      and the secret-less create succeeds), so "expect 2xx" is the
#      correct, unambiguous post-#1478 assertion.
#
# We test each address class separately so a regression on only one class
# (say, cloud-metadata 169.254.x but not RFC1918) is visible in the
# JUnit report rather than masked by a sibling assertion. The list is
# deliberately conservative -- we do not test every CIDR; we test one
# representative per documented blocklist class.
#
# We never test against a real external IP. Every URL here points to an
# address that should be unreachable from outside the test runner OR
# that is universally understood to be a private/management address.
#
# Companion: 7.9 (DNS rebinding / re-validation at delivery time) is a
# separate concern -- this test only covers create-time validation.
#
# Requires: curl, jq

source "$(dirname "$0")/../lib/common.sh"

begin_suite "webhook-ssrf-prevention"

CREATED_IDS=()

cleanup_created() {
  for id in "${CREATED_IDS[@]}"; do
    [ -n "$id" ] && [ "$id" != "null" ] && \
      api_delete "/api/v1/webhooks/${id}" >/dev/null 2>&1 || true
  done
}
add_exit_handler 'cleanup_created'

auth_admin

# -------------------------------------------------------------------------
# Pre-flight.
# -------------------------------------------------------------------------

begin_test "jq available"
if ! command -v jq >/dev/null 2>&1; then
  skip "jq not available"
  end_suite
fi
pass

# -------------------------------------------------------------------------
# attempt_ssrf <label> <url>
#
# Tries to POST /api/v1/webhooks with a destination URL drawn from a
# blocked address class. Behavior:
#
#   - 4xx (validation rejection)   -> PASS. This is the expected outcome.
#   - 2xx with an .id field        -> FAIL (and queue the row for cleanup).
#                                     Test-marker: SSRF allow-list missed
#                                     this class, the webhook is persisted
#                                     and will fire against an internal
#                                     target at delivery time.
#   - 5xx                          -> FAIL. The backend should be reaching
#                                     a deterministic validation verdict,
#                                     not crashing.
#   - 501 / "not implemented"      -> SKIP. The endpoint does not exist
#                                     yet in this build; report it but do
#                                     not silently pass (would be a
#                                     silent-success per #870/#871).
#
# Curl is invoked with -o to capture the body so a 2xx leak can be
# logged with the persisted id; -w to capture the HTTP status so we
# never confuse "request failed" with "validation rejected".
# -------------------------------------------------------------------------

attempt_ssrf() {
  local label="$1"
  local url="$2"
  local name="ssrf-${label}-${RUN_ID}"

  # CreateWebhookRequest does not accept an enabled/is_enabled field
  # (backend webhooks.rs:86-95). Event names are the snake_case Display
  # form of WebhookEvent (webhooks.rs:50-74).
  local payload
  payload=$(jq -n --arg name "$name" --arg url "$url" \
    '{name: $name, url: $url, events: ["artifact_uploaded"]}')

  local tmp status body
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' \
    --max-time 10 \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "$payload" \
    "${BASE_URL}/api/v1/webhooks" 2>/dev/null) || status="000"
  body=$(cat "$tmp" 2>/dev/null || true)
  rm -f "$tmp"

  case "$status" in
    4??)
      pass
      ;;
    501)
      skip "endpoint not implemented (HTTP 501)"
      ;;
    2??)
      # The webhook was accepted. Record the id so the cleanup trap can
      # purge it -- a persisted SSRF target is its own follow-on risk.
      local leaked_id
      leaked_id=$(echo "$body" | jq -r '.id // empty' 2>/dev/null) || leaked_id=""
      if [ -n "$leaked_id" ] && [ "$leaked_id" != "null" ]; then
        CREATED_IDS+=("$leaked_id")
      fi
      fail "SECURITY: webhook URL '${url}' (${label}) accepted with HTTP ${status}. This is a server-side request forgery vector." "${body:0:400}"
      ;;
    000)
      fail "network failure contacting ${BASE_URL}/api/v1/webhooks (curl returned 000) for label='${label}'"
      ;;
    *)
      fail "unexpected HTTP ${status} for url='${url}' (${label}); expected 4xx rejection" "${body:0:400}"
      ;;
  esac
}

# -------------------------------------------------------------------------
# expect_webhook_allowed <label> <url>
#
# The inverse of attempt_ssrf for the RFC1918 private-space cases on the
# webhook surface. In the release-gate test cluster the webhook target is
# the runner pod's own RFC1918 IP and WEBHOOK_ALLOW_PRIVATE_IPS=1 is set
# (helm/values-test-full.yaml), so an RFC1918 webhook URL is INTENTIONALLY
# accepted. Behavior:
#
#   - 2xx with an .id field        -> PASS. RFC1918 allowed as configured;
#                                     record the id for cleanup.
#   - 2xx without an .id field     -> PASS, but no id to clean up.
#   - 4xx (validation rejection)   -> FAIL. WEBHOOK_ALLOW_PRIVATE_IPS is
#                                     expected to be set in this cluster;
#                                     a reject means the toggle is not
#                                     wired through to the webhook
#                                     validator (regression of #1435), or
#                                     the env var was not set on the
#                                     deploy. Either way the suite's other
#                                     webhook tests (mock receiver on the
#                                     pod RFC1918 IP) would also be broken.
#   - 501 / "not implemented"      -> SKIP. Endpoint absent in this build.
#   - 5xx                          -> FAIL. After #1478 (B4) a secret-less
#                                     create must not 500; a 500 here means
#                                     that regression is back.
#
# This asserts a configuration outcome, NOT a relaxation of SSRF defense:
# metadata / loopback / link-local stay hard-blocked (see attempt_ssrf
# cases below) and the remote-proxy SSRF suite still rejects RFC1918.
# -------------------------------------------------------------------------

expect_webhook_allowed() {
  local label="$1"
  local url="$2"
  local name="ssrf-allowed-${label}-${RUN_ID}"

  local payload
  payload=$(jq -n --arg name "$name" --arg url "$url" \
    '{name: $name, url: $url, events: ["artifact_uploaded"]}')

  local tmp status body
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' \
    --max-time 10 \
    -H "$(auth_header)" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "$payload" \
    "${BASE_URL}/api/v1/webhooks" 2>/dev/null) || status="000"
  body=$(cat "$tmp" 2>/dev/null || true)
  rm -f "$tmp"

  case "$status" in
    2??)
      local created_id
      created_id=$(echo "$body" | jq -r '.id // empty' 2>/dev/null) || created_id=""
      if [ -n "$created_id" ] && [ "$created_id" != "null" ]; then
        CREATED_IDS+=("$created_id")
      fi
      pass
      ;;
    501)
      skip "endpoint not implemented (HTTP 501)"
      ;;
    4??)
      fail "RFC1918 webhook URL '${url}' (${label}) was rejected with HTTP ${status}, but WEBHOOK_ALLOW_PRIVATE_IPS is expected to be set on the test cluster so the webhook surface allows RFC1918 (backend #1435). Check helm/values-test-full.yaml and the backend webhook validator wiring." "${body:0:400}"
      ;;
    000)
      fail "network failure contacting ${BASE_URL}/api/v1/webhooks (curl returned 000) for label='${label}'"
      ;;
    *)
      fail "unexpected HTTP ${status} for url='${url}' (${label}); expected 2xx success (RFC1918 allowed on webhook surface). A 5xx here may be a regression of the #1478 secret-less-create fix." "${body:0:400}"
      ;;
  esac
}

# -------------------------------------------------------------------------
# Cloud metadata services. 169.254.169.254 is the long-standing AWS /
# GCP / Azure / DigitalOcean / Oracle Cloud metadata IP. A webhook
# pointed at it can exfiltrate short-lived IAM credentials, instance
# tags, user-data, etc. This is the highest-impact SSRF class.
# -------------------------------------------------------------------------

begin_test "Reject cloud metadata IP (169.254.169.254)"
attempt_ssrf "aws-metadata" "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Newer GCP metadata host. Different from the IP path because some
# allow-lists deny by IP literal but forget the well-known hostname.
begin_test "Reject GCP metadata hostname (metadata.google.internal)"
attempt_ssrf "gcp-metadata" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# -------------------------------------------------------------------------
# Link-local 169.254.0.0/16 (RFC3927). Distinct from the metadata IP
# above because some implementations special-case 169.254.169.254 but
# miss the rest of the /16. A webhook pointed at .169.250 reaches a
# completely different surface (DHCP clients, APIPA, link-local probes).
# -------------------------------------------------------------------------

begin_test "Reject link-local 169.254.x (non-metadata host in same /16)"
attempt_ssrf "linklocal" "http://169.254.169.250/"

# -------------------------------------------------------------------------
# Loopback. 127.0.0.0/8. Pointing a webhook at the host's own loopback
# reaches anything bound to localhost: postgres, redis, kube-proxy's
# health server, debugging endpoints, sidecars. This is the SSRF class
# that lets a tenant hit the backend's own /admin endpoints.
# -------------------------------------------------------------------------

begin_test "Reject IPv4 loopback (127.0.0.1)"
attempt_ssrf "loopback4" "http://127.0.0.1:8080/api/v1/users"

begin_test "Reject IPv4 loopback alias (127.1.2.3)"
attempt_ssrf "loopback-alias" "http://127.1.2.3/"

begin_test "Reject IPv6 loopback ([::1])"
attempt_ssrf "loopback6" "http://[::1]:8080/"

# Allow-lists that filter on the literal string "127.0.0.1" but forget
# that "localhost" resolves to the same place are a recurring class of
# bug. Test the hostname form explicitly.
begin_test "Reject 'localhost' hostname"
attempt_ssrf "localhost-name" "http://localhost:8080/"

# -------------------------------------------------------------------------
# RFC1918 private space. One representative per block. These arbitrary
# RFC1918 IPs are SSRF targets and must be REJECTED.
#
# The release-gate deploy uses a CIDR-SCOPED allowlist
# (AK_SSRF_ALLOW_PRIVATE_CIDRS=10.96.0.0/12,10.244.0.0/16 in
# helm/values-test-full.yaml, backend #1224) instead of the blanket
# WEBHOOK_ALLOW_PRIVATE_IPS toggle. The named-CIDR list, once set, governs
# BOTH the upstream and webhook contexts and overrides the blanket toggles
# (backend validation.rs). Only the cluster Service/Pod CIDR is permitted,
# so legitimate in-cluster webhook delivery to the mock receiver (a pod IP
# inside 10.244.0.0/16) still works -- covered by test-webhook-delivery.sh --
# while these arbitrary RFC1918 addresses (10.0.0.1 / 172.16.0.1 /
# 192.168.1.1, all OUTSIDE the allowed CIDRs) are correctly blocked. This is
# a strictly stronger SSRF posture than the old all-RFC1918 allow. One
# representative per block so a partial regression stays visible per-row.
# -------------------------------------------------------------------------

begin_test "Reject RFC1918 10.0.0.0/8 (10.0.0.1) outside cluster-CIDR allowlist"
attempt_ssrf "rfc1918-10" "http://10.0.0.1/"

begin_test "Reject RFC1918 172.16.0.0/12 (172.16.0.1) outside cluster-CIDR allowlist"
attempt_ssrf "rfc1918-172" "http://172.16.0.1/"

begin_test "Reject RFC1918 192.168.0.0/16 (192.168.1.1) outside cluster-CIDR allowlist"
attempt_ssrf "rfc1918-192" "http://192.168.1.1/"

# -------------------------------------------------------------------------
# 0.0.0.0. Treated as "all addresses on the local host" by most network
# stacks; a webhook firing at 0.0.0.0 hits the loopback equivalently.
# Easy to forget if the allow-list is implemented as "must be a valid
# routable IP" without an explicit 0/8 exclusion.
# -------------------------------------------------------------------------

begin_test "Reject unspecified address (0.0.0.0)"
attempt_ssrf "zero" "http://0.0.0.0:8080/"

# -------------------------------------------------------------------------
# Non-HTTP schemes. Even if the URL parser would accept the host, the
# scheme should be restricted to http/https. file:// would let a webhook
# read local files; gopher:// is the classic SSRF gadget for talking
# arbitrary TCP protocols through a permissive HTTP client.
# -------------------------------------------------------------------------

begin_test "Reject file:// scheme"
attempt_ssrf "scheme-file" "file:///etc/passwd"

begin_test "Reject gopher:// scheme"
attempt_ssrf "scheme-gopher" "gopher://127.0.0.1:6379/_INFO"

end_suite
