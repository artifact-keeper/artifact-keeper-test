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
# The load-bearing assertion of this suite is therefore:
#
#   POST /api/v1/webhooks with a private / loopback / metadata URL must
#   be rejected with a 4xx response. Anything in 2xx is a critical
#   security regression: the webhook is now stored and the backend will
#   happily fan out events to internal targets at delivery time.
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

  local payload
  payload=$(jq -n --arg name "$name" --arg url "$url" \
    '{name: $name, url: $url, events: ["artifact.uploaded"], enabled: true}')

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
# RFC1918 private space. One representative per /8 so the JUnit row
# tells the on-call which block leaked if any of them does.
# -------------------------------------------------------------------------

begin_test "Reject RFC1918 10.0.0.0/8 (10.0.0.1)"
attempt_ssrf "rfc1918-10" "http://10.0.0.1/"

begin_test "Reject RFC1918 172.16.0.0/12 (172.16.0.1)"
attempt_ssrf "rfc1918-172" "http://172.16.0.1/"

begin_test "Reject RFC1918 192.168.0.0/16 (192.168.1.1)"
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
