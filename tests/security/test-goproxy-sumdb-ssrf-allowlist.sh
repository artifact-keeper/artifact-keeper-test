#!/usr/bin/env bash
# test-goproxy-sumdb-ssrf-allowlist.sh
#
# Closes a sub-task of the artifact-keeper-test#181-cohort of untested
# security fixes (triage doc §4, "Critical" tier).
#
# Bug guarded against
# -------------------
# artifact-keeper#879 (commit 3e529938, merged 2026-04-25). The Go
# proxy handler's sumdb route forwards requests to
# `https://{host}/{path}` where `{host}` is a URL path component
# controlled entirely by the caller. Pre-fix, ANY host string was
# accepted, including
#
#   GET /go/{repo}/sumdb/169.254.169.254/latest/meta-data/iam/...
#
# which made the server fetch AWS / GCP cloud-metadata on the
# attacker's behalf and return the response body. Textbook SSRF.
#
# Fix: a static allowlist of permitted upstream sumdb hosts
# (sum.golang.org, sum.golang.google.cn). Any other host returns
# HTTP 403, comparison case-insensitive per RFC 1035.
#
# What this test pins
# -------------------
# 1. Cloud-metadata addresses (169.254.169.254) MUST be rejected.
# 2. Loopback addresses (127.0.0.1, localhost, [::1]) MUST be rejected.
# 3. RFC 1918 private addresses MUST be rejected.
# 4. Typosquatted hosts (sum.golang.org.evil.com) MUST be rejected.
# 5. Random external hosts MUST be rejected.
# 6. Case variations of allowed hosts (SUM.GOLANG.ORG) MUST NOT
#    return 403 from the allowlist check (RFC 1035 case-insensitivity).
#    They may still 4xx/5xx for other reasons (no real upstream, no
#    Go module being looked up) but NOT with the allowlist 403.
#
# Requires: curl

source "$(dirname "$0")/../lib/common.sh"

begin_suite "goproxy-sumdb-ssrf-allowlist"
auth_admin

REPO_KEY="sec-sumdb-ssrf-${RUN_ID}"

# ---------------------------------------------------------------------------
# Setup: local Go repo. Remote isn't needed -- the sumdb proxy logic
# checks the allowlist BEFORE any upstream lookup, so a local repo with
# no upstream still exercises the allowlist code path.
# ---------------------------------------------------------------------------

begin_test "Create local Go repo"
if create_local_repo "$REPO_KEY" "go"; then
  add_exit_handler "api_delete /api/v1/repositories/${REPO_KEY} >/dev/null 2>&1 || true"
  pass
else
  fail "could not create local Go repo (${REPO_KEY})"
fi

# ---------------------------------------------------------------------------
# Helper: probe a sumdb host and assert it is rejected with 403.
#
# 4xx other than 403 is NOT acceptable here: 404 from a router-level
# miss would mean the request never reached the allowlist gate, and
# 401 from an auth middleware would mean we're testing the wrong
# code path. The fix's contract is explicitly 403 with the allowlist
# error message.
# ---------------------------------------------------------------------------

probe_blocked() {
  local description="$1"
  local host="$2"
  local probe_path="${3:-lookup/golang.org/x/text@v0.14.0}"
  local url="${BASE_URL}/go/${REPO_KEY}/sumdb/${host}/${probe_path}"

  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT --path-as-is \
    -H "$(format_auth_header)" \
    "${url}") || status=000

  if [ "$status" = "403" ]; then
    pass
    return 0
  fi
  fail "SSRF probe (${description}) returned HTTP ${status}, expected 403; host=${host} url=${url}"
  return 1
}

# ---------------------------------------------------------------------------
# Cloud-metadata addresses
#
# 169.254.169.254 is the AWS / Azure / GCP IMDS endpoint. The original
# repro in #879 was exactly this address. Other link-local addresses in
# 169.254.0.0/16 are still routable from cloud VMs and would leak less
# obviously interesting data, but the canonical case is .254.
# ---------------------------------------------------------------------------

begin_test "Reject IMDS 169.254.169.254 (original #879 repro)"
probe_blocked "AWS/GCP IMDS" "169.254.169.254" "latest/meta-data/iam/security-credentials/"

# ---------------------------------------------------------------------------
# Loopback addresses
#
# Anything reaching the server's own loopback bypasses external
# firewalls and can scan / actuate localhost-bound services
# (Postgres, admin sockets, debug endpoints).
# ---------------------------------------------------------------------------

begin_test "Reject loopback 127.0.0.1"
probe_blocked "loopback IPv4" "127.0.0.1"

begin_test "Reject loopback localhost"
probe_blocked "loopback by name" "localhost"

begin_test "Reject IPv6 loopback [::1]"
# IPv6 literal — URL-encoded brackets to ensure the path
# parser sees them. --path-as-is so curl does not normalise.
probe_blocked "loopback IPv6" "%5B::1%5D"

# ---------------------------------------------------------------------------
# RFC 1918 private addresses
#
# Internal corp networks. The bug allowed pivoting INTO a network
# from the server's egress.
# ---------------------------------------------------------------------------

begin_test "Reject RFC 1918 10.0.0.1"
probe_blocked "private 10.0.0.0/8" "10.0.0.1"

begin_test "Reject RFC 1918 192.168.1.1"
probe_blocked "private 192.168.0.0/16" "192.168.1.1"

# ---------------------------------------------------------------------------
# Typosquatted / similar-looking hosts
#
# An allowlist that did substring matching instead of exact match
# would fall to these. The fix uses eq_ignore_ascii_case on the full
# host, so typosquats MUST 403.
# ---------------------------------------------------------------------------

begin_test "Reject typosquat sum.golang.org.evil.com"
probe_blocked "typosquat-suffix" "sum.golang.org.evil.com"

begin_test "Reject typosquat evil.com.sum.golang.org"
probe_blocked "typosquat-prefix" "evil.com.sum.golang.org"

# ---------------------------------------------------------------------------
# Random external hosts
#
# Even if a host resolves to a real internet address, the allowlist
# limits the proxy to the two known-good sumdb endpoints.
# ---------------------------------------------------------------------------

begin_test "Reject random external host example.com"
probe_blocked "external" "example.com"

# ---------------------------------------------------------------------------
# Positive control: allowed host MUST NOT trip the allowlist 403.
#
# We cannot assert success here because the runner may have no
# internet access to sum.golang.org, the Go module being looked up
# may not exist, or the upstream may rate-limit. What we CAN assert
# is that the response is not the allowlist's 403. The fix's
# semantics are explicitly "403 = allowlist denied", so any non-403
# response demonstrates the allowlist check passed and the request
# was attempted upstream.
# ---------------------------------------------------------------------------

begin_test "Allow sum.golang.org (not 403)"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT --path-as-is \
  -H "$(format_auth_header)" \
  "${BASE_URL}/go/${REPO_KEY}/sumdb/sum.golang.org/lookup/golang.org/x/text@v0.14.0") || status=000
if [ "$status" != "403" ]; then
  pass
else
  fail "sum.golang.org returned 403; allowlist regressed to deny by default. Got: ${status}"
fi

# ---------------------------------------------------------------------------
# Case-insensitivity: per RFC 1035 DNS hostnames are case-insensitive,
# and the fix uses eq_ignore_ascii_case. Pin this so a future
# refactor to byte-equality doesn't silently denylist hostnames the
# Go toolchain might emit in any other casing.
# ---------------------------------------------------------------------------

begin_test "Allow SUM.GOLANG.ORG (case-insensitive, not 403)"
status=$(curl -s -o /dev/null -w '%{http_code}' $CURL_TIMEOUT --path-as-is \
  -H "$(format_auth_header)" \
  "${BASE_URL}/go/${REPO_KEY}/sumdb/SUM.GOLANG.ORG/lookup/golang.org/x/text@v0.14.0") || status=000
if [ "$status" != "403" ]; then
  pass
else
  fail "uppercase SUM.GOLANG.ORG returned 403; allowlist became case-sensitive. Got: ${status}"
fi

end_suite
