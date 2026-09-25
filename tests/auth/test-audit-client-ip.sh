#!/usr/bin/env bash
# test-audit-client-ip.sh - client IP in authentication audit logs (#3888)
#
# Before #3888, every authentication audit event (LOGIN, LOGOUT, token
# refresh, SSO, TOTP) was written to audit_log with ip_address = NULL. The
# fix resolves the request's client IP (TCP peer authoritative,
# X-Forwarded-For believed under the trusted-proxy policy) and attaches it
# to every authentication audit entry.
#
# This suite logs in, then reads the newest LOGIN row back through the admin
# audit API and requires a non-null ip_address. On an UNFIXED backend the
# row comes back with ip_address = null and the case FAILS.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "audit-client-ip"

auth_admin

begin_test "Newest LOGIN audit row carries a client IP address"
# The login that just happened in auth_admin is the newest LOGIN event. Ask
# for it specifically and require ip_address to be present and plausible.
audit_json=$(curl -sf --max-time 10 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/admin/audit?action=LOGIN&per_page=1" 2>/dev/null) || audit_json=""
if [ -z "$audit_json" ]; then
  fail "could not query /api/v1/admin/audit?action=LOGIN"
fi

ip=$(echo "$audit_json" | jq -r '.items[0].ip_address // empty' 2>/dev/null)
actor=$(echo "$audit_json" | jq -r '.items[0].actor_username // empty' 2>/dev/null)
if [ -z "$ip" ]; then
  fail "newest LOGIN audit row (actor=${actor:-unknown}) has ip_address = null (#3888)"
elif echo "$ip" | grep -qE '^[0-9a-fA-F:.]+$'; then
  pass "newest LOGIN audit row (actor=${actor:-unknown}) carries ip_address=${ip}"
else
  fail "newest LOGIN audit row carries a non-IP ip_address value: '${ip}'"
fi

begin_test "A failed login also records the client IP"
# A bad-password attempt emits LOGIN_FAILED with the same IP attribution;
# SIEM rules key off it for brute-force detection.
_=$(curl -s -o /dev/null --max-time 10 \
  -X POST "${BASE_URL}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"definitely-wrong-${RUN_ID}\"}" 2>/dev/null)
failed_json=$(curl -sf --max-time 10 \
  -H "$(auth_header)" \
  "${BASE_URL}/api/v1/admin/audit?action=LOGIN_FAILED&per_page=1" 2>/dev/null) || failed_json=""
if [ -z "$failed_json" ]; then
  fail "could not query /api/v1/admin/audit?action=LOGIN_FAILED"
fi
failed_ip=$(echo "$failed_json" | jq -r '.items[0].ip_address // empty' 2>/dev/null)
if [ -z "$failed_ip" ]; then
  fail "newest LOGIN_FAILED audit row has ip_address = null (#3888)"
else
  pass "newest LOGIN_FAILED audit row carries ip_address=${failed_ip}"
fi

end_suite
