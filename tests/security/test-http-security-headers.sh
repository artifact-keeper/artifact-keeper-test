#!/usr/bin/env bash
# test-http-security-headers.sh - browser-facing response headers are set
#
# Ported from tests/security/redteam/test-02-security-headers.sh, which could
# not fail: it sourced tests/security/redteam/lib.sh (fail() only incremented
# an unread counter) and ended in `exit 0`. See
# tests/security/README-redteam-port.md.
#
# This is the only place in the repo that asserts on X-Frame-Options,
# X-Content-Type-Options, Content-Security-Policy or Strict-Transport-Security
# (`grep -rl 'X-Frame-Options' tests/` returns this file alone), so the
# assertions are not duplicated by a working sibling.
#
# Why the header set is hard-asserted rather than warned about
# -----------------------------------------------------------
# The backend serves the web console's API on the same origin. Every one of
# these headers is currently emitted on every response by the middleware
# stack; dropping one is a silent regression in a middleware ordering change,
# which is exactly the class a release gate should catch. The values are
# asserted loosely (presence, plus the one directive that carries the
# security property) so a legitimate policy tightening does not red the gate.
#
# X-Powered-By and Server are checked in the other direction: they must be
# absent. They are a version-disclosure surface and neither is emitted today.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "http-security-headers"
auth_admin
setup_workdir

# Collect the headers once, from a real GET (not HEAD): that is what a browser
# sees. /health is unauthenticated and always routed, so a missing header here
# means the middleware is not applied, not that a route is gone.
HDR_FILE="${WORK_DIR}/health-headers.txt"
status=$(curl -s -D "$HDR_FILE" -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  "${BASE_URL}/health" 2>/dev/null) || status="000"

begin_test "GET /health returns response headers"
if [ "$status" = "000" ] || [ ! -s "$HDR_FILE" ]; then
  fail_fatal "could not retrieve response headers from GET /health (status ${status})" \
    "Every assertion in this suite reads the header block captured here. Without it the suite would report all-skip, which certifies nothing."
else
  pass
fi

# Normalise: strip CR so ^name: anchors match, and lowercase the header names.
HEADERS=$(tr -d '\r' < "$HDR_FILE" | sed 's/^\([A-Za-z0-9-]*\):/\L\1:/')

# header_value NAME -> echoes the value of the (lowercased) header, or empty.
# Always returns 0: a missing header is an expected outcome here (it is what
# half these assertions are looking for), and under `set -euo pipefail` a
# non-matching grep inside a command substitution would abort the suite before
# the assertion could record its verdict.
header_value() {
  echo "$HEADERS" | grep -i "^${1}:" | head -1 | sed 's/^[^:]*: *//' || true
}

# ---------------------------------------------------------------------------
# Required headers
# ---------------------------------------------------------------------------

begin_test "X-Frame-Options is set to DENY or SAMEORIGIN"
value=$(header_value "x-frame-options")
if [ -z "$value" ]; then
  fail "X-Frame-Options header is missing from GET /health" \
    "Without it the API origin can be framed, which is the clickjacking precondition. Headers seen: $(echo "$HEADERS" | tr '\n' ' ')"
elif echo "$value" | grep -qiE '^(DENY|SAMEORIGIN)$'; then
  pass
else
  fail "X-Frame-Options has an unexpected value: ${value}" "Expected DENY or SAMEORIGIN."
fi

begin_test "X-Content-Type-Options is nosniff"
value=$(header_value "x-content-type-options")
if [ -z "$value" ]; then
  fail "X-Content-Type-Options header is missing from GET /health" \
    "Browsers may MIME-sniff artifact bytes served from this origin. Headers seen: $(echo "$HEADERS" | tr '\n' ' ')"
elif echo "$value" | grep -qi 'nosniff'; then
  pass
else
  fail "X-Content-Type-Options has an unexpected value: ${value}" "Expected nosniff."
fi

begin_test "Content-Security-Policy is present and forbids framing"
value=$(header_value "content-security-policy")
if [ -z "$value" ]; then
  fail "Content-Security-Policy header is missing from GET /health" \
    "Headers seen: $(echo "$HEADERS" | tr '\n' ' ')"
elif echo "$value" | grep -qi "frame-ancestors"; then
  pass
else
  fail "Content-Security-Policy is present but declares no frame-ancestors directive" \
    "Value: ${value}. frame-ancestors is the directive that carries the anti-framing property; a CSP without it leaves X-Frame-Options as the only defence."
fi

begin_test "Strict-Transport-Security declares a non-zero max-age"
value=$(header_value "strict-transport-security")
if [ -z "$value" ]; then
  fail "Strict-Transport-Security header is missing from GET /health" \
    "Headers seen: $(echo "$HEADERS" | tr '\n' ' ')"
else
  max_age=$(echo "$value" | grep -oiE 'max-age=[0-9]+' | head -1 | cut -d= -f2)
  if [ -n "$max_age" ] && [ "$max_age" -gt 0 ] 2>/dev/null; then
    pass
  else
    fail "Strict-Transport-Security has no positive max-age: ${value}" \
      "max-age=0 instructs the browser to forget the HSTS pin, which is equivalent to not sending the header."
  fi
fi

# ---------------------------------------------------------------------------
# Headers that must NOT be present (version disclosure)
# ---------------------------------------------------------------------------

begin_test "Server header does not disclose the implementation"
value=$(header_value "server")
if [ -z "$value" ]; then
  pass
else
  fail "Server header is present and discloses ${value}" \
    "The backend does not emit a Server header today. One appearing means a proxy or middleware started advertising the stack (and often its version) to every caller."
fi

begin_test "X-Powered-By header is absent"
value=$(header_value "x-powered-by")
if [ -z "$value" ]; then
  pass
else
  fail "X-Powered-By header is present and discloses ${value}"
fi

end_suite
