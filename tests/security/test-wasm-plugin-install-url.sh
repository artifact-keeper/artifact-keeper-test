#!/usr/bin/env bash
# test-wasm-plugin-install-url.sh - plugin install endpoints validate the
# source URL and require authentication
#
# Ported from tests/security/redteam/test-11-wasm-plugin.sh, which could not
# fail: it sourced tests/security/redteam/lib.sh (fail() only incremented an
# unread counter) and ended in `exit 0`. See
# tests/security/README-redteam-port.md.
#
# Not covered by the working sibling
# ----------------------------------
# tests/security/test-wasm-sandbox.sh validates the plugin BYTES
# (POST /api/v1/plugins/install/upload rejects a malformed module). It says
# nothing about the git-install path, where the attacker input is a URL rather
# than a module: `file:///etc/passwd` is a local-file read primitive and
# `gopher://`/`dict://` are classic SSRF smuggling schemes. Nor does it check
# that the plugin endpoints require authentication, which matters more here
# than elsewhere because installing a plugin is remote code execution by
# design.
#
# The scheme allowlist is currently enforced (each probe below returns 400 on
# 1.8.x), so these are regression guards, not aspirations.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "wasm-plugin-install-url"
auth_admin
setup_workdir

# ---------------------------------------------------------------------------
# Pre-flight: is the plugin subsystem mounted?
# ---------------------------------------------------------------------------
#
# A 404 here is a genuine not-shipped capability rather than a defect, and the
# repo already carries a documented capability exemption for the plugin
# overlay not being loaded in the gate deploy (_CAPABILITY_EXEMPTIONS in
# tests/lib/common.sh, keys wasm_plugin_fixture). We deliberately route
# through skip_suite so the RELEASE_GATE contract decides, rather than
# exiting 0 on our own authority.

plugin_status=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -H "$(auth_header)" "${BASE_URL}/api/v1/plugins" 2>/dev/null) || plugin_status="000"

if [ "$plugin_status" = "404" ]; then
  skip_suite "plugin endpoints not mounted (HTTP 404); backend deploy may not include the plugin overlay"
fi

begin_test "Plugin subsystem is reachable with admin credentials"
if [ "$plugin_status" = "200" ]; then
  pass
else
  fail_fatal "GET /api/v1/plugins returned ${plugin_status} for an admin token, expected 200" \
    "Every probe below distinguishes 'the validator said no' from 'the route is missing'. Without a reachable subsystem the suite would certify nothing."
fi

# ---------------------------------------------------------------------------
# Source-URL validation on the git install path
# ---------------------------------------------------------------------------

# assert_scheme_rejected LABEL URL
# The install endpoint must refuse the URL outright (400/422). A 2xx means the
# scheme reached the fetcher.
assert_scheme_rejected() {
  local label="$1" url="$2"
  local status body
  status=$(curl -s -o "${WORK_DIR}/plugin-install.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "{\"url\": \"${url}\"}" \
    "${BASE_URL}/api/v1/plugins/install/git" 2>/dev/null) || status="000"
  body=$(head -c 400 "${WORK_DIR}/plugin-install.json" 2>/dev/null) || body=""

  if [ "$status" = "400" ] || [ "$status" = "422" ]; then
    pass
  elif [ "$status" = "000" ]; then
    fail "${label}: request did not complete (curl status 000); nothing was certified"
  elif [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
    fail "${label}: the install endpoint accepted ${url} (HTTP ${status})" \
      "The URL passed validation and reached the fetcher. Installing a plugin is remote code execution by design, so the source URL is the trust boundary. Response: ${body}"
  else
    fail "${label}: ${url} returned ${status}, expected 400 or 422" \
      "The scheme was not rejected by the validator. A 5xx in particular means the fetcher was invoked before the URL was checked. Response: ${body}"
  fi
}

begin_test "Git install rejects file:// (local file read)"
assert_scheme_rejected "file scheme" "file:///etc/passwd"

begin_test "Git install rejects gopher:// (request smuggling)"
assert_scheme_rejected "gopher scheme" "gopher://attacker.example.com:6379/_SET%20x%20y"

begin_test "Git install rejects dict:// (service probing)"
assert_scheme_rejected "dict scheme" "dict://attacker.example.com:11211/stat"

begin_test "Git install rejects ftp://"
assert_scheme_rejected "ftp scheme" "ftp://attacker.example.com/plugin.git"

# ---------------------------------------------------------------------------
# Authentication on the plugin surface
# ---------------------------------------------------------------------------

begin_test "Plugin endpoints reject unauthenticated callers"
unauth_failures=""
for endpoint in "/api/v1/plugins" "/api/v1/plugins/install/git" "/api/v1/plugins/install/zip"; do
  status=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    "${BASE_URL}${endpoint}" 2>/dev/null) || status="000"
  case "$status" in
    401|403|405) : ;;  # 405 = route exists, method not allowed before auth
    *) unauth_failures="${unauth_failures}${endpoint} -> ${status}; " ;;
  esac
done

if [ -z "$unauth_failures" ]; then
  pass
else
  fail "plugin endpoints answered an unauthenticated caller: ${unauth_failures}" \
    "Plugin installation is remote code execution. Any status other than 401/403 (or 405 for a method the route does not serve) means the surface is reachable without credentials."
fi

end_suite
