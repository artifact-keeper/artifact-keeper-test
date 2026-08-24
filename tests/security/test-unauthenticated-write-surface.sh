#!/usr/bin/env bash
# test-unauthenticated-write-surface.sh - anonymous callers cannot write, and
# the anonymous read surface carries no secrets
#
# Ported from tests/security/redteam/test-04-auth-bypass.sh, which could not
# fail: it sourced tests/security/redteam/lib.sh (fail() only incremented an
# unread counter) and ended in `exit 0`. See
# tests/security/README-redteam-port.md.
#
# Two changes were needed beyond wiring it to common.sh, because the original
# assertions were reachable but hollow:
#
#   1. The upload probes targeted hardcoded repository keys (`test-pypi`,
#      `test-npm`, `test-generic`) that this repo never creates. Every probe
#      404'd, and 404 was on the accept list, so "PyPI upload requires
#      authentication" passed on a backend that had no PyPI route at all. This
#      version creates its own PUBLIC repositories first, so a 401 is the auth
#      layer's verdict on a live route rather than the router's verdict on a
#      missing one, and it asserts the exact code (401) instead of accepting
#      401/403/404/422 interchangeably.
#
#   2. The "repository listing does not leak credentials" check ran against
#      whatever repositories happened to exist. On an empty instance the jq
#      filter matched nothing and passed vacuously. This version registers a
#      REMOTE repository configured with a known upstream username/password
#      first, then asserts those exact strings are absent from the anonymous
#      listing. The DTO omits them today (it reports the boolean
#      `upstream_auth_configured` instead), so this pins that shape.
#
# Repository listing being anonymously readable is a deliberate product
# decision (public repositories are discoverable), so it is not asserted
# against; what is asserted is that the anonymous projection carries no
# secrets.

source "$(dirname "$0")/../lib/common.sh"

begin_suite "unauthenticated-write-surface"
auth_admin
setup_workdir

PYPI_KEY="sec-anonwrite-pypi-${RUN_ID}"
NPM_KEY="sec-anonwrite-npm-${RUN_ID}"
GENERIC_KEY="sec-anonwrite-generic-${RUN_ID}"
REMOTE_KEY="sec-anonwrite-remote-${RUN_ID}"

# Distinctive so a grep for them in the anonymous projection cannot match
# anything else in the response.
UPSTREAM_USER="anonleak-user-${RUN_ID}"
UPSTREAM_PASS="anonleak-pass-${RUN_ID}"

cleanup_repos() {
  local key
  for key in "$PYPI_KEY" "$NPM_KEY" "$GENERIC_KEY" "$REMOTE_KEY"; do
    curl -s -o /dev/null "${CURL_TIMEOUT_ARGS[@]}" -X DELETE \
      -H "$(auth_header)" "${BASE_URL}/api/v1/repositories/${key}" >/dev/null 2>&1 || true
  done
}
add_exit_handler "cleanup_repos"

# ---------------------------------------------------------------------------
# Fixtures: real, PUBLIC repositories so every probe below hits a live route
# ---------------------------------------------------------------------------

begin_test "Create public repositories for the anonymous write probes"
created=true
for spec in "${PYPI_KEY}:pypi" "${NPM_KEY}:npm" "${GENERIC_KEY}:generic"; do
  if ! create_local_repo "${spec%%:*}" "${spec##*:}"; then
    created=false
  fi
done
if $created; then
  pass
else
  fail_fatal "could not create the fixture repositories" \
    "Every assertion below distinguishes 'the auth layer said no' from 'the route does not exist'. Without live repositories that distinction is gone and the suite would certify nothing."
fi

# ---------------------------------------------------------------------------
# Management API: writes must be refused without credentials
# ---------------------------------------------------------------------------

# assert_anonymous_401 NAME METHOD PATH [curl args...]
assert_anonymous_401() {
  local name="$1" method="$2" path="$3"
  shift 3
  local status
  status=$(curl -s -o "${WORK_DIR}/anon-resp.txt" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
    -X "$method" "$@" "${BASE_URL}${path}" 2>/dev/null) || status="000"
  local body
  body=$(head -c 400 "${WORK_DIR}/anon-resp.txt" 2>/dev/null) || body=""

  if [ "$status" = "401" ]; then
    pass
  elif [ "$status" = "000" ]; then
    fail "${name}: request did not complete (curl status 000); nothing was certified"
  else
    fail "${name}: ${method} ${path} returned ${status} without credentials, expected 401" \
      "A 2xx is an unauthenticated write. A 404 means the route is not mounted, which makes the probe meaningless rather than passing. Response: ${body}"
  fi
}

begin_test "Anonymous POST /api/v1/repositories is refused"
assert_anonymous_401 "create repository" POST "/api/v1/repositories" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"anon-created-${RUN_ID}\",\"name\":\"anon-created-${RUN_ID}\",\"format\":\"generic\",\"repo_type\":\"local\"}"

begin_test "Anonymous DELETE of an existing repository is refused"
assert_anonymous_401 "delete repository" DELETE "/api/v1/repositories/${GENERIC_KEY}"

begin_test "Anonymous GET /api/v1/users is refused"
assert_anonymous_401 "list users" GET "/api/v1/users"

# ---------------------------------------------------------------------------
# Format upload endpoints: publishing must require credentials
# ---------------------------------------------------------------------------

begin_test "Anonymous PyPI upload to a public repository is refused"
printf 'not-a-real-sdist' > "${WORK_DIR}/anon-pkg.tar.gz"
assert_anonymous_401 "pypi upload" POST "/api/v1/pypi/${PYPI_KEY}/" \
  -F "content=@${WORK_DIR}/anon-pkg.tar.gz;filename=anonpkg-0.1.0.tar.gz" \
  -F "name=anonpkg" -F "version=0.1.0"

begin_test "Anonymous npm publish to a public repository is refused"
assert_anonymous_401 "npm publish" PUT "/api/v1/npm/${NPM_KEY}/@anon%2fpkg" \
  -H "Content-Type: application/json" \
  -d '{"name":"@anon/pkg","versions":{"0.1.0":{"name":"@anon/pkg","version":"0.1.0"}}}'

begin_test "Anonymous generic upload to a public repository is refused"
assert_anonymous_401 "generic upload" PUT \
  "/api/v1/generic/${GENERIC_KEY}/anon-write/1.0.0/payload.bin" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "anonymous-write-probe"

# ---------------------------------------------------------------------------
# Anonymous read projection must not carry upstream credentials
# ---------------------------------------------------------------------------

begin_test "Register a remote repository holding upstream credentials"
remote_payload=$(cat <<JSON
{"key":"${REMOTE_KEY}","name":"${REMOTE_KEY}","format":"pypi","repo_type":"remote",
 "is_public":true,"upstream_url":"https://pypi.org",
 "upstream_username":"${UPSTREAM_USER}","upstream_password":"${UPSTREAM_PASS}"}
JSON
)
status=$(curl -s -o "${WORK_DIR}/remote-create.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
  -d "$remote_payload" "${BASE_URL}/api/v1/repositories" 2>/dev/null) || status="000"

if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail_fatal "could not register the credentialed remote repository (HTTP ${status})" \
    "The leak assertion below is vacuous without a repository that actually holds an upstream secret. Response: $(head -c 400 "${WORK_DIR}/remote-create.json" 2>/dev/null)"
fi

begin_test "Anonymous repository listing does not expose upstream credentials"
status=$(curl -s -o "${WORK_DIR}/anon-list.json" -w '%{http_code}' "${CURL_TIMEOUT_ARGS[@]}" \
  "${BASE_URL}/api/v1/repositories" 2>/dev/null) || status="000"

if [ "$status" = "401" ] || [ "$status" = "403" ]; then
  # Listing is not anonymous on this deployment; nothing can leak.
  pass
elif [ "$status" != "200" ]; then
  fail "anonymous GET /api/v1/repositories returned ${status}; expected 200 (public listing) or 401/403 (closed listing)" \
    "Neither shape means the anonymous projection could not be inspected. Response: $(head -c 400 "${WORK_DIR}/anon-list.json" 2>/dev/null)"
else
  # The fixture must be visible, otherwise the grep below proves nothing.
  if ! grep -q "$REMOTE_KEY" "${WORK_DIR}/anon-list.json" 2>/dev/null; then
    fail "the credentialed remote repository is absent from the anonymous listing" \
      "Without the fixture in the response, 'no credentials found' is vacuous. Anonymous listing (truncated): $(head -c 500 "${WORK_DIR}/anon-list.json" 2>/dev/null)"
  elif grep -q "$UPSTREAM_PASS" "${WORK_DIR}/anon-list.json" 2>/dev/null; then
    fail "the anonymous repository listing contains the upstream password" \
      "An unauthenticated caller can read the credentials this instance uses against its upstream registries. Repository: ${REMOTE_KEY}."
  elif grep -q "$UPSTREAM_USER" "${WORK_DIR}/anon-list.json" 2>/dev/null; then
    fail "the anonymous repository listing contains the upstream username" \
      "Half of an upstream credential pair is readable without authentication. Repository: ${REMOTE_KEY}."
  else
    secret_fields=$(jq -r '..|objects|keys[]?' "${WORK_DIR}/anon-list.json" 2>/dev/null \
      | grep -iE '^(password|secret|token|credentials?|api_key|private_key|upstream_password|upstream_username)$' \
      | sort -u | tr '\n' ' ') || secret_fields=""
    if [ -n "$secret_fields" ]; then
      fail "the anonymous repository listing exposes secret-shaped fields: ${secret_fields}" \
        "The anonymous projection should carry only the boolean upstream_auth_configured, never the credential fields themselves."
    else
      pass
    fi
  fi
fi

end_suite
