#!/usr/bin/env bash
# =============================================================================
# tiers/pypi-contenttype/oracle.sh — PyPI Content-Type-trust oracle (#2801)
# =============================================================================
# run.sh has already stood up `filesystem + upstreams.mockpypi`: the backend
# plus a canned upstream `mock-pypi` that serves a VALID PEP 691 JSON
# simple-index body with a LYING `Content-Type: application/octet-stream`. It
# exported BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, RELEASE_GATE=1, DTF_SLOT,
# DB_CONTAINER, JUNIT_OUTPUT_DIR. We source common.sh for the assertion + JUnit
# harness.
#
# The bug (#2801): the simple-index proxy render TRUSTS the upstream
# Content-Type. Because the mock's Content-Type is neither JSON nor text/html,
# a pre-#2801 backend falls through to serving the RAW upstream bytes with the
# upstream's own Content-Type — leaking the offsite `files.pythonhosted.org`
# download URL AND handing uv `application/octet-stream` (which it rejects).
#
# Discriminating assertion, applied over BOTH the direct remote AND a virtual
# repo layered over it, using uv's Accept header
# (application/vnd.pypi.simple.v1+json):
#   * the response Content-Type is a REAL simple-index type
#     (application/vnd.pypi.simple.v1+json OR text/html), NOT
#     application/octet-stream, AND
#   * the body contains NO offsite `files.pythonhosted` / `mock-pypi` download
#     URL — every file URL is rewritten under `/pypi/<repo>/...`.
#
# EXPECTED OUTCOME on artifact-keeper-backend:1.6.1-rc (pre-#2801): FAIL — the
# render leaks octet-stream + the pythonhosted URL. That failing run is the
# proof the oracle discriminates. It flips to PASS on the #2801 fix image.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "pypi-contenttype-2801"
auth_admin
setup_workdir

PKG="dtfpkg"
REMOTE_KEY="dtf-pypi-remote-${RUN_ID}"
VIRTUAL_KEY="dtf-pypi-virtual-${RUN_ID}"
MOCK_UPSTREAM="http://mock-pypi/"
UV_ACCEPT="application/vnd.pypi.simple.v1+json"

cleanup_repos() {
  api_delete "/api/v1/repositories/${VIRTUAL_KEY}" >/dev/null 2>&1 || true
  api_delete "/api/v1/repositories/${REMOTE_KEY}"  >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repos"

# create_repo_raw PAYLOAD -> echoes "<status>|<body>"
create_repo_raw() {
  local payload="$1" body_file status body
  body_file="${WORK_DIR}/create.$$"
  status=$(curl -s -o "$body_file" -w '%{http_code}' --max-time 30 \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$payload" "${BASE_URL}/api/v1/repositories" 2>/dev/null) || status="000"
  body=$(cat "$body_file" 2>/dev/null || echo ""); rm -f "$body_file"
  echo "${status}|${body}"
}

# ---------------------------------------------------------------------------
# Setup: a remote (proxy) PyPI repo over the mock, and a virtual over it.
# ---------------------------------------------------------------------------
begin_test "Setup: create remote PyPI repo over mock upstream (${MOCK_UPSTREAM})"
payload=$(jq -n --arg k "$REMOTE_KEY" --arg u "$MOCK_UPSTREAM" \
  '{key:$k, name:$k, format:"pypi", repo_type:"remote", upstream_url:$u, is_public:true}')
resp=$(create_repo_raw "$payload"); status="${resp%%|*}"; body="${resp#*|}"
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  pass
else
  fail "remote PyPI create REJECTED (HTTP ${status}); cannot run the tier. body=${body:0:200}"
  end_suite
fi

begin_test "Setup: create virtual PyPI repo aggregating the remote"
payload=$(jq -n --arg k "$VIRTUAL_KEY" \
  '{key:$k, name:$k, format:"pypi", repo_type:"virtual", is_public:true}')
resp=$(create_repo_raw "$payload"); status="${resp%%|*}"; body="${resp#*|}"
if [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ] 2>/dev/null; then
  # Add the remote as a member.
  member_payload=$(jq -n --arg m "$REMOTE_KEY" '{member_key:$m}')
  mstatus=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
    -X POST -H "$(auth_header)" -H "Content-Type: application/json" \
    -d "$member_payload" "${BASE_URL}/api/v1/repositories/${VIRTUAL_KEY}/members" 2>/dev/null) || mstatus="000"
  if [ "$mstatus" -ge 200 ] 2>/dev/null && [ "$mstatus" -lt 300 ] 2>/dev/null; then
    pass
  else
    fail "could not add remote '${REMOTE_KEY}' as member of virtual '${VIRTUAL_KEY}' (HTTP ${mstatus})"
  fi
else
  fail "virtual PyPI create REJECTED (HTTP ${status}). body=${body:0:200}"
fi

# ---------------------------------------------------------------------------
# The discriminating render check, over one repo key.
# ---------------------------------------------------------------------------
assert_clean_render() {
  local label="$1" key="$2"
  begin_test "${label}: /pypi/${key}/simple/${PKG}/ with uv Accept is a real simple-index type, no offsite URL [#2801]"

  local hdr_file body_file status ct body
  hdr_file="${WORK_DIR}/hdr.$$"; body_file="${WORK_DIR}/body.$$"
  status=$(curl -s -D "$hdr_file" -o "$body_file" -w '%{http_code}' --max-time 40 \
    -H "$(auth_header)" -H "Accept: ${UV_ACCEPT}" \
    "${BASE_URL}/pypi/${key}/simple/${PKG}/" 2>/dev/null) || status="000"
  ct=$(grep -i '^content-type:' "$hdr_file" 2>/dev/null | tr -d '\r' | head -1 | sed 's/^[Cc]ontent-[Tt]ype:[[:space:]]*//')
  body=$(cat "$body_file" 2>/dev/null || echo "")
  rm -f "$hdr_file" "$body_file"

  # Classify.
  local is_octet=0 is_realtype=0 leaked=0
  printf '%s' "$ct"   | grep -qi 'application/octet-stream'                        && is_octet=1
  printf '%s' "$ct"   | grep -qiE 'vnd\.pypi\.simple\.v1\+json|text/html'          && is_realtype=1
  printf '%s' "$body" | grep -qiE 'files\.pythonhosted|://mock-pypi'              && leaked=1

  local snippet="HTTP ${status}  Content-Type='${ct}'
body[0:400]=${body:0:400}"

  if [ "$status" != "200" ]; then
    # A fixed backend serves 200 (valid JSON body). A 5xx here on a valid JSON
    # upstream is itself a render failure, not the intended 502-on-garbage.
    fail "${label}: expected HTTP 200, got ${status}" "$snippet"
    return
  fi
  if [ "$is_octet" = "1" ]; then
    fail "#2801 [${label}]: response Content-Type is application/octet-stream (upstream header trusted, not sniffed)" "$snippet"
    return
  fi
  if [ "$is_realtype" != "1" ]; then
    fail "#2801 [${label}]: Content-Type '${ct}' is not a real simple-index type (v1+json or text/html)" "$snippet"
    return
  fi
  if [ "$leaked" = "1" ]; then
    fail "#2801 [${label}]: response body leaks an offsite download URL (files.pythonhosted / mock-pypi) — URLs not rewritten under /pypi/${key}/" "$snippet"
    return
  fi
  pass
}

assert_clean_render "direct-remote" "$REMOTE_KEY"
assert_clean_render "virtual"       "$VIRTUAL_KEY"

end_suite
