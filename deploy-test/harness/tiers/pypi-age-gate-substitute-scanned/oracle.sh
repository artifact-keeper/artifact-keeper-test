#!/usr/bin/env bash
# =============================================================================
# tiers/pypi-age-gate-substitute-scanned/oracle.sh: the age-gate substitute
# download carries the scan result header like any other distribution download
# (artifact-keeper#5075, PR #5077)
# =============================================================================
# run.sh has already stood up `filesystem + upstreams.mockpypi-agegate`: the
# backend plus `mock-pypi` (pypi-age-gate-pep440-lookup/fixtures/
# mock_pypi_agegate.py). run.sh exported BASE_URL, ADMIN_USER, ADMIN_PASS,
# RUN_ID, DTF_SLOT, DB_CONTAINER, COMMON_SH.
#
# One Remote PyPI repo over http://mock-pypi/ with scan_on_proxy (fail_closed)
# and the age gate (min_age_days 7, mode upstream_publish_time). The mock's
# Warehouse JSON keys releases 13.4.2 (2026-09-16) and 13.5.0 (a day ago). An
# `artifacts` row for 13.4.2 is seeded so the gate has a last-known-good
# version; a GET of the young 13.5.0 wheel is answered with the 13.4.2 wheel.
#
# Order matters: the substitute GET runs first, on a cold cache with no scan
# verdict for the 13.4.2 digest, so its header and verdict row can only come
# from the substitute download itself. A direct GET of the old 13.0.3.0 wheel
# (no seeded row, so the plain scan-on-proxy route) is the control showing
# the scan header on both images.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"; : "${DB_CONTAINER:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "pypi-age-gate-substitute-scanned-5075"
auth_admin
setup_workdir

PKG="cuda-toolkit"
REPO="dtf-pypi-agesub-${RUN_ID}"
MOCK="ak-dtf${DTF_SLOT}-mock-pypi"
MOCK_UPSTREAM="http://mock-pypi/"
TAG="py2.py3-none-any"
LKG_VERSION="13.4.2"
LKG_WHEEL="cuda_toolkit-${LKG_VERSION}-${TAG}.whl"   # release 13.4.2 (old)
YOUNG_WHEEL="cuda_toolkit-13.5.0-${TAG}.whl"         # release 13.5.0, uploaded a day ago
OTHER_WHEEL="cuda_toolkit-13.0.3.0-${TAG}.whl"       # release 13.0.3 (old), no seeded row

cleanup_repos() {
  api_delete "/api/v1/repositories/${REPO}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repos"

psql_q() {
  docker exec "$DB_CONTAINER" psql -U registry -d artifact_registry -v ON_ERROR_STOP=1 -Atc "$1" 2>&1 || true
}

api_call() { # METHOD PATH [BODY] -> sets API_STATUS + API_BODY
  local method="$1" path="$2" body="${3:-}" tmp
  tmp="${WORK_DIR}/api.$$"
  if [ -n "$body" ]; then
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' --max-time 30 -X "$method" \
      -H "$(auth_header)" -H 'Content-Type: application/json' \
      -d "$body" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  else
    API_STATUS=$(curl -s -o "$tmp" -w '%{http_code}' --max-time 30 -X "$method" \
      -H "$(auth_header)" "${BASE_URL}${path}" 2>/dev/null) || API_STATUS=000
  fi
  API_BODY="$(cat "$tmp" 2>/dev/null)"; rm -f "$tmp"
}

# get_download FILENAME OUTFILE HEADERFILE -> status
get_download() {
  curl -s -o "$2" -D "$3" -w '%{http_code}' --max-time 90 -H "$(auth_header)" \
    "${BASE_URL}/pypi/${REPO}/simple/${PKG}/$1" 2>/dev/null || echo "000"
}

# x_ak_scan HEADERFILE -> value of the X-AK-Scan header (empty when absent)
x_ak_scan() {
  grep -i '^x-ak-scan:' "$1" 2>/dev/null | tr -d '\r' | sed 's/^[^:]*:[[:space:]]*//' | head -1 || true
}

# The sha256 the mock advertises for FILENAME (from its own HTML index).
mock_sha() {
  docker exec "$MOCK" python3 -c \
    "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1/simple/${PKG}/').read().decode())" \
    2>/dev/null | grep -oE "files/$1#sha256=[0-9a-f]{64}" | sed 's/.*sha256=//' | head -1 || true
}

file_sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}' || true; }

LKG_SHA="$(mock_sha "$LKG_WHEEL")"

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: create REMOTE pypi repo over the mock (${MOCK_UPSTREAM})"
payload=$(jq -n --arg k "$REPO" --arg u "$MOCK_UPSTREAM" \
  '{key:$k, name:$k, format:"pypi", repo_type:"remote", upstream_url:$u, is_public:true}')
api_call POST "/api/v1/repositories" "$payload"
if [ "$API_STATUS" -ge 200 ] 2>/dev/null && [ "$API_STATUS" -lt 300 ] 2>/dev/null; then pass
else fail "remote PyPI create rejected (HTTP ${API_STATUS})" "${API_BODY:0:300}"; end_suite; fi

begin_test "Setup: enable scan + scan_on_proxy + fail_closed"
api_call PUT "/api/v1/repositories/${REPO}/security" \
  '{"scan_enabled":true,"scan_on_proxy":true,"proxy_scan_action":"fail_closed","block_on_policy_violation":true}'
got="$(printf '%s' "$API_BODY" | jq -r '"\(.scan_on_proxy)|\(.proxy_scan_action)"' 2>/dev/null)"
if [ "$API_STATUS" = "200" ] && [ "$got" = "true|fail_closed" ]; then pass
else fail "scan config not applied (HTTP ${API_STATUS} -> ${got})" "${API_BODY:0:300}"; end_suite; fi

begin_test "Setup: enable the age gate (min_age_days 7, mode upstream_publish_time)"
api_call PUT "/api/v1/repositories/${REPO}/age-gate" \
  '{"enabled":true,"min_age_days":7,"mode":"upstream_publish_time"}'
put_status="$API_STATUS"; put_body="$API_BODY"
api_call GET "/api/v1/repositories/${REPO}/age-gate"
got="$(printf '%s' "$API_BODY" | jq -r '"\(.enabled)|\(.min_age_days)|\(.mode)"' 2>/dev/null)"
if [ "$put_status" = "200" ] && [ "$got" = "true|7|upstream_publish_time" ]; then pass
else fail "age gate not configured (PUT ${put_status}, GET ${API_STATUS} -> ${got})" "${put_body:0:300}"; end_suite; fi

begin_test "Setup: seed the last-known-good row (${PKG} ${LKG_VERSION}) for the repo"
seeded=""
if [ -n "$LKG_SHA" ]; then
  seeded="$(psql_q "
INSERT INTO artifacts (repository_id, path, name, version, size_bytes, checksum_sha256,
                       content_type, storage_key)
SELECT id, 'simple/${PKG}/${LKG_WHEEL}', '${PKG}', '${LKG_VERSION}', 1, '${LKG_SHA}',
       'application/zip', 'seed/${REPO}/${LKG_WHEEL}'
  FROM repositories WHERE key = '${REPO}';
SELECT count(*) FROM artifacts a JOIN repositories r ON r.id = a.repository_id
 WHERE r.key = '${REPO}' AND a.version = '${LKG_VERSION}';" | tail -1)"
fi
if [ "$seeded" = "1" ]; then pass
else fail "could not seed the last-known-good row (mock sha '${LKG_SHA}')" "${seeded:0:300}"; end_suite; fi

begin_test "Setup: no scan verdict exists yet for the ${LKG_WHEEL} digest"
pre="$(psql_q "SELECT count(*) FROM proxy_scan_results WHERE checksum_sha256 = '${LKG_SHA}';" | tail -1)"
if [ "$pre" = "0" ]; then pass
else fail "expected no verdict row before the substitute download, found '${pre}'"; end_suite; fi

# ---------------------------------------------------------------------------
# The age-gate substitute download
# ---------------------------------------------------------------------------
SUB_OUT="${WORK_DIR}/substitute.bin"; SUB_HDR="${WORK_DIR}/substitute.hdr"
sub_status="$(get_download "$YOUNG_WHEEL" "$SUB_OUT" "$SUB_HDR")"
sub_scan="$(x_ak_scan "$SUB_HDR")"
sub_sha="$(file_sha "$SUB_OUT")"
sub_snip="HTTP ${sub_status} X-AK-Scan='${sub_scan}' sha=${sub_sha:-none} (13.4.2 mock sha ${LKG_SHA:-unknown})
headers:
$(tr -d '\r' < "$SUB_HDR" 2>/dev/null | head -20 || true)"

begin_test "CONTROL: GET ${YOUNG_WHEEL} (withheld) is answered 200 with the ${LKG_VERSION} substitute bytes"
if [ "$sub_status" = "200" ] && [ -n "$LKG_SHA" ] && [ "$sub_sha" = "$LKG_SHA" ]; then pass
else fail "expected the age gate to answer with the ${LKG_VERSION} wheel" "$sub_snip"; fi

begin_test "FIX #5075: the age-gate substitute download carries X-AK-Scan: clean"
if [ "$sub_scan" = "clean" ]; then pass
else fail "#5075: the substitute download did not carry the scan result header like other distribution downloads" "$sub_snip"; fi

begin_test "FIX #5075: a clean scan verdict was recorded for the substitute's digest"
rows="$(psql_q "SELECT verdict FROM proxy_scan_results WHERE checksum_sha256 = '${LKG_SHA}';")"
if printf '%s\n' "$rows" | grep -qx "clean"; then pass
else fail "#5075: no clean proxy_scan_results row for the ${LKG_WHEEL} digest after the substitute download" "rows='${rows:0:300}'"; fi

# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------
begin_test "CONTROL: direct GET ${OTHER_WHEEL} (old, not seeded) serves 200 with X-AK-Scan: clean"
st="$(get_download "$OTHER_WHEEL" "${WORK_DIR}/direct.bin" "${WORK_DIR}/direct.hdr")"
scan="$(x_ak_scan "${WORK_DIR}/direct.hdr")"; got="$(file_sha "${WORK_DIR}/direct.bin")"
want="$(mock_sha "$OTHER_WHEEL")"
if [ "$st" = "200" ] && [ "$scan" = "clean" ] && [ -n "$want" ] && [ "$got" = "$want" ]; then pass
else fail "direct download HTTP ${st} X-AK-Scan='${scan}' sha ${got:-none} vs mock ${want:-unknown}"; fi

begin_test "CONTROL: the backend fetched /pypi/${PKG}/json from the mock"
mlog="$(docker exec "$MOCK" python3 -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1/__log').read().decode())" 2>/dev/null || true)"
if printf '%s' "$mlog" | grep -q "GET /pypi/${PKG}/json"; then pass
else fail "no Warehouse JSON fetch in the mock log" "${mlog:0:1200}"; fi

end_suite
