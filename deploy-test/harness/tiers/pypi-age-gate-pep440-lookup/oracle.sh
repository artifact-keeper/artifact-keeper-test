#!/usr/bin/env bash
# =============================================================================
# tiers/pypi-age-gate-pep440-lookup/oracle.sh: a PEP 440-equal filename
# version resolves to its release's publish time (artifact-keeper#4907, #4908)
# =============================================================================
# run.sh has already stood up `filesystem + upstreams.mockpypi-agegate`: the
# backend plus `mock-pypi` (fixtures/mock_pypi_agegate.py). run.sh exported
# BASE_URL, ADMIN_USER, ADMIN_PASS, RUN_ID, DTF_SLOT, COMMON_SH.
#
# One remote PyPI repo over http://mock-pypi/ with the age gate enabled
# (min_age_days 7, mode upstream_publish_time). The mock's Warehouse JSON keys
# releases 13.0.3 (2026-04-14), 13.4.2 (2026-09-16) and 13.5.0 (a day ago);
# its simple index lists the files
#   cuda_toolkit-13.0.3.0-...whl  release 13.0.3, PEP 440-equal  -> served (FIX)
#   cuda_toolkit-13.4.2-...whl    release 13.4.2, exact key      -> served
#   cuda_toolkit-13.5.0-...whl    release 13.5.0, young          -> withheld
#   cuda_toolkit-13.0.3.1-...whl  no equal release key           -> withheld
#
# Order matters only for hygiene: the listings are read first, then the two
# withheld downloads, then the two served ones.
# =============================================================================
set -uo pipefail
: "${BASE_URL:?}"; : "${COMMON_SH:?}"; : "${DTF_SLOT:?}"

# shellcheck source=/dev/null
source "$COMMON_SH"

begin_suite "pypi-age-gate-pep440-lookup-4907"
auth_admin
setup_workdir

PKG="cuda-toolkit"
REPO="dtf-pypi-agegate-${RUN_ID}"
MOCK="ak-dtf${DTF_SLOT}-mock-pypi"
MOCK_UPSTREAM="http://mock-pypi/"
TAG="py2.py3-none-any"
EQUAL_WHEEL="cuda_toolkit-13.0.3.0-${TAG}.whl"    # release 13.0.3 (old), PEP 440-equal
EXACT_WHEEL="cuda_toolkit-13.4.2-${TAG}.whl"      # release 13.4.2 (old), exact key
YOUNG_WHEEL="cuda_toolkit-13.5.0-${TAG}.whl"      # release 13.5.0, uploaded a day ago
ORPHAN_WHEEL="cuda_toolkit-13.0.3.1-${TAG}.whl"   # no PEP 440-equal release key

cleanup_repos() {
  api_delete "/api/v1/repositories/${REPO}" >/dev/null 2>&1 || true
}
add_exit_handler "cleanup_repos"

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

# get_index ACCEPT OUTFILE -> "status|content-type"
get_index() {
  local accept="$1" out="$2" meta
  meta=$(curl -s -o "$out" -w '%{http_code}|%{content_type}' --max-time 40 \
    -H "$(auth_header)" -H "Accept: ${accept}" \
    "${BASE_URL}/pypi/${REPO}/simple/${PKG}/" 2>/dev/null) || meta="000|"
  echo "$meta"
}

# get_download FILENAME OUTFILE -> status
get_download() {
  curl -s -o "$2" -w '%{http_code}' --max-time 40 -H "$(auth_header)" \
    "${BASE_URL}/pypi/${REPO}/simple/${PKG}/$1" 2>/dev/null || echo "000"
}

# The sha256 the mock advertises for FILENAME (from its own HTML index).
mock_sha() {
  docker exec "$MOCK" python3 -c \
    "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1/simple/${PKG}/').read().decode())" \
    2>/dev/null | grep -oE "files/$1#sha256=[0-9a-f]{64}" | sed 's/.*sha256=//' | head -1
}

file_sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
begin_test "Setup: create REMOTE pypi repo over the mock (${MOCK_UPSTREAM})"
payload=$(jq -n --arg k "$REPO" --arg u "$MOCK_UPSTREAM" \
  '{key:$k, name:$k, format:"pypi", repo_type:"remote", upstream_url:$u, is_public:true}')
api_call POST "/api/v1/repositories" "$payload"
if [ "$API_STATUS" -ge 200 ] 2>/dev/null && [ "$API_STATUS" -lt 300 ] 2>/dev/null; then pass
else fail "remote PyPI create rejected (HTTP ${API_STATUS})" "${API_BODY:0:300}"; end_suite; fi

begin_test "Setup: enable the age gate (min_age_days 7, mode upstream_publish_time)"
api_call PUT "/api/v1/repositories/${REPO}/age-gate" \
  '{"enabled":true,"min_age_days":7,"mode":"upstream_publish_time"}'
put_status="$API_STATUS"; put_body="$API_BODY"
api_call GET "/api/v1/repositories/${REPO}/age-gate"
got="$(printf '%s' "$API_BODY" | jq -r '"\(.enabled)|\(.min_age_days)|\(.mode)"' 2>/dev/null)"
if [ "$put_status" = "200" ] && [ "$got" = "true|7|upstream_publish_time" ]; then pass
else fail "age gate not configured (PUT ${put_status}, GET ${API_STATUS} -> ${got})" "${put_body:0:300}"; end_suite; fi

# ---------------------------------------------------------------------------
# HTML simple index (attach_pypi_publish_times)
# ---------------------------------------------------------------------------
HTML_OUT="${WORK_DIR}/index.html"
meta=$(get_index "text/html" "$HTML_OUT"); html_status="${meta%%|*}"
html_body="$(cat "$HTML_OUT" 2>/dev/null)"
html_snip="HTTP ${html_status}
index[0:1200]=${html_body:0:1200}"

begin_test "CONTROL: HTML simple index is served (HTTP 200)"
if [ "$html_status" = "200" ]; then pass; else fail "HTML index HTTP ${html_status}" "$html_snip"; fi

begin_test "CONTROL: HTML index lists ${EXACT_WHEEL} (exact release key, old)"
if printf '%s' "$html_body" | grep -qF "$EXACT_WHEEL"; then pass
else fail "old exact-key release missing from the HTML index" "$html_snip"; fi

begin_test "CONTROL: HTML index omits ${YOUNG_WHEEL} (uploaded a day ago)"
if printf '%s' "$html_body" | grep -qF "$YOUNG_WHEEL"; then
  fail "young release leaked into the HTML index (gate not engaged)" "$html_snip"
else pass; fi

begin_test "CONTROL: HTML index omits ${ORPHAN_WHEEL} (no PEP 440-equal release)"
if printf '%s' "$html_body" | grep -qF "$ORPHAN_WHEEL"; then
  fail "a version with no equal release key leaked into the HTML index" "$html_snip"
else pass; fi

begin_test "FIX #4907: HTML index lists ${EQUAL_WHEEL} (release 13.0.3, 2026-04-14)"
if printf '%s' "$html_body" | grep -qF "$EQUAL_WHEEL"; then pass
else fail "#4907: the months-old 13.0.3.0 file was dropped from the HTML index (exact-string publish-time lookup missed release 13.0.3)" "$html_snip"; fi

# ---------------------------------------------------------------------------
# PEP 691 JSON simple index (fill_missing_publish_times; the mock sends no
# upload-time, so the Warehouse JSON fallback decides every version)
# ---------------------------------------------------------------------------
JSON_OUT="${WORK_DIR}/index.json"
meta=$(get_index "application/vnd.pypi.simple.v1+json" "$JSON_OUT")
json_status="${meta%%|*}"; json_ct="${meta#*|}"
json_files="$(jq -r '.files[]?.filename' "$JSON_OUT" 2>/dev/null)"
json_snip="HTTP ${json_status} content-type=${json_ct}
files=${json_files}
body[0:800]=$(head -c 800 "$JSON_OUT" 2>/dev/null)"

begin_test "CONTROL: PEP 691 JSON simple index is served (HTTP 200, JSON)"
if [ "$json_status" = "200" ] && printf '%s' "$json_ct" | grep -q "vnd.pypi.simple.v1+json"; then
  JSON_OK=1; pass
else
  JSON_OK=0; fail "JSON index not served as PEP 691 (HTTP ${json_status}, ${json_ct})" "$json_snip"
fi

json_has() { printf '%s\n' "$json_files" | grep -qxF "$1"; }

if [ "$JSON_OK" = "1" ]; then
  begin_test "CONTROL: JSON index lists ${EXACT_WHEEL}"
  if json_has "$EXACT_WHEEL"; then pass; else fail "old exact-key release missing from the JSON index" "$json_snip"; fi

  begin_test "CONTROL: JSON index omits ${YOUNG_WHEEL}"
  if json_has "$YOUNG_WHEEL"; then fail "young release leaked into the JSON index" "$json_snip"; else pass; fi

  begin_test "CONTROL: JSON index omits ${ORPHAN_WHEEL}"
  if json_has "$ORPHAN_WHEEL"; then fail "a version with no equal release key leaked into the JSON index" "$json_snip"; else pass; fi

  begin_test "FIX #4907: JSON index lists ${EQUAL_WHEEL}"
  if json_has "$EQUAL_WHEEL"; then pass
  else fail "#4907: the months-old 13.0.3.0 file was dropped from the PEP 691 JSON index (Warehouse fallback lookup missed release 13.0.3)" "$json_snip"; fi
fi

# ---------------------------------------------------------------------------
# Downloads (apply_pypi_download_age_gate). Withheld ones first.
# ---------------------------------------------------------------------------
begin_test "CONTROL: ${YOUNG_WHEEL} download is withheld (451)"
st=$(get_download "$YOUNG_WHEEL" "${WORK_DIR}/young.bin")
if [ "$st" = "451" ]; then pass
else fail "young release download HTTP ${st}, expected 451" "$(head -c 300 "${WORK_DIR}/young.bin" 2>/dev/null)"; fi

begin_test "CONTROL: ${ORPHAN_WHEEL} download is withheld (451)"
st=$(get_download "$ORPHAN_WHEEL" "${WORK_DIR}/orphan.bin")
if [ "$st" = "451" ]; then pass
else fail "no-equal-release download HTTP ${st}, expected 451 (a non-equal version must stay gated)" "$(head -c 300 "${WORK_DIR}/orphan.bin" 2>/dev/null)"; fi

begin_test "FIX #4907: ${EQUAL_WHEEL} downloads 200 with the upstream bytes"
st=$(get_download "$EQUAL_WHEEL" "${WORK_DIR}/equal.bin")
want="$(mock_sha "$EQUAL_WHEEL")"; got="$(file_sha "${WORK_DIR}/equal.bin")"
if [ "$st" = "200" ] && [ -n "$want" ] && [ "$want" = "$got" ]; then pass
else fail "#4907: months-old 13.0.3.0 download HTTP ${st} (expected 200), sha ${got:-none} vs mock ${want:-unknown}" "$(head -c 300 "${WORK_DIR}/equal.bin" 2>/dev/null)"; fi

begin_test "CONTROL: ${EXACT_WHEEL} downloads 200 with the upstream bytes"
st=$(get_download "$EXACT_WHEEL" "${WORK_DIR}/exact.bin")
want="$(mock_sha "$EXACT_WHEEL")"; got="$(file_sha "${WORK_DIR}/exact.bin")"
if [ "$st" = "200" ] && [ -n "$want" ] && [ "$want" = "$got" ]; then pass
else fail "exact-key old release download HTTP ${st} (expected 200), sha ${got:-none} vs mock ${want:-unknown}" "$(head -c 300 "${WORK_DIR}/exact.bin" 2>/dev/null)"; fi

# ---------------------------------------------------------------------------
# The gate read its publish times from the mock's Warehouse JSON.
# ---------------------------------------------------------------------------
begin_test "CONTROL: the backend fetched /pypi/${PKG}/json from the mock"
mlog="$(docker exec "$MOCK" python3 -c \
  "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1/__log').read().decode())" 2>/dev/null)"
if printf '%s' "$mlog" | grep -q "GET /pypi/${PKG}/json"; then pass
else fail "no Warehouse JSON fetch in the mock log" "${mlog:0:1200}"; fi

end_suite
